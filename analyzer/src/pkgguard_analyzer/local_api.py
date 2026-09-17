"""Local stand-in for the deployed cloud API (Step 3), so the CLI, MCP tool and website can be
built and tested against the real `/v1/*` contract before AWS is deployed.

Reuses `cloud.api.handler` and `cloud.scan_handler.handler` unchanged: only the storage layer
differs (an in-memory store instead of DynamoDB, local files instead of S3, a thread pool instead
of Step Functions). Not meant for production use — the store is lost on restart and there's no
auth, rate limiting beyond what `cloud.api` already does, or multi-process support.

  uv run pkgguard-dev-api                  # serves http://127.0.0.1:8787
"""

import argparse
import json
import logging
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from dotenv import find_dotenv, load_dotenv

from pkgguard_analyzer.ai.config import AIConfig, AIMode
from pkgguard_analyzer.ai.reviewer import make_reviewer
from pkgguard_analyzer.analyze import make_client
from pkgguard_analyzer.cloud import scan_handler
from pkgguard_analyzer.cloud.api import Services, handler
from pkgguard_analyzer.schema import ScanStatus, Verdict, VerdictRecord

log = logging.getLogger("pkgguard.dev_api")

DEFAULT_PORT = 8787
DEFAULT_OUT = Path("tmp/dev-api")
FEED_VERDICTS = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
RETRYABLE = (ScanStatus.PENDING, ScanStatus.SCANNING, ScanStatus.FAILED)


class LocalStore:
    """Same method surface as cloud.store.VerdictStore, backed by an in-memory dict instead of DynamoDB."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[tuple[str, str], VerdictRecord] = {}
        self._by_scan_id: dict[str, VerdictRecord] = {}
        self._stats: dict[str, int] = {}

    def get(self, name: str, version: str) -> VerdictRecord | None:
        with self._lock:
            return self._by_key.get((name, version))

    def get_many(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], VerdictRecord]:
        with self._lock:
            return {key: self._by_key[key] for key in dict.fromkeys(packages) if key in self._by_key}

    def by_scan_id(self, scan_id: str) -> VerdictRecord | None:
        with self._lock:
            return self._by_scan_id.get(scan_id)

    def versions(self, name: str, limit: int = 50) -> list[VerdictRecord]:
        with self._lock:
            items = [r for (n, _), r in self._by_key.items() if n == name]
        return sorted(items, key=lambda r: r.requested_at, reverse=True)[:limit]

    def feed(self, limit: int = 50) -> list[VerdictRecord]:
        with self._lock:
            items = [r for r in self._by_key.values() if r.status == ScanStatus.COMPLETE and r.verdict in FEED_VERDICTS]
        return sorted(items, key=lambda r: r.analyzed_at or r.requested_at, reverse=True)[:limit]

    def claim_scan(self, pending: VerdictRecord, stale_before: datetime) -> tuple[bool, VerdictRecord | None]:
        key = (pending.package.name, pending.package.version)
        with self._lock:
            current = self._by_key.get(key)
            if current is not None and not (current.status in RETRYABLE and current.requested_at < stale_before):
                return False, current
            self._by_key[key] = pending
            self._by_scan_id[pending.scan_id] = pending
            return True, pending

    def _replace_if_current(self, record: VerdictRecord, allowed: tuple[ScanStatus, ...]) -> bool:
        key = (record.package.name, record.package.version)
        with self._lock:
            current = self._by_key.get(key)
            if current is None or current.scan_id != record.scan_id or current.status not in allowed:
                return False
            self._by_key[key] = record
            self._by_scan_id[record.scan_id] = record
            return True

    def mark_scanning(self, name: str, version: str, scan_id: str) -> VerdictRecord | None:
        with self._lock:
            current = self._by_key.get((name, version))
            if current is None or current.scan_id != scan_id or current.status != ScanStatus.PENDING:
                return None
            scanning = current.model_copy(update={"status": ScanStatus.SCANNING})
            self._by_key[(name, version)] = scanning
            self._by_scan_id[scan_id] = scanning
            return scanning

    def save_result(self, record: VerdictRecord) -> bool:
        return self._replace_if_current(record, (ScanStatus.PENDING, ScanStatus.SCANNING))

    def save_failed(self, name: str, version: str, scan_id: str, reason: str) -> bool:
        with self._lock:
            current = self._by_key.get((name, version))
        if current is None or current.scan_id != scan_id:
            return False
        failed = current.model_copy(update={"status": ScanStatus.FAILED, "failure_reason": reason[:500] or "scan failed"})
        return self._replace_if_current(failed, (ScanStatus.PENDING, ScanStatus.SCANNING))

    def put_seeded(self, record: VerdictRecord) -> None:
        with self._lock:
            self._by_key[(record.package.name, record.package.version)] = record
            self._by_scan_id[record.scan_id] = record

    def record_completed(self, record: VerdictRecord) -> None:
        outcome = (record.verdict.value if record.verdict else record.status.value).lower()
        with self._lock:
            self._stats["scansCompleted"] = self._stats.get("scansCompleted", 0) + 1
            self._stats[outcome] = self._stats.get(outcome, 0) + 1

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {key: self._stats.get(key, 0) for key in ("scansCompleted", "safe", "suspicious", "malicious", "skipped")}

    def consume_scan_quota(self, client_id: str, now: datetime, per_client: int, per_day: int) -> str | None:
        return None  # no quota locally


class LocalS3:
    """Just enough of the boto3 S3 client interface for cloud.api / cloud.scan_handler: local files instead."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def put_object(self, Bucket: str, Key: str, Body: bytes | str, ContentType: str | None = None) -> None:
        path = self.root / Key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Body if isinstance(Body, bytes) else Body.encode())

    def get_object(self, Bucket: str, Key: str) -> dict:
        return {"Body": _LocalObjectBody((self.root / Key).read_bytes())}


class _LocalObjectBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class LocalStepFunctions:
    """Runs the scan in a background thread instead of starting a real Step Functions execution."""

    def __init__(self, run_scan) -> None:
        self._run_scan = run_scan
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pkgguard-scan")

    def start_execution(self, stateMachineArn: str, name: str, input: str) -> None:
        payload = json.loads(input)
        self._pool.submit(self._run_scan, payload["name"], payload["version"], payload["scanId"])


def make_run_scan(scan_services: scan_handler.ScanServices):
    def run_scan(name: str, version: str, scan_id: str) -> None:
        try:
            scan_handler.handler({"name": name, "version": version, "scanId": scan_id}, None, services=scan_services)
        except Exception as error:  # a Step Functions catch step would normally do this
            log.exception("scan %s for %s@%s failed", scan_id, name, version)
            scan_services.store.save_failed(name, version, scan_id, str(error))

    return run_scan


class DevServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], request_handler: type[BaseHTTPRequestHandler], services: Services) -> None:
        super().__init__(address, request_handler)
        self.services = services
        self.daemon_threads = True


class RequestHandler(BaseHTTPRequestHandler):
    server: DevServer

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8") if length else None
        event = {
            "rawPath": parsed.path,
            "queryStringParameters": query or None,
            "body": body,
            "isBase64Encoded": False,
            "requestContext": {"http": {"method": method, "sourceIp": self.client_address[0]}},
        }
        result = handler(event, None, services=self.server.services)
        payload = result["body"].encode("utf-8")
        self.send_response(result["statusCode"])
        for key, value in result["headers"].items():
            self.send_header(key, value)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A002 (matches BaseHTTPRequestHandler's signature)
        log.info("%s - %s", self.client_address[0], format % args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pkgguard-dev-api", description="Local HTTP API for developing the CLI/MCP tool/website without AWS.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="where reports and scan work dirs go")
    parser.add_argument("--no-ai", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    load_dotenv(find_dotenv(usecwd=True))
    config = AIConfig.from_env()
    reviewer, ai_mode = None, AIMode.OFF
    if not args.no_ai:
        if problem := config.problem():
            print(f"note: AI review disabled ({problem}). Add it to .env or pass --no-ai to silence this.", file=sys.stderr)
        else:
            reviewer, ai_mode = make_reviewer(config), config.mode

    store = LocalStore()
    s3 = LocalS3(args.out / "reports")
    scan_services = scan_handler.ScanServices(store=store, s3=s3, bucket="local", reviewer=reviewer, ai_mode=ai_mode, http=make_client())

    api_services = Services(
        store=store,
        s3=s3,
        stepfunctions=LocalStepFunctions(make_run_scan(scan_services)),
        http=make_client(),
        bucket="local",
        state_machine_arn="local",
        max_new_scans_per_day=1_000_000,
        max_new_scans_per_client_per_day=1_000_000,
    )

    shutil.rmtree(scan_handler.WORK_ROOT, ignore_errors=True)
    server = DevServer(("127.0.0.1", args.port), RequestHandler, api_services)
    print(f"PkgGuard dev API on http://127.0.0.1:{args.port} (AI: {ai_mode.value if reviewer else 'off'})")
    print("Routes: GET /v1/package /v1/report /v1/package/versions /v1/scans/{id} /v1/feed /v1/stats · POST /v1/check")
    print(f"Reports saved under {s3.root}/. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
