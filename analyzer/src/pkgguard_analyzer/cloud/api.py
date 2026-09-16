"""HTTP API (API Gateway HTTP API, payload v2). One Lambda serves every /v1 route.

Clients never touch DynamoDB directly: this handler validates input, applies scan limits and
starts scans through Step Functions.
"""

import base64
import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any

import boto3
import httpx
from botocore.exceptions import ClientError
from pydantic import ValidationError
from ulid import ULID

from pkgguard_analyzer import ANALYZER_VERSION
from pkgguard_analyzer.analyze import make_client
from pkgguard_analyzer.cloud.store import VerdictStore, needs_rescan
from pkgguard_analyzer.npm_registry import PackageNotFound, fetch_abbreviated_packument, resolve_version
from pkgguard_analyzer.schema import EXACT_VERSION_RE, NPM_NAME_RE, Ecosystem, PackageRef, RanOn, ScanStatus, VerdictRecord

MAX_CHECK_PACKAGES = 200
FEED_LIMIT = 50
SCAN_PATH_RE = re.compile(r"^/v1/scans/([0-9A-Za-z]{10,40})$")
log = logging.getLogger()
log.setLevel(logging.INFO)


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Services:
    store: VerdictStore
    s3: Any
    stepfunctions: Any
    http: httpx.Client
    bucket: str
    state_machine_arn: str
    max_new_scans_per_day: int = 300
    max_new_scans_per_client_per_day: int = 30
    stale_after: timedelta = timedelta(minutes=15)
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


@cache
def default_services() -> Services:
    return Services(
        store=VerdictStore(boto3.resource("dynamodb"), os.environ["TABLE_NAME"]),
        s3=boto3.client("s3"),
        stepfunctions=boto3.client("stepfunctions"),
        http=make_client(),
        bucket=os.environ["BUCKET_NAME"],
        state_machine_arn=os.environ["STATE_MACHINE_ARN"],
        max_new_scans_per_day=int(os.environ.get("MAX_NEW_SCANS_PER_DAY", "300")),
        max_new_scans_per_client_per_day=int(os.environ.get("MAX_NEW_SCANS_PER_CLIENT_PER_DAY", "30")),
    )


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    body: str
    client_id: str

    @classmethod
    def from_event(cls, event: dict) -> "Request":
        body = event.get("body") or ""
        if event.get("isBase64Encoded") and body:
            body = base64.b64decode(body).decode("utf-8", "replace")
        http = event.get("requestContext", {}).get("http", {})
        return cls(
            method=http.get("method", "GET"),
            path=event.get("rawPath", ""),
            query=event.get("queryStringParameters") or {},
            body=body,
            client_id=http.get("sourceIp", "unknown"),
        )

    def package_name(self) -> str:
        if self.query.get("ecosystem", "npm") != Ecosystem.NPM.value:
            raise ApiError(400, "Only the npm ecosystem is supported.")
        name = (self.query.get("name") or "").strip()
        if not NPM_NAME_RE.fullmatch(name):
            raise ApiError(400, "Query parameter 'name' must be a valid npm package name.")
        return name


def handler(event: dict, context: object, services: Services | None = None) -> dict:
    services = services or default_services()
    request = Request.from_event(event)
    try:
        status, body = _route(request, services)
    except ApiError as error:
        status, body = error.status, {"error": error.message}
    except Exception:
        log.exception("unhandled error for %s %s", request.method, request.path)
        status, body = 500, {"error": "Internal error."}
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": body if isinstance(body, str) else json.dumps(body),
    }


def _route(request: Request, services: Services) -> tuple[int, Any]:
    routes = {
        ("GET", "/v1/package"): get_package,
        ("GET", "/v1/report"): get_report,
        ("GET", "/v1/package/versions"): get_versions,
        ("POST", "/v1/check"): check_packages,
        ("GET", "/v1/feed"): get_feed,
        ("GET", "/v1/stats"): get_stats,
    }
    if route := routes.get((request.method, request.path.rstrip("/"))):
        return route(request, services)
    if request.method == "GET" and (match := SCAN_PATH_RE.match(request.path)):
        return get_scan(match.group(1), services)
    raise ApiError(404, "Route not found.")


def _dump(record: VerdictRecord) -> dict:
    return record.model_dump(mode="json", by_alias=True)


def _status_code(record: VerdictRecord) -> int:
    return 202 if record.status in (ScanStatus.PENDING, ScanStatus.SCANNING) else 200


def _resolve(services: Services, name: str, version: str | None) -> str:
    try:
        return resolve_version(fetch_abbreviated_packument(services.http, name), version)
    except PackageNotFound as error:
        raise ApiError(404, str(error)) from error
    except httpx.HTTPError as error:
        raise ApiError(502, "The npm registry could not be reached. Try again shortly.") from error


def start_scan(services: Services, name: str, version: str, client_id: str) -> VerdictRecord:
    now = services.clock()
    if reason := services.store.consume_scan_quota(
        client_id, now, services.max_new_scans_per_client_per_day, services.max_new_scans_per_day
    ):
        raise ApiError(429, reason)

    pending = VerdictRecord(
        package=PackageRef(ecosystem=Ecosystem.NPM, name=name, version=version),
        status=ScanStatus.PENDING,
        scan_id=str(ULID()),
        requested_at=now,
        ran_on=RanOn.CLOUD,
        analyzer_version=ANALYZER_VERSION,
    )
    claimed, current = services.store.claim_scan(pending, now - services.stale_after)
    if not claimed:
        return current or pending  # someone else started this scan first; share it

    try:
        services.stepfunctions.start_execution(
            stateMachineArn=services.state_machine_arn,
            name=pending.scan_id,
            input=json.dumps({"name": name, "version": version, "scanId": pending.scan_id}),
        )
    except ClientError as error:
        log.exception("could not start scan %s", pending.scan_id)
        services.store.save_failed(name, version, pending.scan_id, "could not start the scan workflow")
        raise ApiError(502, "Could not start the scan. Try again shortly.") from error
    return pending


def lookup_or_scan(services: Services, name: str, version: str | None, client_id: str) -> VerdictRecord:
    stale_before = services.clock() - services.stale_after
    if version and EXACT_VERSION_RE.fullmatch(version):
        existing = services.store.get(name, version)
        if existing and not needs_rescan(existing, stale_before):
            return existing
    resolved = _resolve(services, name, version)
    existing = services.store.get(name, resolved)
    if existing and not needs_rescan(existing, stale_before):
        return existing
    return start_scan(services, name, resolved, client_id)


def get_package(request: Request, services: Services) -> tuple[int, dict]:
    version = (request.query.get("version") or "").strip() or None
    record = lookup_or_scan(services, request.package_name(), version, request.client_id)
    return _status_code(record), _dump(record)


def get_report(request: Request, services: Services) -> tuple[int, str]:
    name = request.package_name()
    version = (request.query.get("version") or "").strip()
    if not EXACT_VERSION_RE.fullmatch(version):
        raise ApiError(400, "Query parameter 'version' must be an exact version, e.g. 4.18.2.")
    record = services.store.get(name, version)
    if record is None or record.status != ScanStatus.COMPLETE or not record.report_s3_key:
        raise ApiError(404, "No completed report for this package version.")
    response = services.s3.get_object(Bucket=services.bucket, Key=record.report_s3_key)
    return 200, response["Body"].read().decode("utf-8")


def get_scan(scan_id: str, services: Services) -> tuple[int, dict]:
    record = services.store.by_scan_id(scan_id)
    if record is None:
        raise ApiError(404, "Scan not found.")
    return _status_code(record), _dump(record)


def get_versions(request: Request, services: Services) -> tuple[int, dict]:
    return 200, {"items": [_dump(r) for r in services.store.versions(request.package_name())]}


def get_feed(request: Request, services: Services) -> tuple[int, dict]:
    return 200, {"items": [_dump(r) for r in services.store.feed(FEED_LIMIT)]}


def get_stats(request: Request, services: Services) -> tuple[int, dict]:
    return 200, services.store.stats()


def check_packages(request: Request, services: Services) -> tuple[int, dict]:
    """Batch check (used by the CLI and lockfile scans). Versions must be exact; new ones start scans."""
    try:
        payload = json.loads(request.body or "{}")
        items = payload["packages"]
        assert isinstance(items, list)
    except (ValueError, KeyError, AssertionError) as error:
        raise ApiError(400, "Body must be JSON: {\"packages\": [{\"ecosystem\": \"npm\", \"name\": ..., \"version\": ...}]}") from error
    if len(items) > MAX_CHECK_PACKAGES:
        raise ApiError(400, f"At most {MAX_CHECK_PACKAGES} packages per request.")

    valid: list[PackageRef] = []
    errors: list[dict] = []
    for item in items:
        try:
            valid.append(PackageRef.model_validate(item))
        except ValidationError as error:
            errors.append({"package": item, "error": error.errors()[0]["msg"]})

    existing = services.store.get_many([(p.name, p.version) for p in valid])
    stale_before = services.clock() - services.stale_after
    results: list[dict] = []
    unique = {(p.name, p.version): p for p in valid}
    for package in unique.values():
        record = existing.get((package.name, package.version))
        if record is None or needs_rescan(record, stale_before):
            try:
                record = start_scan(services, package.name, package.version, request.client_id)
            except ApiError as error:
                errors.append({"package": package.model_dump(mode="json"), "error": error.message})
                continue
        results.append(_dump(record))
    return 200, {"results": results, "errors": errors}
