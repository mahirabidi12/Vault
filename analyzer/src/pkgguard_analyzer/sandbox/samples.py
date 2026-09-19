"""Drives the malware evaluation on AWS from a laptop. The laptop only sends names and receives short summaries;
sample contents never leave S3/Lambda/Fargate.

  uv run pkgguard-sandbox-samples fetch ../eval/pilot/malware-50-plan.json
  uv run pkgguard-sandbox-samples run   ../eval/pilot/malware-50-plan.json --run-id pilot1
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import boto3
from botocore.config import Config

from pkgguard_analyzer.cloud.sample_handler import sample_key

REGION = "ap-south-1"
OUT = Path("tmp/pilot-malware")


def scan_function_name() -> str:
    cf = boto3.client("cloudformation", region_name=REGION)
    return cf.describe_stack_resource(StackName="pkgguard", LogicalResourceId="ScanFunction")["StackResourceDetail"]["PhysicalResourceId"]


def _transient(summary: dict) -> bool:
    """A network or throttling failure says nothing about the package: never save it as a result, so a rerun retries it."""
    error = summary.get("error", "")
    return bool(error) and error != "no result" and any(k in error for k in ("EndpointConnectionError", "ConnectionError", "Throttl", "TooManyRequests", "Timeout", "timed out", "ReadTimeout"))


def invoke(fn: str, payload: dict) -> dict:
    client = boto3.client("lambda", region_name=REGION, config=Config(read_timeout=300, connect_timeout=15, retries={"max_attempts": 1}))  # a scan takes ~90s; do not sit on a dead connection
    resp = client.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise RuntimeError(f"{body.get('errorType')}: {body.get('errorMessage')}"[:300])
    return body


def cmd_fetch(plan: list[dict], batch: int) -> None:
    fn = scan_function_name()
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    for i in range(0, len(plan), batch):
        chunk = plan[i : i + batch]
        results += invoke(fn, {"action": "fetch_samples", "samples": chunk})["results"]
        print(f"fetched {min(i + batch, len(plan))}/{len(plan)}", flush=True)
    (OUT / "fetched.json").write_text(json.dumps(results, indent=1))
    ok = [r for r in results if r["ok"]]
    print(f"{len(ok)} stored in S3, {len(results) - len(ok)} failed")
    for r in results:
        if not r["ok"]:
            print("  FAILED", r["name"], r.get("error"))


def cmd_run(plan: list[dict], run_id: str, workers: int, store: bool = False) -> None:
    fn = scan_function_name()
    fetched = {r["dirName"]: r for r in json.loads((OUT / "fetched.json").read_text()) if r["ok"]}
    todo = [p for p in plan if p["dirName"] in fetched]
    results_dir = OUT / run_id
    results_dir.mkdir(parents=True, exist_ok=True)

    def run(p: dict) -> dict:
        target = results_dir / (p["name"].replace("/", "__") + ".json")
        if target.exists():
            return json.loads(target.read_text())
        label = "compromised" if p["category"] == "compromised_lib" else "malicious"
        try:
            out = invoke(fn, {"action": "analyze_sample", "run": run_id, "store": store, "sample": {"name": p["name"], "version": p["version"], "label": label, "s3Key": sample_key(p["dirName"], p["version"])}})
            summary = out["summary"]
        except Exception as error:
            summary = {"name": p["name"], "label": label, "error": f"{type(error).__name__}: {error}"[:300]}
        if not _transient(summary):
            target.write_text(json.dumps(summary))
        print(f"[{summary.get('verdict') or 'ERROR':10}] {p['name']:38} by={summary.get('decidedBy')} sandbox={summary.get('sandboxStatus')} {summary.get('error', '')}", flush=True)
        return summary

    with ThreadPoolExecutor(workers) as pool:
        summaries = list(pool.map(run, todo))
    (OUT / f"{run_id}-summary.json").write_text(json.dumps(summaries, indent=1))
    print(f"\n{len(summaries)} samples analysed")


def cmd_run_packages(list_file: Path, run_id: str, workers: int, store: bool) -> None:
    """Real npm packages (latest version, real threat intel), scanned by the Lambda like a live scan."""
    fn = scan_function_name()
    results_dir = OUT / run_id
    results_dir.mkdir(parents=True, exist_ok=True)
    items: list[tuple[str, str, str | None]] = []
    for line in list_file.read_text().splitlines():
        parts = line.split("#", 1)[0].split()
        if parts:
            items.append((parts[0], parts[1] if len(parts) > 1 else "clean", parts[2] if len(parts) > 2 else None))  # optional exact version

    def run(item: tuple[str, str, str | None]) -> dict:
        name, label, version = item
        target = results_dir / (name.replace("/", "__") + ".json")
        if target.exists():
            return json.loads(target.read_text())
        try:
            summary = invoke(fn, {"action": "analyze_package", "run": run_id, "store": store, "name": name, "label": label, "version": version})["summary"]
        except Exception as error:
            summary = {"name": name, "label": label, "error": f"{type(error).__name__}: {error}"[:300]}
        if not _transient(summary):
            target.write_text(json.dumps(summary))
        print(f"[{summary.get('verdict') or 'ERROR':10}] {name:32} by={summary.get('decidedBy')} sandbox={summary.get('sandboxStatus')} {summary.get('error', '')}", flush=True)
        return summary

    with ThreadPoolExecutor(workers) as pool:
        summaries = list(pool.map(run, items))
    (OUT / f"{run_id}-summary.json").write_text(json.dumps(summaries, indent=1))
    print(f"\n{len(summaries)} packages analysed")


def main() -> None:
    ap = argparse.ArgumentParser(prog="pkgguard-sandbox-samples")
    ap.add_argument("action", choices=["fetch", "run", "run-packages"])
    ap.add_argument("plan", type=Path)
    ap.add_argument("--store", action="store_true", help="also write each finished verdict + report into the live database")
    ap.add_argument("--run-id", default="pilot1")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--batch", type=int, default=10)
    args = ap.parse_args()
    if args.action == "run-packages":
        return cmd_run_packages(args.plan, args.run_id, args.workers, args.store)
    plan = json.loads(args.plan.read_text())
    cmd_fetch(plan, args.batch) if args.action == "fetch" else cmd_run(plan, args.run_id, args.workers, args.store)


if __name__ == "__main__":
    sys.exit(main())
