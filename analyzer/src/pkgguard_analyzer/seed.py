"""Pre-fill the database: scan a list of packages locally, then upload the results to the cloud.

  uv run pkgguard-seed scan                  # scan the default list (resumable)
  uv run pkgguard-seed upload --stack pkgguard   # push results to the deployed DynamoDB + S3
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

from pkgguard_analyzer.ai.audit.auditor import make_full_auditor
from pkgguard_analyzer.ai.config import AIConfig, AIMode
from pkgguard_analyzer.ai.reviewer import make_reviewer
from pkgguard_analyzer.analyze import analyze, make_client
from pkgguard_analyzer.npm_registry import RegistryError, fetch_abbreviated_packument, resolve_version
from pkgguard_analyzer.schema import RanOn, Report, ScanStatus, VerdictRecord

DEFAULT_OUT = Path("tmp/seed")


def default_packages() -> list[str]:
    text = files("pkgguard_analyzer").joinpath("data/seed_packages.txt").read_text()
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def read_package_list(path: Path | None) -> list[str]:
    if path is None:
        return default_packages()
    return [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


@dataclass
class SeedResult:
    name: str
    version: str | None
    outcome: str  # "scanned", "already scanned", "error"
    detail: str = ""


def saved_results(out_dir: Path) -> list[tuple[VerdictRecord, Report | None]]:
    results = []
    for record_path in sorted(out_dir.rglob("record.json")):
        record = VerdictRecord.model_validate_json(record_path.read_text())
        report_path = record_path.with_name("report.json")
        report = Report.model_validate_json(report_path.read_text()) if report_path.exists() else None
        results.append((record, report))
    return results


def scan_one(name: str, out_dir: Path, reviewer, ai_mode: AIMode, rescan: bool, auditor=None) -> SeedResult:
    client = make_client()
    try:
        version = resolve_version(fetch_abbreviated_packument(client, name), None)
        scan_dir = out_dir / name / version
        if not rescan and (scan_dir / "record.json").exists():
            return SeedResult(name, version, "already scanned")
        result = analyze(name, version, out_dir=out_dir, ran_on=RanOn.LOCAL, client=client, reviewer=reviewer, ai_mode=ai_mode, auditor=auditor)
        result.scan_dir.mkdir(parents=True, exist_ok=True)
        (result.scan_dir / "record.json").write_text(result.record.model_dump_json(by_alias=True, indent=2))
        if result.report:
            (result.scan_dir / "report.json").write_text(result.report.model_dump_json(by_alias=True, indent=2))
        # Unpacked files aren't needed after the scan and can be large.
        _remove_tree(result.scan_dir / "files")
        record = result.record
        detail = f"{record.verdict} ({record.confidence}, {record.decided_by})" if record.verdict else f"{record.status}: {record.failure_reason}"
        if result.report and (review := result.report.ai_review):
            detail += f" · {review.mode}, {review.duration_seconds:.0f}s, {(review.input_tokens or 0):,} tokens"
            if review.coverage:
                detail += f", {review.coverage.files_analyzed}/{review.coverage.files_total} files"
        if result.report and result.report.ai_error:
            detail += f" · AI failed: {result.report.ai_error[:80]}"
        return SeedResult(name, version, "scanned", detail)
    except (RegistryError, ValueError, OSError) as error:
        return SeedResult(name, None, "error", str(error)[:200])
    except Exception as error:  # keep going: one bad package shouldn't stop the batch
        return SeedResult(name, None, "error", f"{type(error).__name__}: {error}"[:200])
    finally:
        client.close()


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def run_scan(args: argparse.Namespace) -> int:
    load_dotenv(find_dotenv(usecwd=True))
    config = AIConfig.from_env()
    reviewer, auditor, ai_mode = None, None, AIMode.OFF
    if not args.no_ai:
        if problem := config.problem():
            print(f"error: AI review can't run ({problem}). Fix .env or pass --no-ai.", file=sys.stderr)
            return 2
        ai_mode = config.mode
        if args.full_audit:
            auditor = make_full_auditor(config)
        else:
            reviewer = make_reviewer(config)

    packages = read_package_list(args.list)
    ai_label = f"full audit (coordinator {auditor.model_id}, workers {auditor.worker_model_id})" if auditor else ai_mode
    print(f"Scanning {len(packages)} packages into {args.out} ({args.parallel} at a time, AI: {ai_label})", flush=True)
    results: list[SeedResult] = []
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = [pool.submit(scan_one, name, args.out, reviewer, ai_mode, args.rescan, auditor) for name in packages]
        for done, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            label = f"{result.name}@{result.version}" if result.version else result.name
            print(f"[{done:>3}/{len(packages)}] {label:<32} {result.outcome}{': ' + result.detail if result.detail else ''}", flush=True)

    errors = [r for r in results if r.outcome == "error"]
    print_summary(args.out)
    if errors:
        print(f"\n{len(errors)} package(s) failed. Re-run the same command to retry only those.")
    return 1 if errors else 0


def print_summary(out_dir: Path) -> None:
    saved = saved_results(out_dir)
    counts: dict[str, int] = {}
    for record, _ in saved:
        key = record.verdict.value if record.verdict else record.status.value
        counts[key] = counts.get(key, 0) + 1
    print(f"\nSaved results: {len(saved)} · " + " · ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    flagged = [r for r, _ in saved if r.verdict and r.verdict.value != "SAFE"]
    for record in flagged:
        print(f"  {record.verdict:<10} {record.package.name}@{record.package.version}: {record.summary}")


def stack_outputs(stack_name: str, region: str | None) -> dict[str, str]:
    import boto3

    stack = boto3.client("cloudformation", region_name=region).describe_stacks(StackName=stack_name)["Stacks"][0]
    return {output["OutputKey"]: output["OutputValue"] for output in stack.get("Outputs", [])}


def upload_results(saved, store, s3, bucket: str, force: bool) -> tuple[int, int]:
    """Upload local results. Existing completed cloud records are kept unless force is set."""
    from pkgguard_analyzer.cloud.scan_handler import report_key

    uploaded = skipped = 0
    for record, report in saved:
        if record.status != ScanStatus.COMPLETE:
            skipped += 1
            continue
        existing = store.get(record.package.name, record.package.version)
        if existing and existing.status == ScanStatus.COMPLETE and not force:
            skipped += 1
            continue
        if report is not None:
            key = report_key(record.package.name, record.package.version, report.analyzer_version)
            s3.put_object(Bucket=bucket, Key=key, Body=report.model_dump_json(by_alias=True).encode(), ContentType="application/json")
            record = record.model_copy(update={"report_s3_key": key})
        store.put_seeded(record)
        store.record_completed(record)
        uploaded += 1
    return uploaded, skipped


def run_upload(args: argparse.Namespace) -> int:
    import boto3

    from pkgguard_analyzer.cloud.store import VerdictStore

    outputs = stack_outputs(args.stack, args.region)
    saved = saved_results(args.out)
    if not saved:
        print(f"No saved results in {args.out}. Run `pkgguard-seed scan` first.", file=sys.stderr)
        return 2
    store = VerdictStore(boto3.resource("dynamodb", region_name=args.region), outputs["TableName"])
    s3 = boto3.client("s3", region_name=args.region)
    uploaded, skipped = upload_results(saved, store, s3, outputs["ReportsBucketName"], args.force)
    print(f"Uploaded {uploaded} results to stack {args.stack!r}; skipped {skipped} (not complete, or already in the cloud).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pkgguard-seed", description="Pre-fill the PkgGuard database.")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan packages locally and save results")
    scan.add_argument("--list", type=Path, help="file with one package name per line (default: built-in list of 50)")
    scan.add_argument("--out", type=Path, default=DEFAULT_OUT)
    scan.add_argument("--parallel", type=int, default=3, help="packages scanned at the same time")
    scan.add_argument("--rescan", action="store_true", help="scan again even if a result is already saved")
    scan.add_argument("--no-ai", action="store_true")
    scan.add_argument("--full-audit", action="store_true", help="AI reads the complete code with parallel sub-agents")
    scan.set_defaults(run=run_scan)

    upload = commands.add_parser("upload", help="upload saved results to the deployed cloud stack")
    upload.add_argument("--stack", default="pkgguard")
    upload.add_argument("--region", default="ap-south-1")
    upload.add_argument("--out", type=Path, default=DEFAULT_OUT)
    upload.add_argument("--force", action="store_true", help="overwrite records already complete in the cloud")
    upload.set_defaults(run=run_upload)

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
