"""Batch run for the sandbox pilot: full scan (static + AI + AWS sandbox) over a list of npm packages.

  uv run pkgguard-sandbox-pilot ../eval/pilot/clean-50.txt --out tmp/pilot

The laptop only downloads and READS package text (nothing is executed here); the sandbox runs on AWS.
Only for packages that are still on the public npm registry. Resumable: finished packages are skipped.
Each result is saved (record + report) so it can be re-scored later without re-running anything."""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def parse_list(path: Path) -> list[tuple[str, str]]:
    items = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            parts = line.split()
            items.append((parts[0], parts[1] if len(parts) > 1 else "clean"))
    return items


def summarize(name: str, label: str, record, report, seconds: float, error: str | None = None) -> dict:
    if error or record is None or report is None:
        return {"name": name, "label": label, "error": error or "no result", "seconds": round(seconds, 1)}
    sandbox = report.sandbox
    return {
        "name": name,
        "label": label,
        "version": record.package.version,
        "status": record.status.value,
        "verdict": record.verdict.value if record.verdict else None,
        "confidence": record.confidence.value if record.confidence else None,
        "decidedBy": record.decided_by.value if record.decided_by else None,
        "summary": record.summary,
        "aiVerdict": report.ai_review.verdict.value if report.ai_review else None,
        "sandboxStatus": sandbox.status.value if sandbox else None,
        "sandboxFindings": [[f.severity.value, f.rule_id, f.title[:100]] for f in (sandbox.findings if sandbox else [])],
        "entryLoaded": sandbox.coverage.entry_loaded if sandbox else None,
        "staticFindings": [[f.severity.value, f.rule_id] for f in report.findings if f.layer.value != "sandbox" and f.severity.value != "LOW"],
        "seconds": round(seconds, 1),
    }


def main() -> None:
    import boto3
    from dotenv import find_dotenv, load_dotenv

    from pkgguard_analyzer.ai.config import AIConfig
    from pkgguard_analyzer.ai.reviewer import make_reviewer
    from pkgguard_analyzer.analyze import analyze
    from pkgguard_analyzer.cloud.sandbox_runner import FargateSandbox
    from pkgguard_analyzer.sandbox.remote import stack_config
    from pkgguard_analyzer.schema import RanOn

    ap = argparse.ArgumentParser(prog="pkgguard-sandbox-pilot")
    ap.add_argument("list", type=Path)
    ap.add_argument("--out", type=Path, default=Path("tmp/pilot"))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--no-ai", action="store_true")
    args = ap.parse_args()

    load_dotenv(find_dotenv(usecwd=True))
    cfg = AIConfig.from_env()
    if not args.no_ai and cfg.problem():
        sys.exit(f"AI unavailable: {cfg.problem()}")
    reviewer = None if args.no_ai else make_reviewer(cfg)
    box = FargateSandbox(stack_config("pkgguard", "ap-south-1"), boto3.client("ecs", region_name="ap-south-1"), boto3.client("s3", region_name="ap-south-1"))
    args.out.mkdir(parents=True, exist_ok=True)
    results_dir = args.out / "results"
    results_dir.mkdir(exist_ok=True)

    def run(item: tuple[str, str]) -> dict:
        name, label = item
        target = results_dir / (name.replace("/", "__") + ".json")
        if target.exists():
            return json.loads(target.read_text())["summary"]
        started = time.time()
        scan_id = "pilot-" + name.replace("/", "_").replace("@", "")
        try:
            res = analyze(name, out_dir=args.out / "work", ran_on=RanOn.CLOUD, reviewer=reviewer, ai_mode=cfg.mode if reviewer else None, scan_id=scan_id, sandbox_runner=box.runner_for(scan_id, name, "latest"))
            summary = summarize(name, label, res.record, res.report, time.time() - started)
            payload = {"summary": summary, "record": res.record.model_dump(mode="json", by_alias=True), "report": res.report.model_dump(mode="json", by_alias=True) if res.report else None}
        except Exception as error:
            summary = summarize(name, label, None, None, time.time() - started, f"{type(error).__name__}: {error}"[:300])
            payload = {"summary": summary}
        target.write_text(json.dumps(payload))
        print(f"[{summary.get('verdict') or 'ERROR':10}] {name:22} {label:6} sandbox={summary.get('sandboxStatus')} findings={[f[1].removeprefix('sandbox.') for f in summary.get('sandboxFindings', []) if f[0] != 'LOW']} {summary.get('error', '')}", flush=True)
        return summary

    items = parse_list(args.list)
    with ThreadPoolExecutor(args.workers) as pool:
        summaries = list(pool.map(run, items))
    (args.out / "summary.json").write_text(json.dumps(summaries, indent=1))
    flagged = [s for s in summaries if s.get("verdict") in ("SUSPICIOUS", "MALICIOUS")]
    errors = [s for s in summaries if s.get("error")]
    print(f"\n{len(summaries)} packages: {len(flagged)} flagged, {len(errors)} errors")
    for s in flagged:
        print(f"  FLAGGED {s['name']} ({s['label']}): {s['verdict']} by {s['decidedBy']}: {s['summary'][:110]}")
    for s in errors:
        print(f"  ERROR {s['name']}: {s['error']}")


if __name__ == "__main__":
    main()
