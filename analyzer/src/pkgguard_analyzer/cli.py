"""Scan one package from the terminal: uv run analyze express@4.18.2"""

import argparse
import json
import sys
from pathlib import Path

import httpx
from dotenv import find_dotenv, load_dotenv
from pydantic import ValidationError

from pkgguard_analyzer.ai.audit.auditor import make_full_auditor
from pkgguard_analyzer.ai.config import AIConfig, AIMode
from pkgguard_analyzer.ai.reviewer import make_reviewer
from pkgguard_analyzer.analyze import analyze, parse_spec
from pkgguard_analyzer.npm_registry import PackageNotFound
from pkgguard_analyzer.schema import ScanStatus

MAX_PRINTED_FINDINGS = 15


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="analyze", description="Scan one npm package version.")
    parser.add_argument("package", help="name or name@version, e.g. express@4.18.2 or @babel/core")
    parser.add_argument("version", nargs="?", help="exact version or dist-tag (default: latest)")
    parser.add_argument("--json", action="store_true", help="print the full record and report as JSON")
    parser.add_argument("--out", type=Path, default=Path("tmp/scans"), help="where results and unpacked files go")
    parser.add_argument("--no-ai", action="store_true", help="skip the AI review")
    parser.add_argument("--full-audit", action="store_true", help="AI reads the complete code with parallel sub-agents (slower)")
    args = parser.parse_args(argv)

    load_dotenv(find_dotenv(usecwd=True))
    config = AIConfig.from_env()
    ai_mode = AIMode.OFF if args.no_ai else config.mode
    reviewer = auditor = None
    if ai_mode != AIMode.OFF:
        if problem := config.problem():
            print(f"note: AI review skipped ({problem}). Add it to .env to enable.", file=sys.stderr)
            ai_mode = AIMode.OFF
        elif args.full_audit:
            auditor = make_full_auditor(config)
        else:
            reviewer = make_reviewer(config)

    name, spec_version = parse_spec(args.package)
    try:
        result = analyze(name, args.version or spec_version, out_dir=args.out, reviewer=reviewer, ai_mode=ai_mode, auditor=auditor)
    except (ValueError, ValidationError, PackageNotFound) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except httpx.HTTPError as error:
        print(f"error: could not reach npm: {error}", file=sys.stderr)
        return 1

    record, report = result.record, result.report
    result.scan_dir.mkdir(parents=True, exist_ok=True)
    (result.scan_dir / "record.json").write_text(record.model_dump_json(by_alias=True, indent=2))
    if report:
        (result.scan_dir / "report.json").write_text(report.model_dump_json(by_alias=True, indent=2))

    if args.json:
        output = {"record": record.model_dump(mode="json", by_alias=True)}
        if report:
            output["report"] = report.model_dump(mode="json", by_alias=True)
        print(json.dumps(output, indent=2))
        return 0

    print(f"\n{record.package.name}@{record.package.version}")
    if record.status != ScanStatus.COMPLETE:
        print(f"  Status:    {record.status} ({record.failure_reason})")
    else:
        print(f"  Verdict:   {record.verdict} (confidence {record.confidence}, decided by {record.decided_by})")
        print(f"  Summary:   {record.summary}")
    if report:
        code = report.code_scan
        if code:
            print(
                f"  Code:      {code['filesScanned']} files scanned, {code['filesParsed']} parsed"
                f", install-time files: {', '.join(code['installTimeFiles']) or 'none'}"
            )
        print(f"  Findings:  {len(report.findings)}")
        for finding in report.findings[:MAX_PRINTED_FINDINGS]:
            where = f"{finding.file}:{finding.line}" if finding.file and finding.line else finding.file
            extras = " [install]" if finding.install_time else ""
            extras += f" x{finding.occurrences}" if finding.occurrences > 1 else ""
            print(f"    [{finding.severity}] {finding.title}{extras}" + (f"  ({where})" if where else ""))
        if len(report.findings) > MAX_PRINTED_FINDINGS:
            print(f"    ... and {len(report.findings) - MAX_PRINTED_FINDINGS} more in report.json")
        osv, safedep = report.intel.get("osv", {}), report.intel.get("safedep", {})
        osv_text = osv.get("error") and "lookup failed" or f"{len(osv.get('maliciousIds', []))} malicious"
        safedep_text = safedep.get("error") and "lookup failed" or (
            "malware" if safedep.get("isMalware") else "not flagged" if safedep.get("found") else "no report"
        )
        print(f"  Intel:     OSV {osv_text} · SafeDep {safedep_text}")
        if review := report.ai_review:
            tokens = f", {review.input_tokens or 0:,} in / {review.output_tokens or 0:,} out tokens" if review.input_tokens else ""
            print(
                f"  AI:        {review.mode.replace('_', ' ')} → {review.verdict} ({review.confidence})"
                f" · {review.tool_calls} tool calls, read {len(review.files_read)} files{tokens}, {review.duration_seconds}s"
            )
            print(f"             {review.summary}")
            if coverage := review.coverage:
                print(
                    f"  Coverage:  {coverage.files_analyzed}/{coverage.files_total} code files, "
                    f"{coverage.bytes_analyzed:,}/{coverage.bytes_total:,} bytes, {coverage.chunks} parts"
                    f" ({coverage.chunks_failed} failed), {coverage.duplicates_skipped} duplicates skipped, workers: {coverage.worker_model}"
                )
        elif report.ai_error:
            print(f"  AI:        failed ({report.ai_error})")
        if behavior := report.behavior:
            doing = [label for label, on in (("network", bool(behavior.files_by_capability.get("network"))), ("commands", behavior.runs_commands), ("dynamic code", behavior.dynamic_code), ("reads all env", behavior.reads_all_env), ("machine info", behavior.reads_machine_info)) if on]
            print(f"  Behavior:  {', '.join(doing) or 'nothing risky'} · env vars: {', '.join(behavior.env_vars[:6]) or 'none'} · hosts: {len(behavior.hosts)}")
        if report.iocs:
            print(f"  IOCs:      " + ", ".join(f"{i.type}:{i.value}" for i in report.iocs[:5]) + (" ..." if len(report.iocs) > 5 else ""))
        for issue in report.code_issues[:MAX_PRINTED_FINDINGS]:
            lines = f":{issue.line_start}" + (f"-{issue.line_end}" if issue.line_end and issue.line_end != issue.line_start else "") if issue.line_start else ""
            print(f"  Issue:     [{issue.severity}] {issue.file}{lines} {issue.title} ({'+'.join(issue.sources)})")
        if report.review_flags and report.review_flags.needs_human_review:
            print(f"  Review:    needs human review: {' '.join(report.review_flags.reasons)}")
    print(f"  Saved to:  {result.scan_dir}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
