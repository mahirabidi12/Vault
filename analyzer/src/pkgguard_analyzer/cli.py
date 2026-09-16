"""Scan one package from the terminal: uv run analyze express@4.18.2"""

import argparse
import json
import sys
from pathlib import Path

import httpx
from pydantic import ValidationError

from pkgguard_analyzer.analyze import analyze, parse_spec
from pkgguard_analyzer.npm_registry import PackageNotFound
from pkgguard_analyzer.schema import ScanStatus


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="analyze", description="Scan one npm package version.")
    parser.add_argument("package", help="name or name@version, e.g. express@4.18.2 or @babel/core")
    parser.add_argument("version", nargs="?", help="exact version or dist-tag (default: latest)")
    parser.add_argument("--json", action="store_true", help="print the full record and report as JSON")
    parser.add_argument("--out", type=Path, default=Path("tmp/scans"), help="where results and unpacked files go")
    args = parser.parse_args(argv)

    name, spec_version = parse_spec(args.package)
    try:
        result = analyze(name, args.version or spec_version, out_dir=args.out)
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
        print(f"  Findings:  {len(report.findings)}")
        for finding in report.findings:
            where = f"  ({finding.file})" if finding.file else ""
            print(f"    [{finding.severity}] {finding.title}{where}")
        osv, safedep = report.intel.get("osv", {}), report.intel.get("safedep", {})
        osv_text = osv.get("error") and "lookup failed" or f"{len(osv.get('maliciousIds', []))} malicious"
        safedep_text = safedep.get("error") and "lookup failed" or (
            "malware" if safedep.get("isMalware") else "not flagged" if safedep.get("found") else "no report"
        )
        print(f"  Intel:     OSV {osv_text} · SafeDep {safedep_text}")
    print(f"  Saved to:  {result.scan_dir}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
