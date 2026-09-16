"""Scans every selected file of an unpacked package and collects findings."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yara

from pkgguard_analyzer.code_scan.files import select_files
from pkgguard_analyzer.code_scan.js_facts import extract_facts
from pkgguard_analyzer.code_scan.patterns import scan_patterns
from pkgguard_analyzer.code_scan.rules import FindingCollector, add_file_findings
from pkgguard_analyzer.schema import Confidence, Finding, Severity

MAX_FINDINGS = 200


@dataclass
class CodeScanResult:
    summary: dict[str, Any]
    findings: list[Finding]


def scan_code(files_dir: Path, manifest: dict) -> CodeScanResult:
    selection = select_files(files_dir, manifest)
    collector = FindingCollector()
    files_with_parse_errors = 0

    for code_file in selection.code_files:
        data = code_file.full_path.read_bytes()
        try:
            hits = scan_patterns(data)
        except yara.Error as error:
            selection.skipped.append({"path": code_file.path, "reason": f"pattern scan failed: {error}"})
            hits = []
        facts = extract_facts(data) if code_file.parse_ast else None
        files_with_parse_errors += bool(facts and facts.parse_errors)
        add_file_findings(code_file, facts, hits, collector)

    for path, kind in selection.executables:
        collector.add("code.executable", Severity.LOW, Confidence.HIGH, f"Ships a native executable ({kind})", path, None)

    findings = collector.findings()
    summary = {
        "filesScanned": len(selection.code_files),
        "filesParsed": sum(f.parse_ast for f in selection.code_files),
        "filesWithParseErrors": files_with_parse_errors,
        "installTimeFiles": [f.path for f in selection.code_files if f.install_time],
        "entryFiles": [f.path for f in selection.code_files if f.entry],
        "executables": [path for path, _ in selection.executables],
        "skipped": selection.skipped,
        "findingsTruncated": len(findings) > MAX_FINDINGS,
    }
    return CodeScanResult(summary, findings[:MAX_FINDINGS])
