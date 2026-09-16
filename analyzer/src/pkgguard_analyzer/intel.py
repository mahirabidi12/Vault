"""Threat intelligence lookups: OSV.dev and SafeDep community API. A failed lookup never stops a scan."""

from dataclasses import dataclass, field
from typing import Any

import httpx

from pkgguard_analyzer.schema import Confidence, Finding, FindingLayer, Severity

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
SAFEDEP_QUERY_URL = (
    "https://community-api.safedep.io/safedep.services.malysis.v1.MalwareAnalysisService/QueryPackageAnalysis"
)


@dataclass
class IntelResult:
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


def parse_osv(data: dict) -> tuple[dict, list[Finding]]:
    ids = [vuln["id"] for vuln in data.get("vulns", []) if "id" in vuln]
    malicious = [i for i in ids if i.startswith("MAL-")]
    findings = [
        Finding(
            rule_id="intel.osv.malicious",
            layer=FindingLayer.INTEL,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title=f"Listed as malicious in OSV ({osv_id})",
        )
        for osv_id in malicious
    ]
    summary = {"maliciousIds": malicious, "vulnerabilityIds": [i for i in ids if not i.startswith("MAL-")]}
    return summary, findings


def parse_safedep(data: dict) -> tuple[dict, list[Finding]]:
    report = data.get("report") or {}
    inference = report.get("inference") or {}
    # Trust only the boolean: SafeDep's prose can contradict it after a human override.
    is_malware = inference.get("isMalware") is True
    human_verified = bool(data.get("verificationRecord"))
    raw_confidence = inference.get("confidence")

    summary = {
        "found": bool(report),
        "isMalware": is_malware,
        "confidence": raw_confidence,
        "humanVerified": human_verified,
        "analysisId": data.get("analysisId"),
    }
    findings = []
    if is_malware:
        strong = human_verified or raw_confidence == "CONFIDENCE_HIGH"
        findings.append(
            Finding(
                rule_id="intel.safedep.malware",
                layer=FindingLayer.INTEL,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH if strong else Confidence.MEDIUM,
                title="Flagged as malware by SafeDep" + (" (human verified)" if human_verified else ""),
            )
        )
    return summary, findings


def run_intel(client: httpx.Client, name: str, version: str) -> IntelResult:
    result = IntelResult()

    try:
        response = client.post(OSV_QUERY_URL, json={"package": {"name": name, "ecosystem": "npm"}, "version": version})
        response.raise_for_status()
        result.summary["osv"], findings = parse_osv(response.json())
        result.findings += findings
    except (httpx.HTTPError, ValueError) as error:
        result.summary["osv"] = {"error": str(error)}

    try:
        body = {"target": {"packageVersion": {"package": {"ecosystem": "ECOSYSTEM_NPM", "name": name}, "version": version}}}
        response = client.post(SAFEDEP_QUERY_URL, json=body)
        if response.status_code == 404:
            result.summary["safedep"] = {"found": False}
        else:
            response.raise_for_status()
            result.summary["safedep"], findings = parse_safedep(response.json())
            result.findings += findings
    except (httpx.HTTPError, ValueError) as error:
        result.summary["safedep"] = {"error": str(error)}

    return result
