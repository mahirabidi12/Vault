"""Turns findings into a final verdict. v2 covers threat intel, metadata and static code checks; AI rules come in Step 5."""

from dataclasses import dataclass

from pkgguard_analyzer.schema import Confidence, DecidedBy, Finding, Severity, Verdict

MAX_SIGNALS = 5


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    confidence: Confidence
    decided_by: DecidedBy
    summary: str


def decide(findings: list[Finding]) -> Decision:
    if any(f.rule_id == "intel.osv.malicious" for f in findings):
        return Decision(Verdict.MALICIOUS, Confidence.HIGH, DecidedBy.INTEL, "Listed as a known malicious package in OSV.")

    safedep = [f for f in findings if f.rule_id == "intel.safedep.malware"]
    if safedep:
        strong = safedep[0].confidence == Confidence.HIGH
        return Decision(
            Verdict.MALICIOUS if strong else Verdict.SUSPICIOUS,
            Confidence.HIGH if strong else Confidence.MEDIUM,
            DecidedBy.INTEL,
            "Flagged as malware by SafeDep threat intelligence.",
        )

    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    if high:
        return Decision(Verdict.SUSPICIOUS, Confidence.MEDIUM, DecidedBy.RULES, _describe("Suspicious", high + medium))
    # Count kinds of warnings, not repeats: the same rule firing in ten files is still one kind of risk.
    if len({f.rule_id for f in medium}) >= 2:
        return Decision(Verdict.SUSPICIOUS, Confidence.LOW, DecidedBy.RULES, _describe("Several warnings", medium))
    if medium:
        return Decision(Verdict.SAFE, Confidence.LOW, DecidedBy.RULES, f"No issues found, with one warning: {medium[0].title}.")
    return Decision(
        Verdict.SAFE,
        Confidence.MEDIUM,
        DecidedBy.RULES,
        "No issues found in threat intelligence, package metadata or code.",
    )


def signals(findings: list[Finding]) -> list[str]:
    important = [f.title for f in findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]
    return list(dict.fromkeys(important))[:MAX_SIGNALS]


def _describe(prefix: str, findings: list[Finding]) -> str:
    titles = list(dict.fromkeys(f.title for f in findings))
    return f"{prefix}: " + "; ".join(titles[:3]) + "."
