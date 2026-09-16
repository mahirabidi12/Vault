"""Turns findings and the AI review into a final verdict. v3: intel + metadata + static code + AI."""

from dataclasses import dataclass

from pkgguard_analyzer.schema import AIReview, Confidence, DecidedBy, Finding, FindingLayer, Severity, Verdict

MAX_SIGNALS = 5
# Findings the AI can never clear on its own: a "SAFE" from the AI still ends as SUSPICIOUS.
AI_CANNOT_CLEAR_RULES = frozenset({"code.pattern.llm_prompt_injection"})


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    confidence: Confidence
    decided_by: DecidedBy
    summary: str


def decide(findings: list[Finding], ai: AIReview | None = None) -> Decision:
    # 1. Hard evidence from threat intel always wins; the AI can't downgrade it.
    if any(f.rule_id == "intel.osv.malicious" for f in findings):
        return Decision(Verdict.MALICIOUS, Confidence.HIGH, DecidedBy.INTEL, "Listed as a known malicious package in OSV.")
    safedep = [f for f in findings if f.rule_id == "intel.safedep.malware"]
    if safedep and safedep[0].confidence == Confidence.HIGH:
        return Decision(Verdict.MALICIOUS, Confidence.HIGH, DecidedBy.INTEL, "Flagged as malware by SafeDep threat intelligence.")

    rules = _rules_decision(findings)
    if ai is None:
        return rules

    # 2. The AI can always escalate.
    if ai.verdict == Verdict.MALICIOUS:
        strong = ai.confidence == Confidence.HIGH
        return Decision(Verdict.MALICIOUS if strong else Verdict.SUSPICIOUS, Confidence.HIGH if strong else Confidence.MEDIUM, DecidedBy.AI, ai.summary)
    if ai.verdict == Verdict.SUSPICIOUS:
        return Decision(Verdict.SUSPICIOUS, ai.confidence, DecidedBy.AI, ai.summary)

    # 3. The AI says SAFE: it may clear rule warnings, but not strong evidence.
    blockers = [
        f
        for f in findings
        if f.rule_id in AI_CANNOT_CLEAR_RULES
        or (f.severity == Severity.HIGH and f.confidence != Confidence.LOW and f.layer != FindingLayer.INTEL)
    ]
    if blockers or safedep:
        titles = "; ".join(dict.fromkeys(f.title for f in (blockers or safedep)))
        return Decision(Verdict.SUSPICIOUS, Confidence.LOW, DecidedBy.RULES, f"AI review found no harm, but automated checks found strong warning signs: {titles}.")
    if ai.confidence == Confidence.LOW:
        return rules
    return Decision(Verdict.SAFE, ai.confidence, DecidedBy.AI, ai.summary)


def _rules_decision(findings: list[Finding]) -> Decision:
    if any(f.rule_id == "intel.safedep.malware" for f in findings):
        return Decision(Verdict.SUSPICIOUS, Confidence.MEDIUM, DecidedBy.INTEL, "Flagged as malware by SafeDep threat intelligence.")
    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    if high:
        return Decision(Verdict.SUSPICIOUS, Confidence.MEDIUM, DecidedBy.RULES, _describe("Suspicious", high + medium))
    # Count kinds of warnings, not repeats: the same rule firing in ten files is still one kind of risk.
    if len({f.rule_id for f in medium}) >= 2:
        return Decision(Verdict.SUSPICIOUS, Confidence.LOW, DecidedBy.RULES, _describe("Several warnings", medium))
    if medium:
        return Decision(Verdict.SAFE, Confidence.LOW, DecidedBy.RULES, f"No issues found, with one warning: {medium[0].title}.")
    return Decision(Verdict.SAFE, Confidence.MEDIUM, DecidedBy.RULES, "No issues found in threat intelligence, package metadata or code.")


def signals(findings: list[Finding]) -> list[str]:
    important = [f.title for f in findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]
    return list(dict.fromkeys(important))[:MAX_SIGNALS]


def _describe(prefix: str, findings: list[Finding]) -> str:
    titles = list(dict.fromkeys(f.title for f in findings))
    return f"{prefix}: " + "; ".join(titles[:3]) + "."
