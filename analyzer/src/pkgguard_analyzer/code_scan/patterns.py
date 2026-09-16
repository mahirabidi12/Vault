"""Runs the YARA rules on raw file bytes."""

from dataclasses import dataclass
from functools import cache
from importlib.resources import files

import yara

from pkgguard_analyzer.code_scan.js_facts import SNIPPET_CHARS, Location
from pkgguard_analyzer.schema import Confidence, Severity

YARA_TIMEOUT_SECONDS = 30


@dataclass
class PatternHit:
    rule: str
    title: str
    severity: Severity
    confidence: Confidence
    capabilities: frozenset[str]
    location: Location
    occurrences: int


@cache
def compiled_rules() -> yara.Rules:
    source = files("pkgguard_analyzer.code_scan").joinpath("rules/patterns.yar").read_text()
    return yara.compile(source=source)


def location_at(data: bytes, offset: int) -> Location:
    line_start = data.rfind(b"\n", 0, offset) + 1
    line_end = data.find(b"\n", offset)
    line_end = len(data) if line_end == -1 else line_end
    start = max(line_start, offset - 60)
    snippet = data[start : min(line_end, start + SNIPPET_CHARS)]
    return Location(data.count(b"\n", 0, offset) + 1, snippet.decode("utf-8", "replace").strip())


def scan_patterns(data: bytes) -> list[PatternHit]:
    hits = []
    for match in compiled_rules().match(data=data, timeout=YARA_TIMEOUT_SECONDS):
        instances = [instance for string in match.strings for instance in string.instances]
        if not instances:
            continue
        meta = match.meta
        hits.append(
            PatternHit(
                rule=match.rule,
                title=meta["title"],
                severity=Severity(meta["severity"]),
                confidence=Confidence(meta["confidence"]),
                capabilities=frozenset(filter(None, meta.get("capabilities", "").split(","))),
                location=location_at(data, min(instance.offset for instance in instances)),
                occurrences=len(instances),
            )
        )
    return hits
