"""Finds planted fake credentials in outbound data, including encoded copies (base64, hex, URL-encoded).

A canary is a random value only the sandbox knows, so seeing any part of it leave the box means the
package read the decoy and sent it out. That is evidence, not a heuristic."""

import base64
import urllib.parse
from dataclasses import dataclass

MIN_CANARY_LEN = 16
PROBE_LEN = 24
_B64_SKIP_HEAD = {0: 0, 1: 2, 2: 3}


def _probes(form: str) -> list[str]:
    if len(form) < 8:
        return []
    if len(form) <= PROBE_LEN:
        return [form]
    return [form[:PROBE_LEN], form[-PROBE_LEN:]]


def forms(value: str) -> list[tuple[str, bool]]:
    """(form, case_insensitive) variants of a canary that could appear in traffic."""
    data = value.encode()
    out: list[tuple[str, bool]] = [(value, False), (urllib.parse.quote(value, safe=""), False), (value[::-1], False)]
    hexed = data.hex()
    out.append((hexed, True))
    for k, skip in _B64_SKIP_HEAD.items():
        enc = base64.b64encode(b"\0" * k + data).decode()[skip:].rstrip("=")
        enc = enc[:-2] if len(enc) > 26 else enc
        out.append((enc, False))
        out.append((enc.replace("+", "-").replace("/", "_"), False))
    return out


@dataclass(frozen=True)
class Canary:
    id: str
    value: str
    decoy_path: str | None = None


class CanarySet:
    def __init__(self, canaries: list[Canary]) -> None:
        self.canaries = [c for c in canaries if len(c.value) >= MIN_CANARY_LEN]
        self._index: list[tuple[str, bool, Canary]] = []
        for canary in self.canaries:
            for form, ci in forms(canary.value):
                for probe in _probes(form):
                    self._index.append((probe.lower() if ci else probe, ci, canary))

    def find(self, text: str) -> list[Canary]:
        """Canaries whose value (in any known encoding) appears in `text`."""
        if not text:
            return []
        lowered = text.lower()
        squashed = text.replace(".", "").replace("-", "")
        squashed_lower = squashed.lower()
        hits: dict[str, Canary] = {}
        for probe, ci, canary in self._index:
            if canary.id in hits:
                continue
            if (probe in lowered) if ci else (probe in text):
                hits[canary.id] = canary
            elif (probe in squashed_lower) if ci else (probe in squashed):  # split across DNS labels
                hits[canary.id] = canary
        return list(hits.values())


def canaries_from_trace(decoys: dict) -> CanarySet:
    items = [Canary(d["id"], d["value"], d.get("path")) for d in decoys.get("files", []) if d.get("value")]
    items += [Canary(d["id"], d["value"], None) for d in decoys.get("env", []) if d.get("value")]
    return CanarySet(items)
