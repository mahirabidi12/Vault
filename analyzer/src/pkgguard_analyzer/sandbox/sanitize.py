"""Makes captured traces safe to commit: the sandbox plants realistic-looking fake credentials (so
credential-stealing code takes the bait), but committed copies must not match real token formats or
GitHub's push protection will block the push. Rewrites the recognizable prefixes consistently
everywhere they appear, including hex-encoded copies, so canary matching keeps working.

  uv run python -m pkgguard_analyzer.sandbox.sanitize      # sanitizes analyzer/tests/data/sandbox in place"""

import gzip
import json
import re
from pathlib import Path

PREFIXES = [("npm_", "npx_"), ("ghp_", "ghx_"), ("AKIA", "AKXA"), ("sk_live_", "sk_xxxx_"), ("sk-", "sx-"), ("1//", "1/x")]
TEXT_SWAPS = [
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN FAKE SANDBOX KEY-----"),
    ("-----END OPENSSH PRIVATE KEY-----", "-----END FAKE SANDBOX KEY-----"),
]


def swap(value: str) -> str:
    for old, new in PREFIXES:
        if value.startswith(old):
            return new + value[len(old) :]
    return value


def sanitize_text(text: str, values: list[str]) -> str:
    for value in sorted(set(values), key=len, reverse=True):
        new = swap(value)
        if new == value:
            continue
        text = text.replace(value, new)
        for n in (60, len(value.encode()) * 2):
            text = text.replace(value.encode().hex()[:n], new.encode().hex()[:n])
    for old, new in TEXT_SWAPS:
        text = text.replace(old, new)
    # tokens that only appear embedded (for example inside an .npmrc line or a URL)
    text = re.sub(r"npm_([A-Za-z0-9]{36})", r"npx_\1", text)
    text = re.sub(r"ghp_([A-Za-z0-9]{36})", r"ghx_\1", text)
    return re.sub(r"AKIA([A-Z0-9]{16})", r"AKXA\1", text)


def sanitize_trace(trace: dict) -> dict:
    values = [d["value"] for d in trace.get("decoys", {}).get("files", []) if d.get("value")] + [d["value"] for d in trace.get("decoys", {}).get("env", []) if d.get("value")]
    return json.loads(sanitize_text(json.dumps(trace), values))


def main() -> None:
    root = Path(__file__).resolve().parents[3] / "tests" / "data" / "sandbox"
    for path in sorted(root.glob("*.json.gz")):
        trace = json.loads(gzip.open(path).read())
        path.write_bytes(gzip.compress(json.dumps(sanitize_trace(trace)).encode(), 9))
    print(f"sanitized {len(list(root.glob('*.json.gz')))} traces in {root}")


if __name__ == "__main__":
    main()
