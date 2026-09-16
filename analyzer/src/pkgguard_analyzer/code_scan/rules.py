"""Turns code facts and pattern hits into findings, including combinations that are dangerous together."""

import ipaddress
import math
import re
from collections import Counter

from pkgguard_analyzer.code_scan.files import CodeFile
from pkgguard_analyzer.code_scan.js_facts import FileFacts, Location, StringLiteral
from pkgguard_analyzer.code_scan.patterns import PatternHit
from pkgguard_analyzer.schema import Confidence, Finding, FindingLayer, Severity

SENSITIVE_PATHS = (
    (re.compile(r"\.ssh(?:[/\\]|$)|id_rsa|id_ed25519|id_ecdsa"), "SSH keys"),
    (re.compile(r"\.aws[/\\](?:credentials|config)"), "AWS credentials"),
    (re.compile(r"\.npmrc\b"), "npm token file (.npmrc)"),
    (re.compile(r"\.git-credentials"), "git credentials"),
    (re.compile(r"\.docker[/\\]config\.json"), "Docker credentials"),
    (re.compile(r"\.kube[/\\]config"), "Kubernetes credentials"),
    (re.compile(r"\.config[/\\]gcloud|application_default_credentials\.json"), "Google Cloud credentials"),
    (re.compile(r"\.azure[/\\]"), "Azure credentials"),
    (re.compile(r"/etc/(?:passwd|shadow)\b"), "system password files"),
    (re.compile(r"\.(?:bash|zsh)_history"), "shell history"),
    (re.compile(r"Login Data|Local Extension Settings"), "browser passwords or extensions"),
    (
        re.compile(r"nkbihfbeogaeaoehlefnkodbefgpgknn|\.ethereum[/\\]keystore|exodus\.wallet|Electrum[/\\]wallets|\.config[/\\]solana"),
        "crypto wallets",
    ),
)
URL_HOST_RE = re.compile(r"https?://([^\s/'\"`:<>?#\\]+)")
ENCODED_BLOB_RE = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
MIN_HEX_ESCAPES = 20
MIN_BLOB_ENTROPY = 4.5
MAX_STRING_CHECK_CHARS = 10_000
SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def _raise(severity: Severity) -> Severity:
    return Severity.HIGH if severity != Severity.LOW else Severity.MEDIUM


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


class FindingCollector:
    """Merges repeated hits of the same rule in the same file into one finding with an occurrence count."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str], Finding] = {}

    def add(
        self,
        rule_id: str,
        severity: Severity,
        confidence: Confidence,
        title: str,
        file: str,
        location: Location | None,
        install_time: bool = False,
        count: int = 1,
    ) -> None:
        key = (rule_id, file, title)
        if existing := self._items.get(key):
            existing.occurrences += count
            return
        self._items[key] = Finding(
            rule_id=rule_id,
            layer=FindingLayer.STATIC,
            severity=severity,
            confidence=confidence,
            title=title,
            file=file,
            line=location.line if location else None,
            snippet=location.snippet if location and location.snippet else None,
            install_time=install_time,
            occurrences=count,
        )

    def findings(self) -> list[Finding]:
        return sorted(self._items.values(), key=lambda f: (SEVERITY_ORDER[f.severity], not f.install_time, f.file or ""))


def _public_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def add_file_findings(
    code_file: CodeFile, facts: FileFacts | None, hits: list[PatternHit], collector: FindingCollector
) -> None:
    path, install_time = code_file.path, code_file.install_time
    during_install = " during install" if install_time else ""

    pattern_network = False
    for hit in hits:
        collector.add(f"code.pattern.{hit.rule}", hit.severity, hit.confidence, hit.title, path, hit.location, install_time, hit.occurrences)
        pattern_network |= "network" in hit.capabilities
    if facts is None:
        return

    secret_locations: list[Location] = [*facts.env_dumps]
    contacts_ip = False
    for literal in facts.strings:
        secret_locations += _string_findings(literal, path, install_time, collector)
        contacts_ip |= _ip_findings(literal, path, install_time, collector)

    if facts.dynamic_code:
        severity = Severity.MEDIUM if install_time else Severity.LOW
        collector.add("code.dynamic_code", severity, Confidence.HIGH, "Runs dynamically generated code (eval / Function / vm)", path, facts.dynamic_code[0], install_time, len(facts.dynamic_code))
    if facts.exec_calls:
        severity = Severity.MEDIUM if install_time else Severity.LOW
        collector.add("code.exec", severity, Confidence.HIGH, "Runs system commands (child_process)", path, facts.exec_calls[0], install_time, len(facts.exec_calls))
    if facts.env_dumps:
        severity = Severity.MEDIUM if install_time else Severity.LOW
        collector.add("code.env_dump", severity, Confidence.HIGH, "Reads all environment variables at once", path, facts.env_dumps[0], install_time, len(facts.env_dumps))

    uses_network = facts.uses_network or pattern_network or contacts_ip
    reads_secrets = bool(secret_locations)
    if (reads_secrets or facts.recon_calls) and uses_network:
        # Machine details alone (hostname, username) are weaker evidence than secrets.
        confidence = Confidence.HIGH if install_time and reads_secrets else Confidence.MEDIUM if reads_secrets else Confidence.LOW
        what = "secrets" if reads_secrets else "machine details (hostname, username)"
        collector.add(
            "code.exfiltration",
            Severity.HIGH,
            confidence,
            f"Reads {what} and can send data over the network{during_install}",
            path,
            (secret_locations or facts.recon_calls)[0],
            install_time,
        )
    if facts.decode_calls and facts.dynamic_code:
        collector.add("code.decode_and_run", Severity.HIGH, Confidence.MEDIUM, "Decodes hidden data and runs it as code", path, facts.decode_calls[0], install_time)
    if install_time and facts.exec_calls and uses_network:
        collector.add("code.install_download_exec", Severity.MEDIUM, Confidence.MEDIUM, "Downloads and runs programs during install", path, facts.exec_calls[0], install_time)
    elif install_time and uses_network:
        first = facts.network_calls[0] if facts.network_calls else None
        collector.add("code.install_network", Severity.MEDIUM, Confidence.MEDIUM, "Makes network requests during install", path, first, install_time)


def _string_findings(literal: StringLiteral, path: str, install_time: bool, collector: FindingCollector) -> list[Location]:
    """Adds findings for one string literal and returns its location if it points at secrets."""
    raw = literal.raw[:MAX_STRING_CHECK_CHARS]
    secrets: list[Location] = []
    for pattern, label in SENSITIVE_PATHS:
        if pattern.search(raw):
            severity = Severity.HIGH if install_time else Severity.MEDIUM
            collector.add("code.sensitive_path", severity, Confidence.MEDIUM, f"References {label}", path, literal.location, install_time)
            secrets.append(literal.location)

    if len(HEX_ESCAPE_RE.findall(raw)) >= MIN_HEX_ESCAPES:
        collector.add("code.hex_escapes", Severity.MEDIUM, Confidence.MEDIUM, "Hides text with hex escape sequences", path, literal.location, install_time)

    stripped = literal.raw.strip()
    if not stripped.startswith("data:") and ENCODED_BLOB_RE.fullmatch(stripped) and _entropy(stripped) >= MIN_BLOB_ENTROPY:
        severity = Severity.MEDIUM if install_time else Severity.LOW
        collector.add("code.encoded_blob", severity, Confidence.LOW, "Contains a large encoded blob", path, literal.location, install_time)
    return secrets


def _ip_findings(literal: StringLiteral, path: str, install_time: bool, collector: FindingCollector) -> bool:
    found = False
    for host in URL_HOST_RE.findall(literal.raw[:MAX_STRING_CHECK_CHARS]):
        if _public_ip(host):
            collector.add("code.raw_ip", Severity.MEDIUM, Confidence.MEDIUM, f"Contacts a raw IP address ({host})", path, literal.location, install_time)
            found = True
    return found
