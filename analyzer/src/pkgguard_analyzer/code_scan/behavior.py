"""Builds the package's behavior profile and rule-based indicators of compromise from code facts.

The profile comes only from deterministic rules, so two versions of a package can be compared reliably.
"""

import re
from urllib.parse import urlsplit

from pkgguard_analyzer.code_scan.files import CodeFile
from pkgguard_analyzer.code_scan.js_facts import NETWORK_MODULES, FileFacts
from pkgguard_analyzer.code_scan.patterns import PatternHit
from pkgguard_analyzer.code_scan.rules import MAX_STRING_CHECK_CHARS, SENSITIVE_PATHS, URL_HOST_RE, _public_ip
from pkgguard_analyzer.schema import BehaviorProfile, Indicator, IndicatorType

MAX_LIST = 200
MAX_FILES_PER_CAPABILITY = 20
URL_RE = re.compile(r"https?://[^\s'\"`<>\\)]+")
IGNORED_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org", "example.net"})
WEBHOOK_MARKERS = ("discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot")


def classify(value: str) -> IndicatorType:
    lowered = value.lower()
    if any(marker in lowered for marker in WEBHOOK_MARKERS):
        return IndicatorType.WEBHOOK
    if lowered.startswith(("http://", "https://")):
        return IndicatorType.URL
    host = lowered.split(":")[0]
    return IndicatorType.IP if _public_ip(host) else IndicatorType.DOMAIN


class BehaviorBuilder:
    def __init__(self) -> None:
        self.profile = BehaviorProfile()
        self.hosts: set[str] = set()
        self.ips: set[str] = set()
        self.env_vars: set[str] = set()
        self.modules: set[str] = set()
        self.sensitive: set[str] = set()
        self.by_capability: dict[str, list[str]] = {}
        self.install_files: list[str] = []
        self.indicators: dict[tuple[str, str], Indicator] = {}

    def _mark(self, capability: str, path: str) -> None:
        files = self.by_capability.setdefault(capability, [])
        if path not in files and len(files) < MAX_FILES_PER_CAPABILITY:
            files.append(path)

    def _indicator(self, value: str, path: str, line: int | None) -> None:
        kind = classify(value)
        self.indicators.setdefault((kind.value, value), Indicator(type=kind, value=value, file=path, line=line, source="rules"))

    def add_file(self, code_file: CodeFile, facts: FileFacts | None, hits: list[PatternHit]) -> None:
        path, install = code_file.path, code_file.install_time
        profile = self.profile
        if install and path not in self.install_files:
            self.install_files.append(path)

        for hit in hits:
            if "network" in hit.capabilities:
                self._mark("network", path)
                profile.install_time.network |= install
                urls = URL_RE.findall(hit.location.snippet) or hit.matches
                for value in urls[:5]:
                    self._indicator(value.rstrip(".,;"), path, hit.location.line)
            if "exec" in hit.capabilities:
                self._mark("commands", path)
                profile.install_time.commands |= install
        if facts is None:
            return

        network = facts.uses_network
        self.modules |= {m for m in facts.modules if m in NETWORK_MODULES or m in ("child_process", "vm")}
        if network:
            self._mark("network", path)
            profile.install_time.network |= install
        if facts.exec_calls:
            profile.runs_commands = True
            profile.install_time.commands |= install
            self._mark("commands", path)
        if facts.dynamic_code:
            profile.dynamic_code = True
            self._mark("dynamic_code", path)
        if facts.decode_calls:
            profile.decodes_data = True
            self._mark("decoding", path)
        if facts.env_dumps:
            profile.reads_all_env = True
            self._mark("env_all", path)
        if facts.env_names:
            self.env_vars |= facts.env_names
            self._mark("env_vars", path)
        if facts.recon_calls:
            profile.reads_machine_info = True
            self._mark("machine_info", path)

        for literal in facts.strings:
            raw = literal.raw[:MAX_STRING_CHECK_CHARS]
            for pattern, label in SENSITIVE_PATHS:
                if pattern.search(raw):
                    self.sensitive.add(label)
                    self._mark("sensitive_paths", path)
            for host in URL_HOST_RE.findall(raw):
                host = host.lower()
                if _public_ip(host):
                    self.ips.add(host)
                    for url in URL_RE.findall(raw)[:3]:
                        self._indicator(url, path, literal.location.line)
                elif "." in host and host not in IGNORED_HOSTS:
                    self.hosts.add(host)

    def build(self, executables: list[str]) -> tuple[BehaviorProfile, list[Indicator]]:
        profile = self.profile
        profile.network_modules = sorted(self.modules)
        profile.hosts = sorted(self.hosts)[:MAX_LIST]
        profile.ip_addresses = sorted(self.ips)[:MAX_LIST]
        profile.env_vars = sorted(self.env_vars)[:MAX_LIST]
        profile.sensitive_paths = sorted(self.sensitive)
        profile.native_executables = executables[:MAX_LIST]
        profile.install_time.files = self.install_files
        profile.files_by_capability = self.by_capability
        return profile, list(self.indicators.values())


def host_of(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None
