"""Labels hosts and ports the package talked to. Everything the sandbox sees goes to the fake network,
so these describe the *intent* of the connection."""

import ipaddress
import re

from pkgguard_analyzer.schema import NetworkClass

EXPECTED_SUFFIXES = (
    "registry.npmjs.org", "registry.yarnpkg.com", "npmjs.org", "npmjs.com", "github.com",
    "objects.githubusercontent.com", "github-releases.githubusercontent.com", "codeload.github.com", "nodejs.org",
)  # fmt: skip
OAST = re.compile(r"(oast\.(pro|live|site|online|fun|me)|oastify\.com|interact\.sh|interactsh|burpcollaborator|requestbin|pipedream\.net|webhook\.site|dnslog\.|ceye\.io|canarytokens|requestcatcher|beeceptor|mockbin|hookbin)", re.I)
WEBHOOK = re.compile(r"(discord(app)?\.com|api\.telegram\.org|hooks\.slack\.com)", re.I)
PASTE = re.compile(r"(pastebin\.com|paste\.ee|transfer\.sh|temp\.sh|anonfiles|gofile\.io|file\.io|0x0\.st|hastebin|ghostbin|rentry\.co)", re.I)
TUNNEL = re.compile(r"(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|localtunnel|localhost\.run|portmap\.io)", re.I)
METADATA = re.compile(r"(^169\.254\.169\.254$|^169\.254\.170\.2$|metadata\.google\.internal|metadata\.azure)", re.I)
STRATUM_PORTS = {3333, 4444, 5555, 7777, 14444, 45700, 9999}
STRATUM_HOST = re.compile(r"(stratum|xmr|monero|nanopool|minexmr|supportxmr|2miners|f2pool|pool\.)", re.I)
WEB_PORTS = {80, 443, 53, 8080, 8443}


def is_loopback_or_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def classify(host: str | None, port: int | None = None, data: str | None = None) -> NetworkClass:
    h = (host or "").lower().rstrip(".")
    if h and any(h == s or h.endswith("." + s) for s in EXPECTED_SUFFIXES):
        return NetworkClass.EXPECTED
    if METADATA.search(h):
        return NetworkClass.METADATA
    if OAST.search(h):
        return NetworkClass.OAST
    if WEBHOOK.search(h):
        return NetworkClass.WEBHOOK
    if PASTE.search(h):
        return NetworkClass.PASTE
    if TUNNEL.search(h):
        return NetworkClass.TUNNEL
    if (port in STRATUM_PORTS and port not in WEB_PORTS) or (h and STRATUM_HOST.search(h)) or (data and re.search(r"mining\.(subscribe|authorize)|stratum\+tcp", data)):
        return NetworkClass.STRATUM
    if h and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) and not is_loopback_or_private(h):
        return NetworkClass.RAW_IP
    return NetworkClass.UNEXPECTED
