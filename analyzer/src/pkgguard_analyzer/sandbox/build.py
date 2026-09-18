"""Turns raw sandbox traces (one per run) into a `SandboxReport` with findings.

Pure and deterministic: no Docker, no network. Detection rules can change and be re-run over stored
traces without running the sandbox again."""

import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from pkgguard_analyzer.sandbox import strace
from pkgguard_analyzer.sandbox.canary import CanarySet, canaries_from_trace
from pkgguard_analyzer.sandbox.classify import classify
from pkgguard_analyzer.schema import (
    CanaryHit,
    ConditionalBehavior,
    Confidence,
    Finding,
    FindingLayer,
    NetworkClass,
    NetworkKind,
    SandboxCoverage,
    SandboxEval,
    SandboxFileEvent,
    SandboxNetworkEvent,
    SandboxPhaseResult,
    SandboxProcess,
    SandboxReport,
    SandboxResources,
    SandboxRunSummary,
    SandboxStatus,
    Severity,
)

MAX_EVENTS = 300
DATA_LABEL = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def _norm_host(host: str) -> str:
    return DATA_LABEL.sub("<data>", host or "")
SUSPICIOUS_CLASSES = {NetworkClass.OAST, NetworkClass.WEBHOOK, NetworkClass.PASTE, NetworkClass.TUNNEL, NetworkClass.METADATA, NetworkClass.STRATUM, NetworkClass.RAW_IP}
NET_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "ftp", "tftp", "telnet"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
DROP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/sbx/", "/etc/", "/proc/", "/sys/")
MINER_NAMES = re.compile(r"(xmrig|minerd|cpuminer|ethminer|nbminer|t-rex|lolminer|cgminer|bfgminer)", re.I)
SHELL_ABUSE = re.compile(r"(\|\s*(sh|bash|zsh)\b|base64\s+(-d|--decode)|/dev/tcp/|\bnc\b.*\s-e\b|\b(curl|wget)\b.*(-o|-O|>)|chmod\s+\+?[0-7]*x)", re.I)
REVERSE_SHELL_ARGS = re.compile(r"(/dev/tcp/|\bnc(at)?\b[^|;]*\s-(e|c)\b|socat[^|;]*exec:|pty\.spawn|mkfifo[^|;]*\bnc\b|bash\s+-i\s*>&)", re.I)
EVAL_TOKENS = re.compile(r"(require\(|child_process|\bexec|spawn|https?://|fetch\(|XMLHttpRequest|process\.env|Buffer\.from|atob\(|writeFile|\.ssh|\.npmrc)")
PERSISTENCE = [
    (re.compile(r"/\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv)$"), "shell startup file"),
    (re.compile(r"/\.config/autostart/"), "desktop autostart"),
    (re.compile(r"/\.config/systemd/user/|/\.local/share/systemd/"), "systemd user unit"),
    (re.compile(r"/\.ssh/authorized_keys$"), "SSH authorized_keys"),
    (re.compile(r"/Library/LaunchAgents/|/Library/LaunchDaemons/"), "launch agent"),
    (re.compile(r"^/(var/spool/cron|etc/cron)"), "cron"),
    (re.compile(r"/\.(npmrc|yarnrc|gitconfig)$"), "tool configuration"),
]
SENSITIVE = [
    (re.compile(r"/\.ssh/(id_|authorized_keys)"), "ssh_key"),
    (re.compile(r"/(shadow|sudoers)$|/\.git-credentials$|/\.netrc$|/\.gnupg/|/\.password-store/"), "credentials"),
    (re.compile(r"/\.(mozilla|config/(google-chrome|chromium|BraveSoftware))/"), "browser_data"),
]
PROBE_PATHS = re.compile(r"(\.dockerenv|/proc/1/cgroup|/sys/class/dmi|/proc/(cpuinfo|version)|virtualbox|vmware|qemu|hypervisor)", re.I)


@dataclass
class RunResult:
    name: str
    summary: SandboxRunSummary
    network: list[SandboxNetworkEvent] = field(default_factory=list)
    processes: list[SandboxProcess] = field(default_factory=list)
    files: list[SandboxFileEvent] = field(default_factory=list)
    evals: list[SandboxEval] = field(default_factory=list)
    canary_hits: list[CanaryHit] = field(default_factory=list)
    reverse_shell: list[str] = field(default_factory=list)
    droppers: list[str] = field(default_factory=list)
    persistence: list[tuple[str, str]] = field(default_factory=list)
    suspicious_exec: list[str] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)
    env_dumps: int = 0
    recon: set[str] = field(default_factory=set)
    resource_flags: list[str] = field(default_factory=list)
    coverage_notes: list[str] = field(default_factory=list)
    entry_failed: bool = False
    coverage: SandboxCoverage = field(default_factory=SandboxCoverage)
    cpu: float = 0.0
    memory_mb: float = 0.0
    seconds: float = 0.0


def _base(exe: str) -> str:
    return os.path.basename(exe)


def _net_key(e: SandboxNetworkEvent) -> tuple:
    return (e.kind, (e.host or e.ip or "").lower(), e.port, e.method, e.url)


class _NetworkBook:
    def __init__(self, run: str, canaries: CanarySet) -> None:
        self.run, self.canaries = run, canaries
        self.events: dict[tuple, SandboxNetworkEvent] = {}
        self.hits: dict[tuple[str, str], CanaryHit] = {}

    def add(self, kind: NetworkKind, host: str | None, *, ip: str | None = None, port: int | None = None, method: str | None = None, url: str | None = None, body: str = "", extra_text: str = "", phase: str | None = None, data: str | None = None) -> None:
        klass = classify(host or ip, port, data or body)
        text = " ".join(x for x in (url or "", extra_text, body, data or "", host or "") if x)
        found = self.canaries.find(text) if kind != NetworkKind.CONNECT else []
        ev = SandboxNetworkEvent(run=self.run, kind=kind, classification=klass, host=host, ip=ip, port=port, method=method, url=url, body_preview=body[:2000] or None, canary_hit=bool(found), phase=phase)
        key = _net_key(ev)
        cur = self.events.get(key)
        if cur:
            cur.count += 1
            cur.canary_hit |= ev.canary_hit
            if ev.body_preview and not cur.body_preview:
                cur.body_preview = ev.body_preview
        elif len(self.events) < MAX_EVENTS:
            self.events[key] = ev
        if klass != NetworkClass.EXPECTED:
            for canary in found:
                sink = f"{kind.value} {_norm_host(host or ip or '')}"
                self.hits.setdefault((canary.id, sink), CanaryHit(canary_id=canary.id, decoy_path=canary.decoy_path, sink=sink, run=self.run))


def analyze_run(trace: dict) -> RunResult:
    run = trace["run"]
    name = run["name"]
    phases_raw = trace.get("phases", [])
    phase_lines = {p["name"]: p.get("straceLines", []) for p in phases_raw}
    events, procs = strace.parse(phase_lines)
    ip_to_name: dict[str, str] = trace.get("sinkhole", {}).get("ipToName", {})
    canaries = canaries_from_trace(trace.get("decoys", {}))
    decoy_files = {d["path"]: d for d in trace.get("decoys", {}).get("files", [])}
    root_groups = {p.pid for p in procs.values() if p.is_root and p.phase.startswith("install")}
    root_install = {pid for pid in procs if strace.group_of(procs, pid) in root_groups}
    pid_phase = {pid: p.phase for pid, p in procs.items()}

    summary = SandboxRunSummary(
        name=name, ci=run["env"].get("ci", False), clock_offset_days=run["env"].get("clockOffsetDays", 0), hostname=run["env"].get("hostname", ""), user=run["env"].get("user", ""),
        phases=[SandboxPhaseResult(name=p["name"], exit_code=p.get("exitCode"), timed_out=p.get("timedOut", False), seconds=p.get("seconds", 0.0), cpu_seconds=p.get("cpuSeconds", 0.0)) for p in phases_raw],
        notes=list(trace.get("notes", [])),
    )  # fmt: skip
    res = RunResult(name=name, summary=summary)
    book = _NetworkBook(name, canaries)

    # ---- fake-network logs: the authoritative view of what left the package's processes
    for e in trace.get("sinkhole", {}).get("events", []):
        if e["type"] == "dns" and e.get("name"):
            book.add(NetworkKind.DNS, e["name"])
        elif e["type"] == "http":
            host = (e.get("host") or e.get("sni") or "").split(":")[0] or None
            scheme = "https" if e.get("tls") else "http"
            book.add(NetworkKind.HTTP, host, port=443 if e.get("tls") else 80, method=e.get("method"), url=f"{scheme}://{host}{e.get('path', '')}"[:600], body=e.get("body", ""), extra_text=json.dumps(e.get("headers", {})))
        elif e["type"] == "tcp":
            book.add(NetworkKind.TCP, ip_to_name.get(e.get("dest", "")), ip=e.get("dest"), port=e.get("port"), data=e.get("data", ""))

    # ---- hook events (best effort; attributed to the package, not to npm itself)
    for h in trace.get("hookEvents", []):
        pid = h.get("pid")
        if pid in root_install:
            continue
        phase = pid_phase.get(pid)
        kind = h.get("type")
        if kind == "connect" and h.get("host"):
            book.add(NetworkKind.CONNECT, h["host"], port=h.get("port"), phase=phase)
        elif kind == "dns" and h.get("host"):
            book.add(NetworkKind.DNS, str(h["host"]), phase=phase)
        elif kind == "http" and h.get("url"):
            u = urlsplit(h["url"])
            book.add(NetworkKind.HTTP, u.hostname, port=u.port or (443 if u.scheme == "https" else 80), method=h.get("method"), url=h["url"][:600], body=h.get("body") or "", extra_text=h.get("headers") or "", phase=phase)
        elif kind == "udp":
            book.add(NetworkKind.UDP, h.get("address"), port=h.get("port"), data=h.get("data") or "", phase=phase)
        elif kind == "eval":
            code = h.get("code", "")
            if len(code) >= 60 or EVAL_TOKENS.search(code):
                res.evals.append(SandboxEval(run=name, api=h.get("api", "eval"), length=h.get("length", len(code)), sha256=h.get("sha256", ""), preview=code[:4000], phase=phase))
        elif kind == "env" and h.get("op") == "dump":
            res.env_dumps += 1
        elif kind == "recon":
            res.recon.add(h.get("api", ""))
        elif kind == "probe" and PROBE_PATHS.search(h.get("path", "")):
            res.probes.append(h["path"])
        elif kind == "spawn":
            cmdline = " ".join([str(h.get("cmd", "")), *map(str, h.get("args") or [])])
            if REVERSE_SHELL_ARGS.search(cmdline):
                res.reverse_shell.append(f"command: {cmdline[:200]}")

    # ---- strace: connects, execs, file writes, chmod, dup2 onto sockets
    sockets: dict[int, set[int]] = defaultdict(set)  # pid -> fds that connected out
    connected_nonweb: dict[int, tuple[str, int]] = {}
    fd_socket: dict[tuple[int, int], bool] = {}
    executed: list[tuple[str, int, str]] = []
    chmodded: set[str] = set()
    for ev in events:
        if ev.pid in root_install and ev.call != "execve":
            continue
        if ev.call == "socket" and ev.ok and ("AF_INET" in ev.args):
            fd_socket[(ev.pid, ev.ret)] = True
        elif ev.call == "connect":
            addr = strace.sock_addr(ev.args)
            fd_m = re.match(r"(\d+),", ev.args)
            if addr and ev.pid not in root_install:
                ip, port = addr
                if ip == "127.0.0.1" or ip == "::1":
                    continue
                if ev.ok or ev.err in ("EINPROGRESS", "ENETUNREACH", "ECONNREFUSED", "EHOSTUNREACH", "ETIMEDOUT"):
                    book.add(NetworkKind.CONNECT, ip_to_name.get(ip), ip=ip, port=port, phase=ev.phase)
                    if fd_m:
                        sockets[ev.pid].add(int(fd_m[1]))
                    if port not in (80, 443, 53, 8080, 8443):
                        connected_nonweb[strace.group_of(procs, ev.pid)] = (ip_to_name.get(ip) or ip, port)
        elif ev.call in ("dup2", "dup3") and ev.ok:
            m = re.match(r"(\d+), (\d+)", ev.args)
            if m and int(m[2]) in (0, 1, 2) and int(m[1]) in sockets.get(ev.pid, set()):
                res.reverse_shell.append(f"stdin/stdout redirected onto an outbound socket by pid {ev.pid}")
        elif ev.call in ("execve", "execveat") and ev.ok and ev.pid not in root_install:
            quoted = strace.QUOTED.findall(ev.args)
            if quoted and not quoted[0].endswith("/setpriv"):
                executed.append((strace.unescape(quoted[0]), ev.pid, " ".join(quoted[1:6])))
        elif ev.call in ("chmod", "fchmodat") and ev.ok:
            m = re.search(r'"((?:[^"\\]|\\.)*)",\s*(0[0-7]+)', ev.args)
            if m and int(m[2], 8) & 0o111:
                chmodded.add(strace.unescape(m[1]))
        opened = strace.open_path(ev)
        if opened and ev.pid not in root_install:
            path, is_write = opened
            if is_write:
                for pat, label in PERSISTENCE:
                    if pat.search(path):
                        res.persistence.append((path, label))
            else:
                reader = procs.get(strace.group_of(procs, ev.pid))
                if path in decoy_files and decoy_files[path]["kind"] == "shell_history" and reader and _base(reader.exe) in SHELLS:
                    continue  # an interactive shell reads its own history at startup
                if path in decoy_files and decoy_files[path]["kind"] == "npmrc" and reader and any(a.endswith(("/npm", "npm-cli.js")) for a in reader.argv[:3]):
                    continue  # a package's installer running `npm` (esbuild does) reads ~/.npmrc as part of normal npm use
                if path in decoy_files:
                    d = decoy_files[path]
                    res.files.append(SandboxFileEvent(run=name, op="read", path=path, decoy=True, category=d["kind"], phase=ev.phase))
                else:
                    for pat, label in SENSITIVE:
                        if pat.search(path):
                            res.files.append(SandboxFileEvent(run=name, op="read", path=path, decoy=False, category=label, phase=ev.phase))
                if path in ("/.dockerenv", "/proc/1/cgroup") or PROBE_PATHS.search(path):
                    res.probes.append(path)

    # ---- processes
    for proc in procs.values():
        if proc.is_root or not proc.exe or proc.exe.startswith("/opt/sbx"):
            continue
        if "/opt/sbx/loader.js" in " ".join(proc.argv):
            continue
        res.processes.append(SandboxProcess(run=name, pid=proc.pid, ppid=proc.ppid, exe=proc.exe, argv=proc.argv[:20], phase=proc.phase))
        base, cmdline = _base(proc.exe), " ".join(proc.argv)
        if REVERSE_SHELL_ARGS.search(cmdline):
            res.reverse_shell.append(f"command: {cmdline[:200]}")
        if base in SHELLS and ("-i" in proc.argv or len(proc.argv) <= 1) and proc.ppid is not None and strace.group_of(procs, proc.ppid) in connected_nonweb:
            host, port = connected_nonweb[strace.group_of(procs, proc.ppid)]
            res.reverse_shell.append(f"interactive shell started by a process connected to {host}:{port}")
        if base in NET_TOOLS or base in ("powershell", "pwsh", "crontab"):
            res.suspicious_exec.append(f"{base}: {cmdline[:160]}")
            hits = canaries.find(cmdline)
            if hits and base in NET_TOOLS:
                for c in hits:
                    book.hits.setdefault((c.id, f"argument of {base}"), CanaryHit(canary_id=c.id, decoy_path=c.decoy_path, sink=f"argument of {base}", run=name))
        elif base in SHELLS and "-c" in proc.argv and SHELL_ABUSE.search(cmdline):
            res.suspicious_exec.append(f"shell: {cmdline[:160]}")
        elif base.startswith("python") and "-c" in proc.argv:
            res.suspicious_exec.append(f"python: {cmdline[:160]}")
        elif base == "node" and ("-e" in proc.argv or "--eval" in proc.argv) and len(cmdline) > 200:
            res.suspicious_exec.append(f"node -e: {cmdline[:160]}")
        if MINER_NAMES.search(proc.exe) or MINER_NAMES.search(cmdline):
            res.resource_flags.append(f"miner-like process: {base}")

    # ---- filesystem changes and dropped executables
    added_exec: set[str] = set()
    for c in trace.get("fsChanges", [])[:MAX_EVENTS]:
        path = c["path"]
        op = c["change"]
        res.files.append(SandboxFileEvent(run=name, op=op, path=path, decoy=path in decoy_files, category=decoy_files.get(path, {}).get("kind"), executable=bool(c.get("executable")), sha256=c.get("sha256"), preview=(c.get("preview") or None) and c["preview"][:600]))
        if op in ("added", "modified"):
            for pat, label in PERSISTENCE:
                if pat.search(path):
                    res.persistence.append((path, label))
            if c.get("executable") or path in chmodded:
                added_exec.add(path)
    for exe, pid, cmdline in executed:
        if exe.startswith(SYSTEM_PREFIXES):
            continue
        if exe in added_exec or (exe in chmodded and exe.startswith(DROP_DIRS)) or exe.startswith(DROP_DIRS):
            res.droppers.append(exe)

    # ---- resources and coverage
    for p in phases_raw:
        res.seconds += p.get("seconds", 0.0)
        res.cpu = max(res.cpu, p.get("cpuSeconds", 0.0))
        res.memory_mb = max(res.memory_mb, p.get("peakMemoryKb", 0) / 1024)
        compiled = any(_base(x.exe) in ("gcc", "cc", "g++", "make", "node-gyp", "python3", "cmake", "clang") for x in procs.values() if x.phase == p["name"])
        if p.get("timedOut") and p.get("seconds", 0) >= 8 and p.get("cpuSeconds", 0) >= 0.35 * p["seconds"] and not compiled:
            res.resource_flags.append(f"{p['name']} used the CPU flat out until it was killed ({p['seconds']:.0f}s)")
    loader = trace.get("coverage", {}).get("loader") or {}
    res.coverage = SandboxCoverage(
        installed=trace.get("coverage", {}).get("installed", False),
        install_scripts_ran=not any(p["name"] == "install-noscripts" for p in phases_raw),
        entry_loaded=loader.get("loaded") if loader else None,
        entry_error=(loader.get("error") or "")[:200] or None,
        bins_run=sum(1 for p in phases_raw if p["name"].startswith("bin-")),
        timed_out=any(p.get("timedOut") for p in phases_raw),
    )  # fmt: skip
    pkg_name = trace.get("package", {}).get("name", "")
    res.entry_failed = res.coverage.entry_loaded is False and not (res.coverage.entry_error or "").startswith(f"Cannot find module '{pkg_name}'")
    res.network = list(book.events.values())
    res.canary_hits = list(book.hits.values())
    return res


def _finding(rule: str, severity: Severity, confidence: Confidence, title: str, *, file: str | None = None, snippet: str | None = None, install: bool = False, n: int = 1) -> Finding:
    return Finding(rule_id=f"sandbox.{rule}", layer=FindingLayer.SANDBOX, severity=severity, confidence=confidence, title=title, file=file, snippet=(snippet or "")[:300] or None, install_time=install, occurrences=max(1, n))


def _signature(r: RunResult) -> dict[tuple, str]:
    sig: dict[tuple, str] = {}
    for e in r.network:
        if e.classification != NetworkClass.EXPECTED and e.kind in (NetworkKind.HTTP, NetworkKind.TCP, NetworkKind.UDP, NetworkKind.DNS):
            sig[("net", _norm_host((e.host or e.ip or "").lower()))] = f"contacts {_norm_host(e.host or e.ip or '')}"
    for h in r.canary_hits:
        sig[("canary", h.canary_id, h.sink)] = f"sends the fake {h.canary_id} credential ({h.sink})"
    for s in r.suspicious_exec:
        sig[("exec", s.split(":")[0])] = f"runs {s[:80]}"
    for path, _ in r.persistence:
        sig[("persist", path)] = f"writes {path}"
    for d in r.droppers:
        sig[("dropper", d)] = f"runs the dropped file {d}"
    return sig


def make_findings(results: list[RunResult]) -> list[Finding]:
    out: list[Finding] = []
    seen_hosts: set[tuple] = set()

    # proof-grade: fake credentials that left the box
    hits: dict[tuple[str, str], CanaryHit] = {}
    for r in results:
        for h in r.canary_hits:
            hits.setdefault((h.canary_id, h.sink), h)
    by_sink: dict[str, list[CanaryHit]] = defaultdict(list)
    for h in hits.values():
        by_sink[h.sink].append(h)
    for sink, group in by_sink.items():
        names = ", ".join(dict.fromkeys(h.canary_id.replace("env:", "").replace("_", " ").lower() for h in group))
        out.append(_finding("canary_exfil", Severity.HIGH, Confidence.HIGH, f"Sent planted fake credentials ({names[:120]}) to {sink.split(' ', 1)[-1]}", file=group[0].decoy_path, snippet=f"{sink}: " + ", ".join(h.canary_id for h in group), install=True, n=len(group)))

    reverse = list(dict.fromkeys(x for r in results for x in r.reverse_shell))
    if reverse:
        out.append(_finding("reverse_shell", Severity.HIGH, Confidence.HIGH, "Opens a remote shell (reverse shell behavior)", snippet="; ".join(reverse[:3]), install=True, n=len(reverse)))

    unexpected_net = any(e.classification != NetworkClass.EXPECTED and e.kind != NetworkKind.DNS for r in results for e in r.network)
    for path in dict.fromkeys(x for r in results for x in r.droppers):
        if unexpected_net:
            out.append(_finding("dropper_exec", Severity.HIGH, Confidence.MEDIUM, "Runs a file it just created after contacting an outside host (dropper pattern)", file=path, install=True))
        else:
            out.append(_finding("dropper_exec", Severity.LOW, Confidence.LOW, "Runs a binary it just created (only the npm registry was contacted)", file=path, install=True))

    persist = {p: label for r in results for p, label in r.persistence}
    for path, label in persist.items():
        out.append(_finding("persistence", Severity.HIGH, Confidence.HIGH, f"Modifies a {label} so code keeps running later", file=path, install=True))

    reads = Counter((e.category, e.path) for r in results for e in r.files if e.op == "read")
    for (category, path), _ in reads.items():
        out.append(_finding("decoy_read", Severity.MEDIUM, Confidence.HIGH, f"Reads {str(category).replace('_', ' ')} credentials", file=path, install=True))

    for r in results:
        for e in r.network:
            key = (e.classification, _norm_host((e.host or e.ip or "").lower()))
            if e.classification == NetworkClass.EXPECTED or key in seen_hosts:
                continue
            if e.classification in SUSPICIOUS_CLASSES:
                seen_hosts.add(key)
                label = {NetworkClass.OAST: "a request-capture / out-of-band testing service", NetworkClass.WEBHOOK: "a chat webhook (Discord/Telegram/Slack)", NetworkClass.PASTE: "a paste / file-drop site", NetworkClass.TUNNEL: "a tunnelling service", NetworkClass.METADATA: "a cloud metadata endpoint", NetworkClass.STRATUM: "a port used by mining pools and reverse shells", NetworkClass.RAW_IP: "a raw IP address"}[e.classification]
                out.append(_finding("suspicious_network", Severity.MEDIUM, Confidence.HIGH, f"Contacts {label}: {e.host or e.ip}", file=e.host or e.ip, snippet=e.url or f"{e.kind.value} {e.host or e.ip}:{e.port}", install=True))
            elif e.kind == NetworkKind.DNS and e.classification == NetworkClass.UNEXPECTED and DATA_LABEL.search(e.host or ""):
                seen_hosts.add(key)
                out.append(_finding("suspicious_network", Severity.MEDIUM, Confidence.MEDIUM, "Looks up a hostname that carries encoded data (possible DNS exfiltration)", file=_norm_host(e.host or ""), snippet=(e.host or "")[:120], install=True))
            elif e.classification == NetworkClass.UNEXPECTED and e.kind != NetworkKind.DNS:
                seen_hosts.add(key)
                sends = bool(e.body_preview) and (e.method or "").upper() in ("POST", "PUT")
                out.append(_finding("unexpected_network", Severity.MEDIUM if sends else Severity.LOW, Confidence.MEDIUM, f"{'Sends data to' if sends else 'Contacts'} a host that is not the npm registry: {e.host or e.ip}", file=e.host or e.ip, snippet=e.url, install=True))

    execs = list(dict.fromkeys(x for r in results for x in r.suspicious_exec))
    if execs:
        out.append(_finding("suspicious_process", Severity.MEDIUM, Confidence.MEDIUM, "Runs download / decode / shell tools", snippet="; ".join(execs[:3]), install=True, n=len(execs)))

    evals = {e.sha256: e for r in results for e in r.evals}
    for e in evals.values():
        risky = bool(EVAL_TOKENS.search(e.preview))
        if risky:
            out.append(_finding("eval_payload", Severity.MEDIUM, Confidence.MEDIUM, f"Runs code built at runtime ({e.api}) that uses the network, commands or secrets", snippet=e.preview[:200]))

    flags = list(dict.fromkeys(x for r in results for x in r.resource_flags))
    stratum = any(e.classification == NetworkClass.STRATUM for r in results for e in r.network)
    if flags:
        out.append(_finding("resource_abuse", Severity.HIGH if (stratum or any("miner" in f for f in flags)) else Severity.MEDIUM, Confidence.MEDIUM, "Behaves like a crypto miner or resource hog", snippet="; ".join(flags[:3]), install=True))

    if any(r.env_dumps for r in results) or any(len(r.recon) >= 2 for r in results):
        out.append(_finding("env_recon", Severity.LOW, Confidence.MEDIUM, "Collects environment variables or machine details", install=True))

    probes = list(dict.fromkeys(p for r in results for p in r.probes))
    if probes:
        out.append(_finding("sandbox_detection", Severity.MEDIUM, Confidence.MEDIUM, "Checks whether it is running in a container or VM", snippet=", ".join(probes[:3]), n=len(probes)))

    # behavior that only shows up under one condition
    if len(results) == 2:
        base = next((r for r in results if r.name == "baseline"), None)
        hostile = next((r for r in results if r.name == "hostile"), None)
        if base and hostile:
            sb, sh = _signature(base), _signature(hostile)
            only_hostile = [sh[k] for k in sh.keys() - sb.keys()]
            only_base = [sb[k] for k in sb.keys() - sh.keys()]
            if only_hostile:
                out.append(_finding("conditional_behavior", Severity.HIGH, Confidence.MEDIUM, f"Only under CI / a later date: {only_hostile[0]}" + (f" (+{len(only_hostile) - 1} more)" if len(only_hostile) > 1 else ""), snippet="; ".join(sorted(only_hostile))[:300], install=True, n=len(only_hostile)))
            if only_base:
                out.append(_finding("conditional_behavior", Severity.MEDIUM, Confidence.LOW, f"Stops when it looks like CI or the date moves: {only_base[0]}" + (f" (+{len(only_base) - 1} more)" if len(only_base) > 1 else ""), snippet="; ".join(sorted(only_base))[:300], install=True, n=len(only_base)))

    if any(r.entry_failed for r in results):
        err = next((r.coverage.entry_error for r in results if r.entry_failed), "") or ""
        out.append(_finding("coverage_gap", Severity.LOW, Confidence.HIGH, "The package's entry file could not be loaded in the sandbox (its dependencies are not installed), so behavior on import was not observed", snippet=err.splitlines()[0] if err else None))
    for r in results:
        if not r.coverage.installed:
            out.append(_finding("coverage_gap", Severity.LOW, Confidence.HIGH, "The package could not be installed in the sandbox, so its behavior was not observed"))
            break
    return out


def build_report(traces: list[dict], *, raw_trace_key: str | None = None, version: str = "0.1.0") -> SandboxReport:
    if not traces:
        return SandboxReport(version=version, status=SandboxStatus.FAILED, skip_reason="no trace produced")
    results = [analyze_run(t) for t in traces]
    findings = make_findings(results)
    first = results[0]
    partial = (not first.coverage.installed) or first.coverage.timed_out or first.entry_failed or any(r.summary.notes for r in results)
    files: list[SandboxFileEvent] = []
    for r in results:
        files += r.files
    return SandboxReport(
        version=version,
        status=SandboxStatus.PARTIAL if partial else SandboxStatus.COMPLETE,
        duration_seconds=round(max(r.seconds for r in results), 1),
        raw_trace_s3_key=raw_trace_key,
        coverage=first.coverage,
        runs=[r.summary for r in results],
        network=[e for r in results for e in r.network][:MAX_EVENTS],
        processes=[p for r in results for p in r.processes][:MAX_EVENTS],
        files=files[:MAX_EVENTS],
        eval_payloads=list({e.sha256: e for r in results for e in r.evals}.values())[:50],
        canary_hits=list({(h.canary_id, h.sink): h for r in results for h in r.canary_hits}.values()),
        conditional=[ConditionalBehavior(description=f.title, only_in_run="hostile" if f.severity == Severity.HIGH else "baseline") for f in findings if f.rule_id == "sandbox.conditional_behavior"],
        resources=SandboxResources(peak_cpu_seconds=max(r.cpu for r in results), peak_memory_mb=round(max(r.memory_mb for r in results), 1), timed_out_phases=[p.name for r in results for p in r.summary.phases if p.timed_out]),
        findings=findings,
    )
