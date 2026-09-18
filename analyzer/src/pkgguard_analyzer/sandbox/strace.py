"""Parses strace output from the sandbox into events and a process tree. Only the calls the supervisor traces."""

import re
from dataclasses import dataclass, field

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
UNFINISHED = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*?)\s*<unfinished \.\.\.>\s*$")
RESUMED = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
EXIT = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+\+\+\+ exited with (\d+)")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
SOCK_V4 = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
SOCK_V6 = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"\)')
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


@dataclass
class Ev:
    pid: int
    ts: float
    call: str
    args: str
    ret: int | None
    err: str | None = None
    phase: str = ""

    @property
    def ok(self) -> bool:
        return self.ret is not None and self.ret >= 0


@dataclass
class Proc:
    pid: int
    ppid: int | None = None
    exe: str = ""
    argv: list[str] = field(default_factory=list)
    phase: str = ""
    is_root: bool = False
    thread_of: int | None = None


def unescape(s: str) -> str:
    return s.encode("latin-1", "backslashreplace").decode("unicode_escape", "replace") if "\\" in s else s


def parse(phase_lines: dict[str, list[str]]) -> tuple[list[Ev], dict[int, Proc]]:
    """`phase_lines` maps phase name -> raw strace lines. Returns all events plus the process tree."""
    events: list[Ev] = []
    procs: dict[int, Proc] = {}
    for phase, lines in phase_lines.items():
        root: int | None = None
        pending: dict[tuple[int, str], str] = {}
        for raw in lines:
            m = LINE.match(raw)
            if not m:
                u = UNFINISHED.match(raw)
                if u:
                    pending[(int(u[1]), u[3])] = u[4]
                    continue
                r = RESUMED.match(raw)
                if not r:
                    continue
                # Rebuild a call strace split in two (common for execve and other blocking calls).
                first = pending.pop((int(r[1]), r[3]), "")
                m = re.match(r"(.*)", "")
                pid, ts, call, args, ret, err = int(r[1]), float(r[2]), r[3], (first + r[4]), r[5], r[6]
            else:
                pid, ts, call, args, ret, err = int(m[1]), float(m[2]), m[3], m[4], m[5], m[6]
            if root is None:
                root = pid
                procs.setdefault(pid, Proc(pid=pid, phase=phase, is_root=True))
            ev = Ev(pid, ts, call, args, None if ret == "?" else int(ret), err, phase)
            events.append(ev)
            proc = procs.setdefault(pid, Proc(pid=pid, phase=phase))
            if call in ("clone", "clone3", "fork", "vfork") and ev.ok and ev.ret:
                procs.setdefault(ev.ret, Proc(pid=ev.ret, ppid=pid, phase=phase))
                procs[ev.ret].ppid = pid
                if "CLONE_THREAD" in args:
                    procs[ev.ret].thread_of = pid
            elif call in ("execve", "execveat") and ev.ok:
                strs = QUOTED.findall(args)
                if not strs:
                    continue
                exe = unescape(strs[0])
                if exe.endswith("/setpriv"):
                    continue
                argv_part = args.split("[", 1)[1].rsplit("]", 1)[0] if "[" in args else ""
                proc.exe, proc.argv = exe, [unescape(a) for a in QUOTED.findall(argv_part)]
    return events, procs


def sock_addr(args: str) -> tuple[str, int] | None:
    m = SOCK_V4.search(args) or SOCK_V6.search(args)
    if not m:
        return None
    return m[2], int(m[1])


def open_path(ev: Ev) -> tuple[str, bool] | None:
    """(path, is_write) for a successful openat/creat."""
    if not ev.ok or ev.call not in ("openat", "creat"):
        return None
    m = re.match(r'(?:AT_FDCWD|\d+), "((?:[^"\\]|\\.)*)", ([A-Z_|]+)', ev.args) if ev.call == "openat" else re.match(r'"((?:[^"\\]|\\.)*)"', ev.args)
    if not m:
        return None
    flags = m[2] if ev.call == "openat" else "O_WRONLY|O_CREAT"
    return unescape(m[1]), any(f in flags for f in WRITE_FLAGS)


def group_of(procs: dict[int, Proc], pid: int) -> int:
    """The process a thread belongs to (strace lists each thread as its own pid)."""
    seen = 0
    while pid in procs and procs[pid].thread_of is not None and seen < 50:
        pid = procs[pid].thread_of  # type: ignore[assignment]
        seen += 1
    return pid
