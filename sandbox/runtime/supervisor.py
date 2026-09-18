#!/usr/bin/env python3
"""Runs one package inside this container and writes a raw trace. Runs as root; the package never does.

  supervisor.py --input - --output - --run baseline        (tarball on stdin, gzipped JSON trace on stdout)
  supervisor.py --input s3://b/k.tgz --output s3://b/t.json.gz --run hostile

The package runs as an unprivileged user with no way to regain privileges, under strace, with a Node
hook, next to a fake network. Three phases: install (scripts enabled), require, and each bin with --help."""

import argparse
import glob
import gzip
import hashlib
import io
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, "/opt/sbx")
from decoys import make_decoys  # noqa: E402
from sinkhole import Sinkhole  # noqa: E402

VERSION = "0.1.0"
UID = 10001
HOME = "/home/sandbox"
WORK = f"{HOME}/project"
STATE = "/var/sbx"
HOOK_DIR = f"{STATE}/hook"
TMP = "/tmp/sbx"
MAX_TARBALL = 60 * 1024 * 1024
MAX_STRACE_LINES = 120_000
MAX_HOOK_EVENTS = 50_000
TOTAL_BUDGET = 100
STRACE_TRACE = (
    "execve,execveat,clone,clone3,fork,vfork,connect,bind,listen,sendto,socket,dup2,dup3,openat,creat,"
    "unlink,unlinkat,rename,renameat,renameat2,chmod,fchmod,fchmodat,symlink,symlinkat,link,linkat,mkdir,mkdirat,ptrace,setsid,kill"
)
NOISE_OPEN = re.compile(
    r'openat\(AT_FDCWD, "(/usr/(lib|share|local/lib|local/include)|/lib|/proc/self|/sys/|/opt/sbx|/dev/(null|urandom|tty|pts)|/etc/(ld\.so|ssl|localtime|nsswitch|resolv|hosts|host\.conf|gai\.conf|ca-certificates))'
)
OPEN_PATH = re.compile(r'openat\(AT_FDCWD, "([^"]+)", ([A-Z_|]+)')


def log(msg: str) -> None:
    print(f"[sbx] {msg}", file=sys.stderr, flush=True)


def read_input(spec: str) -> bytes:
    if spec == "-":
        data = sys.stdin.buffer.read(MAX_TARBALL + 1)
    elif spec.startswith("s3://"):
        import boto3

        bucket, _, key = spec[5:].partition("/")
        data = boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read(MAX_TARBALL + 1)
    else:
        with open(spec, "rb") as fh:
            data = fh.read(MAX_TARBALL + 1)
    if len(data) > MAX_TARBALL:
        raise SystemExit("tarball too large")
    return data


def write_output(spec: str, data: bytes) -> None:
    if spec == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    elif spec.startswith("s3://"):
        import boto3

        bucket, _, key = spec[5:].partition("/")
        boto3.client("s3").put_object(Bucket=bucket, Key=key, Body=data, ContentType="application/gzip")
    else:
        with open(spec, "wb") as fh:
            fh.write(data)


def prepare_tarball(raw: bytes) -> tuple[str, dict, list[str], dict[str, int]]:
    """Removes dependency fields from package.json so an offline install can run the package's own scripts.
    Nothing is extracted or executed here."""
    src = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    members = src.getmembers()
    manifest_member = min((m for m in members if m.isfile() and m.name.endswith("package.json")), key=lambda m: m.name.count("/"), default=None)
    if manifest_member is None:
        raise SystemExit("no package.json in tarball")
    prefix = manifest_member.name[: -len("package.json")]
    manifest = json.loads(src.extractfile(manifest_member).read().decode("utf-8", "replace"))
    stripped = [k for k in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies", "bundleDependencies", "bundledDependencies") if k in manifest]
    files: dict[str, int] = {}
    os.makedirs(TMP, exist_ok=True)
    out_path = f"{TMP}/pkg.tgz"
    with tarfile.open(out_path, "w:gz") as out:
        for m in members:
            if m.isfile():
                files[m.name[len(prefix):] if m.name.startswith(prefix) else m.name] = m.size
            if m is manifest_member:
                clean = {k: v for k, v in manifest.items() if k not in stripped}
                data = json.dumps(clean, indent=1).encode()
                info = tarfile.TarInfo(m.name)
                info.size, info.mode, info.mtime = len(data), 0o644, m.mtime
                out.addfile(info, io.BytesIO(data))
            elif m.isfile():
                out.addfile(m, src.extractfile(m))
            else:
                out.addfile(m)
    os.chmod(TMP, 0o755)
    os.chmod(out_path, 0o644)
    return out_path, manifest, stripped, files


def snapshot(roots: list[str], skip: tuple[str, ...]) -> dict[str, tuple]:
    snap: dict[str, tuple] = {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not any(os.path.join(dirpath, d).startswith(s) for s in skip)]
            for name in filenames + dirnames:
                p = os.path.join(dirpath, name)
                if any(p.startswith(s) for s in skip):
                    continue
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                snap[p] = (st.st_size, st.st_mode, st.st_mtime_ns, os.path.islink(p))
                if len(snap) > 60_000:
                    return snap
    return snap


def file_info(path: str, change: str, st: tuple | None) -> dict:
    info: dict = {"path": path, "change": change}
    try:
        stat = os.lstat(path)
        info["size"] = stat.st_size
        info["executable"] = bool(stat.st_mode & 0o111) and os.path.isfile(path)
        if os.path.islink(path):
            info["symlinkTo"] = os.readlink(path)
        elif os.path.isfile(path) and stat.st_size <= 5 * 1024 * 1024:
            with open(path, "rb") as fh:
                blob = fh.read()
            info["sha256"] = hashlib.sha256(blob).hexdigest()
            head = blob[:600]
            info["preview"] = head.decode("utf-8", "replace") if b"\x00" not in head else "<binary>"
    except OSError:
        pass
    return info


def keep_strace_line(line: str) -> bool:
    if "openat(" in line:
        if NOISE_OPEN.search(line):
            return False
        m = OPEN_PATH.search(line)
        if m and m.group(1).startswith((f"{WORK}/node_modules/", f"{HOME}/.npm/")) and "O_WRONLY" not in m.group(2) and "O_RDWR" not in m.group(2) and "O_CREAT" not in m.group(2):
            return False
    return True


def tracee_command(cmd: list[str], env_prefix: list[str], strace_path: str) -> list[str]:
    return [
        "strace", "-f", "-q", "-ttt", "-s", "400", "-e", f"trace={STRACE_TRACE}", "-o", strace_path, "--",
        "setpriv", f"--reuid={UID}", f"--regid={UID}", "--clear-groups", "--no-new-privs", "--inh-caps=-all", "--bounding-set=-all", "--",
        *env_prefix, *cmd,
    ]  # fmt: skip


def live_cpu_seconds() -> float:
    """CPU time used so far by everything the package started (RUSAGE_CHILDREN misses killed processes)."""
    total, ticks = 0.0, os.sysconf("SC_CLK_TCK")
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != UID:
                continue
            fields = open(f"/proc/{entry}/stat").read().rsplit(")", 1)[1].split()
            total += (int(fields[11]) + int(fields[12]) + int(fields[13]) + int(fields[14])) / ticks
        except (OSError, IndexError, ValueError):
            continue
    return total


def kill_sandbox_user() -> int:
    r = subprocess.run(["pgrep", "-c", "-u", str(UID)], capture_output=True, text=True)
    running = int((r.stdout or "0").strip() or 0)
    subprocess.run(["pkill", "-9", "-u", str(UID)], capture_output=True)
    return running


def run_phase(name: str, cmd: list[str], env: dict, env_prefix: list[str], timeout: float) -> dict:
    strace_path = f"{STATE}/strace-{name}.txt"
    out_path, err_path = f"{STATE}/{name}.out", f"{STATE}/{name}.err"
    for private in (strace_path, out_path, err_path):
        os.close(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.time()
    timed_out = False
    live_cpu = 0.0
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.Popen(
            tracee_command(cmd, env_prefix, strace_path), cwd=WORK, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True
        )
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            live_cpu = live_cpu_seconds()
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            code = proc.wait()
    seconds = time.time() - started
    left_behind = kill_sandbox_user()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)

    lines: list[str] = []
    try:
        with open(strace_path, errors="replace") as fh:
            for line in fh:
                if keep_strace_line(line):
                    lines.append(line.rstrip("\n")[:700])
                    if len(lines) >= MAX_STRACE_LINES:
                        break
    except OSError:
        pass

    def tail(p: str) -> str:
        try:
            with open(p, "rb") as fh:
                return fh.read()[-4000:].decode("utf-8", "replace")
        except OSError:
            return ""

    return {
        "name": name,
        "cmd": cmd,
        "startedAtMs": int(started * 1000),
        "exitCode": code,
        "timedOut": timed_out,
        "seconds": round(seconds, 2),
        "cpuSeconds": round(max(live_cpu, (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)), 2),
        "peakMemoryKb": after.ru_maxrss,
        "leftBehindProcesses": left_behind,
        "stdoutTail": tail(out_path),
        "stderrTail": tail(err_path),
        "straceLines": lines,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--run", choices=["baseline", "hostile"], default="baseline")
    args = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("supervisor must start as root (it drops privileges for the package)")
    deadline = time.time() + TOTAL_BUDGET
    notes: list[str] = []

    os.makedirs(STATE, exist_ok=True)
    os.chmod(STATE, 0o711)  # the package can traverse but not list or read our files
    os.makedirs(HOOK_DIR, exist_ok=True)
    os.chmod(HOOK_DIR, 0o777)
    raw = read_input(args.input)
    tarball_sha = hashlib.sha256(raw).hexdigest()
    tgz, manifest, stripped, tar_files = prepare_tarball(raw)
    name = manifest.get("name", "unknown")

    os.makedirs(WORK, exist_ok=True)
    with open(f"{WORK}/package.json", "w") as fh:
        json.dump({"name": "sbx-host", "version": "1.0.0", "private": True}, fh)
    decoy_files, decoy_env = make_decoys(HOME)
    subprocess.run(["chown", "-R", f"{UID}:{UID}", HOME], check=False)
    hook_log = f"{HOOK_DIR}/hook.jsonl"
    open(hook_log, "w").close()
    os.chmod(hook_log, 0o666)

    sink = Sinkhole("/opt/sbx/ca.pem", "/opt/sbx/ca.key")
    sink.start()
    try:
        with open("/etc/resolv.conf") as fh:
            original_resolv = fh.read()
    except OSError:
        original_resolv = None
    try:
        with open("/etc/resolv.conf", "w") as fh:
            fh.write("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
    except OSError as exc:
        notes.append(f"could not point DNS at the sinkhole: {exc}")

    hostile = args.run == "hostile"
    run_env = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "RUNNER_OS": "Linux"} if hostile else {}
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": HOME, "USER": "sandbox", "LOGNAME": "sandbox", "SHELL": "/bin/bash", "LANG": "C.UTF-8", "TERM": "xterm",
        "NODE_OPTIONS": "--require /opt/sbx/hook.js", "NODE_EXTRA_CA_CERTS": "/opt/sbx/ca.pem", "SBX_HOOK_LOG": hook_log,
        "npm_config_cache": f"{HOME}/.npm", "npm_config_offline": "true", "npm_config_audit": "false",
        "npm_config_fund": "false", "npm_config_update_notifier": "false",
        **{d["name"]: d["value"] for d in decoy_env}, **run_env,
    }  # fmt: skip
    env_prefix: list[str] = []
    if hostile:
        env["SBX_FAKE_HOSTNAME"], env["SBX_FAKE_USER"] = "ci-runner-04", "runner"
        lib = next(iter(glob.glob("/usr/lib/*/faketime/libfaketime.so.1")), None)
        if lib:
            env_prefix = ["env", f"LD_PRELOAD={lib}", "FAKETIME=+60d", "FAKETIME_DONT_FAKE_MONOTONIC=1", "FAKETIME_NO_CACHE=1"]
        else:
            notes.append("libfaketime not found: clock was not moved forward")

    watch = [HOME, "/tmp", "/var/tmp", "/dev/shm"]
    skip = (f"{HOME}/.npm", f"{HOME}/.cache", WORK, TMP, STATE)
    snap_before = snapshot(watch, skip)

    phases = []
    install_cmd = ["npm", "install", tgz, "--no-package-lock", "--no-audit", "--no-fund", "--offline", "--foreground-scripts", "--loglevel=error"]
    phases.append(run_phase("install", install_cmd, env, env_prefix, min(30, max(5, deadline - time.time()))))
    pkg_dir = f"{WORK}/node_modules/{name}"
    installed = os.path.isdir(pkg_dir)
    if not installed and deadline - time.time() > 8:
        # A crashing install script makes npm roll the package back. Install the files without scripts
        # so the require and bin phases can still observe the code.
        notes.append("install scripts failed and npm rolled the package back: re-installed with scripts disabled to still load the code")
        phases.append(run_phase("install-noscripts", [*install_cmd, "--ignore-scripts"], env, env_prefix, 20))
        installed = os.path.isdir(pkg_dir)
    loader = None
    if installed:
        remaining = deadline - time.time()
        if remaining > 3:
            phases.append(run_phase("require", ["node", "/opt/sbx/loader.js", name], env, env_prefix, min(15, remaining)))
        bins = manifest.get("bin")
        bin_names = [name.split("/")[-1]] if isinstance(bins, str) else list(bins)[:5] if isinstance(bins, dict) else []
        for b in bin_names:
            remaining = deadline - time.time()
            path = f"{WORK}/node_modules/.bin/{b}"
            if remaining > 3 and os.path.exists(path):
                phases.append(run_phase(f"bin-{re.sub(r'[^A-Za-z0-9_.-]', '_', b)}", [path, "--help"], env, env_prefix, min(10, remaining)))
    else:
        notes.append("package directory missing after install: install failed or was blocked")
    for p in phases:
        m = re.search(r"SBX_LOAD (\{.*\})", p["stdoutTail"])
        if p["name"] == "require" and m:
            try:
                loader = json.loads(m.group(1))
            except ValueError:
                pass

    snap_after = snapshot(watch, skip)
    changes = []
    for path, meta in snap_after.items():
        if "faketime" in path:
            continue
        if path not in snap_before:
            changes.append(file_info(path, "added", meta))
        elif snap_before[path][:2] != meta[:2] or snap_before[path][2] != meta[2]:
            changes.append(file_info(path, "modified", meta))
    for path in snap_before:
        if path not in snap_after:
            changes.append({"path": path, "change": "deleted"})
    extra = 0
    if installed:
        for dirpath, dirnames, filenames in os.walk(pkg_dir):
            dirnames[:] = [d for d in dirnames if d != "node_modules"]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, pkg_dir)
                try:
                    size = os.lstat(full).st_size
                except OSError:
                    continue
                if rel not in tar_files and rel != "package.json":
                    changes.append({**file_info(full, "added", None), "where": "package_dir"})
                    extra += 1
                elif rel in tar_files and rel != "package.json" and tar_files[rel] != size:
                    changes.append({**file_info(full, "modified", None), "where": "package_dir"})
    changes = changes[:400]

    hook_events = []
    try:
        with open(hook_log) as fh:
            for line in fh:
                try:
                    hook_events.append(json.loads(line))
                except ValueError:
                    continue
                if len(hook_events) >= MAX_HOOK_EVENTS:
                    break
    except OSError:
        pass

    trace = {
        "sandboxVersion": VERSION,
        "run": {"name": args.run, "env": {"ci": hostile, "clockOffsetDays": 60 if env_prefix else 0, "hostname": env.get("SBX_FAKE_HOSTNAME", "container"), "user": env.get("SBX_FAKE_USER", "sandbox")}},
        "package": {
            "name": name, "version": manifest.get("version"), "tarballSha256": tarball_sha, "strippedDependencyFields": stripped,
            "bin": manifest.get("bin"), "scripts": manifest.get("scripts") or {}, "main": manifest.get("main"), "files": len(tar_files),
        },
        "coverage": {"installed": installed, "loader": loader},
        "phases": phases,
        "hookEvents": hook_events,
        "sinkhole": {"events": sink.events, "ipToName": sink.ip_to_name},
        "decoys": {"files": decoy_files, "env": decoy_env},
        "fsChanges": changes,
        "notes": notes,
    }  # fmt: skip
    blob = gzip.compress(json.dumps(trace).encode(), 6)
    # The package is finished. Give our own upload the real resolver back (it was pointed at the fake DNS).
    kill_sandbox_user()
    if original_resolv is not None:
        try:
            with open("/etc/resolv.conf", "w") as fh:
                fh.write(original_resolv)
        except OSError:
            pass
    write_output(args.output, blob)
    log(f"done: {len(blob)} bytes, {sum(len(p['straceLines']) for p in phases)} strace lines, {len(hook_events)} hook events, {len(sink.events)} sinkhole events")
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
