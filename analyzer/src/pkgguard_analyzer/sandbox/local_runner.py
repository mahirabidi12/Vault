"""Runs a HARMLESS fixture in the sandbox image with local Docker, for development and tests.

Safety: this runner only accepts directories inside this repo's `eval/fixtures/` or `sandbox/fixtures/`.
Real malware is never fetched or run on a laptop; it only ever runs in the AWS sandbox. The container
has no network, no host mounts (the tarball goes in on stdin, the trace comes out on
stdout), dropped capabilities and memory/CPU/process caps."""

import argparse
import gzip
import io
import json
import subprocess
import sys
import tarfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
ALLOWED_ROOTS = (REPO / "eval" / "fixtures", REPO / "sandbox" / "fixtures")
IMAGE = "pkgguard-sandbox:dev"
RUN_TIMEOUT = 180
DEFAULT_OUT = Path("tmp/sandbox")


class UnsafeInput(Exception):
    pass


def ensure_harmless(path: Path) -> Path:
    resolved = path.resolve()
    if not any(resolved == root or root in resolved.parents for root in ALLOWED_ROOTS):
        raise UnsafeInput(
            f"{path} is not inside eval/fixtures/ or sandbox/fixtures/. The local runner only runs the harmless "
            "fixtures in this repo. Real packages are analysed in the AWS sandbox, never on this machine."
        )
    if not resolved.is_dir():
        raise UnsafeInput(f"{path} is not a directory")
    return resolved


def pack_fixture(directory: Path) -> bytes:
    """Like `npm pack`: everything under a top-level `package/` folder. Skips our own metadata file."""
    gate = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for file in sorted(directory.rglob("*")):
            if file.is_file() and not file.is_symlink() and file.name != "fixture.json":
                # Time-gated fixtures use a date 30 days out, so the "hostile" run (clock +60 days) trips them.
                data = file.read_bytes().replace(b"__GATE_DAYS_30__", gate.encode())
                info = tarfile.TarInfo(f"package/{file.relative_to(directory).as_posix()}")
                info.size, info.mode = len(data), file.stat().st_mode & 0o777
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def docker_command(name: str, run: str) -> list[str]:
    caps = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "NET_BIND_SERVICE", "SYS_PTRACE"]
    cmd = [
        "docker", "run", "--rm", "-i", "--init", "--name", name,
        "--network", "none",
        "--tmpfs", "/tmp:rw,exec,size=256m", "--tmpfs", "/home/sandbox:rw,exec,size=256m", "--tmpfs", "/var/sbx:rw,size=128m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", "1g", "--cpus", "1",
    ]  # fmt: skip
    for cap in caps:
        cmd += ["--cap-add", cap]
    return cmd + [IMAGE, "--input", "-", "--output", "-", "--run", run]


def run_tarball(tarball: bytes, run: str = "baseline", *, harmless_fixture: bool = False) -> dict:
    if not harmless_fixture:
        raise UnsafeInput("run_tarball only runs harmless repo fixtures locally; real packages run in the AWS sandbox")
    name = f"sbx-{uuid.uuid4().hex[:10]}"
    try:
        proc = subprocess.run(docker_command(name, run), input=tarball, capture_output=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        raise
    if proc.returncode != 0:
        raise RuntimeError(f"sandbox exited {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[-1500:]}")
    return json.loads(gzip.decompress(proc.stdout))


def run_fixture(directory: Path, run: str = "baseline") -> dict:
    return run_tarball(pack_fixture(ensure_harmless(directory)), run, harmless_fixture=True)


def main() -> None:
    ap = argparse.ArgumentParser(prog="pkgguard-sandbox", description="Run a harmless fixture in the local sandbox image.")
    ap.add_argument("fixture", type=Path, help="directory under eval/fixtures/ or sandbox/fixtures/")
    ap.add_argument("--run", choices=["baseline", "hostile", "both"], default="both")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    try:
        directory = ensure_harmless(args.fixture)
    except UnsafeInput as exc:
        sys.exit(f"refused: {exc}")
    args.out.mkdir(parents=True, exist_ok=True)
    tarball = pack_fixture(directory)
    for run in ("baseline", "hostile") if args.run == "both" else (args.run,):
        trace = run_tarball(tarball, run, harmless_fixture=True)
        target = args.out / f"{directory.name}.{run}.json"
        target.write_text(json.dumps(trace))
        print(f"{directory.name} [{run}]: {target}  phases={[p['name'] + ':' + str(p['exitCode']) for p in trace['phases']]}")


if __name__ == "__main__":
    main()
