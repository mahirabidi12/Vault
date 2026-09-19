"""Fetches a package's dependencies so the sandbox can actually load and run it.

The sandbox has no internet, so this runs OUTSIDE it (in the scan Lambda). It only downloads and unpacks:
`npm install --ignore-scripts` never executes any script from any package. Only registry dependencies are
fetched (no git, URL or file sources). The result is one tarball of a `node_modules` folder that the sandbox
puts on NODE_PATH, separate from the package under test."""

import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger()
MAX_DEPENDENCIES = 60
MAX_TOTAL_SECONDS = 120
BULK_TIMEOUT = 90
ONE_TIMEOUT = 25
MAX_UNPACKED_BYTES = 400 * 1024 * 1024
MAX_PACKED_BYTES = 150 * 1024 * 1024
# Registry version ranges, tags and npm: aliases only. Excludes git+, http(s):, file:, github: and similar sources.
SAFE_SPEC = re.compile(r"^(npm:[@A-Za-z0-9._/~^<>=* |+-]+|[A-Za-z0-9._~^<>=*|+\- ]*)$")
UNSAFE_PREFIXES = ("git", "http:", "https:", "file:", "link:", "github:", "gitlab:", "bitbucket:", "ssh:", "workspace:", "portal:")


@dataclass
class DepsResult:
    tarball: bytes | None
    count: int
    note: str


def registry_dependencies(manifest: dict) -> dict[str, str]:
    """Dependencies worth providing: runtime and optional, registry sources only, capped."""
    out: dict[str, str] = {}
    for field in ("dependencies", "optionalDependencies"):
        values = manifest.get(field)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            spec = spec.strip()
            if spec.lower().startswith(UNSAFE_PREFIXES) or "://" in spec or not SAFE_SPEC.fullmatch(spec):
                continue
            out.setdefault(name, spec or "*")
            if len(out) >= MAX_DEPENDENCIES:
                return out
    return out


def _npm(args: list[str], cwd: Path, timeout: float, runner) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": str(cwd), "npm_config_ignore_scripts": "true", "npm_config_update_notifier": "false"}
    return runner(["npm", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


def _first_error_line(stderr: str | None) -> str:
    for line in (stderr or "").splitlines():
        if "npm error" in line and not line.strip().endswith("error"):
            return re.sub(r"\s+", " ", line.split("npm error", 1)[1]).strip()[:120]
    return ""


def _tree_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def _pack(node_modules: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=3) as tar:
        tar.add(node_modules, arcname="node_modules")
    return buf.getvalue()


def fetch_dependencies(manifest: dict, *, runner=subprocess.run, work_root: Path | None = None) -> DepsResult:
    deps = registry_dependencies(manifest)
    if not deps:
        return DepsResult(None, 0, "package has no registry dependencies")
    if runner is subprocess.run and shutil.which("npm") is None:
        return DepsResult(None, 0, "npm is not available here, so dependencies were not provided")
    work = Path(tempfile.mkdtemp(prefix="deps-", dir=work_root))
    started = time.monotonic()
    try:
        (work / "package.json").write_text(json.dumps({"name": "deps-host", "version": "1.0.0", "private": True, "dependencies": deps}))
        flags = ["--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund", "--no-package-lock", "--loglevel=error", "--cache", str(work / ".cache")]
        note = ""
        reason = ""
        try:
            result = _npm(["install", *flags], work, BULK_TIMEOUT, runner)
            failed = result.returncode != 0
            reason = _first_error_line(result.stderr)
        except subprocess.TimeoutExpired:
            failed, reason = True, "timed out"
        if failed:
            # One missing or fake dependency makes npm fail the whole install; keep whatever can be fetched one by one.
            # Each success is saved into package.json so a later install does not prune it.
            note = "some dependencies could not be fetched (missing, fake or unreachable), the rest were provided" + (f" [{reason}]" if reason else "")
            shutil.rmtree(work / "node_modules", ignore_errors=True)
            (work / "package.json").write_text(json.dumps({"name": "deps-host", "version": "1.0.0", "private": True}))
            for name, spec in list(deps.items())[:40]:
                if time.monotonic() - started > MAX_TOTAL_SECONDS:
                    note += "; stopped early to stay within the time limit"
                    break
                try:
                    _npm(["install", f"{name}@{spec}", *flags], work, ONE_TIMEOUT, runner)
                except subprocess.TimeoutExpired:
                    continue
        node_modules = work / "node_modules"
        if not node_modules.is_dir() or not any(node_modules.iterdir()):
            return DepsResult(None, 0, note or "no dependency could be fetched")
        if _tree_size(node_modules) > MAX_UNPACKED_BYTES:
            return DepsResult(None, 0, "dependencies are larger than the size limit")
        packed = _pack(node_modules)
        if len(packed) > MAX_PACKED_BYTES:
            return DepsResult(None, 0, "dependencies are larger than the size limit")
        count = sum(1 for p in node_modules.iterdir() if p.is_dir() and not p.name.startswith("."))
        return DepsResult(packed, count, note)
    except Exception as error:
        log.exception("dependency fetch failed")
        return DepsResult(None, 0, f"dependency fetch failed: {type(error).__name__}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
