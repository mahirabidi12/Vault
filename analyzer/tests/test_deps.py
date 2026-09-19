"""Dependency fetching (outside the sandbox) and the sandbox's safe unpacking of it. No network, no real npm."""

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from pkgguard_analyzer.cloud.deps import DepsResult, fetch_dependencies, registry_dependencies

RUNTIME = Path(__file__).resolve().parents[2] / "sandbox" / "runtime"


def load_supervisor():
    sys.path.insert(0, str(RUNTIME))
    spec = importlib.util.spec_from_file_location("sbx_supervisor", RUNTIME / "supervisor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_registry_dependencies_are_fetched() -> None:
    manifest = {
        "dependencies": {"ok": "^1.2.3", "tag": "latest", "alias": "npm:other@2", "git": "git+https://evil.example/x.git", "url": "https://evil.example/x.tgz", "gh": "github:a/b", "file": "file:../x", "star": "*", "empty": ""},
        "optionalDependencies": {"opt": "~2.0.0"},
        "devDependencies": {"dev": "1.0.0"},
    }
    assert registry_dependencies(manifest) == {"ok": "^1.2.3", "tag": "latest", "alias": "npm:other@2", "star": "*", "empty": "*", "opt": "~2.0.0"}


def test_dependency_count_is_capped() -> None:
    manifest = {"dependencies": {f"dep{i}": "1.0.0" for i in range(500)}}
    assert len(registry_dependencies(manifest)) == 60


def test_no_dependencies_means_nothing_to_fetch() -> None:
    result = fetch_dependencies({"name": "x"}, runner=lambda *a, **k: None)
    assert result.tarball is None and "no registry dependencies" in result.note


def fake_npm(created: dict[str, bool], calls: list, fail_bulk: bool = False, bad: set[str] = frozenset()):
    def run(cmd, cwd, env, capture_output, text, timeout):
        calls.append(cmd)
        assert env["npm_config_ignore_scripts"] == "true" and "--ignore-scripts" in cmd  # scripts must never run
        if cmd[1] == "install" and len(cmd) > 2 and not cmd[2].startswith("--"):  # single: install name@spec
            assert "--no-save" not in cmd  # a --no-save install is pruned by the next one, leaving only the last
            name = cmd[2].split("@")[0] if not cmd[2].startswith("@") else "@" + cmd[2].split("@")[1]
            if name in bad:
                return subprocess.CompletedProcess(cmd, 1, "", "npm error code E404\nnpm error 404 Not Found")
            (cwd / "node_modules" / name).mkdir(parents=True, exist_ok=True)
            (cwd / "node_modules" / name / "index.js").write_text("module.exports = 1")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if fail_bulk:
            return subprocess.CompletedProcess(cmd, 1, "", "npm error code E404")
        for name in json.loads((cwd / "package.json").read_text())["dependencies"]:
            (cwd / "node_modules" / name).mkdir(parents=True, exist_ok=True)
            (cwd / "node_modules" / name / "index.js").write_text("module.exports = 1")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run


def names(blob: bytes) -> list[str]:
    return sorted(m.name for m in tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz").getmembers() if m.isfile())


def test_bulk_install_success_packs_node_modules(tmp_path) -> None:
    calls: list = []
    result = fetch_dependencies({"dependencies": {"a": "1.0.0", "b": "^2.0.0"}}, runner=fake_npm({}, calls), work_root=tmp_path)
    assert result.count == 2 and result.note == "" and names(result.tarball) == ["node_modules/a/index.js", "node_modules/b/index.js"]
    assert len(calls) == 1


def test_a_missing_dependency_falls_back_to_one_by_one(tmp_path) -> None:
    calls: list = []
    manifest = {"dependencies": {"good": "1.0.0", "fake-internal-pkg": "1.0.0", "@scope/ok": "2.0.0"}}
    result = fetch_dependencies(manifest, runner=fake_npm({}, calls, fail_bulk=True, bad={"fake-internal-pkg"}), work_root=tmp_path)
    assert result.count == 2 and "some dependencies could not be fetched" in result.note and "E404" in result.note
    assert names(result.tarball) == ["node_modules/@scope/ok/index.js", "node_modules/good/index.js"]


def test_nothing_fetchable_returns_no_tarball(tmp_path) -> None:
    result = fetch_dependencies({"dependencies": {"nope": "1.0.0"}}, runner=fake_npm({}, [], fail_bulk=True, bad={"nope"}), work_root=tmp_path)
    assert result.tarball is None and result.count == 0


def test_work_directory_is_always_cleaned_up(tmp_path) -> None:
    fetch_dependencies({"dependencies": {"a": "1.0.0"}}, runner=fake_npm({}, []), work_root=tmp_path)
    assert list(tmp_path.iterdir()) == []


# ---- the sandbox side: unpacking must refuse anything unsafe
def make_tar(entries: list[tuple[str, bytes | str, str]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, content
                tar.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
    return buf.getvalue()


def test_extract_deps_unpacks_normal_dependencies(tmp_path) -> None:
    sup = load_supervisor()
    blob = make_tar([("node_modules", b"", "dir"), ("node_modules/a/index.js", b"x", "file"), ("node_modules/.bin/a", "../a/index.js", "symlink"), ("node_modules/@s/b/index.js", b"y", "file")])
    assert sup.extract_deps(blob, str(tmp_path / "home")) == 2
    assert (tmp_path / "home/node_modules/a/index.js").read_text() == "x"
    assert (tmp_path / "home/node_modules/.bin/a").is_symlink()


def test_extract_deps_refuses_traversal_absolute_paths_and_escaping_symlinks(tmp_path) -> None:
    sup = load_supervisor()
    outside = tmp_path / "outside.txt"
    blob = make_tar([
        ("node_modules/ok/index.js", b"fine", "file"),
        ("../outside.txt", b"pwned", "file"),
        ("node_modules/../../outside.txt", b"pwned", "file"),
        (str(outside), b"pwned", "file"),
        ("node_modules/evil-link", "/etc/passwd", "symlink"),
        ("node_modules/evil-link2", "../../../../etc/passwd", "symlink"),
    ])  # fmt: skip
    sup.extract_deps(blob, str(tmp_path / "home"))
    assert not outside.exists()
    assert (tmp_path / "home/node_modules/ok/index.js").exists()
    assert not (tmp_path / "home/node_modules/evil-link").exists() and not (tmp_path / "home/node_modules/evil-link2").exists()


def test_extract_deps_only_writes_inside_node_modules(tmp_path) -> None:
    sup = load_supervisor()
    blob = make_tar([("node_modules/ok/index.js", b"fine", "file"), (".bashrc", b"export EVIL=1", "file"), (".ssh/authorized_keys", b"ssh-rsa AAAA", "file"), ("node_modules/x/../../.profile", b"boom", "file"), ("node_modules/link-to-home", "../.ssh", "symlink")])
    sup.extract_deps(blob, str(tmp_path / "home"))
    home = tmp_path / "home"
    assert (home / "node_modules/ok/index.js").exists()
    assert not (home / ".bashrc").exists() and not (home / ".ssh").exists() and not (home / ".profile").exists()
    assert not (home / "node_modules/link-to-home").exists()  # a symlink must stay inside node_modules
