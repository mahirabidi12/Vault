import pytest
from helpers import make_tgz

from pkgguard_analyzer.extract import ArchiveTooLarge, safe_extract


def test_strips_top_level_folder(tmp_path):
    tgz = make_tgz({"package/": None, "package/package.json": "{}", "package/lib/index.js": "module.exports = 1"})
    result = safe_extract(tgz, tmp_path / "out")
    assert (tmp_path / "out" / "package.json").read_text() == "{}"
    assert (tmp_path / "out" / "lib" / "index.js").exists()
    assert result.file_count == 2
    assert result.skipped == []


def test_path_traversal_is_skipped(tmp_path):
    tgz = make_tgz({"package/../../evil.js": "boom", "/etc/evil": "boom", "package/ok.js": "ok"})
    result = safe_extract(tgz, tmp_path / "out")
    assert {entry.reason for entry in result.skipped} == {"path_traversal"}
    assert len(result.skipped) == 2
    assert not (tmp_path / "evil.js").exists()
    assert (tmp_path / "out" / "ok.js").exists()


def test_symlinks_are_skipped(tmp_path):
    tgz = make_tgz({"package/ok.js": "ok"}, links={"package/secret": "/Users/someone/.ssh/id_rsa"})
    result = safe_extract(tgz, tmp_path / "out")
    assert [entry.reason for entry in result.skipped] == ["link"]
    assert not (tmp_path / "out" / "secret").exists()


def test_too_many_files_raises(tmp_path):
    tgz = make_tgz({f"package/f{i}.js": "x" for i in range(5)})
    with pytest.raises(ArchiveTooLarge, match="files"):
        safe_extract(tgz, tmp_path / "out", max_files=3)


def test_too_large_raises(tmp_path):
    tgz = make_tgz({"package/big.js": "x" * 1000})
    with pytest.raises(ArchiveTooLarge, match="MB"):
        safe_extract(tgz, tmp_path / "out", max_unpacked_bytes=100)
