from pkgguard_analyzer.code_scan.files import entry_targets, install_time_targets, select_files


def test_install_time_targets_from_scripts():
    scripts = {"postinstall": "node ./scripts/setup.js && echo done", "preinstall": "node --no-warnings lib/pre"}
    targets = install_time_targets(scripts)
    assert "scripts/setup.js" in targets
    assert {"lib/pre.js", "lib/pre/index.js"} <= targets


def test_entry_targets_cover_main_bin_and_exports():
    manifest = {"main": "lib/index.js", "bin": {"tool": "./bin/cli.js"}, "exports": {".": {"require": "./dist/main.cjs"}, "./utils": "./dist/utils.js"}}
    targets = entry_targets(manifest)
    assert {"lib/index.js", "bin/cli.js", "dist/main.cjs"} <= targets
    assert "dist/utils.js" not in targets


def test_entry_defaults_to_index():
    assert "index.js" in entry_targets({})


def test_select_files_orders_and_filters(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "index.js").write_text("module.exports = 1")
    (tmp_path / "install.js").write_text("console.log(1)")
    (tmp_path / "lib" / "a.js").write_text("x")
    (tmp_path / "types.d.ts").write_text("export {}")
    (tmp_path / "README.md").write_text("docs")
    (tmp_path / "prebuilt").write_bytes(b"\x7fELF\x02\x01")
    selection = select_files(tmp_path, {"scripts": {"postinstall": "node install.js"}})
    assert [f.path for f in selection.code_files] == ["install.js", "index.js", "lib/a.js"]
    assert selection.code_files[0].install_time and selection.code_files[1].entry
    assert selection.executables == [("prebuilt", "Linux executable")]
