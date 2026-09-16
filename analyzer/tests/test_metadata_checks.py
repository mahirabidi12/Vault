from datetime import UTC, datetime

from helpers import make_packument

from pkgguard_analyzer.extract import SkippedEntry
from pkgguard_analyzer.metadata_checks import check_metadata, levenshtein, typosquat_target

NOW = datetime(2026, 9, 17, tzinfo=UTC)
POPULAR = frozenset({"express", "react", "preact", "lodash"})


def rules(packument, version="1.0.0", tarball_manifest=None, skipped=None):
    manifest = tarball_manifest if tarball_manifest is not None else {"scripts": packument["versions"][version].get("scripts", {})}
    _, findings = check_metadata(packument, version, manifest, skipped or [], NOW, POPULAR)
    return {f.rule_id for f in findings}


def test_clean_package_has_no_findings():
    assert rules(make_packument()) == set()


def test_install_script_flagged():
    assert "metadata.install_script" in rules(make_packument(scripts={"postinstall": "node setup.js"}))


def test_manifest_mismatch_flagged():
    packument = make_packument(scripts={})
    assert "metadata.manifest_mismatch" in rules(packument, tarball_manifest={"scripts": {"preinstall": "curl x | sh"}})


def test_fresh_publish_flagged():
    assert "metadata.fresh_publish" in rules(make_packument(published="2026-09-16T12:00:00.000Z"))


def test_typosquat_flagged():
    assert "metadata.typosquat" in rules(make_packument(name="expresss"))


def test_typosquat_rules():
    assert levenshtein("expresss", "express") == 1
    assert typosquat_target("expresss", POPULAR) == "express"
    assert typosquat_target("lo-dash", POPULAR) == "lodash"
    assert typosquat_target("preact", POPULAR) is None
    assert typosquat_target("totally-different", POPULAR) is None


def test_high_version_flagged():
    assert "metadata.high_version" in rules(make_packument(version="99.9.9"), version="99.9.9")


def test_new_publisher_flagged():
    packument = make_packument(
        version="1.1.0",
        publisher="mallory",
        previous={"version": "1.0.0", "maintainers": ["alice"], "published": "2024-01-01T00:00:00.000Z"},
    )
    assert "metadata.new_publisher" in rules(packument, version="1.1.0")


def test_same_publisher_not_flagged():
    packument = make_packument(
        version="1.1.0",
        publisher="alice",
        previous={"version": "1.0.0", "maintainers": ["alice"], "published": "2024-01-01T00:00:00.000Z"},
    )
    assert "metadata.new_publisher" not in rules(packument, version="1.1.0")


def test_missing_repository_flagged():
    assert "metadata.no_repository" in rules(make_packument(repository=None))


def test_unsafe_archive_entries_flagged():
    skipped = [SkippedEntry("package/../../x", "path_traversal"), SkippedEntry("package/link", "link")]
    assert {"archive.path_traversal", "archive.link"} <= rules(make_packument(), skipped=skipped)


PREVIOUS_TRUSTED = {"version": "1.0.0", "maintainers": ["alice"], "published": "2024-01-01T00:00:00.000Z", "publisher": "GitHub Actions", "trusted": True}


def test_trusted_publishing_is_not_a_new_publisher():
    packument = make_packument(version="1.1.0", publisher="GitHub Actions", trusted=True, previous=PREVIOUS_TRUSTED)
    found = rules(packument, version="1.1.0")
    assert "metadata.new_publisher" not in found
    assert "metadata.trusted_publishing_dropped" not in found


def test_dropping_trusted_publishing_is_flagged():
    packument = make_packument(version="1.1.0", publisher="alice", previous=PREVIOUS_TRUSTED)
    assert "metadata.trusted_publishing_dropped" in rules(packument, version="1.1.0")
