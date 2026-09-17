import json
from pathlib import Path

from cloud_helpers import record

from pkgguard_analyzer.ai.config import AIMode
from pkgguard_analyzer.eval import (
    FIXTURES_DIR,
    BenignResult,
    FixtureResult,
    load_benign,
    load_fixtures,
    print_fixture_report,
    run_fixture,
    run_fixtures,
)
from pkgguard_analyzer.schema import ScanStatus, Verdict
from pkgguard_analyzer.seed import default_packages


def test_loads_all_committed_fixtures():
    fixtures = load_fixtures(FIXTURES_DIR)
    assert len(fixtures) == 15
    for fixture_dir in fixtures:
        assert (fixture_dir / "package.json").exists()
        assert (fixture_dir / "fixture.json").exists()


def test_every_real_fixture_scores_as_expected_without_ai(tmp_path):
    """The real, committed fixtures are the eval's headline number — this is the regression guard for it."""
    results = run_fixtures(FIXTURES_DIR, tmp_path, reviewer=None, ai_mode=AIMode.OFF)
    assert len(results) == 15
    assert not any(r.error for r in results)

    skipped_needing_ai = [r for r in results if r.requires_ai and not r.flagged]
    skipped_ids = {r.id for r in skipped_needing_ai}
    scored = [r for r in results if r.id not in skipped_ids]
    assert [r.id for r in skipped_needing_ai] == ["02-typosquat-expresss"]
    assert all(r.passed for r in scored), [(r.id, r.record.verdict if r.record else None) for r in scored if not r.passed]
    assert print_fixture_report(results) is True


def test_run_fixture_captures_scan_errors_instead_of_raising(tmp_path):
    """A bad package name is invalid enough to reach analyze()'s own validation, without being a fixture-authoring typo."""
    fixture_dir = tmp_path / "broken"
    fixture_dir.mkdir()
    (fixture_dir / "package.json").write_text(json.dumps({"name": "Not A Valid Npm Name", "version": "1.0.0"}))
    (fixture_dir / "index.js").write_text("module.exports = {};\n")
    (fixture_dir / "fixture.json").write_text(json.dumps({"description": "broken", "shouldFlag": True}))

    result = run_fixture(fixture_dir, tmp_path / "out", reviewer=None, ai_mode=AIMode.OFF)

    assert result.error is not None
    assert result.record is None
    assert result.passed is False


class TestFixtureResult:
    def test_flagged_true_for_suspicious_or_malicious(self):
        r = FixtureResult("id", "d", should_flag=True, requires_ai=False, record=record(status=ScanStatus.COMPLETE, verdict=Verdict.SUSPICIOUS))
        assert r.flagged is True
        assert r.passed is True

    def test_flagged_false_for_safe(self):
        r = FixtureResult("id", "d", should_flag=False, requires_ai=False, record=record(status=ScanStatus.COMPLETE, verdict=Verdict.SAFE))
        assert r.flagged is False
        assert r.passed is True

    def test_fails_when_expectation_does_not_match(self):
        r = FixtureResult("id", "d", should_flag=True, requires_ai=False, record=record(status=ScanStatus.COMPLETE, verdict=Verdict.SAFE))
        assert r.passed is False

    def test_never_passes_without_a_record(self):
        r = FixtureResult("id", "d", should_flag=False, requires_ai=False, record=None, error="boom")
        assert r.passed is False


class TestBenignResult:
    def test_known_noisy_packages(self):
        assert BenignResult("esbuild", "0.28.2", record()).known_noisy is True
        assert BenignResult("lodash", "4.17.21", record()).known_noisy is False

    def test_unscanned_package_is_not_flagged(self):
        assert BenignResult("lodash", None, None).flagged is False


def test_load_benign_merges_saved_results_with_the_full_list(tmp_path):
    packages = default_packages()
    scanned_name = packages[0]
    scan_dir = tmp_path / scanned_name / "1.2.3"
    scan_dir.mkdir(parents=True)
    saved = record(name=scanned_name, version="1.2.3", status=ScanStatus.COMPLETE, verdict=Verdict.SAFE)
    (scan_dir / "record.json").write_text(saved.model_dump_json(by_alias=True))

    results = load_benign(tmp_path)

    assert len(results) == len(packages)
    found = next(r for r in results if r.name == scanned_name)
    assert found.record is not None
    assert found.version == "1.2.3"
    unscanned = next(r for r in results if r.name != scanned_name)
    assert unscanned.record is None
