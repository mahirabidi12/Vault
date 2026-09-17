"""Accuracy eval (README §14): ~15 harmless fixture packages (never published, never executed —
only ever parsed) plus the benign seed list, run through the real, unmodified `analyze()`.

Fixtures never touch the real npm registry or network: each one is packed into an in-memory
tarball with a synthetic packument, served to `analyze()` over an `httpx.MockTransport` (the
threat-intel lookups are mocked clean too, since a fixture obviously can't be in a real feed).
This is the same technique the test suite already uses for end-to-end `analyze()` tests, just
pointed at `eval/fixtures/` instead of an inline fixture.

  uv run pkgguard-eval                 # fixtures only, rules-only (fast, free, deterministic)
  uv run pkgguard-eval --with-ai       # also runs the AI review on each fixture
  uv run pkgguard-eval --benign        # also reports accuracy over `tmp/seed/` (run `pkgguard-seed scan` first)
"""

import argparse
import base64
import hashlib
import io
import json
import sys
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from dotenv import find_dotenv, load_dotenv

from pkgguard_analyzer.ai.config import AIConfig, AIMode
from pkgguard_analyzer.ai.reviewer import make_reviewer
from pkgguard_analyzer.analyze import analyze
from pkgguard_analyzer.intel import OSV_QUERY_URL, SAFEDEP_QUERY_URL
from pkgguard_analyzer.npm_registry import packument_url
from pkgguard_analyzer.schema import RanOn, ScanStatus, Verdict, VerdictRecord
from pkgguard_analyzer.seed import default_packages, saved_results

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "eval" / "fixtures"
DEFAULT_OUT = Path("tmp/eval")
DEFAULT_BENIGN_DIR = Path("tmp/seed")
# README §14/§15: these are known to need AI to clear cleanly, not a scanner bug.
KNOWN_NOISY_BENIGN = frozenset({"esbuild", "sharp", "puppeteer", "bcrypt", "husky"})
FLAGGED_VERDICTS = (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


@dataclass
class FixtureResult:
    id: str
    description: str
    should_flag: bool
    requires_ai: bool
    record: VerdictRecord | None
    error: str | None = None

    @property
    def flagged(self) -> bool:
        return self.record is not None and self.record.status == ScanStatus.COMPLETE and self.record.verdict in FLAGGED_VERDICTS

    @property
    def passed(self) -> bool:
        if self.error or self.record is None:
            return False
        return self.flagged == self.should_flag


@dataclass
class BenignResult:
    name: str
    version: str | None
    record: VerdictRecord | None

    @property
    def flagged(self) -> bool:
        return self.record is not None and self.record.status == ScanStatus.COMPLETE and self.record.verdict in FLAGGED_VERDICTS

    @property
    def known_noisy(self) -> bool:
        return self.name in KNOWN_NOISY_BENIGN


def load_fixtures(fixtures_dir: Path) -> list[Path]:
    return sorted(p for p in fixtures_dir.iterdir() if p.is_dir())


def _build_tarball(fixture_dir: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(fixture_dir.rglob("*")):
            if path.is_dir() or path.name == "fixture.json":
                continue
            data = path.read_bytes()
            info = tarfile.TarInfo(f"package/{path.relative_to(fixture_dir).as_posix()}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _build_packument(manifest: dict, tarball: bytes, tarball_url: str, published_at: datetime) -> dict:
    name, version = manifest["name"], manifest["version"]
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    version_manifest = {
        **manifest,
        "_npmUser": {"name": "fixture-author"},
        "maintainers": [{"name": "fixture-author"}],
        "repository": manifest.get("repository") or {"type": "git", "url": f"git+https://example.invalid/{name}.git"},
        "dist": {"tarball": tarball_url, "integrity": integrity},
    }
    return {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: version_manifest},
        "time": {version: published_at.isoformat().replace("+00:00", "Z")},
    }


def _mock_transport(packument: dict, tarball: bytes, tarball_url: str) -> httpx.MockTransport:
    name = packument["name"]

    def handle(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == packument_url(name):
            return httpx.Response(200, json=packument)
        if url == tarball_url:
            return httpx.Response(200, content=tarball)
        if url == OSV_QUERY_URL:
            return httpx.Response(200, json={"vulns": []})
        if url == SAFEDEP_QUERY_URL:
            return httpx.Response(404)
        return httpx.Response(404)

    return httpx.MockTransport(handle)


def run_fixture(fixture_dir: Path, out_dir: Path, reviewer, ai_mode: AIMode) -> FixtureResult:
    config = json.loads((fixture_dir / "fixture.json").read_text())
    manifest = json.loads((fixture_dir / "package.json").read_text())
    name, version = manifest["name"], manifest["version"]
    result = FixtureResult(
        id=fixture_dir.name,
        description=config["description"],
        should_flag=config["shouldFlag"],
        requires_ai=config.get("requiresAi", False),
        record=None,
    )
    try:
        tarball = _build_tarball(fixture_dir)
        tarball_url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
        published_at = datetime.now(UTC) - timedelta(days=200)  # old enough that fresh_publish never fires
        packument = _build_packument(manifest, tarball, tarball_url, published_at)
        client = httpx.Client(transport=_mock_transport(packument, tarball, tarball_url))
        try:
            scan = analyze(name, version, out_dir=out_dir, ran_on=RanOn.LOCAL, client=client, reviewer=reviewer, ai_mode=ai_mode)
        finally:
            client.close()
        result.record = scan.record
    except Exception as error:  # a bad fixture shouldn't stop the rest of the eval
        result.error = f"{type(error).__name__}: {error}"
    return result


def run_fixtures(fixtures_dir: Path, out_dir: Path, reviewer, ai_mode: AIMode) -> list[FixtureResult]:
    return [run_fixture(fixture_dir, out_dir, reviewer, ai_mode) for fixture_dir in load_fixtures(fixtures_dir)]


def load_benign(benign_dir: Path) -> list[BenignResult]:
    saved = {record.package.name: record for record, _ in saved_results(benign_dir)}
    return [BenignResult(name=name, version=saved[name].package.version if name in saved else None, record=saved.get(name)) for name in default_packages()]


def print_fixture_report(results: list[FixtureResult]) -> bool:
    scored = [r for r in results if not (r.requires_ai and r.record and not r.flagged)]
    passed = [r for r in scored if r.passed]
    print(f"\nFixtures: {len(passed)}/{len(scored)} correct" + (f" ({len(results) - len(scored)} AI-dependent, shown separately)" if len(scored) != len(results) else ""))
    for r in results:
        if r.error:
            mark = "ERROR"
        elif r.requires_ai and not r.flagged and r.should_flag:
            mark = "SKIP (needs AI)"
        else:
            mark = "ok" if r.passed else "MISS"
        verdict = r.record.verdict.value if r.record and r.record.verdict else (r.record.status.value if r.record else "?")
        print(f"  [{mark:<15}] {r.id:<32} expected {'flag' if r.should_flag else 'safe':<4} got {verdict:<12} — {r.description}")
        if r.error:
            print(f"                     {r.error}")
    return all(r.passed for r in scored)


def print_benign_report(results: list[BenignResult]) -> None:
    scanned = [r for r in results if r.record is not None]
    if not scanned:
        print("\nBenign set: nothing scanned yet. Run `pkgguard-seed scan` first, then re-run with --benign.")
        return
    false_positives = [r for r in scanned if r.flagged and not r.known_noisy]
    cleared_noisy = [r for r in scanned if r.known_noisy and not r.flagged]
    still_noisy = [r for r in scanned if r.known_noisy and r.flagged]
    print(f"\nBenign set: {len(scanned)}/{len(results)} scanned so far, {len(false_positives)} unexpected false positive(s)")
    for r in false_positives:
        print(f"  FALSE POSITIVE  {r.name}@{r.version}: {r.record.verdict.value if r.record.verdict else r.record.status.value} — {r.record.summary}")
    if cleared_noisy:
        print(f"  Correctly cleared {len(cleared_noisy)}/{len(cleared_noisy) + len(still_noisy)} known-noisy package(s): {', '.join(r.name for r in cleared_noisy)}")
    if still_noisy:
        print(f"  Still flagged (expected without AI, or needs a closer look): {', '.join(r.name for r in still_noisy)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pkgguard-eval", description="Run the fixture + benign accuracy eval (README §14).")
    parser.add_argument("--fixtures-dir", type=Path, default=FIXTURES_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--with-ai", action="store_true", help="also run the AI review on each fixture (uses API credits)")
    parser.add_argument("--benign", action="store_true", help="also report accuracy over an existing `pkgguard-seed scan` run")
    parser.add_argument("--benign-dir", type=Path, default=DEFAULT_BENIGN_DIR)
    args = parser.parse_args(argv)

    if not args.fixtures_dir.is_dir():
        print(f"error: no fixtures directory at {args.fixtures_dir}", file=sys.stderr)
        return 2

    reviewer, ai_mode = None, AIMode.OFF
    if args.with_ai:
        load_dotenv(find_dotenv(usecwd=True))
        config = AIConfig.from_env()
        if problem := config.problem():
            print(f"error: --with-ai was passed but AI can't run ({problem})", file=sys.stderr)
            return 2
        reviewer, ai_mode = make_reviewer(config), config.mode

    print(f"Running {len(load_fixtures(args.fixtures_dir))} fixtures from {args.fixtures_dir} (AI: {ai_mode.value if reviewer else 'off'})...")
    fixture_results = run_fixtures(args.fixtures_dir, args.out, reviewer, ai_mode)
    all_passed = print_fixture_report(fixture_results)

    if args.benign:
        print_benign_report(load_benign(args.benign_dir))

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
