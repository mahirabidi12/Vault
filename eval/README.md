# eval

Accuracy harness for PkgGuard (README §14). Two things get measured:

1. **Fixtures** (`fixtures/`) — 15 small, harmless packages that each exercise one detection
   pattern. They are **never published to npm and never executed** — only ever parsed, the same as
   any real scan. Run via `uv run pkgguard-eval` from `analyzer/`.
2. **The benign set** — the same ~50 popular packages `pkgguard-seed` scans
   (`analyzer/src/pkgguard_analyzer/data/seed_packages.txt`), checked for false positives. Run
   `uv run pkgguard-seed scan` first, then `uv run pkgguard-eval --benign`.

```bash
cd analyzer
uv run pkgguard-eval               # fixtures only, rules-only — fast, free, deterministic
uv run pkgguard-eval --with-ai     # also runs the AI review on each fixture (uses API credits)
uv run pkgguard-eval --benign      # also reports false positives on tmp/seed/ (run pkgguard-seed scan first)
```

## How a fixture gets scanned without touching npm

Each fixture is packed into an in-memory tarball with a synthetic packument (registry metadata) and
fed to the real, unmodified `analyze()` over an `httpx.MockTransport` — no real download, and the
threat-intel lookups (OSV, SafeDep) are mocked to return "not found", since a fixture obviously
isn't in any real feed. This is the same approach the test suite already uses for end-to-end
`analyze()` tests; `pkgguard-eval` just points it at real fixture directories instead of an inline
one. See `analyzer/src/pkgguard_analyzer/eval.py`.

## Fixture format

```
fixtures/<NN>-<slug>/
  package.json     # the manifest — also becomes the tarball's package.json
  fixture.json      # {"description": "...", "shouldFlag": true|false, "requiresAi"?: true}
  *.js              # whatever code the fixture needs
```

`shouldFlag` is intentionally binary (matches README's framing: "fixtures caught X/Y"), not a
specific verdict string — a fixture is a **detection test** ("should this end up SUSPICIOUS or
MALICIOUS") or a **false-positive test** ("should this stay SAFE"), not a bet on exactly which
rule fires or what confidence comes out.

`requiresAi: true` marks a fixture the rules alone are known not to catch (currently just
`02-typosquat-expresss` — see its `fixture.json` for why). `pkgguard-eval` reports these
separately instead of counting them as misses when AI isn't running.

Adding a 16th fixture is just a new directory with those three pieces — `pkgguard-eval` picks up
everything under `fixtures/` automatically, and `tests/test_eval.py::test_every_real_fixture_scores_as_expected_without_ai`
in `analyzer/` re-runs all of them on every `pytest` run, so a fixture that stops behaving as
expected fails CI immediately.

## Not built yet

- **A GPT-vs-Claude comparison** (README §14's "good blog material" idea).
- **Persisting results to `results/`** — right now `pkgguard-eval` only prints; redirect the output
  yourself (`uv run pkgguard-eval > ../eval/results/$(date +%F).md`) if you want a saved copy.
