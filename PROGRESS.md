# PkgGuard: Build Progress

> **For agents:** read this first, then [`README.md`](README.md) (full plan and decisions) and [`FUTURE_SCOPE.md`](FUTURE_SCOPE.md).
> README = what we *planned*. This file = what is *actually built*, how to run it, and where the build differs from the plan.
> **Update this file at the end of every step.**

Last updated: 2026-09-17, after Step 2.

---

## Status

| Step | What | Status |
|---|---|---|
| 0 | Setup (accounts, tools) | 🟡 Partly done: Node, Docker, AWS CLI, uv installed. **SAM CLI not installed.** AWS region not chosen |
| 1 | Project setup + verdict format | ✅ Done (commit `b0cdc24`) |
| 2 | Scanner: download, safe unpack, threat intel, metadata red flags, verdict | ✅ Built |
| 3 | Cloud backend (SAM: API, DynamoDB, S3, SQS, Step Functions) | ⏳ Not started. Needs SAM CLI + user OK to create AWS resources |
| 4 | Code scanning (static rules on JS files) | ⏳ Next |
| 5 | AI agent | ⏳ Not started. See open decision below |
| 6 | Final verdict + full report | ⏳ |
| 7 | Eval, tuning, seed 50 packages, OSV import | ⏳ |
| 8 | CLI installer | ⏳ |
| 9 | MCP agent tool | ⏳ |
| 10 | Website | ⏳ |
| 11 | Login + dashboard | ⏳ |
| 12 | Admin review (if time) | ⏳ |
| 13 | Demo + submit | ⏳ |

---

## How to run what exists

```bash
cd analyzer
uv sync                                  # installs Python 3.12 + deps into analyzer/.venv
uv run pytest -q                         # all tests (network-free, uses mocks)
uv run analyze express@4.18.2            # scan one package (live npm, OSV, SafeDep)
uv run analyze @babel/core               # scoped names; no version = latest
uv run analyze esbuild --json            # full record + report as JSON
uv run pkgguard-export-schema            # re-run after ANY change to schema.py
```

Scan output goes to `analyzer/tmp/scans/<name>/<version>/` (gitignored): `record.json`, `report.json`, `files/` (unpacked package).

**Known-good live results (2026-09-17):**
| Package | Result |
|---|---|
| `express@4.18.2` | SAFE, MEDIUM, 0 findings |
| `safedep-test-pkg@0.1.3` | MALICIOUS, HIGH, decided by intel (SafeDep human-verified) |
| `@babel/core@8.0.5` | SAFE, MEDIUM, 0 findings |
| `esbuild@0.28.2` | SAFE, LOW, 1 warning (postinstall script) |
| `../evil`, unknown package, unknown version | clean error, exit code 2 |

---

## What is built

### `analyzer/` (Python 3.12, uv, package `pkgguard_analyzer`)
| Module | Responsibility |
|---|---|
| `schema.py` | Shared data contract (Pydantic, camelCase JSON). `PackageRef`, `Finding`, `VerdictRecord` (DynamoDB summary), `Report` (S3 full report). Enforces exact versions, valid npm names, status/verdict consistency |
| `export_schema.py` | Writes `schema/verdict-record.schema.json` + `schema/report.schema.json` for TypeScript code |
| `npm_registry.py` | Fetch packument, resolve dist-tag → exact version, streamed tarball download (50 MB cap), SRI/shasum integrity check |
| `extract.py` | Safe tar extraction: strips top folder, skips `../`/absolute paths, symlinks, hardlinks, special files; caps 20k files / 200 MB. Skipped entries become findings |
| `intel.py` | OSV (`MAL-` ids = malicious) + SafeDep community API. Trusts SafeDep `isMalware` boolean only, never its prose. Lookup failures are recorded, never fatal |
| `metadata_checks.py` | Red flags: install scripts, tarball vs registry script mismatch, published < 48h, typosquat (edit distance 1 / separator variants vs `data/popular_packages.txt`), major version ≥ 99, new publisher, trusted publishing dropped, no repository, unsafe archive entries |
| `scoring.py` | v1 verdict rules (below) + `signals()` |
| `analyze.py` | Orchestrates one scan → `ScanResult(record, report, scan_dir)`. Same code intended for local and Lambda (`ran_on`) |
| `cli.py` | `uv run analyze <name[@version]> [version] [--json] [--out DIR]` |

### v1 scoring rules (`scoring.py`), metadata + intel only
1. OSV `MAL-` match → MALICIOUS / HIGH / intel
2. SafeDep `isMalware` → MALICIOUS/HIGH if human-verified or `CONFIDENCE_HIGH`, else SUSPICIOUS/MEDIUM (intel)
3. Any HIGH-severity finding → SUSPICIOUS / MEDIUM / rules
4. ≥ 2 MEDIUM findings → SUSPICIOUS / LOW / rules
5. 1 MEDIUM finding → SAFE / LOW / rules
6. Otherwise → SAFE / MEDIUM / rules (summary says code not scanned yet)

Rules 3–6 get replaced when code scanning + AI land.

### Tests (`analyzer/tests/`, 70 passing)
Schema rules, registry helpers, integrity, extraction attacks (traversal, symlinks, size caps), OSV/SafeDep parsing (incl. the SafeDep "prose contradicts boolean" case), each metadata rule, scoring rules, and end-to-end `analyze()` with `httpx.MockTransport` (clean, known-malicious, tampered tarball, intel outage). `tests/helpers.py` builds fake tarballs and packuments.

---

## Differences from the README plan (discovered while building)

- **Trusted publishing:** many popular packages now publish via npm trusted publishing (`_npmUser.name = "GitHub Actions"`, `_npmUser.trustedPublisher` set). The "new publisher" rule falsely flagged them, so it now **skips trusted publishes**. Added `metadata.trusted_publishing_dropped` (previous version trusted, current not), a stolen-token signal. Report metadata includes `trustedPublishing` and `provenance` (`dist.attestations`).
- **`manifest_mismatch` check added** (not in README): install scripts in the tarball's `package.json` differ from registry metadata ("manifest confusion").
- **`VerdictRecord` rules:** only `COMPLETE` records may have a verdict; `FAILED` and `SKIPPED` require `failureReason`.
- **`reportS3Key` is left empty** until Step 3 actually uploads to S3.
- **Weekly downloads check not implemented yet** (README §8.1 lists it).
- **OSV pagination not handled** (fine for `MAL-` lookups; revisit if listing many CVEs).
- **Popular packages list** is hand-curated (~130 names), with legit look-alikes (`preact`, `mysql2`, `lodash-es`) included so they aren't flagged.
- **Build order may change:** Step 4 (code scanning) may be built before Step 3 (cloud), since it needs no AWS.

---

## Open decisions

- 🟡 **AI coverage (Step 5).** Proposed to the user, awaiting confirmation: the AI does a **quick look on every package** (install scripts + the files they run + main entry file, later the diff vs previous version), and a **deep-dive agent** only when rules or the quick look find something. Reason: rules-only gating means novel malware that trips no rule never reaches the AI. OpenAI credits are sponsored, so cost is low. The AI can never downgrade hard evidence (OSV/SafeDep).
- 🟡 AWS region, SAM CLI install, Bedrock model access (see README §21 for the rest).

---

## Conventions for agents working on this repo

- **The user stages and commits manually.** Never commit. After each step, stop and give `git add` / `git commit` commands with a descriptive message.
- **Explain each finished step in a few easy words:** what was built as a whole + where it's used. No file-by-file breakdowns for the user.
- Keep `uv run pytest -q` green. Tests must not need the network.
- After changing `schema.py`, run `uv run pkgguard-export-schema` and commit the updated `schema/*.json`.
- Never execute package code. Never commit `.env` or keys.
- Update this file at the end of every step.
