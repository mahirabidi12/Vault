# PkgGuard: Build Progress

> **For agents:** read this first, then [`README.md`](README.md) (full plan and decisions) and [`FUTURE_SCOPE.md`](FUTURE_SCOPE.md).
> README = what we *planned*. This file = what is *actually built*, how to run it, and where the build differs from the plan.
> **Update this file at the end of every step.**

Last updated: 2026-09-17, after Step 4.

---

## Status

| Step | What | Status |
|---|---|---|
| 0 | Setup (accounts, tools) | 🟡 Partly done: Node, Docker, AWS CLI, uv installed. **SAM CLI not installed.** AWS region not chosen |
| 1 | Project setup + verdict format | ✅ Done (commit `b0cdc24`) |
| 2 | Scanner: download, safe unpack, threat intel, metadata red flags, verdict | ✅ Done (commit `5b47f13`) |
| 3 | Cloud backend (SAM: API, DynamoDB, S3, SQS, Step Functions) | ⏳ Not started. Needs SAM CLI + user OK to create AWS resources |
| 4 | Code scanning (tree-sitter JS analysis + YARA patterns + combined-risk rules) | ✅ Built (done before Step 3; needs no AWS) |
| 5 | AI agent | ⏳ Next candidate. See open decision below |
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

**Known-good live results (2026-09-17, after Step 4):**

| Package | Result | Notes |
|---|---|---|
| `express@4.18.2` | SAFE, MEDIUM, 0 findings | |
| `axios`, `@babel/core`, `puppeteer`, `sharp`, `typescript`, `dotenv` | SAFE | Only LOW findings (child_process in CLIs, dotenv's env handling) or the postinstall warning |
| `lodash` | SAFE, 6 LOW | `Function(...)` in `template` is legit; LOW by design |
| `esbuild` | SUSPICIOUS, **LOW** | install.js really downloads and runs a binary. Rules can't tell this from malware; **the AI step must clear it** |
| `safedep-test-pkg@0.1.3` | MALICIOUS, HIGH, decided by intel | |
| `../evil`, unknown package, unknown version | Clean error, exit code 2 | |

Scan time: ~2–7 s per package on a laptop, including downloads (`lodash`: 1,048 files in 4 s; `typescript`: 114 files in 3 s).

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
| `code_scan/` | Static code scanning (Step 4), see below |
| `scoring.py` | v2 verdict rules (below) + `signals()` |
| `analyze.py` | Orchestrates one scan (download → unpack → intel → metadata → code scan → score) → `ScanResult(record, report, scan_dir)`. Same code intended for local and Lambda (`ran_on`) |
| `cli.py` | `uv run analyze <name[@version]> [version] [--json] [--out DIR]` |

### `code_scan/` (parses files only, never executes them)

| Module | Responsibility |
|---|---|
| `files.py` | Selects files. JS (`.js .cjs .mjs .jsx`) gets parsed; `.ts .sh .ps1 .py .bat …` get pattern-scanned only; `.d.ts` skipped. Marks **install-time files** (targets of `node <file>` in pre/install/postinstall scripts) and **entry files** (`main`, `bin`, `exports["."]`). Detects shipped native executables by magic bytes. Caps: AST parse ≤ 1 MB/file, pattern scan ≤ 20 MB/file, ≤ 5,000 files. Install-time and entry files are scanned first |
| `js_facts.py` | tree-sitter JavaScript walk → `FileFacts`: required/imported modules with alias + destructuring tracking; `child_process` exec calls (so `regex.exec()` isn't counted); network calls (http/https/net/dns/tls/dgram modules, `fetch`, `XMLHttpRequest`, `WebSocket`); dynamic code (`eval`, `Function`, `globalThis["eval"]`, `vm.*`); whole-env reads vs single-variable reads vs env **copies** passed to child processes; recon (`os.hostname/userInfo/networkInterfaces`); decoding (`Buffer.from(x,'base64'\|'hex')`, `atob`, long `String.fromCharCode`); string literals with line + snippet (comments excluded) |
| `rules/patterns.yar` | YARA rules on raw bytes: Discord webhook, Telegram bot API, request-capture/OAST services (webhook.site, pipedream, oastify, `.interact.sh`, ngrok…), crypto miner, reverse shell, curl/wget piped to shell, encoded PowerShell, javascript-obfuscator `_0x` names (> 30). `meta.capabilities` marks network/exec |
| `patterns.py` | Compiles (cached) and runs the YARA rules; converts byte offsets to line + snippet |
| `rules.py` | Turns facts + YARA hits into findings. **Standalone:** dynamic code, exec, env dump (LOW, MEDIUM at install time); sensitive paths (SSH keys, AWS/GCP/Azure/Docker/kube creds, `.npmrc`, git creds, shell history, browser data, crypto wallets; MEDIUM, HIGH at install time); raw public IP URLs; hex-escape obfuscation; high-entropy encoded blobs (skips `data:` URIs). **Combined per file:** secrets + network → `code.exfiltration` HIGH; hostname/username only + network → same rule, LOW confidence; decode + dynamic code → `code.decode_and_run` HIGH; install-time exec + network → `code.install_download_exec` MEDIUM; install-time network only → `code.install_network` MEDIUM. `FindingCollector` merges repeats into one finding with `occurrences` |
| `scan.py` | `scan_code(files_dir, manifest) -> CodeScanResult(summary, findings)`; max 200 findings, highest severity first. Summary lands in `Report.codeScan` (files scanned/parsed, install-time files, entry files, executables, skipped files) |

### v2 scoring rules (`scoring.py`): intel + metadata + static code

1. OSV `MAL-` match → MALICIOUS / HIGH / intel
2. SafeDep `isMalware` → MALICIOUS/HIGH if human-verified or `CONFIDENCE_HIGH`, else SUSPICIOUS/MEDIUM (intel)
3. Any HIGH-severity finding → SUSPICIOUS / MEDIUM / rules
4. ≥ 2 **distinct rule kinds** at MEDIUM → SUSPICIOUS / LOW / rules (the same rule firing in many files counts once)
5. 1 MEDIUM rule kind → SAFE / LOW / rules
6. Otherwise → SAFE / MEDIUM / rules

Rules 3–6 get revisited when the AI step lands.

### Tests (`analyzer/tests/`, 110 passing, no network)

- **Steps 1–2:** schema rules, registry helpers, integrity, extraction attacks (traversal, symlinks, size caps), OSV/SafeDep parsing (incl. the SafeDep "prose contradicts boolean" case), each metadata rule, scoring rules.
- **End-to-end `analyze()`** with `httpx.MockTransport`: clean, known-malicious, tampered tarball, intel outage, suspicious code.
- **Step 4:** file selection + install/entry detection, every `js_facts` extraction (incl. `regex.exec` and env-copy non-matches), every YARA rule plus false-positive regressions, combined-risk rules, end-to-end `scan_code`.
- Malicious-looking test code is plain text with `.invalid` domains that only gets parsed. `tests/helpers.py` builds fake tarballs and packuments.

---

## Differences from the README plan (discovered while building)

- **Trusted publishing:** many popular packages now publish via npm trusted publishing (`_npmUser.name = "GitHub Actions"`, `_npmUser.trustedPublisher` set). The "new publisher" rule falsely flagged them, so it now **skips trusted publishes**. Added `metadata.trusted_publishing_dropped` (previous version trusted, current not), a stolen-token signal. Report metadata includes `trustedPublishing` and `provenance` (`dist.attestations`).
- **`manifest_mismatch` check added** (not in README): install scripts in the tarball's `package.json` differ from registry metadata ("manifest confusion").
- **`VerdictRecord` rules:** only `COMPLETE` records may have a verdict; `FAILED` and `SKIPPED` require `failureReason`.
- **`reportS3Key` is left empty** until Step 3 actually uploads to S3.
- **Weekly downloads check not implemented yet** (README §8.1 lists it).
- **OSV pagination not handled** (fine for `MAL-` lookups; revisit if listing many CVEs).
- **Popular packages list** is hand-curated (~130 names), with legit look-alikes (`preact`, `mysql2`, `lodash-es`) included so they aren't flagged.
- **Build order changed:** Step 4 (code scanning) was built before Step 3 (cloud), since it needs no AWS.
- **Semgrep not used (yet).** README listed YARA + Semgrep + tree-sitter. Built with **tree-sitter (structure) + YARA (raw patterns) + Python rules (combinations)**. Semgrep would duplicate tree-sitter's role, adds a heavy dependency and slow startup per scan (bad for Lambda). Revisit only if a rule needs Semgrep's dataflow.
- **Schema additions (Step 4):** `Finding.installTime` (bool), `Finding.occurrences` (int ≥ 1), `Report.codeScan` (dict). `schema/*.json` re-exported.
- **False positives fixed during live testing:**
  - esbuild/sharp: `{ ...process.env, X }` / `env: process.env` passes the environment to a child process. Now recorded as `env_copies`, not as reading secrets.
  - TypeScript: YARA `requestbin` matched inside `apiRequestBinary`. Capture-service rules now require real domain forms (`requestbin.(com|net|io)`, `.interact.sh`). Regression test added.

### Known limits of the static scanner (for the AI step / later)

- Per file only: reading secrets in one file and sending them from another isn't combined.
- String-splitting tricks (`"." + "ssh"`, `"ev"+"al"`) and computed property names evade the AST checks.
- Inline install scripts (`node -e "..."`) are only covered by the metadata install-script finding, not parsed.
- TypeScript and shell files get YARA patterns only (no AST facts).
- Tools that legitimately touch `.npmrc` (npm clients) get a MEDIUM `sensitive_path` warning.

---

## Parallel work: UI agent

A second Claude instance builds the website in `web/` at the same time (decided 2026-09-17, so the UI isn't squeezed at the end).
- Its instructions: [`web/BRIEF.md`](web/BRIEF.md). Its progress log: `web/PROGRESS.md`.
- It builds against real scan results in `schema/examples/` (express SAFE, lodash SAFE with LOW findings, esbuild SUSPICIOUS, safedep-test-pkg MALICIOUS, plus pending/scanning/failed/skipped records), through a single data module, so switching to the real API later is one file.
- **Contract the scanner agent must honor:** `schema/*.json` + `schema/examples/`. When changing `schema.py`, re-export the schema, **regenerate the examples**, and tell the user so the UI agent can re-copy them. `web/BRIEF.md` §5.3 holds a **draft `aiReview` shape**: build Step 5 to match it, or update the brief and tell the user.
- Ownership: the UI agent edits only `web/`; the scanner agent edits everything else.

---

## Open decisions

- 🟡 **AI coverage (Step 5).** Proposed to the user, still awaiting explicit confirmation: the AI does a **quick look on every package** (install scripts + the files they run + main entry file, later the diff vs previous version), and a **deep-dive agent** only when rules or the quick look find something. Reason: rules-only gating means novel malware that trips no rule never reaches the AI. OpenAI credits are sponsored, so cost is low. The AI can never downgrade hard evidence (OSV/SafeDep). `codeScan.installTimeFiles` / `entryFiles` already identify the files the quick look would read. esbuild is the reference case the AI must clear.
- 🟡 AWS region, SAM CLI install, Bedrock model access (see README §21 for the rest).

---

## Conventions for agents working on this repo

- **The user stages and commits manually.** Never commit. After each step, stop and give `git add` / `git commit` commands with a descriptive message. Commands must start with `cd ~/Vault` (the user sometimes runs them from `analyzer/`).
- **Explain each finished step in a few easy words:** what was built as a whole + where it's used. No file-by-file breakdowns for the user.
- Keep `uv run pytest -q` green. Tests must not need the network.
- After changing `schema.py`, run `uv run pkgguard-export-schema` and commit the updated `schema/*.json`.
- Never execute package code. Never commit `.env` or keys.
- The user's editor may reformat Markdown (table padding, backticks). Don't rely on exact-text replacement in `.md` files; re-read first.
- Update this file at the end of every step.
