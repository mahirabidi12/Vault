# pkgguard (CLI)

Checks npm packages against PkgGuard's threat intelligence, static analysis and AI review —
before you install them, not after.

```
$ pkgguard install safedep-test-pkg
Resolving the dependency tree for safedep-test-pkg...
Checking 1 package(s) with PkgGuard...
🛑 safedep-test-pkg@0.1.3 — MALICIOUS (HIGH, intel): Flagged as malware by SafeDep threat intelligence.
   Report: https://pkgguard.example/npm/safedep-test-pkg?version=0.1.3

🛑 Blocked: at least one package is MALICIOUS. Nothing was installed.
$ echo $?
2
```

## Commands

### `pkgguard check [package]`

- `pkgguard check lodash` / `pkgguard check lodash@4.17.21` — check one package. No version resolves
  to the latest published one.
- `pkgguard check` (no argument, run inside a project) — reads `package-lock.json` and checks every
  resolved package (batched, ≤ 200 per request, chunked automatically for larger lockfiles).
- `--json` — print the full decision(s) as JSON instead of (or alongside) the summary.

### `pkgguard install <packages...>`

0. By default only the packages you name are checked (same as the website and the MCP tool). Add `--deep` to check every transitive dependency too; that scans each dependency that is not cached yet, so it is slower.
1. Copies your `package.json` (+ lockfile, if you have one) into a temp dir and runs
   `npm install --package-lock-only --ignore-scripts --save-exact` there — this resolves the *full*
   dependency tree (every transitive package) without installing anything or running any script.
2. Batch-checks every resolved package with PkgGuard.
3. **Any `MALICIOUS` verdict blocks the whole install** — nothing is written to your project.
4. Any `SUSPICIOUS` verdict (or a scan that failed/was skipped) asks for confirmation before
   proceeding (`-y`/`--yes` skips this; it never skips a block).
5. If it's clear, copies the *resolved* `package.json`/`package-lock.json` into your project and
   runs a normal `npm install` there — so the versions that actually get installed are exactly the
   ones that were checked (a version publishing in the gap between check and install can't sneak in
   something different).

Exit codes: `0` allow/installed, `1` warn/cancelled, `2` blocked, `3` timed out or errored — safe to
use in scripts and CI.

## Setup

```bash
cp .env.example .env    # set PKGGUARD_API_URL
npm install
npm run build
npm link                # optional: makes `pkgguard` available globally while developing
```

- **Cloud** (once `infra/` is deployed): set `PKGGUARD_API_URL` to the stack's `ApiUrl` output.
- **Local, no AWS**: run `uv run pkgguard-dev-api` from `analyzer/` (serves `http://127.0.0.1:8787`,
  the `.env.example` default) — the real scan pipeline, no DynamoDB/S3/Step Functions needed.

Published as `pkgguard-cli` (plain `pkgguard` was blocked by npm as too similar to an unrelated
existing package, `pkg-guard`). Once installed (`npm install -g pkgguard-cli`), the command is still
just `pkgguard` — only the package name on npm differs from the command name. Use
`npx pkgguard-cli@0.1.2 install <pkg>` with the version pinned, for the same reason the MCP tool's
README gives: an unpinned `npx -y pkgguard-cli` trusts whatever that package currently resolves to.

## Development

```bash
npm test         # vitest — lockfile parsing, spec parsing, decision logic, a mocked-fetch client,
                  # and resolveTree against a fake npm runner (no real npm/network calls in tests)
npm run typecheck
```

`src/resolve-tree.ts` is the only part that shells out (to `npm`, with `--ignore-scripts`, in a
throwaway temp directory) or touches the real project directory (only after everything passes).
Nothing here ever runs a checked package's own code.
