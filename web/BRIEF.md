# PkgGuard Website: Brief for the UI Agent

> You are building the **PkgGuard website** in `web/`. Another agent is building the scanner and backend in parallel.
> Read this whole file first, then the sections of the root docs listed in §2.
> Written 2026-09-17. The hackathon submission deadline is **Sunday, Sep 20, 2026**.

---

## 1. Your boundaries (read carefully)

- **Only create or edit files inside `web/`.** Never edit `analyzer/`, `schema/`, `README.md`, `PROGRESS.md`, `FUTURE_SCOPE.md` or `CLAUDE.md`. The scanner agent owns those.
- **The data format is owned by the scanner agent.** If the UI needs a new or changed field, **tell the user** what you need and why. Don't work around it by inventing fields in real data.
- **Never commit.** The user stages and commits manually. At the end of each piece of work, give the user commands that only add `web/`:
  ```bash
  cd ~/Vault
  git add web
  git commit -m "Web: <what was built>" -m "<one or two lines: what it is and where it's used>"
  git push
  ```
  Never suggest `git add .`, because the scanner agent's uncommitted work lives in the same folder.
- **Track your work in `web/PROGRESS.md`** (create it): what's built, how to run it, deviations, open questions. Update it after every piece of work.
- **Talking to the user:** they prefer short explanations in easy words. After each piece of work, say in a few lines what was built and where it's used. No file-by-file breakdowns.

---

## 2. Context to read

1. [`../PROGRESS.md`](../PROGRESS.md): what the scanner does today (checks, rules, verdict logic)
2. [`../README.md`](../README.md), especially:
   - §1 TL;DR (what PkgGuard is)
   - §7 Architecture (where the website fits)
   - §9 Data model
   - §10 API (the endpoints the website will call later)
   - §11.3 Website pages
   - §19 Demo script (the flows the website must make look great)
3. `../schema/verdict-record.schema.json` and `../schema/report.schema.json`: the exact data format
4. `../schema/examples/`: real scan results to build against (§5)

---

## 3. What PkgGuard is (short)

A security check for npm packages. Before a developer or AI agent installs a package, PkgGuard says whether it's **safe, suspicious or malicious**, with evidence. Packages already scanned answer instantly; new ones get scanned live (download → threat intel → package info checks → code scan → AI review) and the result is saved for everyone.

**The website lets people:** search a package and read its report, upload a `package-lock.json` to check a whole project, see recently caught threats, and learn how to install the CLI and agent tool.

---

## 4. Tech stack (decided)

| Part | Choice |
|---|---|
| Framework | **Next.js (App Router) + TypeScript** |
| Styling | **Tailwind CSS + shadcn/ui** |
| Code highlighting (evidence view) | **Shiki** |
| Data fetching / polling | **TanStack Query** |
| Types | Generated from `../schema/*.json` with `json-schema-to-typescript` (add an npm script like `gen:types`; never hand-write these types) |
| Hosting (later) | AWS Amplify Hosting |
| Package manager | npm |

**No backend logic in Next.js API routes.** The real backend is AWS Lambda (built by the other agent). The website only calls the API through one data module (§6).

---

## 5. The data

### 5.1 Two objects

**`VerdictRecord`** is the short answer (what search results, feed and badges use):
`package {ecosystem, name, version}`, `status` (`PENDING | SCANNING | COMPLETE | FAILED | SKIPPED`), `verdict` (`SAFE | SUSPICIOUS | MALICIOUS`, only when COMPLETE), `confidence` (`HIGH | MEDIUM | LOW`), `decidedBy` (`intel | rules | ai | human`), `summary`, `signals[]` (short red-flag titles), `sha256`, `publishedAt`, `requestedAt`, `analyzedAt`, `model`, `ranOn` (`local | cloud`), `analyzerVersion`, `source` (`pkgguard | osv-import`), `failureReason` (FAILED/SKIPPED), `aiFailed`.

**`Report`** is the full detail (for the package report page):
- `findings[]`: `ruleId`, `layer` (`intel | metadata | static`), `severity` (`HIGH | MEDIUM | LOW`), `confidence`, `title`, `file`, `line`, `snippet` (the code line), `installTime` (runs during `npm install`), `occurrences`
- `intel`: `osv {maliciousIds[], vulnerabilityIds[]}` and `safedep {found, isMalware, confidence, humanVerified}`. Either can be `{error}` if the lookup failed
- `metadata`: `description, license, publisher, trustedPublishing, provenance, maintainers[], publishedAt, previousVersion, installScripts{hook: command}, repository, dependencies{}, sha256, fileCount, unpackedBytes`
- `codeScan`: `filesScanned, filesParsed, installTimeFiles[], entryFiles[], executables[], skipped[], findingsTruncated`
- `aiReview`: currently `null` (AI step not built yet; see 5.3)
- `humanReview`: currently `null`

### 5.2 Real examples in `../schema/examples/`

| Example | Shows |
|---|---|
| `safe-express/` | SAFE, no findings: the calm, clean state |
| `safe-lodash-low-findings/` | SAFE with only LOW findings: show them, but de-emphasized |
| `suspicious-esbuild/` | SUSPICIOUS (low confidence): install script downloads + runs a binary; install-time findings with code snippets |
| `malicious-safedep-test-pkg/` | MALICIOUS, decided by threat intel (human-verified) |
| `pending.record.json`, `scanning.record.json` | Scan in progress: live progress UI |
| `failed.record.json`, `skipped.record.json` | Scan couldn't finish: show `failureReason` clearly |

Copy them into `web/` as fixtures (e.g. `web/src/fixtures/`), or import from `../schema/examples/`. If the scanner agent regenerates them, re-copy.

### 5.3 AI review (DRAFT, not built yet)

The AI step will fill `report.aiReview`. Planned shape (**may change**, so render it defensively and treat every field as optional):
```json
{
  "model": "model id",
  "mode": "quick_look | deep_dive",
  "verdict": "SAFE | SUSPICIOUS | MALICIOUS",
  "confidence": "HIGH | MEDIUM | LOW",
  "summary": "One or two sentences",
  "reasoning": "Markdown explanation",
  "evidence": [{ "file": "install.js", "line": 103, "explanation": "Why this line matters" }],
  "filesRead": ["install.js", "lib/main.js"],
  "findingAssessments": [{ "ruleId": "code.install_download_exec", "file": "install.js", "assessment": "benign | malicious | uncertain", "explanation": "..." }]
}
```
For design work, make a **mock** aiReview fixture for esbuild (e.g. "The install script downloads esbuild's own platform binary from registry.npmjs.org and verifies it; this is expected behavior"). Name it clearly as a mock (`*.mock.json`).

### 5.4 UI wording rules (important)

- **Never say "Safe" as a guarantee.** Show `SAFE` as **"No issues found"**. Suspicious → "Suspicious", Malicious → "Malicious".
- Always show **confidence** and **who decided** (`decidedBy`): "Threat intelligence", "Automated rules", "AI review", "Human verified".
- Group findings by `layer`: `intel` → "Threat intelligence", `metadata` → "Package info", `static` → "Code".
- Show an **"Runs during install"** badge when `installTime` is true. That code runs automatically on `npm install`, so it matters most.
- Show `×N` when `occurrences > 1`.
- Records with `source: "osv-import"` must say **"Source: OSV"**. We didn't detect those ourselves.
- Color must never be the only signal: pair verdict colors with icons + text (accessibility).

---

## 6. Data layer (so switching to the real API is one file)

Create **one module**, e.g. `web/src/lib/api.ts`, with these functions. Pages must only use these:

| Function | Planned real endpoint (README §10) |
|---|---|
| `getPackage(name, version?)` → `VerdictRecord` | `GET /v1/package?ecosystem=npm&name=&version=` (returns 202 + scanId if not scanned yet) |
| `getReport(name, version)` → `Report` | (served via S3 / API; TBD) |
| `getScan(scanId)` → `VerdictRecord` | `GET /v1/scans/{scanId}` |
| `getVersions(name)` → `VerdictRecord[]` | `GET /v1/package/versions?ecosystem=npm&name=` |
| `checkPackages(list)` → `VerdictRecord[]` | `POST /v1/check` |
| `getFeed()` → `VerdictRecord[]` | `GET /v1/feed` |
| `getStats()` | `GET /v1/stats` |
| `search(query)` | TBD (prefix search) |

- **Now:** implement them with fixtures. For a package that isn't in the fixtures, **simulate a live scan** (PENDING → SCANNING → COMPLETE over a few seconds) so the progress UI can be built and demoed.
- **Later:** switch to `fetch(NEXT_PUBLIC_API_URL + ...)`. Control with an env flag like `NEXT_PUBLIC_USE_FIXTURES=true`.
- **Scoped names contain `/`** (`@babel/core`). Handle them in routes (catch-all segments) and URL-encode them.
- Versions are always **exact** (`4.18.2`). No version means latest.

---

## 7. Pages (priority order)

| # | Page | Route (suggested) | Must show | Priority |
|---|---|---|---|---|
| 1 | **Package report** ⭐ | `/npm/[...name]` (+ version) | Verdict hero (verdict, confidence, decided by, summary); signals; findings grouped by layer with severity, "Runs during install", ×N, file:line; **code evidence viewer** (Shiki, highlighted line); AI review section (mock for now); package info (publisher, trusted publishing/provenance, license, repo, install scripts, size, files); threat intel results; scan details (analyzer version, model, analyzed at, sha256); **live scanning state** for pending packages; failed/skipped state | **Must: Best UI showpiece, spend the most time here** |
| 2 | Home | `/` | Big package search, short pitch, live stats, install snippets (CLI: `npx pkgguard install <pkg>`; agent tool setup) | Must |
| 3 | Search results | `/search?q=` | Matching packages with verdict badges | Must |
| 4 | Scan a project | `/scan` | Upload/paste `package-lock.json` → parse **in the browser** → list every package + verdict, suspicious/malicious first, summary counts | Must (great demo moment) |
| 5 | Threat feed | `/feed` | Recent malicious/suspicious packages | Must |
| 6 | Docs | `/docs` | CLI setup, agent (MCP) setup, API overview, **privacy note: the CLI sends only package names and versions, never your code** | Must |
| 7–11 | Login, dashboard, API keys, admin review, policies | | **Don't build yet.** Wait until the user asks | Later |

**Parsing `package-lock.json` (page 4):** lockfile v2/v3 has a `packages` map keyed like `node_modules/express` and `node_modules/@babel/core` with `version`. Skip the root `""` entry. It all happens client-side; the file never leaves the browser.

---

## 8. Design goals (Best UI prize)

- **Trustworthy security product**, not a flashy template. Calm, precise, confident.
- **The verdict must be understood in under 2 seconds** on the report page.
- **Evidence feels concrete:** real code, the exact line highlighted, why it matters.
- Clear hierarchy: HIGH findings first; LOW findings collapsed or muted.
- **Light and dark mode.** Responsive down to phone width.
- Fast: no heavy animations; skeletons while loading; smooth live-scan progress.
- Consistent verdict design system (badge, color, icon) used on every page.

---

## 9. Demo flows the website must support (README §19)

1. Open a **malicious** package report → the evidence is instantly clear.
2. Search a package **nobody has scanned** → live scanning progress → verdict appears.
3. Upload a `package-lock.json` → whole-project risk summary.
4. Show esbuild: rules flagged it, **the AI explains why it's fine** (the mock AI review until Step 5 is built).

---

## 10. Not your job

- The scanner, AI agent, AWS backend, CLI tool and MCP agent tool (other agent).
- Changing the data format (ask the user).
- Deployment to AWS (later, together with the backend).
