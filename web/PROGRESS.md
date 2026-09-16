# PkgGuard Website: Build Progress

> For agents: read [`BRIEF.md`](BRIEF.md) first, then this file for what's actually built.
> Ownership: this agent edits only `web/`. The scanner/backend agent owns everything else.

Last updated: 2026-09-17.

---

## Status: all 6 "Must" pages built and working

| # | Page | Route | Status |
|---|---|---|---|
| 1 | Package report | `/npm/[...name]?version=` | ✅ Built — verdict hero, signals, findings by layer (grouped, LOW collapsed), Shiki code evidence, AI review section, package info, threat intel, scan details, live scanning progress, failed/skipped states |
| 2 | Home | `/` | ✅ Built — 3D hero (react-three-fiber), search, live stats, pipeline explainer, CLI/MCP install snippets, recent threats teaser |
| 3 | Search results | `/search?q=` | ✅ Built — matches + "scan it now" CTA when no exact match |
| 4 | Scan a project | `/scan` | ✅ Built — drag/drop or paste `package-lock.json` (v1/v2/v3), parsed client-side, batch-checked with live polling |
| 5 | Threat feed | `/feed` | ✅ Built |
| 6 | Docs | `/docs` | ✅ Built — CLI, MCP config snippet, API table, privacy note |
| 7–11 | Login/dashboard/keys/admin/policies | — | Not built, per BRIEF.md §7 ("wait until asked") |

## How to run it

```bash
cd web
npm install
npm run dev       # http://localhost:3000
npm run build     # production build (verified passing)
npm run gen:types # regenerate src/lib/types/*.ts from ../schema/*.json
```

Runs entirely on fixtures right now (`NEXT_PUBLIC_USE_FIXTURES` defaults to true; there's no backend yet).

---

## Stack actually used

Matches BRIEF.md §4, plus what filled the gaps:
- Next.js 16 (App Router, Turbopack — new default in this version), TypeScript, Tailwind v4.
- **shadcn/ui, `base-nova` preset** — this shadcn version builds on `@base-ui/react` (Base UI, not Radix) and a `cn` package for the class merge helper. Same idea as classic shadcn, different primitives underneath: composing a link *into* a `Button` uses `render={<Link href=... />}` instead of `asChild`+`<Link>` children.
- TanStack Query, Shiki (dual light/dark theme baked into one render via `--shiki-light`/`--shiki-dark` CSS vars), next-themes, Framer Motion (light use — most motion is CSS), **react-three-fiber + drei + three** for the home page hero.
- `json-schema-to-typescript` — `npm run gen:types` regenerates `src/lib/types/{report,verdict-record}.ts` from `../schema/*.json`. Never hand-edit those two files.

### Next.js 16 is newer than training data — what changed
`node_modules/next/dist/docs/` (bundled, version-matched) was read before writing any App Router code, per its own `AGENTS.md` block. Relevant: `params`/`searchParams` are `Promise`s (must `await`), and a generated `PageProps<'/route'>` / `LayoutProps<'/route'>` global helper exists after `next dev`/`build`/`typegen` runs. `root layout.tsx` uses `LayoutProps<"/">`; the `/npm/[...name]` route uses explicit inline `Promise<{...}>` prop types instead (simpler than coordinating typegen timing for a catch-all + query param route).

---

## Data layer (`src/lib/api.ts`, `src/lib/queries.ts`)

One module, exactly the functions BRIEF.md §6 lists (`getPackage`, `getReport`, `getScan`, `getVersions`, `checkPackages`, `getFeed`, `getStats`, `search`). Every page/component calls through it or through the TanStack Query hooks in `queries.ts`. Swapping to the real API later means rewriting the bodies of these functions only.

**Fixtures**: `src/fixtures/` is a synced copy of `../schema/examples/` (safe-express, safe-lodash-low-findings, malicious-safedep-test-pkg, `ai-cleared-esbuild`, plus the pending/scanning/failed/skipped shape examples) plus one hand-authored file, `feed-seed.ts` — **fictional** packages (not real npm names) so `/feed` and the homepage stats don't look empty next to only two real malicious/suspicious fixtures. Clearly commented as demo seed data, not real threat intel.

**`ai-cleared-esbuild` vs `suspicious-esbuild`**: the scanner agent's schema/examples now includes both — the original rules-only SUSPICIOUS esbuild result, and a newer one where the AI step reviewed it and produced SAFE/HIGH/`decidedBy: ai` (README §19 demo flow #4: "rules flagged it, the AI explains why it's fine"). Both fixtures describe the same `esbuild@0.28.2`, which can't both be "the" record for that version (one DynamoDB row per package+version). This app serves `ai-cleared-esbuild` as canonical for `/npm/esbuild`; `suspicious-esbuild` is copied into `src/fixtures/` but unused, kept only for reference. My earlier hand-written `esbuild.aiReview.mock.json` (built before the scanner agent's real Step 5 landed) has been deleted — no longer needed.

**Live scan simulation**: package not in fixtures → `getPackage` starts an in-memory timer (`PENDING` 700ms → `SCANNING` 2.6s → `COMPLETE`, exported as `PENDING_MS`/`SCANNING_MS`/`LIVE_SCAN_TOTAL_MS`), generating a plausible SAFE result (or MALICIOUS/SUSPICIOUS if the name contains `evil`/`malware`/`hack`/`sus`/`backdoor` — a demo easter egg). Typing `tampered-package` or `huge-package` demos the FAILED/SKIPPED states, reusing the exact `failureReason` text from `failed.record.json`/`skipped.record.json`.
- **Known limitation**: this simulator's in-memory state lives separately in the server bundle and the client bundle (two different JS module instances). The report page avoids relying on both agreeing: it fetches the record **once, server-side**, and if the status is PENDING/SCANNING, a tiny client component (`ScanAutoRefresh`) just schedules a single `router.refresh()` timed to land after `LIVE_SCAN_TOTAL_MS`, which re-runs the *server* copy of the simulator (single source of truth) and reveals the real, memoized result. No client-side polling of `getPackage` happens on this page, so the two module instances never need to agree. `checkPackages`/`useCheckPackages` (used by `/scan`) *does* poll client-side by design (batch lockfile check), which is fine since that path only needs eventual consistency, not a stable scanId.

---

## Design system

- `src/lib/verdict.ts` — the single source of truth for verdict/status/decidedBy/layer/severity labels, icons and colors. Enforces BRIEF.md §5.4 wording rules: SAFE renders as **"No issues found"**, decidedBy always shown, layer grouping labels, `Confidence` is always paired with text (never color-only).
- `src/components/verdict-ui.tsx` — the badge kit (`VerdictBadge`, `StatusBadge`, `DecidedByPill`, `SeverityBadge`, `InstallTimeBadge`, `OccurrencesBadge` with `×N`, `OsvImportBadge` for `source: "osv-import"`).
- Brand: an indigo/violet primary (`--brand`) plus dedicated `--safe`/`--suspicious`/`--malicious`/`--pending` token pairs (fg + tinted bg) in `globals.css`, both light and dark. Light and dark mode both implemented (`next-themes`, class-based).
- `src/components/code-evidence.tsx` — Shiki `codeToHtml` per finding's file/line/snippet, dual-themed via CSS so no re-render is needed on theme toggle.

---

## Known gaps / things to revisit

- **Version timeline** (README §11.3, not in BRIEF's "Must" table) — not built. Each fixture package only has one scanned version right now anyway.
- **`getVersions`** works but is untested by any UI (nothing calls it yet — no version-switcher UI).
- Home page's live-stats numbers are seeded with a large illustrative baseline (`totalScanned: 48213 + ...`) so the homepage doesn't look like a fresh empty demo; real counts come from `getStats()` once the backend exists.
- No `NEXT_PUBLIC_API_URL`/`NEXT_PUBLIC_USE_FIXTURES=false` real-backend path has been exercised (Step 3 cloud backend isn't built yet) — the branch exists in `api.ts` but is unused.

## Open question for the user

None right now — the AI review draft shape in BRIEF.md §5.3 was resolved automatically: the scanner agent shipped the real `AIReview`/`AIEvidence`/`FindingAssessment` schema and real examples mid-session, so the report page's AI review section renders real data (express, lodash, `ai-cleared-esbuild`), not a mock.

---

## Commit

```bash
cd ~/Vault
git add web
git commit -m "Web: full site v1 — all 6 must-have pages" -m "Next.js + Tailwind + shadcn/ui site: package report page (verdict, findings, AI review, code evidence), home with 3D hero, search, project (lockfile) scan, threat feed, and docs. Backed by real schema/examples fixtures + a live-scan simulator until the cloud backend exists."
git push
```
