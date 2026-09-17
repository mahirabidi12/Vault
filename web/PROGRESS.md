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

### AI-vs-final-verdict disagreement (`malicious-safedep-test-pkg`)

That fixture's AI read the code as harmless (`aiReview.verdict: "SAFE"`) while the record's actual verdict stays `MALICIOUS` (`decidedBy: "intel"` — SafeDep's human-verified malware flag). `AiReviewSection` now takes a `finalVerdict` prop (passed from `record.verdict` in `report-detail.tsx`) and shows an explicit callout when the two disagree: *"PkgGuard's final verdict is malicious, not what the AI read below. Threat intelligence and other hard evidence always outrank the AI's own read of the code — the AI never gets to downgrade a confirmed threat."* This is the FUTURE_SCOPE.md "one source of truth" lesson made visible in the UI, not just true in the scoring logic.

---

## Visual redesign pass (2026-09-17, after the AI-review sync)

User asked for a much stronger, "2026 startup" visual bar for the hackathon's Best UI track, referencing
`wspx.vercel.app` (repo: `github.com/zingzy/wsp`, `apps/www`), `traycer.ai`, `era0.com`, `maritime.sh`. I cloned
the `wsp` repo to `/tmp` (read-only, not vendored — deleted after) to study its actual code rather than guess
from screenshots. It turned out to already use the same shadcn `base-nova`/`@base-ui/react` foundation this
site is built on, which confirmed the architecture and made adapting its craft straightforward.

**Adapted (not copied) into PkgGuard's own identity:**
- Sharper design language: `--radius` dropped 0.75rem → 0.5rem (cascades to every card/button/badge since
  they're all `calc(var(--radius) * n)`); several cards additionally pinned to `rounded-lg` for a uniform,
  less-soft feel across the whole site (search/feed/scan/docs included, not just home).
- New display font (Space Grotesk, `.font-display` utility / `--font-display`) for all headings, kept
  separate from the body font (Geist Sans) and code/meta font (Geist Mono).
- Dark mode is now the default theme (`providers.tsx`), background pushed toward near-black for a more
  premium feel.
- CSS-only scroll-driven animations in `globals.css` (`.rise`, `.hero-out`, both gated behind
  `@supports (animation-timeline: view())` with `prefers-reduced-motion` fallbacks) — no JS scroll listener
  needed for these. Plus `.dots` texture, `.grain` (inline SVG noise overlay), `.kicker` (uppercase mono
  micro-label used everywhere: section eyebrows, finding severity tags, badges), and `.threat-box` (a slow
  breathing red glow for HIGH-severity findings and the malicious hero).

**Home page**: bigger hero with a scroll-exit fade (`.hero-out`), and the static 4-card "pipeline" grid was
replaced with a sticky-scroll storytelling section (`components/home/pipeline-story.tsx` +
`pipeline-terminal.tsx`) — a scroll-tracked list of 5 narrative beats beside a sticky fake terminal window
that reveals lines as you scroll, playing out the real `ai-cleared-esbuild` story (rules flag two things, AI
clears them, verdict lands SAFE). Also added `components/home/compare-table.tsx`, a sharp-bordered comparison
table ("installing blind" vs "reading the code yourself" vs PkgGuard) for extra credibility.

**Package report page — the specific ask ("malicious lines in special boxes")**:
- `FindingCard` now renders differently per severity, not just a different badge color: HIGH gets a hard red
  left edge, a breathing glow (`.threat-box`), an uppercase "Threat detected" kicker, and a connected
  annotation line below the code explaining why it's flagged (and that it runs on install, when relevant).
  MEDIUM gets the same shape in amber ("Warning"), no glow. LOW stays fully neutral on purpose, so severity
  reads before you've parsed any text.
- `CodeEvidence` grew a `tone` prop (`threat`/`warn`/`neutral`): the code box itself gets a colored border and
  header tint, plus a `→` pointer glyph in the line-number gutter next to the flagged line.
- `VerdictHero`: MALICIOUS gets a hazard-stripe top bar, a pulsing red dot next to the badge, and an explicit
  "Do not install this package" banner. SAFE gets a large, very faint watermark shield-check in the corner.
  Both are new — previously every verdict shared one calm treatment.

Verified after each change: `tsc --noEmit`, `eslint .`, and `next build` all clean; spot-checked
`/npm/safedep-test-pkg` (malicious), `/npm/esbuild` (AI-cleared, mixed warnings), and `/` for the new sections
against the production build.

### Bugs found and fixed right after ("the UI is messed up")

Since the redesign shipped without a screenshot tool, real bugs got through. Fixed by installing Playwright
in the scratchpad (not a project dependency) and actually looking at the rendered pages:

1. **Stale server serving a mismatched build.** A `next start` process from an earlier build was still
   running on port 3000 while a later `next build` overwrote `.next/`, so the browser loaded an HTML shell
   referencing JS chunk files that no longer existed — 500s and failed chunk loads, which looks like a fully
   broken page. Not a code bug; a leftover process. Fix: always `lsof -ti :3000 | xargs kill -9` before a
   fresh `next start`, never assume `pkill -f "next start"` catches it (the process shows up as
   `next-server`, not `next start`, once running).
2. **`.rise`/`.hero-out` scroll-driven CSS animations (`animation-timeline: view()`) left whole sections
   stuck at `opacity: 0`** — the pipeline-story intro, compare table, install snippets and recent-threats
   sections were in the DOM but invisible. This is a real browser-timing gap with this still-new API (not
   just a Playwright full-page-screenshot artifact — confirmed by scrolling incrementally with real `scroll`
   events, where it was intermittent). Removed the scroll-timeline dependency entirely; `.rise`/`.hero-out`
   are now harmless no-ops (`opacity: 1`) so nothing can hide content this way again. The `PipelineStory`
   section's own active/inactive state (plain React state + a scroll listener, not CSS scroll-timelines) was
   verified working correctly with real scroll events.
3. **`PipelineStory` had too much dead space per step** (`min-h-[60vh]` × 5 beats) and inactive beats were
   dimmed too far (`opacity-35`) to read comfortably against the near-black background. Tightened to
   `min-h-[46vh]` / `opacity-60`.
4. **Hero 3D scene overlapped the headline with no contrast separation, especially in light mode** — the
   sphere sat at the scene origin, directly behind the centered text. Moved the whole decorative group off
   to one side (`position={[2.6, -1.5, -1.5]}`), reduced its opacity a bit in light mode, and added a radial
   gradient scrim behind the text as a second line of defense so this can't reoccur even if the 3D scene
   changes again.

Re-verified all 5 pages (home, malicious report, AI-cleared esbuild report, feed, scan) with zero console
errors via Playwright, plus an actual incremental-scroll pass (not just `fullPage` screenshots, which don't
fire real scroll events) confirming the pipeline story's active-step tracking behaves correctly.

## Commit

```bash
cd ~/Vault
git add web
git commit -m "Web: full site v1 — all 6 must-have pages" -m "Next.js + Tailwind + shadcn/ui site: package report page (verdict, findings, AI review, code evidence), home with 3D hero, search, project (lockfile) scan, threat feed, and docs. Backed by real schema/examples fixtures + a live-scan simulator until the cloud backend exists."
git push
```
