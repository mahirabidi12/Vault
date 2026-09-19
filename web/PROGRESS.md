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
npm run dev       # http://localhost:3000, fixtures by default
npm run build     # production build (verified passing)
npm run test      # vitest: lib/lockfile.ts, lib/verdict.ts, BRIEF §5.4 wording rules
npm run gen:types # regenerate src/lib/types/*.ts from ../schema/*.json
```

To run it against the **real backend** instead of fixtures:

```bash
cd analyzer && uv run pkgguard-dev-api --no-ai   # serves http://127.0.0.1:8787
cd web && cp .env.local.example .env.local       # NEXT_PUBLIC_API_URL + USE_FIXTURES=false
npm run dev
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

## Scanner agent's punch list, worked through (2026-09-17)

The scanner agent left a review of `web/` in the root `PROGRESS.md` ("Punch list for the UI agent"). Went
through it item by item. **No visual/design changes** — this was all data-layer, correctness and test work.

1. **`npm run gen:types`** — re-run. `report.ts` now has `codeIssues`, `behavior`, `iocs`, `reviewFlags`.
   Still can't render any of it: `schema/examples/*.json` haven't been regenerated to match, so there's no
   real data shaped like the new fields yet. That part is genuinely blocked on the scanner agent, as they
   said themselves.
2. **Fixed the `/v1/check` body bug in `docs/page.tsx`** — it showed a bare array; the real endpoint
   (`cloud/api.py`) requires `{"packages": [...]}`. Also now notes the 200-per-request cap.
3. **Wired up the real backend and actually ran the site against it** — this was the big one:
   - `lib/api.ts`: every function now has a working real-mode branch (`getPackage`, `getReport`, `getScan`,
     `getVersions`, `getFeed`, `getStats`, `checkPackages`, `search`), not just the two that existed before.
     Shared `apiFetch`/`apiFetchOrNull` helpers parse `{"error": msg}` responses the way `cli/src/client.ts`
     does. `checkPackages` now sends a real batched `POST /v1/check` (`{"packages": [...]}`), chunked at
     `MAX_CHECK_PACKAGES` (200), with the same chunk/errorRecord pattern as the CLI's `checkMany`.
   - `getFeed`'s real branch returns `{record, report: null}` — the real `/v1/feed` only ever returns
     summaries, never full reports, and nothing in the UI reads `.report` (checked first). `FeedItem.report`
     is now `Report | null` to match reality instead of a shape the endpoint can't produce.
   - `getStats`'s real branch maps the store's actual shape (`{scansCompleted, safe, suspicious, malicious}`)
     to the UI's `Stats` type. `avgScanSeconds` isn't tracked server-side; kept as the same illustrative
     constant fixtures use.
   - `search` has no real endpoint yet (README §10 marks it TBD) — the real branch calls `getVersions`
     instead of inventing one. Deliberately a read, not a scan trigger: typing in the search box shouldn't
     start scanning packages as a side effect. The search page's own "scan it now" button is still the one
     intentional way to start a scan from that page.
   - **Actually ran it**: started `uv run pkgguard-dev-api --no-ai`, pointed the site at it
     (`NEXT_PUBLIC_API_URL` + `NEXT_PUBLIC_USE_FIXTURES=false`), and drove it with Playwright — home page
     stats, a live scan of a real package (`is-odd`), the lockfile scan page's batch check, the feed, and
     search all worked against real, freshly-scanned data with zero console errors. Added
     `.env.local.example` (committed) documenting how; `.env.local` itself stays gitignored and unset by
     default so `npm run dev` keeps working with fixtures out of the box.
   - Found a real (expected) failure while testing this: `EXAMPLE_LOCKFILE`'s three filler dependencies
     (`@acme/fetch-helper`, `left-pad-pro`, `some-fresh-dependency`) don't exist on the real npm registry —
     they're fixture-only demo names. Swapped them for real, tiny, harmless packages (`chalk`, `picocolors`,
     `zod`) so the "Try an example" button produces a clean result in both fixtures and real-backend mode.
4. **Version history** — genuinely missing (README §11.3, dropped from BRIEF's checklist). Added
   `components/report/version-history.tsx`: calls the now-real `getVersions`, renders a row of version chips
   (verdict-colored dot, current version highlighted) using the exact same card style as the rest of the
   report page. Only renders when there's more than one scanned version — verified this both ways: hidden on
   every current fixture (each has exactly one version) and correctly populated by scanning the same real
   package at two versions through the dev API.
5. **Tests** — there were none. Added `vitest` (matching `cli`/`mcp`'s existing choice) plus
   `vitest.config.mts` (path-aliases `@/*` to `src/`). `lib/lockfile.test.ts` (18 cases: v1/v2/v3 lockfile
   parsing, scoped names, dedup, nested `node_modules`, malformed input) and `lib/verdict.test.ts` (9 cases,
   including one asserting BRIEF §5.4's wording rule by name — SAFE must render as "No issues found", never
   "Safe"). 27/27 passing, `npm run test`.
6. **Update, 2026-09-17 (scanner agent): both packages are now actually published**, fixed on homepage +
   docs. CLI is `pkgguard-cli` (not `pkgguard` — npm blocked that name as too similar to an unrelated
   existing package, `pkg-guard`); the command itself is still `pkgguard` after install. MCP tool is
   `pkgguard-mcp@0.1.0` (was showing the wrong version, `1.0.0`, which was never a real release).

Also fixed in passing: `<html>` used `scroll-behavior: smooth` without the `data-scroll-behavior="smooth"`
attribute Next.js 16 wants for it, which printed a console warning on every client-side navigation. One
attribute, `layout.tsx`, no visual change.

Verified: `tsc --noEmit`, `eslint .`, `npm run test` (27/27), `next build`, and a full Playwright pass over
both fixtures mode and real-backend mode with zero console errors in either.

## Commit

```bash
cd ~/Vault
git add web
git commit -m "Web: wire up the real backend, add tests, version history" -m "Works through the scanner agent's punch list: every api.ts function now has a real backend branch (verified live against pkgguard-dev-api, not just written), batched /v1/check chunked at 200, fixed the docs page's check-body bug, added a version history component, and added the first tests (vitest: lockfile parsing, verdict wording rules incl. BRIEF §5.4). No visual changes."
git push
```

## Home page redesign, pure black (2026-09-19)
- Site is now dark-only, true black (`.dark` tokens in `globals.css`; `forcedTheme="dark"`; theme toggle removed from header). Headings use Geist to match the new look.
- New hero (DebateAi-style): tight-tracked headline with a white→grey second line, white pill + outlined buttons, search box. The 3D scene is gone (`hero-scene*.tsx` deleted).
- New `components/home/request-flow.tsx`: animated diagram of CLI and MCP agent requests flowing into the PkgGuard API and the shared verdict database, with a live request log. Pure SVG animation, no libraries.
- Kept: stats, sticky-scroll pipeline + terminal code box, compare table, install snippets, recent threats.
- Other pages inherit the black theme; not yet reviewed one by one.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: pure black home page redesign with CLI/MCP request-flow diagram"
```

## Home hero: living dithered background (2026-09-19)
- Hero is now a rounded framed card (like maritime.sh) with `components/home/dither-field.tsx`: a canvas of animated halftone dots that flow like waves, a scan line sweeping down, and red target boxes blinking where "threats" are caught. Centre stays clear so text is readable; static when the user prefers reduced motion. No video file needed.

## Home: setup boxes moved up, sweep removed (2026-09-19)
- Removed the white sweeping line from the hero background (`dither-field.tsx`); waves and red threat boxes stay.
- The CLI / MCP setup boxes now sit right after the hero as `components/home/get-started.tsx`: shadcn Tabs (CLI | Agent tool), a description panel with 3 points, and a window-style code panel with copy buttons (MCP tab includes the copyable `mcp.json`). The old bottom install section is removed from `page.tsx`.
- Setup section reworked: tabs replaced by two cards side by side (CLI | Agent tool), each with its install command (copy button) and 3 short steps. Stacks on mobile.

## Home: new hero background + motion pass (2026-09-19)
- Hero background is now `network-field.tsx`: a drifting graph of package nodes with light pulses travelling along links, and red "MALICIOUS" rings appearing on a node and its links. The dither field is deleted. The hero is full-bleed (no card frame) and fades out at the bottom so it blends into the page.
- New `home/ticker.tsx`: scrolling strip of scanned packages with verdict dots, right under the hero.
- New `reveal.tsx` (sections fade/slide in on scroll; content stays visible if JS fails) and `spotlight-card.tsx` (cursor-following glow on hover), used on setup cards, stats, flow and compare sections. Stats count up.
- Note: `.env.local` points at the dev API on :8787; with it stopped, stats show empty and the console logs connection-refused. Delete the file to use fixtures.

## Home: navbar, ticker, setup cards (2026-09-19)
- `site-header.tsx` is now a floating pill: invisible over the hero, turns into a dark pill with border/shadow after scrolling. Hero slides under it (`-mt-[60px]` in `page.tsx`). Theme toggle already removed; a "Scan" button added.
- Ticker chips are bigger.
- CLI/MCP cards: animated border beam (`.border-beam` in `globals.css`, via `SpotlightCard beam`), plus a looping typed terminal demo (`home/terminal-demo.tsx`) showing a block / an agent check. Demo text is illustrative, not real output.

## Home: scroll-driven "how a package gets tested" journey (2026-09-19)
- New `components/home/scan-journey.tsx` replaces the old `PipelineStory` + `PipelineTerminal` (deleted). A tall sticky section: scrolling scrubs one made-up package (`nodelogger-pro`) through all 7 steps. A progress rail (steps 1-7, clickable) sits on top, the background glow turns amber then red as evidence builds.
- Scenes are in `journey-scenes.tsx`: fetch + hash check, threat intel (no match, because new malware isn't in any database), package-info flags, then the **parallel fork**: a static-scan window (reads it) beside the big `sandbox-container.tsx` (runs it): planted decoys, live event log with Run A / Run B, fake internet with a blocked real-internet link, a "proof of exfiltration" alert, run timelines and `sandbox.*` finding chips. Then AI review (types out its reasoning) and the verdict (Malicious, decided by sandbox proof, with evidence and the four "decided by" tiers).
- All copy, timings and demo data live in `lib/pipeline-flow.ts`. `SANDBOX_LIVE = false` shows "In development" badges everywhere the sandbox appears; every demo visual says "Illustrative example". Nothing is presented as a real scan or real sandbox result.
- Also added: "Read / Run / Reason" strip above, "What the sandbox can't see" strip below, a "Runs it in a locked sandbox" row in the compare table.
- Tests: `lib/pipeline-flow.test.ts` (stage order, progress mapping, typing helper, SANDBOX_LIVE flag). **Could not run locally**: vitest still hits the rolldown native-binding error (see backlog). `tsc` is clean; checked in a real browser (Playwright) at 1440px and 375px.
- Known, not from this change: the ticker marquee makes `scrollWidth` exceed the viewport at 375px; `eslint` flags `terminal-demo.tsx` (setState in effect); `next build` fails when `.env.local` points at a dev API that isn't running.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: scroll-driven journey showing every check, with a big sandbox container"
```

- Follow-up (2026-09-19): removed the "In development" badges (`SANDBOX_LIVE = true` in `lib/pipeline-flow.ts`; the "Illustrative example" labels stay). Scrolling is slower and steadier: 130vh per stage unit (was 62) and the animation eases toward the scroll position instead of jumping with the wheel.

- Follow-up (2026-09-19): reverted the uniform-box-size experiment; box sizes are back to the committed layout. The only change is the transition: when the step changes, the whole stage fades and slides out (about 0.3 s), swaps, and fades back in, instead of snapping. The scene on screen lags the scroll position by that fade.

## Home copy: CLI and agent are equal audiences (2026-09-19)
- The page leaned toward the AI agent. Copy now names both: hero ("Use the CLI in your terminal, or give your AI agent a tool…") plus a new "Get the CLI" button that jumps to the setup cards (`#get-started`); setup heading "Guard every install, from your terminal or your agent."; the CLI card is badged "For developers"; the request-flow heading and the journey intro mention the CLI and the website as well as the agent; new compare-table row "Guards your own installs" (CLI).

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: give the CLI equal billing with the agent tool in home copy"
```

## Home: new hero background (2026-09-19)
- The hero background is now `components/home/aurora-field.tsx`: slow drifting blue/violet/cyan light with a few thin flowing ribbons, calm behind the headline. It pauses off-screen and draws one still frame under reduced motion. (Two earlier attempts, a node graph and a scanned-crates tunnel, were replaced.) Checked in a 1440px screenshot only; mobile not checked.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: aurora hero background"
```

## Home: sections removed, edges blended (2026-09-19)
- Removed the "What the sandbox can't see" strip, the "Every other option is slower, or blind" compare table (`compare-table.tsx` deleted) and the "Scan a whole project" card at the bottom. "Recently caught" now spans the full width. The journey has soft top and bottom fades and no hard borders, so it melts into the sections around it. The `/scan` page is still reachable from the header and hero.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: remove limits strip, compare table and scan CTA; blend journey edges"
```

## Home: request-flow simplified to three checks and a verdict (2026-09-19)
- `components/home/request-flow.tsx`: CLI and MCP tool feed the API, which fans out to three boxes, **Static checks**, **Dynamic checks** (sandbox) and **Agent checks** (AI), that merge into one **Verdict** box. A wave travels left to right on a loop (about 5 s, with a pause at the end); only each box's border brightens and thickens as the wave reaches it, with no glow or light band in the background; packets flow along every line. The earlier full-pipeline list panel was removed. Checked in a 1440px screenshot only.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: request-flow shows static, dynamic and agent checks feeding one verdict"
```

## Home: trimmed, new footer, GitHub link (2026-09-19)
- Removed the hero badge ("Built for the AWS First Commit hackathon"), the "Checked against npm registry · OSV.dev …" line under the hero, and the "Recently caught" section (`recent-threats.tsx` deleted). The header GitHub icon now links to https://github.com/mahirabidi12/Vault.
- New `site-footer.tsx` (all pages): fades in from the page instead of a hard border, a closing "Know before you npm install." with Scan and Docs buttons, link columns (Product; Get it, including a GitHub link), a copyright/disclaimer line, and a large faded "pkgguard" wordmark that fades out at the very bottom. Docs sections got ids (`#cli`, `#mcp`, `#api`) so the footer links land on them.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: trim home page, add a blended footer, link GitHub icon to the repo"
```

- Footer spacing fix (2026-09-19): the closing "Know before you npm install." block sat too low, far from the walkthrough and crowding the link columns. The footer now overlaps the walkthrough's empty tail (`-mt-24`) and the block is centered in the gap between the last step and the footer links.

## Navbar: reverted (2026-09-19)
- Two navbar redesigns (a full-width bar, then shadcn dropdown menus) were tried and dropped. `site-header.tsx` is back to the original floating pill, with only the GitHub icon now linking to the repo. Hero offset (`-mt-[60px]`) and walkthrough top padding (68 px) are back to the pill's sizes. The unused `ui/navigation-menu.tsx` and `ui/sheet.tsx` were removed.

- Navbar tweak (2026-09-19): the pill is slightly bigger (56 px tall, was 48; larger logo, links and Scan button) and the search box placeholder is shortened to "Search packages" so it no longer gets cut off. Hero offset is now `-mt-[68px]` and the walkthrough's top padding 76 px.
- Navbar no longer follows the scroll (2026-09-19): `site-header.tsx` is `relative` instead of `sticky`, so it scrolls away with the page. The scroll-triggered background change was removed (the pill now always has a soft dark blurred background), and the walkthrough's top padding is back to 24 px since it no longer has to clear a fixed bar.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: navbar scrolls away instead of following the page"
```
- Footer text and buttons are about 15% larger (2026-09-19): bigger closing heading, subtitle, buttons, logo, description, link columns and copyright line.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: slightly larger footer"
```

## Search results page redesign (2026-09-19)
- `app/search/page.tsx`: a proper page header ("Search" kicker, "Results for <query>", a count line), then result cards with a verdict-colored edge and icon tile, the package name and a version pill, the summary, and a meta row (analyzed time, who decided it, confidence), the verdict badge on the right and a hover lift. The "Scan it now" prompt is a full-width card with a button and a time estimate. The search icon in the hero search box was hidden behind the input; it now sits on top (`search-bar.tsx`).
- `site-footer.tsx` now checks the route: the big "Know before you npm install." block and the overlap with the page above only appear on the home page. Other pages get the compact footer with normal spacing (this was what made the closing block collide with the search results).

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: redesigned search results, footer CTA only on the home page"
```

## Report page: motion and a live feel (2026-09-19)
- `verdict-hero.tsx` rebuilt: a large glass hero with drifting glow blobs tinted by the verdict, a one-time light sweep, staggered rise-in of the name, badges and summary, and a **verdict gauge** (a ring that fills to the confidence level with a pinging halo and the verdict icon). The metadata card sits under the gauge.
- New `stat-tiles.tsx` (with `components/count-up.tsx`): four tiles (files scanned, findings, install-time files, unpacked KB) whose numbers count up when scrolled into view.
- New `pipeline-trace.tsx`: "Every check this package went through": six stages (threat intel, package info, static scan, sandbox, AI review, verdict) that light up one after another with a connector line filling between them, each showing a real result from the report. The sandbox stage says "Not run" because no report carries sandbox data yet; it will need the report type regenerated once the scanner agent ships it.
- `report-detail.tsx`: sections reveal on scroll (`Reveal`), and the info, intel and scan-detail cards get the cursor-following glow (`SpotlightCard`); their own borders were removed from the three card components. New CSS motion classes at the end of `globals.css` (blob-drift, ring-fill, sweep-x, rise-in, ping-ring, line-grow); all are switched off under reduced motion.
- Checked in a browser at 1440px and 375px with the express report; the malicious and suspicious variants and the live "scanning" page were not restyled or re-checked.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: animated package report page (verdict gauge, count-up stats, check trace, reveal and glow cards)"
```

- Report info cards redesigned (2026-09-19): **Package info**, **Threat intelligence** and **Scan details** now use icon headers with a subtitle, much larger text, and tile layouts. Package info has icon fact tiles, two trust tiles (trusted publishing, provenance), maintainer chips with colored initials, install scripts in a callout, and a footer with the dependency toggle and a "View repository" button. Threat intel has two source tiles with a large status circle (pulsing when clean) and confidence bars. Scan details has four stat tiles (scan duration counted up, where it ran, AI model, analyzer version), request and analysis times, a copyable scan ID, and a code-scan block with a parsed-files bar and four mini counters. Fixed a mobile overflow (grid children needed `min-w-0`). Checked at 1440px and 375px.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: redesign package info, threat intel and scan details cards"
```

## Sandbox results on the report page (2026-09-19)
- Ran `npm run gen:types`: the generated types now include `sandbox`, `sandboxStatus`, the `sandbox` layer and `decidedBy: "sandbox"`. `lib/verdict.ts` has the wording: **"Confirmed by sandbox run"** (decided by) and **"Dynamic analysis"** (layer); the findings section lists sandbox findings too.
- New `lib/sandbox.ts` (pure logic, tested in `lib/sandbox.test.ts` against the real `schema/examples/sandbox-*` reports): stage summary, coverage line, coverage gaps, network ordering and host classes, hosts seen only in run B, process tree, file grouping (persistence / dropped / fake-credential reads / other) with the same change in both runs merged into one row.
- **Check trace**: the hardcoded "Not run" sandbox step in `report-detail.tsx` is gone. Headline is the status (Complete / Partial / Failed / Skipped / Not run), the detail line says what ran (e.g. "2 runs, entry loaded, 64 dependencies"), and the tone is red for HIGH findings, amber for MEDIUM (or a partial run), green for a complete quiet run. One deliberate extra: a quiet run whose main file never loaded is grey, not green, so it doesn't read as an all-clear.
- New `components/report/dynamic-analysis.tsx`, the "Dynamic analysis" section (placed after the check trace; a "not run" card when there is no sandbox report): status, duration and coverage chips; sandbox finding chips; an amber "Not everything could be observed" box with the specific reasons; a red "Carried your fake credentials out" proof box from `canaryHits`; run A vs run B cards (CI flag, clock offset, hostname, user, phases) plus an "Only appears under hostile conditions" callout; a network timeline (kind, host, port, class badge, count, request body via the existing Shiki `CodeEvidence`, red marker for `canaryHit`); the process tree per run; file activity groups with sha256 and previews; decoded eval payloads. The verdict hero shows a red "Confirmed by sandbox run" chip (linking to the section) when `decidedBy` is `sandbox`.
- **Evaluation sample**: when `report.metadata.evaluationSample` is true the hero shows an "Evaluation sample" pill (tooltip explains the data was synthetic and intel lookup was off) and the threat-intel card shows the `intelLookup` note.
- Fixtures: the five `sandbox-*` examples were copied into `src/fixtures/` and registered in `lib/api.ts`, so fixture mode can show them (`pkgguard-fixture-postinstall-exfil`, `sbx-persistence`, `sbx-conditional`, `sbx-dropper`, `pkgguard-fixture-clean-control`). The persistence fixture copy has `evaluationSample: true` added to demo the label.
- Tests: `npm run test` now runs (49 passing). It was failing to start with the rolldown binding error; fixed locally with `npm install --no-save @rolldown/binding-darwin-arm64@1.2.9` (does not touch `package.json` or the lockfile, so Amplify's `npm ci` is unaffected; on another machine or CI the same optional-dependency bug may need the platform's binding). Also fixed a rounding bug in `typed()` that the run exposed.
- Not done: the attack-chain diagram (stretch, §13 item 3), the home page's sandbox copy still says "Illustrative example" (unchanged), and the feed and search cards don't show "Confirmed by sandbox run". Checked in a browser at 1440px (exfil, persistence, conditional, clean) and once at 390px for overflow only; the sections were not visually reviewed at mobile width.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: dynamic analysis section, real sandbox stage in the check trace, evaluation sample label"
```

## Live scan page: the whole test process, step by step (2026-09-19)
- `components/report/live-scan-progress.tsx` (the page shown while a new package is being scanned) is rebuilt. A header with the package name, a live mm:ss timer and a seven-segment progress bar; a **step rail** of all seven steps (fetch, threat intel, package info, static scan, sandbox, AI review, verdict) with done / running / waiting states; and a large **"now running" panel** for the current step with its own animated view: the tarball travelling and the hash filling in (fetch), two database lookups (intel), a checklist flipping (info), a code view with a scanning beam (static), the **sandbox container** (planted decoys, what it is doing now, run A and run B bars filling in parallel, the blocked internet, an "analysing" badge), AI tool calls appearing with a thinking indicator, and a verdict ring. The old page had five steps and no sandbox.
- **Honest by design:** the API only reports pending / scanning / done, not which step a scan is on, so the step shown is an **estimate from typical timings** (about 3, 3, 2, 5, 14, 14, 2 seconds). Every panel is tagged "estimated view", the sandbox panel says it shows the steps rather than the package's real events, and a footer note explains this. If a scan runs long the last step stays on screen with a "taking longer than usual" note; nothing claims to be stuck or finished. The timer starts from the request time (bounded to one minute of offset in case of clock differences) and shows a "waiting for a worker" state while the record is pending.
- To make the page show real steps later, the backend would need to expose a stage field on the scan record; the estimate can then be replaced by it.
- Checked in a browser at 1440px by holding the fixture simulator in "scanning" for a few minutes (temporarily; restored) and screenshotting steps 4, 5 and 7. Not checked at mobile width; fetch, intel, info and the AI panel were only seen in an earlier screenshot of the AI step.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: live scan page shows every step, with a sandbox analysing view"
```

## Home: stats moved under the hero and redesigned (2026-09-20)
- `components/home/live-stats.tsx` now sits directly below the hero (before the ticker) instead of further down the page. New layout: a large "Packages scanned" tile (huge counting number, a pulsing "Live" tag, an animated equalizer strip, drifting glow) and three verdict tiles ("No issues found", "Suspicious", "Malicious caught") each with a **ring gauge that fills to that verdict's share of all scans**, a pinging halo, a colored glow, a count-up number and the percentage. Below them, a segmented **distribution bar** grows in with a legend. Tiles rise in one after another and lift on hover. Uses the shared `components/count-up.tsx`; new `eq-bar` and `grow-x` keyframes in `globals.css`, all switched off under reduced motion. Checked at 1440px with the live API numbers (418 scanned: 316, 23, 79); the 390px view was rendered but not looked at.

Commit:
```bash
cd ~/Vault
git add web
git commit -m "Web: stats under the hero with ring gauges, count-up and distribution bar"
```
