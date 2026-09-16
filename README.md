# PkgGuard: Project Handoff README

> **What this file is:** the complete record of the project idea, the research behind it, every decision made so far (and why), the architecture, the build plan and the gotchas.
> **Who it's for:** a new Claude instance (or teammate) picking this project up with no prior context.
> **Last updated:** 2026-09-16, the night before hackathon kickoff.
> **Related file:** [`FUTURE_SCOPE.md`](FUTURE_SCOPE.md), which holds everything deliberately postponed (MCP/skill scanning, dynamic sandbox, more ecosystems…).

---

## 0. How to use this document

**Status markers used below:**
- ✅ **Decided**: discussed with the user and agreed. Don't re-open unless the user asks.
- 🟡 **Open**: not decided yet. Ask the user or decide during the build.
- 🔍 **Verify**: stated from memory or estimates. Check against live docs, pricing or the console before relying on it.

**Working with this user:**
- Full-stack developer (strong in JS/TS, web, backend) with working knowledge of classical ML. **Currently learning AI agents and deep learning.**
- Building this for **two goals**: a hackathon submission **and** a strong resume project. Favor designs that are real and explainable in interviews over hacks.
- **Prefers explanations in easy words, step by step.** They asked for "easy words" several times. Keep answers short and plain, and use tables and small diagrams.
- Likes to make decisions themselves. Give options with a clear recommendation, then respect their choice. Once they pick, proceed.
- "PkgGuard" is a **placeholder name** 🟡.

---

## 1. TL;DR

**PkgGuard is a security check for npm packages, for humans and AI agents.**

Before a developer or an AI coding agent installs a package, they ask PkgGuard "is this safe?":
- **Already in our database** → instant answer (fast path).
- **Not in our database** → we analyze it on the spot (download → threat intel → metadata checks → static code scan → AI agent triage), return the verdict, and **store it so nobody waits for that package again** (slow path).

Four "doors" into one cloud backend:
1. **CLI**: `pkgguard install express` checks the full dependency tree, then runs the real `npm install` only if it's clean.
2. **Agent tool (MCP server)**: a `check_package` tool that Claude Code or Cursor calls before installing anything.
3. **Website**: search packages, read detailed reports, upload a `package-lock.json`, threat feed, dashboard.
4. **Cloud backend on AWS**: API + analysis pipeline + database. The brain.

**Hackathon track:** Ship It (deployed on AWS). Also aiming at Best UI through the package report page.

---

## 2. The hackathon

| | |
|---|---|
| Name | **First Commit**, Event 01 of the **Bharat Builds Tour** (WeMakeDevs × AWS) |
| URL | https://www.wemakedevs.org/aws/first-commit (schedule: `/schedule`) |
| Dates | **Thu Sep 17 – Sun Sep 20, 2026**. Online all 4 days |
| In-person (optional) | Sat Sep 19, Polaris School of Technology, Bangalore, 8 AM–8 PM (limited seats) |
| Eligibility | University students in India, teams of 1–4 |
| Theme | "Build something that solves a real problem" |
| Tracks | **Ship It** (deploy on AWS) · **Build It** (open-source AWS tools, run locally) |
| Must use | AWS services (Lambda, DynamoDB, Bedrock, Cognito…) **or** open-source AWS tools (Strands, PartyRock, Cedar, SAM CLI, OpenSearch) |
| Submission | Working project + **3-minute demo video**. Optional blog post |
| Judging | **Problem impact, AWS integration, learning demonstrated, execution quality, demo video** |
| Prizes (as listed on the site 🔍) | Ship It ₹2,00,000 + $3,000 AWS credits · Build It ₹1,50,000 + $2,000 · Best UI ₹1,00,000 + $1,000 · 4 runner-up teams $1,000 credits · top 10 students get Amazon fast-track interviews · top 5 bloggers get Logitech keyboards |
| Sponsor | **AWS only.** SafeDep is **not** a sponsor (checked). There is no bonus for using SafeDep |

**Schedule:** Thu kickoff (teams form, **repos created**) → Fri build (AWS mentors on call) → Sat Bangalore day + online → **Sun submissions**.

🟡 **Check the rules on pre-kickoff work.** Repos are created at kickoff, so assume **no project code before Thu Sep 17**. Setup (accounts, installs, reading docs) is fine. Seeding the database also happens after kickoff.

---

## 3. The problem we're solving

- **Malicious packages are hostile by design.** Typosquats, dependency confusion, install scripts that run on `npm install`, backdoors, credential theft, and **hijacked releases of popular packages**.
- This is **not** the same as vulnerabilities (CVEs), which are accidental flaws. CVE scanners don't catch malware.
- **Speed matters.** Mini Shai-Hulud (May 19, 2026): **637 malicious versions across 317 npm packages published in a 22-minute automated burst**, including packages with millions of monthly downloads (e.g. `size-sensor` ~4.2M/mo, `echarts-for-react` ~3.8M/mo).
- **AI coding agents now install packages with no human reading them.** That's a new, fast-growing entry point for malware.

---

## 4. Prior art: SafeDep (research findings)

The user asked for a deep look at https://safedep.io before designing. Our idea is **architecturally almost identical to SafeDep** (9/9 core features overlap). The user knows this and chose to build it anyway, for learning and resume value, with a tight scope. Option B (MCP/skill scanning) is the differentiated part and lives in `FUTURE_SCOPE.md`.

### 4.1 What SafeDep is
Open-source supply-chain security company (SOC 2 Type II, ISO 27001). Thesis: *"malicious code doesn't break in, it gets installed."* A paid cloud platform plus free open-source tools.

| OSS tool | What it does | GitHub stars (Sep 2026) |
|---|---|---|
| **vet** | Dependency scanning + CEL policy gate for CI/PRs | ~1.1k |
| **pmg** | Wraps npm/pnpm/yarn/bun/pip/poetry/uv and blocks malicious packages at install time | ~513 |
| **gryph** | Hooks into AI coding agents (Claude Code, Cursor…) and logs every file read/write/command to local SQLite, with YAML/CEL block/warn rules. No cloud | ~162 |
| **xbom** | BOM enriched with AI/SaaS/crypto usage, via static analysis | ~37 |
| **vet-action** | GitHub Action for vet | ~14 |
| **pinner-mcp** | MCP server that pins components to immutable versions | ~13 |

**PMG's 3 layers (worth copying ideas from):** (1) threat intel lookup, keyless; (2) **cooldown window** that blocks versions published very recently, covering the gap before detection; (3) optional OS sandbox for install scripts (macOS Seatbelt, Linux Landlock, bubblewrap). It runs as a proxy with an on-the-fly CA to inspect registry HTTPS traffic.

### 4.2 How SafeDep detects malware
Continuous registry monitoring → **static analysis** (YARA etc.) → **dynamic analysis** (network/fs/process) → **metadata analysis** → **AI agent triage** (separates real threats from false alarms using baselines of normal OSS code) → **human expert verification** → real-time malicious package DB used by all their tools.

- **Fast path:** lookup in the already-analyzed DB. Milliseconds, free.
- **Slow path:** on-demand scan of a named component (package version, VS Code extension, GitHub repo at a commit). Minutes, metered/paid. Verdicts: `malware` / `benign` / `inconclusive` + confidence.
- Threat Intel Feed data model (paid API): verdict `SUSPICIOUS` (confidence `AUTOMATED`) vs `MALICIOUS` (`HUMAN_VERIFIED`, `verifiedAt` set). Reports are never deleted; false positives get `withdrawn: true`. Campaigns group related reports. IOCs are typed `(type, value)` pairs.

### 4.3 SafeDep pricing (Sep 2026)
| Plan | Price |
|---|---|
| Free | $0, up to 3 endpoints, 7-day history |
| Team | $20/endpoint/month, 90-day history, 50 on-demand package scans + 125 repo scans/month |
| Enterprise | Custom |
| On-demand scan overage | $0.50/scan (allowance: 10 scans per endpoint/month) |
| Threat Intel Feed | Paid add-on (Team/Enterprise) |

### 4.4 SafeDep public API (tested live on 2026-09-16)
Host `community-api.safedep.io`, **keyless**, ConnectRPC. That means **plain JSON over HTTP POST** to `/<package>.<Service>/<Method>`. No gRPC or codegen needed.

**Malware analysis lookup (works):**
```bash
curl -X POST \
  "https://community-api.safedep.io/safedep.services.malysis.v1.MalwareAnalysisService/QueryPackageAnalysis" \
  -H "Content-Type: application/json" \
  -d '{"target":{"packageVersion":{"package":{"ecosystem":"ECOSYSTEM_NPM","name":"express"},"version":"4.18.2"}}}'
```
Response: `analysisId`, `status` (e.g. `ANALYSIS_STATUS_COMPLETED`), `report`, optional `verificationRecord`.
`report` can contain: `packageVersion`, `target` {`origin` tarball URL, `sha256`}, `fileSystem` (file list), `fileEvidences[]`, `projectEvidences[]`, `warnings`, `analyzedAt`, `inference` {`isMalware`, `confidence`, `summary`, `details`}, `reportId`, `packageMetrics`, `publishers`.
Each file evidence has `fileKey` + `evidence` {`title`, `behavior`, `details` (matched pattern, byte offset, snippet), `confidence`, `source` e.g. `"YARA Analyzer"`}.
YARA rule names seen: `exotic_tld`, `post_exotic_tld`, `discord_bot`, `hidden_short_path_temp`.

**Package insights (works):**
```bash
curl -X POST \
  "https://community-api.safedep.io/safedep.services.insights.v2.InsightService/GetPackageVersionInsight" \
  -H "Content-Type: application/json" \
  -d '{"packageVersion":{"package":{"ecosystem":"ECOSYSTEM_NPM","name":"express"},"version":"4.18.2"}}'
```
Returns the resolved dependency list and package metadata.

**Behavior notes:**
- Behind Cloudflare. Headers show `x-ratelimit-limit: 0` / `remaining: 0`, meaning no limit is exposed. 12 parallel requests all returned 200. Docs say "fair usage". **Be polite: cache results and never bulk-mirror.**
- No keyless "list all malicious packages" endpoint. Bulk data is the paid Threat Intel Feed. **Design around lookups, not mirroring.**
- With an API key, `api.safedep.io` (data plane) allows 500 req/s.
- Other hosts: `app.safedep.io` (console), `cloud.safedep.io` (control plane, JWT), `auth.safedep.io` (OIDC), `mcp.safedep.io` (hosted MCP, API key).
- Schemas: https://buf.build/safedep/api. Docs index: https://docs.safedep.io/llms.txt
- `vetpkg.dev/mal` (old public feed) is **deprecated**. Don't use it.
- **Test package:** `safedep-test-pkg` (npm `0.1.3`, and PyPI) is harmless but **deliberately flagged malicious**. Perfect for demos.

**Sample results:**
| Package | Result |
|---|---|
| `express@4.18.2` (npm) | Not malware, `CONFIDENCE_MEDIUM`. AI explained a YARA hit in `History.md` was a false positive. ~5 KB report |
| `safedep-test-pkg@0.1.3` (npm) | `isMalware: true`, HIGH, verification record |
| `pino-sdk-v2@1.0.0` (npm) | `isMalware: true`, "Human analysis confirms that this package is malware" (typosquat of `pino`) |
| `litellm@1.82.8` (PyPI) | `isMalware: true`, HIGH, 16 file evidences, **~690 KB report** |

### 4.5 ⚠️ SafeDep bug we found (design lesson)
On `litellm@1.82.8` the report says `isMalware: true, confidence: HIGH`, but `inference.details` **still reads "The package is not a malware…"** A human verification record flipped the boolean and prepended `**Note:** *This report is updated by a verification record*`, while the stale AI narrative stayed underneath.
**Lessons:** (1) when consuming SafeDep, **trust `isMalware`, never parse the prose**; (2) in our system, **one source of truth for the verdict**. When a verdict is overridden, regenerate or clearly replace the explanation.

### 4.6 SafeDep Threat Intel Data Hub stats (safedep.io/ti, Sep 2026)
**1,128 malicious packages · 859 IOCs · 34 campaigns · 144 MITRE ATT&CK TTPs.** That's the human-curated malicious set. The total *analyzed* set is registry-scale (benign packages have reports too).

---

## 5. Scope

| ✅ In the MVP (Option A) | ❌ Not now (see FUTURE_SCOPE.md) |
|---|---|
| **npm only** | PyPI, Go, Cargo, RubyGems, Maven, VS Code extensions, GitHub Actions |
| Threat intel lookup (OSV + SafeDep) | **Dynamic analysis sandbox** (running the code) |
| Metadata checks | Install-time proxy (PMG-style) |
| Static code analysis (**read-only, never executes code**) | **MCP server / agent skill scanning (Option B)** |
| AI agent triage (only for flagged packages) | ML classifier |
| Verdict cache + on-demand scans + request coalescing | GitHub App / PR checks |
| ~50 pre-scanned packages + OSV malicious imports | Orgs, SSO, SBOM export |
| CLI + MCP agent tool + website | OpenSearch full-text search |
| Cognito login, dashboard, API keys, rate limits | Campaign clustering, IOC extraction |
| Admin review queue (should-have), Cedar policies (stretch) | |

---

## 6. Decisions log

| # | Decision | Status | Why |
|---|---|---|---|
| D1 | Build Option A (package verdict platform) first; Option B later | ✅ | Hackathon + resume; B is the differentiator for later |
| D2 | **npm only** for MVP | ✅ | 3-day scope |
| D3 | **Never execute package code** in MVP; static analysis only | ✅ | Safety on AWS + scope. Dynamic analysis is future scope |
| D4 | Ship It track, deployed on AWS | ✅ | Bigger prize; plays to full-stack strength |
| D5 | **Pre-seed only ~50 popular packages** (not 500) | ✅ | ~10× fewer AI calls; enough for the demo |
| D6 | **Seed locally on the laptop with the exact same analyzer code**, writing to the same AWS DynamoDB/S3 | ✅ | Fast iteration; same results as cloud. Record `ranOn: local` |
| D7 | Deployed version does everything in the cloud (live scans) | ✅ | Judges need to see the AWS pipeline run |
| D8 | **AI provider: OpenAI (sponsored "Codex" API key with large credits) as the primary provider, locally and in the cloud** | ✅ | AI is the biggest cost; credits are free for the user |
| D9 | **Keep Bedrock as a config switch** (`MODEL_PROVIDER=openai\|bedrock`) and show at least one Bedrock scan in the demo | ✅ | Protects the "AWS integration" score; fallback if credits end or the key is revoked |
| D10 | **One model for all verdicts saved to the DB** (the chosen GPT model). Claude key used for a comparison run | ✅ | Mixing models makes verdicts inconsistent |
| D11 | Store `model`, `ranOn`, `analyzerVersion` on every verdict | ✅ | Traceability + re-scan when rules improve |
| D12 | **Clients never touch the DB.** CLI/MCP/web → API Gateway → Lambda → DynamoDB | ✅ | No AWS credentials on user machines |
| D13 | CLI sends **only package names + versions**, never user code | ✅ | Privacy; say so in the docs |
| D14 | CLI checks first, then **delegates to real `npm install`**. No custom downloader | ✅ | Simpler; users keep their trusted tool |
| D15 | Import known-malicious npm packages from **OSV** as records (label `source: OSV`) | ✅ | Malicious tarballs are removed from npm; the feed has real data on day 1 |
| D16 | AI runs **only when rules flag something** | ✅ | Cost |
| D17 | Protect sponsored credits: per-user/IP scan limits, **daily AI scan cap**, max ~10 concurrent scans | ✅ | The public site could be abused to burn credits |
| D18 | IaC with **AWS SAM** | ✅ | On the hackathon tool list; Lambda-centric |
| D19 | No NAT Gateway, no OpenSearch Serverless, Lambdas outside VPC | ✅ | Fixed monthly costs |
| D20 | Full report in **S3**, summary in **DynamoDB** | ✅ | DynamoDB 400 KB item limit (SafeDep's litellm report was 690 KB) |
| D21 | Which exact OpenAI model | 🟡 | Pick from models the key can access; choose with the eval set |
| D22 | Which Claude model for Bedrock backup/comparison | 🟡 | Options: Opus 5 / Sonnet 5 / Haiku 4.5; decide with the eval set |
| D23 | Solo or team | 🟡 | Affects how Day 3 is split |
| D24 | Final project name | 🟡 | Check npm availability for CLI + MCP package names |
| D25 | AWS region | 🟡 | `ap-south-1` (Mumbai) for latency vs a region with the needed Bedrock models 🔍 |

---

## 7. Architecture

```
 ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
 │ CLI          │  │ Agent tool (MCP) │  │ Website          │
 │ pkgguard     │  │ check_package    │  │ Next.js/Amplify  │
 └──────┬───────┘  └────────┬─────────┘  └────────┬─────────┘
        └───────────────────┼─────────────────────┘
                            ▼
                  ┌───────────────────┐
                  │ API Gateway (REST)│  throttling
                  └─────────┬─────────┘
                            ▼
                  ┌───────────────────┐   hit    ┌────────────────────┐
                  │ Lookup Lambda (TS)│─────────▶│ DynamoDB Verdicts  │──▶ verdict (ms)
                  └─────────┬─────────┘          └────────────────────┘
                     miss   │  conditional write status=PENDING
                            │  (attribute_not_exists) → exactly one scan
                            ▼
                  ┌───────────────────┐    ┌───────────────────────────┐
                  │ SQS scan queue    │◀───│ EventBridge Scheduler     │
                  │ (+ DLQ)           │    │ (watchlist new versions)  │
                  └─────────┬─────────┘    └───────────────────────────┘
                            ▼
      ┌──────────── Step Functions (Standard) ─────────────────────┐
      │ 1 Fetch     npm metadata + tarball → S3, verify integrity  │
      │ 2 Intel     OSV + SafeDep community API                    │
      │ 3 Metadata  age, scripts, typosquat, maintainers, repo     │
      │ 4 Static    YARA + Semgrep + tree-sitter JS heuristics     │
      │ 5 AI triage Strands agent (OpenAI | Bedrock), flagged only │
      │ 6 Score     combine → SAFE / SUSPICIOUS / MALICIOUS        │
      │ 7 Save      summary → DynamoDB, full report → S3           │
      └────────────────────────────────────────────────────────────┘
      Analyzer Lambdas = Python container images (ECR), same code as local seeding
```

### 7.1 Request flow
- **Fast path:** item exists with `status=COMPLETE` → return it.
- **Slow path:** no item → conditional `PutItem` with `status=PENDING` and a new `scanId` → enqueue to SQS → return `202 {scanId}`. Clients poll.
- **Request coalescing:** if the conditional write fails because someone else already created PENDING, just return `202` with the existing `scanId`. 50 simultaneous requests → **1 scan**.
- **Stale PENDING:** if `PENDING`/`SCANNING` is older than N minutes (e.g. 20), allow a re-enqueue (the scan probably crashed). Failures after retries → `status=FAILED` + reason; the DLQ keeps the message.
- **Step Functions payload limit (256 KB):** pass **S3 keys and IDs** between steps, never file contents. The same applies to SQS messages.

---

## 8. Analysis pipeline

### 8.1 Checks
| Layer | Checks | Notes |
|---|---|---|
| **Fetch** | `GET https://registry.npmjs.org/<name>` (packument: versions, `time`, maintainers) and `/<name>/<version>` (`dist.tarball`, `dist.integrity`). Download tarball → verify integrity → S3 | Scoped names: `@scope/name` → URL-encode `/` as `%2f` for the registry. Tarball files live under `package/` |
| **Threat intel** | **OSV.dev** `POST https://api.osv.dev/v1/query` `{"package":{"name":…,"ecosystem":"npm"},"version":…}`. **`MAL-` IDs = known malicious** (OpenSSF malicious-packages). **SafeDep** `QueryPackageAnalysis` (§4.4) | 🔍 verify request shapes when implementing |
| **Metadata** | Published < 48h ago; `preinstall`/`install`/`postinstall` scripts; name close to a popular package (edit distance, separators, scope confusion); new or changed maintainer; big version jump / weird version (e.g. `99.9.9` dependency-confusion pattern); missing or mismatched repository link; weekly downloads (`https://api.npmjs.org/downloads/point/last-week/<name>`) | Many attacks show up here before reading any code |
| **Static code** | YARA rules; Semgrep rules; tree-sitter JS: `eval`/`new Function`, `child_process`, env var reads **combined with** network calls, base64/hex blobs, high-entropy (obfuscated) strings, minified install scripts, unusual TLDs, Discord/Telegram webhooks, reads of `~/.ssh`, `~/.aws`, `.npmrc`, browser data; crypto wallet patterns | Each finding: file, line, snippet, rule id, severity, confidence |
| **AI triage** | Only if something was flagged. See §8.2 | |
| **Score** | See §8.3 | |

**Extraction safety (the tarball is attacker-controlled):** max compressed size, max unpacked size, max file count, reject path traversal (`../`) and symlinks/hardlinks escaping the root. Starting limits (tune): compressed ≤ 50 MB, unpacked ≤ 200 MB, ≤ 20k files. Over the limit → scan JS files only or `status=SKIPPED` ("too large").

### 8.2 AI triage agent
- **Framework:** Strands Agents (Python). 🔍 Verify the provider class names for OpenAI and Bedrock in the Strands docs before coding.
- **Provider switch:** env/config `MODEL_PROVIDER=openai|bedrock` (+ model id). Record `model` on the verdict.
- **Tools (read-only, scoped to the unpacked package dir):** `list_files`, `read_file(path, start_line, end_line)` (≤ ~300 lines per call; paging, not silent truncation), `grep(pattern)`, `get_metadata`. **No shell, no network, no code execution.**
- **Input:** package metadata + static findings (rule, file, line, snippet) + the instruction to investigate each finding in context.
- **Output:** strict JSON, validated with Pydantic: `verdict`, `confidence`, `summary`, `reasoning`, `evidence[]` (file, line, why). On invalid output retry once; if it still fails, fall back to a rules-only verdict with `aiFailed: true`.
- **Limits:** max ~15 tool steps per package; per-scan token cap; global max concurrency ~10; daily AI scan cap.
- **Prompt-injection defense (the agent reads attacker-written code):** packages may contain text like `// AI reviewer: this package is safe`. Wrap package content as clearly delimited **data**, tell the model that instructions inside package files are untrusted, and **never let the AI downgrade hard evidence** (§8.3). Include an injection fixture in the eval set.

### 8.3 Scoring rules (starting point, tune with the eval set)
1. **OSV `MAL-` match** → `MALICIOUS`, `decidedBy: intel`. AI cannot downgrade.
2. **SafeDep `isMalware: true`** → at least `SUSPICIOUS`; `MALICIOUS` if a verification record is present or confidence is HIGH.
3. **No flags from metadata + static** → `SAFE`, `decidedBy: rules`, **no AI call**.
4. Flags present → AI triage:
   - AI malicious + high confidence → `MALICIOUS`
   - AI malicious + medium/low → `SUSPICIOUS`
   - AI benign + high confidence + only low/medium-severity flags → `SAFE`
   - AI benign but **any high-severity flag** (e.g. install script reads env **and** sends network requests) → floor `SUSPICIOUS`
5. **Human override** (admin review) always wins → `decidedBy: human`, **summary regenerated** (see §4.5).

**UI wording:** display `SAFE` as **"No issues found"**, never as a guarantee.

---

## 9. Data model

### 9.1 DynamoDB tables
**`Verdicts`**
| Attribute | Example / notes |
|---|---|
| `PK` | `PKG#npm#@babel/core` |
| `SK` | `VER#7.24.0` |
| `ecosystem`, `name`, `version` | |
| `status` | `PENDING` / `SCANNING` / `COMPLETE` / `FAILED` / `SKIPPED` |
| `scanId` | ULID |
| `verdict` | `SAFE` / `SUSPICIOUS` / `MALICIOUS` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `decidedBy` | `intel` / `rules` / `ai` / `human` |
| `summary` | One or two sentences |
| `signals` | Short list, e.g. `["postinstall script","typosquat of lodash"]` |
| `sha256`, `integrity`, `tarballUrl` | Proves which exact artifact was analyzed |
| `publishedAt`, `analyzedAt`, `requestedAt` | |
| `model` | e.g. the GPT model id, or `none` when no AI ran |
| `ranOn` | `local` / `cloud` |
| `analyzerVersion` | semver, e.g. `0.3.0`; re-scan older versions when rules improve |
| `source` | `pkgguard` / `osv-import` |
| `reportS3Key` | Pointer to the full report |
| `aiFailed`, `failureReason` | Optional |
| **GSI1** | `GSI1PK = VERDICT#MALICIOUS`, `GSI1SK = analyzedAt` → threat feed |
| **GSI2** | `scanId` → `GET /v1/scans/{scanId}` |

**`ApiKeys`**: `PK = KEY#<sha256(apiKey)>` (never store raw keys), `userId`, `createdAt`, `revoked`, `tier`.
**`Events`**: `PK = USER#<userId>`, `SK = <timestamp>#<ulid>`, `action` (`blocked`/`warned`/`installed`), `packages[]`, TTL 90 days.
**`Counters`**: rate limits and caps via atomic `ADD` with TTL, e.g. `RL#<ip|keyHash>#<yyyy-mm-dd>`, `AICAP#<yyyy-mm-dd>`.

### 9.2 S3 layout
```
tarballs/npm/<name>/<version>.tgz                    lifecycle: delete after 7 days
reports/npm/<name>/<version>/<analyzerVersion>.json  full report
eval/                                                fixtures + results
```

### 9.3 Full report (S3) contents
Package info (description, maintainers, repo, license, scripts, dependencies, publish time, downloads) · file list with sizes · every static finding (file, line, snippet, rule, severity, confidence) · threat intel results (OSV + SafeDep raw summary) · AI review (verdict, reasoning, evidence, files it read, model, token usage) · human review record (who, when, old → new verdict) · analyzer version.

### 9.4 Shared schema
Define the verdict and report schemas **once** in `schema/` (Pydantic), export JSON Schema, and generate TypeScript types (e.g. `json-schema-to-typescript`). Python and TS must never drift.

---

## 10. API (API Gateway REST + TypeScript Lambdas)

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/v1/package?ecosystem=npm&name=<name>&version=<exact>` | Verdict, or `202 {scanId}` |
| `POST` | `/v1/check` | Batch: `[{ecosystem,name,version}]` → verdicts + pending scanIds (used by CLI/lockfile scan) |
| `GET` | `/v1/scans/{scanId}` | Scan status |
| `GET` | `/v1/package/versions?ecosystem=npm&name=<name>` | All scanned versions |
| `GET` | `/v1/feed` | Recent malicious/suspicious |
| `GET` | `/v1/stats` | Homepage counters |
| `POST` | `/v1/events` | CLI reports blocked/installed (API key required) |
| `POST` | `/v1/keys` · `DELETE /v1/keys/{id}` | Manage API keys (Cognito auth) |
| `POST` | `/v1/admin/review/{pk}/{sk}` | Human override (admin group) |

**Notes:**
- **Scoped names contain `/`**, so use **query params** for name/version rather than path segments. (Earlier chat drafts used `/v1/packages/npm/{name}/{version}`; this is the refined version.)
- **Exact versions only.** `latest`, `^1.2.0` and other ranges are resolved to an exact version by the client, or by the API via the npm registry, before lookup.
- Anonymous lookups allowed with strict limits; API keys get higher limits.

---

## 11. Clients

### 11.1 CLI (`pkgguard`, TypeScript, Commander, published to npm)
- `pkgguard check <pkg>[@version]`: show verdict.
- `pkgguard install <pkg...>`: resolve the full tree **without installing** (copy `package.json` + lockfile to a temp dir → `npm install --package-lock-only --ignore-scripts <pkgs>`), batch `POST /v1/check`, poll pending scans with a spinner, then **block** (any MALICIOUS), **warn + confirm** (SUSPICIOUS), or run the real install.
- `pkgguard check` (in a project): read `package-lock.json` and check everything.
- **TOCTOU gotcha:** a new version could publish between check and install. Install **exact checked versions** (`pkg@x.y.z`) and keep the checked lockfile so npm honors it.
- Reads the API key from env/config. Sends **only names + versions**.

### 11.2 Agent tool (`pkgguard-mcp`, TypeScript, official MCP SDK, stdio, published to npm)
- One tool: `check_package({ecosystem, name, version?})` → verdict + summary + report URL. Handles pending scans by polling briefly, or returns "scan in progress, don't install yet".
- Tool description + setup docs instruct the agent to **always call it before installing any package**.
- **Irony gotcha:** tell users to **pin our MCP server version** in their config (`npx pkgguard-mcp@1.0.0`), not `npx -y pkgguard-mcp`.
- Test with Claude Code: "Install the npm package safedep-test-pkg" → the agent should refuse.

### 11.3 Website (Next.js App Router, TS, Tailwind, shadcn/ui, Shiki, TanStack Query, Amplify Hosting, Cognito)
| # | Page | Route | Priority |
|---|---|---|---|
| 1 | Home: search bar, live stats, CLI/MCP install snippets | `/` | Must |
| 2 | **Package report**: verdict badge, confidence, decidedBy, signals, file-level evidence with highlighted code, AI reasoning, version timeline, **live scanning progress** | `/npm/[...name]` + version param | **Must: Best UI showpiece** |
| 3 | Search results | `/search?q=` | Must |
| 4 | Scan a project: upload/paste `package-lock.json` → tree risk report | `/scan` | Must |
| 5 | Threat feed | `/feed` | Must |
| 6 | Docs: CLI, MCP setup, API, privacy note | `/docs` | Must |
| 7 | Login / signup (Cognito) | `/login` | Should |
| 8 | Dashboard: your events + scans | `/dashboard` | Should |
| 9 | API keys / settings | `/settings` | Should |
| 10 | Admin review queue | `/admin/review` | Should |
| 11 | Policies (Cedar editor) | `/policies` | Stretch |

Report page route: scoped names need a catch-all (`[...name]`) or encoding. Label OSV-imported records clearly ("Source: OSV"), and never imply we detected them.

---

## 12. Tech stack & repo layout

| Part | Tech |
|---|---|
| Analyzer + AI agent | Python 3.12, `uv`, Strands Agents, `yara-python`, Semgrep, tree-sitter (JS), Pydantic, httpx, boto3 |
| AI | OpenAI (sponsored key, primary) · Amazon Bedrock (switch/backup) |
| API | TypeScript, Node 22 Lambda runtime, AWS SDK v3, Zod |
| AWS | API Gateway (REST), Lambda, DynamoDB, S3, SQS (+DLQ), Step Functions (Standard), EventBridge Scheduler, Cognito, Secrets Manager, CloudWatch/X-Ray, ECR (analyzer images), Amplify Hosting, optional Cedar |
| IaC | AWS SAM (`infra/template.yaml`) |
| Web | Next.js, TypeScript, Tailwind, shadcn/ui, Shiki, TanStack Query |
| CLI / MCP | TypeScript, Commander / official MCP TypeScript SDK |
| Tests | pytest, Vitest |

```
pkgguard/
├── analyzer/   Python: fetch, intel, metadata, static, ai_agent, scoring, local_seed.py, lambda handlers
├── api/        TypeScript Lambda handlers
├── infra/      SAM template
├── web/        Next.js site
├── cli/        CLI (npm package)
├── mcp/        MCP server (npm package)
├── schema/     Pydantic models → JSON Schema → TS types
├── eval/       fixtures (never published), benign list, accuracy script, results
└── scripts/    seed 50 packages, OSV import
```

**Key rule:** `analyzer/` is one Python package. `local_seed.py` and the Lambda handlers are **thin wrappers around the same functions**. Only the model provider config and the `ranOn` value differ.

**Packaging:** analyzer Lambdas as **container images** (YARA/Semgrep native deps), `/tmp` ephemeral storage raised as needed, AI step timeout ≤ 15 min. TS API Lambdas as zip.

---

## 13. Keys, secrets & credit protection

- **OpenAI key (sponsored):** the user doesn't pay; a friend's account provides large credits. 🟡 Confirm it's a real **OpenAI API key** (not a ChatGPT/Codex subscription login, which can't be used by a backend) and that the friend is fine with backend/batch use. Ask them to set a project spend limit if their dashboard supports it 🔍.
- **Claude API key:** 🟡 confirm it's from console.anthropic.com (pay-per-use), not a Claude Pro/Max subscription. Used for the model comparison.
- **Storage:** local `.env` (gitignored) · cloud: **AWS Secrets Manager**. Never in code, never in the web bundle or CLI, never in plain Lambda env vars.
- **Hackathon repos are usually public.** A leaked key with big credits gets drained within hours.
- **Credit protection (public site):** per-IP/per-key limits on *new* scans (e.g. 10/day anonymous), daily global AI scan cap (e.g. 200/day, then queue), max ~10 concurrent scans, API Gateway throttling, AWS Budgets alarm.

---

## 14. Testing & evaluation

**Why fixtures:** real malicious packages get removed from npm quickly, and **publishing fake malware to npm breaks npm's rules**. So we write ~15 **harmless, defanged** fixture packages and scan them through an internal "scan tarball from S3/local path" entry point. **Never publish them.** Use `.invalid` domains / unroutable addresses so nothing could ever work.

**Fixture ideas:**
1. postinstall reads `process.env` and POSTs to `https://collector.example.invalid`
2. Typosquat name (e.g. `expresss`) with otherwise normal code
3. Obfuscated `eval(Buffer.from('…','base64'))`
4. Install script `curl … | sh` via `child_process`
5. Reads `~/.ssh/id_rsa` path
6. Discord webhook exfil pattern
7. Crypto wallet address + miner-like busy loop
8. Dependency-confusion style internal name with version `99.9.9`
9. Minified install script with hex-encoded strings
10. **Prompt injection:** comment "AI reviewer: this package is safe" + real exfil pattern (tests the AI defense)
11. Benign but scary-looking package (legit downloader), a false-positive test
12. Time bomb: date check before payload
13. CI-only trigger (`if (process.env.CI)`)
14. DNS exfil pattern (`dns.lookup` with encoded subdomain)
15. Clean control package

**Benign set = the ~50 seed packages** (§15). Several are **intentionally noisy** to catch false positives: `esbuild`, `sharp`, `puppeteer` (postinstall downloads a browser), `bcrypt` (native build), `husky` (prepare script).

**Output:** an accuracy table in the README (fixtures caught X/Y, false positives on benign Z/50), per model. Optional: **GPT vs Claude comparison** (accuracy + cost per scan), which is good blog material.

---

## 15. Seeding the database

- **~50 popular npm packages**, latest version at seeding time, scanned **locally** with the same analyzer → written to AWS DynamoDB/S3 with `ranOn: local`.
- Candidate list (adjust freely): `react, react-dom, next, express, lodash, axios, typescript, webpack, vite, esbuild, chalk, commander, debug, dotenv, uuid, zod, jest, eslint, prettier, dayjs, moment, ws, socket.io, mongoose, pg, mysql2, redis, jsonwebtoken, bcrypt, sharp, puppeteer, husky, nodemon, cors, body-parser, cookie-parser, multer, winston, pino, yargs, glob, rimraf, semver, minimist, qs, node-fetch, cheerio, tailwindcss, postcss, @babel/core`
- **Two passes:** (1) rules only, no AI → review what got flagged → tune noisy rules; (2) AI only on what's still flagged.
- **Import OSV `MAL-` npm records** as `source: osv-import` (no download, no AI).
- **Before recording the demo:** confirm every package shown is already in the DB, and keep **one small unscanned package** to show the live slow path.
- README must state: *"Initial ~50 packages were pre-scanned with a local batch run of the same analyzer code."*

---

## 16. Costs (estimates 🔍, US East prices; verify with the AWS Pricing Calculator)

**AI model prices (Anthropic first-party, per 1M tokens, in/out):** Claude Opus 5 $5/$25 · Sonnet 5 $2/$10 · Haiku 4.5 $1/$5. Bedrock is priced separately by AWS 🔍. OpenAI usage is covered by sponsored credits.

**Rough AI cost per flagged-package investigation (~8 steps):** Opus 5 ~$0.90 (~$0.40 with prompt caching) · Sonnet 5 ~$0.36 (~$0.16) · Haiku 4.5 ~$0.18 (~$0.08).

| Service | Price notes | Our usage |
|---|---|---|
| Lambda | Always-free 1M requests + 400K GB-s/month | ~free |
| DynamoDB | 25 GB always free; on-demand R/W fractions of a cent | ~free |
| S3 | ~$0.023/GB-month | cents (7-day tarball lifecycle) |
| SQS | 1M requests/month free | free |
| Step Functions | 4,000 transitions/month free, then $0.025/1K | cents |
| API Gateway REST | ~$3.50/million | cents |
| EventBridge Scheduler | 14M invocations/month free | free |
| Cognito | first 10K MAU free | free |
| Amplify Hosting | build minutes + traffic | ~$1 |
| CloudWatch Logs | ~$0.50/GB ingested | <$1 if we log only IDs |
| Secrets Manager | $0.40/secret/month | ~$1 |

| Stage | Estimated total |
|---|---|
| **Hackathon** (OpenAI credits for AI, small Bedrock demo/backup use) | **under ~$10** |
| **Portfolio site kept live** (watchlist of top packages, low traffic, credits last) | **~$2–5/month** |
| Real product, ~10K scans/month, paid AI | ~$200–850/month (AI dominates) |
| + dynamic sandbox (future) | + ~$25/month fixed + ~$0.003–0.01/package |

**Cost traps:** NAT Gateway (~$33/month idle), OpenSearch Serverless (high idle minimum), scanning *all* npm releases (thousands/day), verbose logs, leaked keys, no concurrency/budget limits.

**Set on day one:** AWS Budgets alarm (e.g. $10), S3 lifecycle rule, concurrency limits.

---

## 17. Build plan (step by step)

Each step has a **Done when** check. Don't move on until it passes.

### Step 0: Setup (Sep 16 night, no project code)
AWS account + billing alarm + IAM user · install AWS CLI, SAM CLI, Docker, Node 22, Python 3.12, `uv` · check which models the OpenAI key can access · request Bedrock model access · read the hackathon rules on pre-kickoff work · check npm name availability · pick the AWS region (🟡 D25).
**Done when:** `aws sts get-caller-identity`, `sam --version`, `docker ps` all work.

### Day 1: Thu Sep 17 (backbone)
**Step 1: Repo + schema.** Folders, `.gitignore` (`.env`!), verdict/report schema in `schema/` → TS types.
Done when: a sample verdict validates in both Python and TS.

**Step 2: Analyzer v1 (laptop only).** Fetch + integrity + safe extraction · OSV + SafeDep lookup · metadata checks · CLI entry `uv run analyze <name> <version>`.
Done when: `express` works and `safedep-test-pkg` → MALICIOUS.

**Step 3: Walking skeleton on AWS.** SAM: DynamoDB, S3, API lookup with conditional-write coalescing, SQS (+DLQ), Step Functions → analyzer Lambda (same code) → save.
Done when: `curl` unknown package → `202`, then `curl` again → verdict. **Most important checkpoint.**

### Day 2: Fri Sep 18 (brain)
**Step 4: Static analysis.** YARA + Semgrep + tree-sitter heuristics; build the ~15 fixtures.
Done when: most fixtures are flagged and `express` has few or no flags.

**Step 5: AI agent.** Strands, read-only tools, provider switch, strict JSON, injection defenses, step cap, flagged-only gating, **rate limits + daily AI cap + concurrency limit**.
Done when: a flagged fixture gets a correct verdict with reasoning on **both** `openai` and `bedrock`.

**Step 6: Scoring + full report.** Rules from §8.3, summary → DynamoDB, report → S3.
Done when: the S3 report contains all findings + AI reasoning.

**Step 7: Eval, tune, seed.** Run fixtures + benign set → accuracy · tune noisy rules · seed ~50 locally · import OSV `MAL-` records.
Done when: an accuracy number exists and the DB holds ~50 packages + OSV records.

### Day 3: Sat Sep 19 (doors)
**Step 8: CLI.** `check`, `install` (tree resolution, block/warn/install), lockfile check, polling spinner, events.
Done when: `npx pkgguard install safedep-test-pkg` is blocked.

**Step 9: MCP agent tool.** `check_package`, instructions, test with Claude Code.
Done when: Claude Code refuses to install `safedep-test-pkg`. **Record a backup demo clip immediately.**

**Step 10: Website core.** Order: package report → home → search → scan project → feed → docs. Deploy on Amplify.
Done when: a stranger can search a package and understand the report.

**Step 11: Auth + dashboard.** Cognito, dashboard, API keys page.
Done when: log in → create key → CLI uses it → events appear on the dashboard.

### Day 4: Sun Sep 20 (ship)
**Step 12: Extras (only if everything works).** Admin review queue · Cedar policies · version-diff check · GPT vs Claude comparison.
**Step 13: Submit.** Polish the report page · public README (architecture diagram, AWS services, accuracy table, local-seeding note) · **record the 3-min video by early afternoon** · blog post · **submit with buffer**.

**If there's a team:** (1) infra + API, (2) analyzer + AI agent, (3) website, (4) CLI + MCP + eval + video.

---

## 18. Cut order & risks

**Cut first → last:** Step 12 extras → Step 11 auth/dashboard → feed + docs pages → search page.
**Never cut:** Step 3 (cloud pipeline), Step 5 (AI agent), Step 9 (agent demo), package report page.

**Biggest risks:**
- **Day 2 is the heaviest.** If the AI agent is late, ship rules + scoring first and add AI on top.
- Noisy static rules on popular packages → too many AI calls and bad-looking reports. Tune in pass 1.
- AWS setup friction on Day 1 → that's why the walking skeleton comes before features.
- Bedrock model access or region availability → provider switch + OpenAI primary.

---

## 19. Demo script (3 minutes)

1. **0:00** Problem: 317 npm packages poisoned in 22 minutes; AI agents install packages unsupervised.
2. **0:30** Claude Code asked to install a package → PkgGuard (MCP) blocks it live.
3. **1:00** Open the report: verdict, file-level evidence with highlighted code, AI reasoning.
4. **1:40** Scan a package nobody has scanned → live pipeline progress → verdict (**show this run on Bedrock** for the AWS story).
5. **2:15** Upload a `package-lock.json` → whole-tree risk.
6. **2:35** Architecture slide (AWS services) + accuracy numbers.
7. **2:50** What's next: MCP server + agent skill scanning (Option B), dynamic sandbox.

---

## 20. Gotchas & eccentricities (consolidated)

1. **SafeDep narrative bug**: trust `isMalware`, never the prose (§4.5). Our own verdict has one source of truth.
2. **Scoped package names contain `/`**: use query params; URL-encode for the registry (`%2f`); catch-all web routes.
3. **Exact versions only**: resolve `latest`/ranges first.
4. **Malicious packages vanish from npm**: can't download them to test → OSV import + fixtures.
5. **Never publish fixtures to npm.**
6. **The AI reads attacker-controlled text**: prompt-injection defenses + hard-evidence floor + injection fixture.
7. **Popular build tools legitimately trip rules** (`esbuild`, `sharp`, `puppeteer`…). Tune rules, but **don't whitelist popular packages**: compromised releases target exactly those (Shai-Hulud).
8. **Request coalescing + stale PENDING recovery.**
9. **DynamoDB 400 KB item limit** → full report in S3.
10. **Step Functions/SQS 256 KB payload limit** → pass S3 keys, not contents.
11. **TOCTOU between check and install** → install exact checked versions / checked lockfile.
12. **Tarball extraction is dangerous**: size/file limits, path traversal, symlinks.
13. **Public repo** → key leakage risk. `.env` gitignored, Secrets Manager.
14. **Public API** → credit burning. Limits, daily AI cap, concurrency cap.
15. **Cost traps**: NAT Gateway, OpenSearch Serverless, logging whole files, scanning all of npm.
16. **One model for stored verdicts**; always record `model`, `ranOn`, `analyzerVersion`.
17. **"SAFE" is not a guarantee** → UI says "No issues found".
18. **Hackathon rules**: no project code before kickoff (verify); seed after kickoff; be transparent about local seeding.
19. **Bedrock model availability/pricing varies by region** 🔍.
20. **SafeDep community API**: keyless, no exposed rate limit, lookups only (bulk = paid). Cache, be polite, and fail open to our own checks if it's down.
21. **SafeDep is not a sponsor**: it's one intel input, not the pitch.
22. **ConnectRPC** = JSON `POST` to `/<pkg>.<Service>/<Method>`.
23. **YARA/Semgrep native deps** → Lambda container images.
24. **Lambdas outside VPC** in the MVP (no NAT).
25. **AI output can be malformed** → Pydantic validation, one retry, fall back to rules-only with `aiFailed`.
26. **Our own MCP server is distributed via npx** → tell users to pin the version.
27. **The CLI never sends user code**, only names + versions. State it in the docs.

---

## 21. Open questions (ask the user)

- 🟡 Solo or team (1–4)? Who does what?
- 🟡 Final project name + npm package names.
- 🟡 Which OpenAI model does the sponsored key allow? Is it definitely an API key? Is the friend okay with backend use and a spend limit?
- 🟡 Is the Claude key a console API key?
- 🟡 AWS region.
- 🟡 Which Claude model for the Bedrock backup/comparison (decide with the eval).
- 🟡 Attending the Bangalore day (Sat Sep 19)?
- 🟡 Hackathon rule confirmation on pre-kickoff prep.

---

## 22. Future scope (summary; details in FUTURE_SCOPE.md)

1. **Option B: MCP server & agent skill scanner** (top priority after A). Tool poisoning (hidden instructions in tool descriptions, which YARA can't catch, so an LLM is needed), rug pulls (fingerprint tool descriptions, alert on change), tool shadowing, unpinned `npx -y` installs, over-broad permissions/tokens, remote servers (no code, so analyze exposed tools), skills (`SKILL.md` + scripts).
   - MCP background: standard way for AI apps to plug into tools; servers expose tools/resources/prompts; the **model reads tool descriptions** (attack surface); local servers are usually npm/PyPI packages via `npx`/`uvx`, Docker or GitHub repos; remote servers are URLs; sources include npm, PyPI, Docker Hub, GitHub, the official MCP Registry (a catalog pointing to those), Smithery/mcp.so/Glama, `.mcpb` bundles.
2. **Dynamic analysis sandbox**: flagged packages only; Fargate task per package (then gVisor/Firecracker on EC2); `npm install` + `require()`; record network attempts, file access, processes, env reads, CPU; **no real internet** (private subnet, fake DNS/HTTP sinkhole, DNS-exfil blocking; malware reaching the internet from your account can break the AWS acceptable use policy); plant fake credentials as bait; ~$0.003–0.01/package + ~$20–30/month for VPC endpoints 🔍.
3. More ecosystems (PyPI first), install-time proxy, cooldown policy, GitHub App/Action, AWS CodeArtifact gate, IDE extension, version-diff analysis, ML classifier, campaign clustering/IOCs, public feed/webhooks, SBOM export, orgs/SSO, OpenSearch.

---

## 23. Resume bullets (once built; fill in real numbers)

- Built a supply-chain security platform that detects malicious npm packages for developers and AI coding agents, deployed on AWS (Lambda, Step Functions, DynamoDB, SQS, S3, Bedrock).
- Designed a cached verdict API with request coalescing via DynamoDB conditional writes, so each new package is analyzed once however many clients request it.
- Built a model-agnostic AI triage agent (Strands; OpenAI/Bedrock) that investigates static-analysis findings, with prompt-injection defenses against attacker-written code; measured X% detection with Y false positives on an eval set.
- Shipped a CLI and an MCP server that let Claude Code/Cursor check packages before installing them.
