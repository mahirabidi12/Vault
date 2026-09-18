# PkgGuard Sandbox (dynamic analysis): spec and task list

> **Status (2026-09-19): built and verified locally with harmless fixtures (18/18 behave as expected in real Docker runs); AWS infrastructure DEPLOYED (2026-09-19, stack `pkgguard`, `SandboxEnabled=true`, image `v1` pushed) and VERIFIED on AWS 2026-09-19: isolation probe 19/19 blocked (including DNS through the VPC resolver) and all 18 harmless fixtures behave as expected. No regular npm package or real malware has been run in it yet.** See "What is built" below. This file is the single source of truth for the feature.
> **For agents:** read `PROGRESS.md` first (what exists), then this file. The scanner agent builds everything except `web/`. The UI agent builds only the "UI agent tasks" (section 13) and only edits `web/`.
> Update the status line and section 15 as pieces land.

---

## 0. What is built (and how it differs from the design below)

| Piece | Where | State |
|---|---|---|
| Sandbox image: supervisor, Node hook, fake DNS/HTTP(S)/TCP server, decoys, per-host TLS certs from a sandbox-only CA | `sandbox/` (`Dockerfile`, `runtime/`) | Built, tested in Docker |
| Harmless fixtures for every detector + isolation probe | `sandbox/fixtures/` (13) plus 5 of `eval/fixtures/` | 18/18 correct in live runs (`uv run pkgguard-sandbox-eval`) |
| Trace parsing + detectors + report builder (pure Python, no Docker needed) | `analyzer/src/pkgguard_analyzer/sandbox/` (`build.py`, `strace.py`, `canary.py`, `classify.py`) | Built, 45 unit tests over real captured traces |
| Schema: `SandboxReport`, `FindingLayer.SANDBOX`, `DecidedBy.SANDBOX`, `VerdictRecord.sandboxStatus`, `StageTimings.sandboxSeconds` | `schema.py`, exported to `schema/*.json` | Done |
| Scoring v4: canary exfiltration or a reverse shell = MALICIOUS/HIGH decided by `sandbox`, AI cannot clear it | `scoring.py` | Done |
| AI prompt includes a sandbox section (coverage, hosts, processes, decoded eval payloads, PROOF lines) | `ai/prompts.py` | Done |
| `analyze(..., sandbox_runner=...)`: runs after the code scan and before the AI; a sandbox failure never fails the scan | `analyze.py` | Done |
| AWS launcher: stages tarball in S3, starts 2 Fargate tasks, waits, reads traces, always cleans up | `cloud/sandbox_runner.py`, wired into `cloud/scan_handler.py` | Built, tested with moto and a fake ECS |
| AWS infrastructure (VPC with no internet route, endpoints, DNS Firewall, ECS task, IAM, S3 lifecycle) | `infra/template.yaml`, all behind `SandboxEnabled` (default `false`) | **Deployed and verified** 2026-09-19 (22 resources added, 8 modified in place, nothing replaced) |
| Image push script | `sandbox/push.sh` | Ran once: image `v1` (ARM64) is in ECR |
| Remote runner for real samples and the isolation test on AWS | `pkgguard-sandbox-remote` | Written, not run |
| Example reports with sandbox data for the UI | `schema/examples/sandbox-*` (5) | Generated from real traces |

**Deviations from the design in sections 2 to 10 (decided while building):**
- **Orchestration:** the scan Lambda starts and waits for the two Fargate tasks itself (about 60 to 90 s inside a 10-minute Lambda), instead of adding Step Functions states. Sandbox runs **before** the AI so the AI sees the trace (open decision 2 resolved: AI last). Moving it into Step Functions later is possible without changing the report format.
- **Root filesystem is not read-only.** The supervisor must rewrite `/etc/resolv.conf` to point at the fake DNS server. The package still runs as an unprivileged user with no way to gain privileges, so it cannot write anywhere root-owned.
- **HTTPS succeeds inside the sandbox.** The image trusts a sandbox-only CA and the fake server mints a certificate per requested host, so malware's HTTPS calls complete and we see the whole request body (a self-signed cert made scripts crash and roll the install back). Node also gets `NODE_EXTRA_CA_CERTS`.
- **Dependencies are stripped** from the package's `package.json` so an offline install can run its own scripts. If an install script crashes, npm rolls the package back, so the supervisor reinstalls with `--ignore-scripts` to still run the require and bin phases; the report notes this (`PARTIAL`).
- **The Node hook is best-effort** (code in the same process can tamper with it). `strace` and the fake-network logs are the authoritative sources. The hook's unique value is the decoded source passed to `eval` / `Function` / `vm`. Replacing `eval` makes every call indirect, so the hook exposes `require` / `__filename` / `__dirname` to eval'd code.
- **Threads:** strace lists each thread as a pid. npm's own threads read `~/.npmrc` at startup, so events from npm's process (including its threads) are ignored in the install phase.
- **libfaketime** moves the clock for the package only (`env` after privilege drop), so strace timestamps stay real.
- **Committed traces are sanitized.** The sandbox's fake credentials look like real tokens on purpose (so stealers take the bait), which could trip GitHub push protection. `analyzer/tests/data/sandbox/` and `schema/examples/sandbox-*` hold sanitized copies (`python -m pkgguard_analyzer.sandbox.sanitize`); re-run it after refreshing traces.
- **DNS Firewall checks the whole CNAME chain.** S3 bucket names resolve through `s3-r-w.<region>.amazonaws.com` (and `s3-w`, `s3-1-w`), so those had to be allowed or the task could not even pull its image. Found on the first AWS run.
- **The supervisor restores the real `/etc/resolv.conf` before uploading its result**, otherwise its own S3 upload was answered by the fake DNS server.
- **On Fargate a task has half a CPU**, so the CPU-hog rule triggers at 35% of wall time, not 70%.
- **Fargate does not look like Docker** (no `/.dockerenv`, no docker cgroup), so malware that only checks for Docker keeps running and gets caught (fixture s07).
- **Sinkhole details:** every DNS name gets its own `127.x.y.z` address so a later `connect()` maps back to the name; raw-IP connects fail but are still recorded from strace.

**Commands**
```bash
cd analyzer
uv run pkgguard-sandbox ../sandbox/fixtures/s02-persistence      # run one harmless fixture (Docker, no network); refuses anything else
uv run pkgguard-sandbox-eval                                      # all fixtures, live, prints pass/fail per detector
uv run pytest -q tests/test_sandbox.py tests/test_sandbox_runner.py
uv run pkgguard-sandbox-examples                                  # regenerate schema/examples/sandbox-*
# AWS (after deploying with SandboxEnabled=true and running sandbox/push.sh):
uv run pkgguard-sandbox-remote --fixture ../sandbox/fixtures/s13-isolation-probe --show-probe   # MUST say ALL BLOCKED before any real sample
uv run pkgguard-sandbox-eval --remote                             # all fixtures in the AWS sandbox
```
**Safety rule for real malware:** the local runner only accepts directories inside `eval/fixtures/` or `sandbox/fixtures/` and `run_tarball` refuses without an explicit fixture flag. Real samples are never downloaded to or executed on a laptop; they go to AWS (`pkgguard-sandbox-remote --tarball`, or fetched inside AWS).

**Deploy steps (steps 1 to 3 DONE 2026-09-19; about $0.94/day while enabled, endpoints in one AZ)**
1. `sam build --template infra/template.yaml && sam deploy ... --parameter-overrides SandboxEnabled=true` (creates the ECR repo, VPC, endpoints, DNS Firewall, ECS task).
2. `sandbox/push.sh v1` (build ARM64 image, push to ECR).
3. `uv run pkgguard-sandbox-remote --fixture ../sandbox/fixtures/s13-isolation-probe --show-probe` must print `ALL BLOCKED`. Also confirm from the task logs that a direct query to the VPC resolver returns nothing (DNS Firewall).
4. Run the other fixtures remotely, then real samples.
5. Disable with `SandboxEnabled=false` to stop the endpoint charges.

---

## 1. What it is and why

Today PkgGuard only **reads** packages: threat intel (OSV, SafeDep), metadata red flags, static code scan (tree-sitter + YARA), and an AI review. Nothing is ever executed. Every competitor (Socket, SafeDep, Snyk, Aikido) does some version of this.

The sandbox **runs** the package in a locked-down, internet-less container and records what it actually does: DNS lookups, connection attempts, HTTP requests, processes spawned, files touched, code passed to `eval`. The pitch: *"we catch what static tools miss by running it and reading it, and we show you exactly what it tried to do."*

What it fixes, from `PROGRESS.md` "Known limits of the static scanner":
- String tricks (`"ev"+"al"`, `process["e"+"nv"]`) fool the AST checks. A sandbox only sees what really happens.
- Obfuscated payloads (base64, hex, `_0x` names): we capture the **decoded** source at the moment it reaches `eval` / `Function` / `vm`.
- Evidence instead of opinion: a fake credential leaving the box is proof, not a heuristic.

Not a replacement for the static + AI layers. All three run and their results are merged.

---

## 2. Decisions already made (do not re-litigate)

| Decision | Choice |
|---|---|
| Where it runs | **AWS ECS Fargate**, one task per run (each task is its own Firecracker microVM). Never on a laptop. |
| Where real malware is tested | Only in this sandbox. Never `npm install` a malicious sample on a dev machine. |
| Network | **No route to the internet.** Fake DNS + fake HTTP(S) sinkhole inside the task. Connect attempts to raw IPs fail, but are still recorded. |
| Runs per package | **Two, in parallel:** A = baseline, B = "hostile conditions" (`CI=true`, clock +60 days, different hostname/user). |
| Time budget | About 60-90 s wall clock. Hard kill at 120 s. |
| Verdict weight | Proof-grade signals count like threat intel (`decidedBy: "sandbox"`, AI cannot clear them). Everything else goes to the AI as evidence. |
| Raw traces | **Always stored in S3**, separate from scoring, so scoring changes can be re-run offline for free. |
| Who is sandboxed | Every package that has install scripts or is flagged by earlier layers. Packages with neither may run a short require-only pass (see open decisions). |

---

## 3. Architecture and flow

```
Step Functions ScanStateMachine
  ScanPackage (Lambda, existing)         static scan + intel + metadata, stages the verified tarball to S3
     ├─► AIReview (existing, in ScanPackage today)
     └─► Sandbox (NEW): ECS RunTask.sync x2 in parallel (run A, run B)
            reads tarball from S3 → runs → writes raw trace to S3
  Merge (NEW Lambda): raw traces → SandboxReport + sandbox findings → rescore → save verdict + report
  (any failure/timeout → MarkFailed, existing)
```

Open point for the implementer: today one Lambda does static + AI. The AI should see the sandbox trace, so either (a) run the sandbox first and feed the trace into the AI prompt, or (b) run AI first and re-run a short "AI over sandbox trace" step after. **Recommendation:** run the sandbox in parallel with the static scan, then run the AI last with both. Costs a little wall time, gives the AI the full picture. Decide and record it here.

The **same container image** is used everywhere (built once, pushed to ECR). Local Docker is only for building it (section 12), not for running.

---

## 4. Isolation requirements (must all hold before any real malware is run)

1. Private subnet, **no internet gateway, no NAT**. Security group egress only to the VPC endpoints (ECR, CloudWatch Logs, S3 gateway). Nothing else.
2. **DNS must not leave the VPC resolver.** The VPC resolver (base IP + 2) recurses to the internet, which would let DNS-exfil reach an attacker. Use **Route 53 Resolver DNS Firewall** with a block-all rule, allowing only the AWS endpoint names. Inside the task, `resolv.conf` points at our sinkhole.
3. Task runs the package as an **unprivileged user**, read-only root filesystem where possible, no host mounts, all capabilities dropped except `SYS_PTRACE` (needed for `strace`, the only capability Fargate allows adding).
4. **Task IAM credentials hidden from the package.** The entrypoint (root) reads what it needs, unsets `AWS_CONTAINER_CREDENTIALS_*`, then drops to the sandbox user. The task role can only `PutObject` to `sandbox-traces/<scanId>/` and read the staged tarball. No other permissions.
5. CPU/RAM caps, PID limit, output size caps (a package cannot fill the log).
6. Task always torn down, success or failure. A leaked running task is a cost and safety bug.
7. **Isolation test (section 11-B) passes before any real sample goes in.**

Why (2) matters: a malware sample that reaches the real internet from our AWS account can breach the AWS acceptable use policy and get the account suspended.

---

## 5. What gets executed (phases)

Inputs: the exact verified tarball already fetched by the scanner (staged in S3). The sandbox never talks to npm.

1. **Install phase:** `npm install ./pkg.tgz --omit=dependencies --no-package-lock` **with scripts enabled**. Fires the package's own `preinstall` / `install` / `postinstall`. (Dependencies are scanned as their own packages; code that needs them may throw on load, which is recorded as a coverage gap.)
2. **Require phase:** `require()` the `main` / `exports["."]` entry in a fresh Node process.
3. **Bin phase:** run each `bin` entry once with `--help`.

Per-phase timeouts (about 25 s install, 15 s require, 10 s per bin). A timeout is recorded, not fatal.

**Run A (baseline):** normal env. **Run B (hostile conditions):** `CI=true`, GitHub Actions env vars set, fake clock +60 days (libfaketime), different hostname and username. Any behavior present in B but not in A is reported as **conditional behavior** (time bombs, CI gates: a strong malice signal).

**Decoys planted on the box** (each holds a unique canary string): `~/.npmrc` (`_authToken`), `~/.ssh/id_rsa` + `known_hosts`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.kube/config`, `.env` in the working dir, browser profile with `Login Data`, Discord `leveldb`, crypto wallet dirs (`~/.config/Exodus`, `~/.electrum`, etc.), `~/.bash_history`. Env vars: `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`/`SECRET`, `OPENAI_API_KEY`, all with canary values.

**Fake network:** DNS answers every name with the sinkhole address and logs the query. HTTP/HTTPS listeners on 80/443 (self-signed cert, any SNI) log method, URL, headers and body, and reply `200` with a harmless stub (`#!/bin/sh\nexit 0` for anything that looks like a script). That lets `curl | sh` chains continue harmlessly and reveal more behavior. Raw-IP connections fail (no route) but are recorded by `strace`.

---

## 6. Instrumentation (three independent layers)

1. **Node hook** (`--require sandbox-hook.js`): wraps `net`, `dns`, `http`/`https`, `child_process`, `fs`, `process.env` reads, and, importantly, logs the **decoded string** given to `eval`, `new Function`, `vm.*`, `require` of dynamic paths. Gives high-level, readable events. Misses native code and other runtimes.
2. **`strace -f -tt -e trace=network,process,file`**: catches shell scripts, child processes, native binaries: `connect`, `execve`, `openat`, `write` to sensitive paths, `chmod`, `rename`, `unlink`. Catches what the hook misses. Noisy, so filter to what is interesting.
3. **Sinkhole logs**: every DNS query and HTTP request that reached the fake servers, with full bodies (size-capped, secrets already fake).

A supervisor process starts the sinkhole, starts the trace, runs the phases, collects everything into one JSON trace, uploads to S3, exits.

---

## 7. What we check (signals -> finding rule IDs)

All findings use layer `sandbox` and rule ids prefixed `sandbox.`. Severity is the default; the merge step may adjust with context.

| Rule id | What it detects | Severity |
|---|---|---|
| `sandbox.canary_exfil` | A canary value appears in any outbound URL, body, header or DNS name. **Proof of exfiltration.** | HIGH |
| `sandbox.reverse_shell` | Socket connect + `dup2` to stdin/stdout + `execve` of a shell, or `nc -e` / `bash -i >& /dev/tcp` | HIGH |
| `sandbox.dropper_exec` | A file was written, made executable, then run | HIGH |
| `sandbox.persistence` | Writes to `.bashrc`, `.profile`, crontab, `authorized_keys`, systemd user units, LaunchAgents | HIGH |
| `sandbox.conditional_behavior` | Suspicious behavior appears only in run B (CI, date, host gates) | HIGH |
| `sandbox.decoy_read` | A decoy credential/secret path was opened | MEDIUM (HIGH with a network event after it) |
| `sandbox.suspicious_network` | DNS/connect/HTTP to OAST or capture services, Discord/Telegram webhooks, pastebins, ngrok-style tunnels, raw public IPs, stratum ports (3333/4444/5555/7777/14444), cloud metadata (169.254.169.254) | MEDIUM-HIGH |
| `sandbox.unexpected_network` | Any other outbound attempt during install that is not a known registry/CDN host | LOW-MEDIUM |
| `sandbox.suspicious_process` | `curl`, `wget`, `powershell`, `node -e`, `base64 -d`, `nc`, `python -c`, `chmod +x` chains | MEDIUM |
| `sandbox.eval_payload` | Runtime `eval`/`Function`/`vm` of a decoded string (the deobfuscated payload is stored) | MEDIUM (HIGH if that payload itself does network/exec) |
| `sandbox.resource_abuse` | Sustained high CPU, miner-like process names, infinite loop hit the timeout | MEDIUM-HIGH |
| `sandbox.env_recon` | Whole-env dump, `/etc/passwd` read, hostname/user/interfaces collection | LOW-MEDIUM |
| `sandbox.sandbox_detection` | Checks for `/.dockerenv`, cgroups, VM hostnames, timing checks | MEDIUM |
| `sandbox.coverage_gap` | Install failed, entry threw on load, missing dependencies, timeout before anything ran. Means "we could not observe", **not** "clean" | info |

**Coverage matters:** a SAFE-looking sandbox result on code that never loaded must not lift the verdict. The report always includes what actually ran.

Benign packages that legitimately trip these (esbuild/sharp/puppeteer download binaries; husky writes git hooks): handled with a per-package **expected-hosts allowlist** (registry.npmjs.org, github.com release assets, the package's own declared CDN) plus AI judgment. Keep the allowlist small and versioned in `analyzer/data/`.

---

## 8. Scoring integration (`scoring.py` v4)

1. Existing intel rules unchanged (OSV / SafeDep win first).
2. **Proof-grade sandbox findings** (`canary_exfil`, `reverse_shell`, `dropper_exec`, `persistence`, `conditional_behavior` with a HIGH payload) -> **MALICIOUS / HIGH, `decidedBy: "sandbox"`**. Like intel, **the AI cannot clear it.**
3. Other sandbox findings are added to the finding list and included in the AI prompt (`build_task()` gets a sandbox trace summary, wrapped as untrusted content like everything else). The AI can escalate or clear them the same way it does static findings.
4. Rules-only fallback (AI off/failed): any HIGH sandbox finding -> SUSPICIOUS/MEDIUM; two or more MEDIUM kinds -> SUSPICIOUS/LOW; same shape as the existing static rules.
5. Sandbox failed or skipped -> verdict falls back to the v3 result and `reviewFlags` notes "no dynamic analysis". **A sandbox failure never blocks or fails the whole scan.**
6. New enum value `decidedBy: "sandbox"`, new layer `sandbox`. **Schema change, so `schema/*.json` + examples must be regenerated and the UI told (section 13).**

---

## 9. Data contract (DRAFT, finalize in `schema.py` when building)

New optional `Report.sandbox: SandboxReport | null`. `VerdictRecord` gains `sandboxStatus` (`COMPLETE | PARTIAL | SKIPPED | FAILED | NOT_RUN`).

```
SandboxReport {
  version: string                       // sandbox analyzer version, part of settingsHash
  status: COMPLETE | PARTIAL | SKIPPED | FAILED
  skipReason?: string
  durationSeconds: number
  rawTraceS3Key: string                 // full trace, for offline re-scoring
  coverage: { installExitCode, installCompleted, entryLoaded, entryError?, binsRun[], timedOut: bool }
  runs: [{ name: "baseline" | "hostile", env: { ci, clockOffsetDays, hostname, user }, phases: [{name, exitCode, timedOut, seconds}] }]
  network: [{ run, atMs, kind: "dns"|"connect"|"http", host?, ip?, port?, method?, url?,
              bodyPreview?, classification, canaryHit: bool, pid, process }]
  processes: [{ run, atMs, pid, ppid, exe, argv[], phase }]
  files: [{ run, atMs, op: "read"|"write"|"delete"|"chmod"|"exec", path, decoy: bool, category? }]
  dropped: [{ path, sha256, size, executed: bool, preview }]
  evalPayloads: [{ run, api: "eval"|"Function"|"vm", decodedPreview, sha256 }]
  canaryHits: [{ canaryId, decoyPath, sink, run }]
  resource: { peakCpuPercent, peakMemoryMb, killedReason? }
  conditional: [{ description, onlyInRun }]
  findings: Finding[]                   // layer "sandbox", ids as in section 7
}
```

Rules: caps on every array (for example 500 network events, 500 file events, 200 processes), previews truncated (2 KB), everything JSON-safe. `BehaviorProfile` (existing, static-derived) is **filled from sandbox data when present** instead of guesses, with a flag saying which source produced it.

---

## 10. Raw traces and re-scoring

- The sandbox uploads the **entire raw trace** to `sandbox-traces/npm/<name>/<version>/<sandboxVersion>.json` (S3, private, lifecycle rule to expire after N days).
- A separate **Merge/score** step turns the trace into `SandboxReport` + findings. Changing a detection rule or scoring weight = re-run Merge over stored traces (seconds, ~free), **not** re-run the sandbox.
- `pkgguard-eval` and `pkgguard-seed` get a `--rescore-from-traces` mode for this.
- Old records (scanned before the sandbox existed) have `sandboxStatus: NOT_RUN`. `ScanSettings.settingsHash` changes with the sandbox version, so they are known stale; `pkgguard-seed --force` re-scans them.

---

## 11. Testing plan (what we test, in order)

**A. Detector correctness (harmless fixtures, no real malware).** Extend `eval/fixtures/` with harmless packages that *do* each behavior against `.invalid` domains: DNS lookup, HTTP POST with a canary, write `.bashrc`, spawn `curl`, base64 + `eval`, CPU spin, sleep, `CI`-gated and date-gated behavior, reverse-shell-shaped (connect to a sinkhole IP + spawn `sh`), write-chmod-exec dropper, read decoy files. Each detector fires on its own fixture and stays silent on the benign controls. The 15 existing fixtures already cover about half of these.

**B. Isolation test (gate before anything real).** A special fixture that, from inside the sandbox, tries: connect to `1.1.1.1:443`, resolve a public name via the VPC resolver and directly at `8.8.8.8`, reach the ECS credentials endpoint and the instance metadata endpoint, read the supervisor's environment, write outside allowed dirs, fork-bomb, fill disk. **All must fail or be contained, and the task must still tear down.** Automate it; run it on every sandbox image change.

**C. Real malware.** About 100 real malicious npm packages (source: Datadog's `malicious-software-packages-dataset`, password-protected zips, password `infected`) plus about 350 benign (including about 40 known-noisy legit packages). Same set scanned three ways: static only / static + AI / static + AI + sandbox. Record per package which layer(s) caught it. **Step 0:** profile the 100 with the existing static scanner first (no execution) to see which families they really are, then adjust detectors before building against guesses.

**D. False positives.** Benign set through the sandbox: esbuild, sharp, puppeteer, husky, bcrypt, node-gyp-heavy packages. Must not flip to MALICIOUS. Allowlist + AI clear the noisy ones.

**Metrics to report:** detection rate per mode (with counts), false-positive rate, detection *added by* the sandbox, coverage rate (how many samples actually loaded), per-package time and cost, isolation test pass/fail.

Handling rules for real samples: keep zips out of git; unzip only inside the sandbox job; never run a sample outside the sandbox.

---

## 12. Docker and builds

Docker is **not** needed to run anything: all runtime is on AWS. It is only needed to **build** the container images (`sam build` builds image Lambdas via Docker on the laptop). Two ways: run Docker Desktop while building, or build in AWS (CodeBuild, or CloudShell which has Docker) and skip local Docker entirely. Either is fine; the sandbox image is built the same way as the analyzer image (`analyzer/Dockerfile` is the model), pushed to ECR by the stack.

---

## 13. Tasks

### UI agent tasks (edit only `web/`; contract is section 9; ask the user for schema changes)

Real sandbox data does not exist until the scanner agent ships it. Build against a **clearly-labeled hand-authored mock** shaped like section 9, and swap to `schema/examples/` when the real ones land. Run `npm run gen:types` after the schema is exported.

1. **Types and wording** (`lib/verdict.ts`, `lib/types`): add layer `sandbox`, `decidedBy: "sandbox"` ("Confirmed by sandbox run"), `sandboxStatus` states. Keep the wording rules in BRIEF §5.4 (SAFE = "No issues found"; never color-only).
2. **"Dynamic analysis" section on the report page** (`components/report/`):
   - Header strip: sandbox status, duration, coverage ("installed, loaded, 2 bins run", or an amber "could not run: <reason>" so a clean result is never overstated).
   - **Network timeline:** DNS / connect / HTTP rows with host, port, classification badge, and a red "carried your fake credential" marker for `canaryHit`.
   - **Process tree** (parent/child, argv, phase).
   - **File activity:** grouped reads/writes/deletes; decoy hits highlighted; persistence writes called out.
   - **Dropped files and decoded `eval` payloads:** code blocks via the existing Shiki `CodeEvidence`, with sha256.
   - **Run A vs run B:** side by side; "only appears under hostile conditions" callout for conditional behavior.
3. **Attack-chain diagram** (stretch): a simple left-to-right graph from the trace, for example `install script -> reads .npmrc -> POST evil.example`. Highest demo value on a malicious verdict.
4. **Verdict hero / feed / home:** show "Confirmed by sandbox" when `decidedBy: "sandbox"`; add a sandbox line to the home pipeline story and the compare table; docs page section describing the sandbox and its limits (honest about what it cannot see).
5. **Fixtures:** add mock malicious and mock benign sandbox fixtures (clearly commented as mock until real ones ship).
6. **Tests:** vitest for the new formatting/grouping logic and the wording rules.
7. Update `web/PROGRESS.md`.

### Other UI-agent backlog (not sandbox, any order)
- **Version diff view:** what changed between this version and the previous scanned one (new install scripts, new hosts, new files). Needs the scanner-side item below.
- **Fix `npm run test`** locally (rolldown native binding error: remove `node_modules` and `package-lock.json`, reinstall, verify lockfile still passes `npm ci` on Amplify before committing).
- **Search page** against a real endpoint once one exists.

### Scanner agent tasks (in order; each ends with tests green + `PROGRESS.md` updated)
_Progress: 1 to 4 and 7 are done; 5 is written but not deployed; 6 (isolation test on AWS) and 8 (real samples) are next; 0 and 9 not started. See section 0._

0. Profile the ~100 real malware samples with the static scanner (add a `--local-tarball` entry to `analyze()`), summarize families, adjust section 7 if needed.
1. Sandbox image: supervisor, Node hook, strace wrapper, sinkhole, decoy generator. Runs locally against fixtures for development only.
2. Schema: `SandboxReport`, `decidedBy: sandbox`, layer, `sandboxStatus`; export schema; regenerate examples; **tell the user so the UI agent re-copies.**
3. Detectors + Merge/score from a stored trace (pure Python, unit-tested against captured traces, so no infra needed to test rules).
4. Scoring v4 + AI prompt gets the trace summary.
5. Infra (`infra/template.yaml`): VPC, private subnets, endpoints, DNS Firewall, security groups, ECS cluster + task definition, task/execution roles, Step Functions integration, trace bucket prefix + lifecycle.
6. Isolation test (section 11-B) automated. **Must pass before step 7.**
7. Fixtures for all detectors (11-A) + `pkgguard-eval` sandbox mode + `--rescore-from-traces`.
8. Real-sample run (11-C, 11-D), results table into `PROGRESS.md` and the README pitch.
9. Version diff data (new schema field: `diffFromPrevious`) for the UI's diff view.

### User / ops tasks
- Confirm the open decisions below.
- Decide Amplify basic auth (currently blocks the public site) and set or disable it.
- Approve the sandbox VPC endpoints (about $20-30/month while up; tear down after the hackathon).
- Raise the AWS budget alarm and the daily scan cap deliberately before bulk runs (`MaxNewScansPerDay`, the $10 monthly budget).

---

## 14. Known limits (say these honestly in the demo)

- Linux only: Windows/macOS-only payloads and PowerShell stages are not observed (static + AI still see them).
- Browser-only code (clipboard hijackers, wallet drainers in front-end bundles) never runs.
- Code that only fires when a specific exported function is called is not exercised (v1 does not call exports).
- Second-stage downloads are not fetched (no internet), so we see the intent and URL, not the real payload.
- Sandbox-aware malware can sleep past the timeout or detect the environment; the hostile run B and `sandbox_detection` reduce, not remove, this.
- Dependencies are omitted, so code that needs them may fail early (reported as a coverage gap).
- Hostname/username-gated logic beyond run B's one variation, and geo-gated payloads, are only seen up to the check.

---

## 15. Cost and time (estimates, verify)

- Per package: about 35-65 s wall clock (sandbox in parallel with AI); Fargate cost well under $0.001-0.005 for two tasks; AI cost unchanged (about $0.01-0.04).
- Fixed: about $20-30/month for VPC endpoints while the stack is up.
- 500 packages: about 45-60 min at 10 concurrent tasks (the account's concurrency and Fargate task quotas are the real limit; request increases early).

## 16. Open decisions

1. Sandbox every package or only those with install scripts / flagged? Recommendation: install-script or flagged packages get the full two-run; the rest get a 10 s require-only pass (cheap, catches malware that fires on `require`).
2. AI ordering: AI last with the trace (recommended) or in parallel and re-checked.
3. Whether run B also varies the OS platform reported to Node (`process.platform` = win32) to trip platform gates. Cheap to add, may cause more crashes.
4. Expected-hosts allowlist ownership and how it is reviewed.
