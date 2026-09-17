# pkgguard-mcp

An MCP server with one tool, `check_package`, that checks an npm package against PkgGuard's
threat intelligence, static analysis and AI review before an AI coding agent installs it.

```
Agent: "Install the npm package safedep-test-pkg"
  → calls check_package({ name: "safedep-test-pkg" })
  → 🛑 BLOCK — do not install this package: safedep-test-pkg@0.1.3
     Verdict: MALICIOUS (HIGH confidence, decided by intel).
     Flagged as malware by SafeDep threat intelligence.
     Refuse to install this package and tell the user why. Do not attempt a workaround.
  → the agent refuses
```

## How it decides

`check_package` calls `GET /v1/package` on the PkgGuard API and polls briefly if the scan just
started. The verdict maps to a `recommendation` the agent is told to act on:

| PkgGuard verdict / status | Recommendation | The agent is told to... |
|---|---|---|
| `MALICIOUS` | `block` | Refuse to install, explain why. |
| `SUSPICIOUS` | `warn` | Ask the user to confirm before installing. |
| `SAFE`, but flagged for human review (`needsReview`) | `warn` | Same — treat with a little extra caution. |
| `SAFE` | `allow` | Proceed. |
| `FAILED` / `SKIPPED` (no verdict could be produced) | `warn` | Treat as unverified, not as safe. |
| `PENDING` / `SCANNING`, still running after polling | `wait` | Call `check_package` again shortly instead of installing. |

## Setup

### 1. Point it at a PkgGuard API

```bash
cp .env.example .env
```

- **Cloud** (once `infra/` is deployed): set `PKGGUARD_API_URL` to the stack's `ApiUrl` output.
- **Local, no AWS**: run `uv run pkgguard-dev-api` from `analyzer/` (serves `http://127.0.0.1:8787`,
  the `.env.example` default) — the same scan pipeline the CLI uses, minus DynamoDB/S3/Step
  Functions. Good enough to build and test this tool end to end before anything is deployed.

### 2. Build

```bash
npm install
npm run build
```

### 3. Add it to your agent

**Claude Code** (`.mcp.json` in your project, or `claude mcp add`):
```json
{
  "mcpServers": {
    "pkgguard": {
      "command": "node",
      "args": ["/absolute/path/to/pkgguard/mcp/dist/index.js"],
      "env": { "PKGGUARD_API_URL": "http://127.0.0.1:8787" }
    }
  }
}
```

**Cursor** (`~/.cursor/mcp.json`): same shape, under `mcpServers`.

Once published to npm, this becomes `"command": "npx", "args": ["pkgguard-mcp@0.1.0"]` — **pin the
exact version** (`npx -y pkgguard-mcp` without a version lets anyone who compromises the package
silently change what your agent trusts).

Most agents also let you add a standing instruction ("always call pkgguard's check_package before
installing any npm package") — the tool description already says this, but a rule file makes it
stick even when the agent's context is very long.

## Try it

With `pkgguard-dev-api` running:
```bash
npm run dev   # or: node dist/index.js
```
Then, from Claude Code or Cursor with this server configured, ask it to install
`safedep-test-pkg` — it's a harmless npm package deliberately flagged as malware, made for exactly
this kind of demo. The agent should call `check_package`, see `block`, and refuse.

## Development

```bash
npm test         # vitest — pure decision/formatting logic + a mocked-fetch client
npm run typecheck
```

`src/client.ts` is the only network-facing code (fetch with a timeout, polling, error handling).
`src/format.ts` is pure and fully unit-tested: given a verdict record, what should the agent be
told to do. `src/tools/check-package.ts` wires the two into an MCP tool with a Zod input/output
schema. Nothing here executes package code or reads local files — it only calls the PkgGuard API.
