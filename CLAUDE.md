# PkgGuard

**Two agents work in this repo at the same time. Figure out which one you are before editing anything.**

| If your task is… | You are the | You own (only edit these) | Read first |
|---|---|---|---|
| The website / UI / dashboard | **UI agent** | `web/` | `web/BRIEF.md`, then `web/PROGRESS.md` if it exists |
| Scanner, AI agent, AWS backend, CLI, MCP tool, data format, docs | **Scanner agent** | everything except `web/` | `PROGRESS.md` |

Shared reading for both, in this order: `PROGRESS.md` (what's built) → `README.md` (full plan, architecture, decisions, gotchas) → `FUTURE_SCOPE.md` (postponed ideas).

**The data contract** is `schema/*.json` (generated from `analyzer/src/pkgguard_analyzer/schema.py`), with real examples in `schema/examples/`. Only the scanner agent changes it. The UI agent asks the user for changes.

Key rules for both:
- The user commits manually. Give commands, never commit. Always start with `cd ~/Vault` and `git add` **only your own folders** (never `git add .`), so the two agents' work stays in separate commits.
- Explain finished work briefly in easy words: what it is and where it's used.
- Never run package code. Never commit secrets.
- Scanner agent: keep `cd analyzer && uv run pytest -q` passing; update `PROGRESS.md` after every step.
- UI agent: update `web/PROGRESS.md` after every piece of work.
