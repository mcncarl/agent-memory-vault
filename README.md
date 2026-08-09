# Agent Memory Vault: Shared Memory for Claude Code and Codex

**English** | [简体中文](./README.zh-CN.md)

[![Tests](https://github.com/mcncarl/agent-memory-vault/actions/workflows/tests.yml/badge.svg)](https://github.com/mcncarl/agent-memory-vault/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)

Agent Memory Vault is a local-first, Git-backed long-term memory system that Claude Code and Codex can safely share. Markdown remains the source of truth; SQLite provides structured and full-text retrieval; optional EmbeddingGemma + Zvec adds local semantic search.

The repository contains only reusable templates, scripts, and fictional examples. Your real memories, paths, credentials, project names, and conversation content stay in your private local vault.

## Why it exists

AI coding agents are useful inside one session, but durable collaboration needs more than chat history. This project provides a verifiable memory lifecycle:

- Start important work by retrieving only the relevant long-term context.
- Preserve stable facts, decisions, workflows, project state, and agent lessons as readable Markdown.
- Let Claude Code and Codex use one vault, one Git history, and one retrieval index.
- Prevent sessions from accidentally committing each other's changes with session-scoped claims.
- Validate high-impact writes with source checks, content-bound intents, approvals, and immutable receipts.
- Keep every derived store rebuildable from Markdown.

Obsidian is optional. The vault is an ordinary Markdown directory and works with any editor.

## Design

```text
Private Markdown vault (source of truth)
              │
              ├── Git history and rollback
              ├── SQLite metadata + FTS search
              ├── optional EmbeddingGemma + Zvec semantic search
              └── session claims, write intents, closeout, and audit
                         │
                 ┌───────┴───────┐
                 │               │
             Claude Code        Codex
```

The repository is organized around a small set of auditable components:

```text
templates/vault/                 reusable private-vault template
scripts/bootstrap.py            create a local vault and Git baseline
scripts/memoryctl               shared CLI for Claude Code and Codex
scripts/agent_memory_index.py   SQLite index and full-text search
scripts/agent_memory_search.py  unified keyword + optional vector search
scripts/agent_memory_retrieve.py
                                bounded, revalidated Markdown retrieval
scripts/agent_memory_write.py   host read/prepare/apply/cancel boundary
scripts/agent_memory_closeout.py
                                checks, indexing, audit, and scoped commit
scripts/agent_memory_doctor.py  end-to-end health checks
```

See [Architecture](./docs/architecture.md), [Privacy](./docs/privacy.md), and [Automation](./docs/automation.md) for the detailed model.

## Quick start

Requirements: Python 3.10+ and Git.

```bash
git clone https://github.com/mcncarl/agent-memory-vault.git
cd agent-memory-vault
cp .env.example .env
python3 scripts/bootstrap.py --memory-root "$HOME/agent-memory-vault" --write-env
source .env
python3 scripts/agent_memory_evolution.py --init --scan --report
python3 scripts/agent_memory_index.py --init --scan --report
python3 scripts/agent_memory_check.py
python3 scripts/agent_memory_doctor.py
```

`bootstrap.py` creates an independent Git repository in the private vault and commits the template baseline. Existing Git history is preserved. Use `--no-init-git` only when you intentionally do not want Git.

If the source checkout has neither `.env` nor a runtime TOML file, generated databases and logs stay in the ignored local `.agent-memory/` directory. They do not silently reuse another installed memory system.

### Windows 10/11

Use the PowerShell installer from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
  -MemoryRoot "$HOME\Documents\Agent Memory Vault"
```

The installer accepts paths containing spaces or non-ASCII characters, creates a private virtual environment, installs a verifiable runtime, initializes the vault and indexes, and runs the built-in checks. See the complete [Windows guide](./docs/windows.md).

## Share one vault between Claude Code and Codex

Keep one Markdown vault, one Git baseline, one SQLite database, one optional Zvec index, and one audit schedule. Each host needs only a thin adapter:

- Codex reads the vault's shared `AGENTS.md`.
- Claude Code imports the same file from `CLAUDE.md` with `@/absolute/path/to/AGENTS.md`.
- Claude Code's native auto-memory should remain separate from the formal vault.
- Both hosts call `memoryctl` with their own actor and session identity.

```bash
python3 scripts/memoryctl --actor codex search "project status" --limit 5

python3 scripts/memoryctl --actor codex prewrite \
  "Stable fact to preserve" \
  --source-class user_direct \
  --knowledge-kind fact \
  --asserted-by user \
  --evidence-ref "current-conversation"

python3 scripts/memoryctl --actor codex claim \
  --file "/absolute/path/to/changed-memory.md"

python3 scripts/memoryctl --actor codex closeout --dry-run
python3 scripts/memoryctl --actor codex closeout
```

Claims are stored as session hashes. A session closeout processes only the files claimed by that session and explicitly excludes changes owned by other sessions. When there is nothing to process, closeout exits successfully as a no-op; unclaimed memory changes still fail closed.

## Retrieval

The unified search combines SQLite/FTS results with the optional Zvec sidecar, deduplicates candidates, and applies orthogonal filters such as project, memory type, track, scope, and status.

```bash
python3 scripts/agent_memory_search.py "project closeout" --limit 5
python3 scripts/agent_memory_search.py "preferences" --track user
python3 scripts/agent_memory_search.py "deployment boundary" --current-project example-app
```

Search indexes are candidate generators, not authorization or truth sources. Host applications should use `retrieve`, which reopens the current Markdown, validates containment and symlinks, requires strict UTF-8, reapplies scope and status rules, checks for sensitive content, and returns bounded excerpts with current hashes.

## Safe writes and closeout

The normal write sequence is:

1. Run `prewrite` to classify the source, knowledge type, target, and duplicate risk.
2. Edit the Markdown source of truth.
3. Claim the changed files for the current session.
4. Run `closeout --dry-run` and review the result.
5. Run `closeout` to check, index, audit, and optionally commit only the claimed files.

For protected paths and host applications, the repository also provides a content-bound two-phase workflow: `read-target` → `prepare` → explicit user confirmation → `apply`. It verifies the base Git version, session, target, scope, and raw/canonical hashes before writing, then records an immutable receipt after closeout.

This is designed as a strong accidental-misuse boundary for local agents. It is not a security boundary against malicious software that already controls the local user account.

## Privacy and security

- Formal memory stays in the private vault, outside this public repository.
- Markdown is canonical; SQLite and vector indexes are disposable derivatives.
- Search logs retain hashes and classifications rather than raw private queries.
- Secret-like content is rejected by checks before it enters formal memory.
- Retrieval revalidates current files instead of trusting stale index excerpts.
- Deletion evidence requires explicit authorization and a recoverable Trash copy.
- Runtime manifests and dependency locks make local installations auditable.

Before publishing a fork, run:

```bash
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -v
AGENT_MEMORY_ROOT="$PWD/templates/vault" \
AGENT_MEMORY_STATE_DB="$PWD/.agent-memory/state.sqlite" \
python3 scripts/agent_memory_index.py --init --scan --report
python3 scripts/agent_memory_check.py --skip-state-db
python3 scripts/agent_memory_doctor.py
```

Also inspect the Git diff and scan for private paths, credentials, databases, and generated vector data. See [Privacy](./docs/privacy.md).

## Optional semantic retrieval

Keyword search works without large dependencies. To enable fully local semantic retrieval, install the pinned vector environment and configure EmbeddingGemma + Zvec:

```bash
python3 -m venv .venv-vector
.venv-vector/bin/python -m pip install -r requirements-vector.lock
```

The vector layer only recalls candidates. SQLite continues to own structured filtering, and Markdown remains authoritative. The doctor verifies model manifests, dependency locks, vector/index hashes, and offline-query behavior.

## Runtime installation and upgrades

For a stable machine-wide entry point, install the current Git version into a private runtime directory:

```bash
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
cp config/agent-memory.example.toml "$HOME/.config/agent-memory/config/agent-memory.toml"
# Edit memory_root, git_root, and state_db in the TOML file.
"$HOME/.config/agent-memory/scripts/install_runtime.py" \
  --config-root "$HOME/.config/agent-memory" --verify --json
```

Running the installer again upgrades the runtime without overwriting your private configuration or host adapters.

## Project status

Agent Memory Vault is actively maintained and tested on Ubuntu, macOS, and Windows with Python 3.11, plus Ubuntu with Python 3.12. The public template is intentionally free of personal memory and generated state.

Created and primarily maintained by [Yichen (@mcncarl)](https://github.com/mcncarl).

## Contributing

Issues and pull requests are welcome. Please keep changes cross-platform, add tests for behavior changes, and never include real memory, absolute private paths, credentials, generated databases, or vector indexes.

## License

Released under the [MIT License](./LICENSE). Third-party notices are listed in [ACKNOWLEDGMENTS.md](./ACKNOWLEDGMENTS.md).
