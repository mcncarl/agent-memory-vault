# Agent Memory Vault: Shared Memory for Claude Code and Codex

**English** | [简体中文](./README.zh-CN.md)

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
                 │               │               │
             Claude Code        Codex           Ailu
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
scripts/agent_memory_observability.py
                                opt-in, privacy-preserving task telemetry
scripts/agent_memory_decision_outcomes.py
                                versioned decision/outcome evidence report
scripts/agent_memory_write.py   host read/prepare/apply/cancel boundary
scripts/agent_memory_migrate.py explicit state-v4 plan/init/apply/verify gate
scripts/agent_memory_closeout.py
                                checks, indexing, audit, and scoped commit
scripts/agent_memory_doctor.py  end-to-end health checks
```

See [Architecture](./docs/architecture.md), [Privacy](./docs/privacy.md), and [Automation](./docs/automation.md) for the detailed model.

## Quick start

Requirements: Python 3.10+ and Git.

The recommended macOS/Linux entry point is read-only planning followed by one
explicit apply. Choose host hooks explicitly; this example intentionally uses
no host hooks:

```bash
python3 scripts/install-posix.py --plan \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks --json
python3 scripts/install-posix.py --apply \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks \
  --launchagent-backup-dir "$HOME/.config/agent-memory/backups/launchagent-NEW" \
  --json
```

`--plan` always runs the migrator from the source checkout with an existing
Python 3.10+ (use `--python /absolute/python` to select one). It therefore reads
and reports a live v1 TOML/state database even when the installed v1 Runtime
does not contain `agent_memory_migrate.py`. The plan is read-only.

For an upgrade, copy the plan's `disposition_template` to a private reviewed
JSON file when requested, then pass new, non-existing `--config-backup` and
`--state-backup` paths plus `--disposition-file`. When the plan reports an
existing audit ledger, also pass a new, non-existing `--audit-backup`; both
SQLite backups are online snapshots and are never overwritten. To install lifecycle hooks,
replace `--no-host-hooks` with `--host codex` and/or `--host claude`, and pass a
new `--hook-backup-dir`. On macOS every apply also requires a separate, unused
`--launchagent-backup-dir`. Any failed stage leaves the runtime non-ready.

The entry point recognizes only two unambiguous modes: both private TOML and
state DB missing means a fresh install, while both present means an upgrade.
Any half-present combination fails closed. Apply validates every state blocker
and the exact reviewed disposition before installing Runtime files or touching
the Vault. Fresh install alone runs `bootstrap.py`; upgrade only validates the
existing roots plus `AGENTS.md`/`INDEX.md` and never installs template Markdown.
Its one governed Markdown mutation is the initial machine-generated `INDEX.md`
migration: after state/audit readiness, it requires every Vault Markdown file
to be clean and exactly bound to HEAD, then uses the closeout capability and an
isolated exact Git commit. Unrelated non-Markdown work is neither staged nor
committed.

The commands below show the same lower-level primitives for a **fresh install**
only. Upgrade operators should use `install-posix.py`; do not run `bootstrap.py`
against an existing Vault:

```bash
git clone https://github.com/mcncarl/agent-memory-vault.git
cd agent-memory-vault
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
test ! -e "$HOME/.config/agent-memory/config/agent-memory.toml" && \
  cp config/agent-memory.example.toml "$HOME/.config/agent-memory/config/agent-memory.toml"
# Edit memory_root, git_root, config_root, state_db, python, and identity fields.
python3 "$HOME/.config/agent-memory/scripts/bootstrap.py" \
  --memory-root "$HOME/agent-memory-vault" \
  --config-root "$HOME/.config/agent-memory" \
  --state-db "$HOME/.config/agent-memory/state.sqlite"
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate init --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate audit-init --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate generated-index-migrate --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate verify --json
python3 "$HOME/.config/agent-memory/scripts/install_host_hooks.py" \
  --host codex --host claude --auto-closeout \
  --backup-dir "$HOME/.config/agent-memory/backups/hooks-v2" --apply --json
"$HOME/.config/agent-memory/scripts/memoryctl" \
  --actor migration migrate verify --publish-ready --require-host-hooks --json
```

`bootstrap.py` creates an independent Git repository only for a fresh private
Vault and commits the template baseline. Never use it as an upgrade step. Use
`--no-init-git` only when you intentionally do not want Git. `migrate init` is
only for a missing state database. If a database already exists, stop all
writers, use the source-checkout plan, review its exact disposition when
required, and let the backed-up migration apply it. The migrator never
overwrites a backup or silently chooses a winner for an active legacy claim.

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
- All hosts call `memoryctl` with their own actor and session identity. Supported automatic writers are exactly `codex`, `claude`, and `ailu`; unknown actors are rejected.

```bash
scripts/memoryctl --actor codex search "project status" --limit 5

AGENT_MEMORY_SESSION_ID="host-session-id" \
scripts/memoryctl --actor codex write read-target --json <<'JSON'
{"schema_version":2,"target_relative_path":"项目/example.md","app_id":"example-app","project_id":"example-project"}
JSON
```

Use the returned full content and `read_token` to create one exact final proposal, then send it to `write prepare` and, after the required exact authorization, `write apply`. Apply carries the returned proposal hashes and monotonic `fencing_token`; successful apply runs scoped closeout itself. Claims are session-hashed projections of the active intent, not write permission. One canonical path has at most one live lease, and a late holder of an older fencing token cannot apply or close out.

## Retrieval

The unified search combines Unicode FTS, trigram FTS, and the optional Zvec sidecar with fixed Hybrid RRF, deduplicates candidates by stable `memory_id`, and applies orthogonal filters such as project, memory type, track, scope, and status. Search and Canonical Retrieve use the same production candidate path.

```bash
scripts/memoryctl --actor codex search "project closeout" --limit 5
scripts/memoryctl --actor codex search "preferences" --track user
scripts/memoryctl --actor codex search "deployment boundary" \
  --current-project example-app --semantic-mode auto
```

Search indexes are candidate generators, not authorization or truth sources. Host applications should use `retrieve`, which reopens the current Markdown, validates containment and symlinks, requires strict UTF-8, reapplies scope and status rules, checks for sensitive content, and returns bounded excerpts with current hashes.

By default, `active` and `pending_verification` documents are discoverable, but
`pending_verification` is always reference-only and returns
`can_authorize_action=false`. `outdated` and `archived` documents appear only
with `--include-inactive`. If current project context is absent, a project-bound
hit may still be discovered as `scope_status=project_context_unknown`,
`analogy_only=true`; only `--cross-project` exposes other-project analogies.
Neither case can authorize an action.

Large files can be navigated without loading the full document. `outline` returns the current H1-H6 tree and a source hash; `section` requires that hash, reads one bounded section, and supplies a continuation offset when needed:

```bash
scripts/memoryctl --actor codex retrieve --view outline \
  --file "项目/example.md" --project-id example-app --json
scripts/memoryctl --actor codex retrieve --view section \
  --file "项目/example.md" --project-id example-app \
  --section-id s0002 --expected-sha256 '<outline-sha256>' --json
```

Task observability is enabled for v4 installs and stores only one-way task/memory references, controlled labels, counters, and timestamps. Canonical retrieve automatically records the opened `memory_id` plus current content hash; it never stores query text, excerpts, answers, URLs, or raw session IDs. Every candidate must be declared `adopted`, `reference_only`, or `rejected`; tool observations, agent declarations, human labels, and independent-model labels remain separate in reports.

Hybrid v2, stale-adoption enforcement, and the explicit temporal/risk-metadata gate use a manifest/config-bound seven-day gate. Start it with `memoryctl --actor migration shadow start --benchmark-file <runtime>/benchmarks/private-quality.json`, run that same complete private dataset through the three-pass production quality benchmark with `memoryctl --actor migration retrieval-benchmark --benchmark-file <runtime>/benchmarks/private-quality.json --runs 3 --attest-success` (attestation rejects `--case-id`), and prove the stale-adoption lifecycle with `memoryctl --actor migration shadow canary`. Shadow start pins the private dataset digest and complete required-case-set digest before day one; later evidence from a substituted fixture is rejected. If corpus governance reveals a real shadow failure, never edit or resolve the old evidence in place: after remediation, use `memoryctl --actor migration shadow restart --benchmark-file <same-private-dataset> --supersede-epoch <current-epoch-attestation-sha256>`. Restart appends an immutable child epoch, preserves the full parent chain, and resets the benchmark, canary, real-task denominator, and seven-day clock. The dataset must contain at least five required cases with `required_at <= 5`, including the mandatory automatic-closeout query. `memoryctl --actor migration shadow status` requires seven full days, at least one real Search/Retrieve task after excluding benchmark/canary/synthetic traffic, zero required-case regressions or metadata would-blocks, zero raw-query/path leakage, zero missing task denominators, and no consecutive semantic failures or Worker crash loop. Missing, invalid, and downgraded risk declarations are observed with stable `METADATA_RISK_CLASS_*` reason codes. Only `memoryctl --actor migration shadow cutover --config-backup <new-private-path>` can atomically activate `ranking_version = "hybrid-v2"`, `stale_adoption_enforcement = "enforce"`, and `metadata_enforcement = "enforce"`; a CLI flag or config edit alone cannot bypass the gate. Evidence files contain hashes, controlled metrics, and timestamps only.

## Safe writes and closeout

Write Gateway v2 protects the entire formal Markdown vault. Automatic writers never edit first and add a claim later. The only normal sequence is `read-target` → `prepare` → exact authorization → `apply`. Prepare performs source safety and reconciliation, acquires the target lease, and returns a monotonic fencing token without changing Markdown. Apply verifies the session, actor, scope, Git base, target bytes, proposal hashes, live lease, and fencing token before a conditional file replacement. Closeout rechecks those facts and atomically records the Git-bound receipt, file observation, claim completion, and terminal intent. Runtime 2.1 adds session-scoped, side-effect-free `status`/`list` recovery queries and replays the original receipt for terminal apply/cancel requests.

Root governance files (`AGENTS.md`, `README.md`, and `STRUCTURE.md`) use the same gateway without frontmatter and are writable only by Codex or Claude under the `agent-memory` governance scope. `INDEX.md` is the exception: it is a generated, read-only projection of every governed Markdown document and may change only inside the same closeout/Git transaction as its source change. Direct Gateway or editor writes return `GENERATED_FILE_READ_ONLY`; Doctor requires both missing and broken entries to be zero. Ailu uses `app_id=ailu` and must provide one actual project ID or `global`; global writes are limited to `用户记忆/`, and Ailu cannot write root governance.

Every active project, workflow, or decision write declares `risk_class` as
exactly `ordinary` or `action_sensitive`. A declaration cannot lower the
canonical directory policy. Decisions,
atomic fact types, `expiring` content, explicit validity deadlines, and
`事实-*.md` records are action-sensitive. They require one fact per file, a
stable `fact_key`, ISO `valid_from`, a real `verified_at`, and a Write Gateway
`evidence_ref`; an expiring fact also needs an evidence-based `valid_until`.
A successor must explicitly list predecessor vault paths in `supersedes`.
Only same-scope, same-key, forward-dated, unambiguous edges take effect.
Default Search and Canonical Retrieve exclude superseded versions, while
`--as-of` resolves the historical head. Text such as “obsolete” or semantic
similarity never creates a supersession edge.

Status changes also use Write Gateway v2 with `operation=status_transition`.
Codex and Claude may move `active` to `pending_verification`, `outdated`, or
`archived`; reactivation requires new verification evidence. Ailu cannot
perform status transitions. To decode a stable failure without relying on an
old low-level recipe, run `memoryctl --actor codex explain <reason_code> --json`.

For an existing manual or Obsidian edit, either re-read and prepare a new proposal against the current bytes, or have Codex/Claude explicitly adopt the exact dirty bytes with `adopt_external: true` and a user-bound confirmation. Adoption still runs safety, reconciliation, lease/fence checks, CAS, Git, and closeout; it is not a direct-edit bypass. Ailu does not automatically adopt external edits. See [Write Gateway v2](./docs/write-gateway-v2.md).

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
python3 scripts/run_tests_isolated.py
AGENT_MEMORY_ROOT="$PWD/templates/vault" \
AGENT_MEMORY_STATE_DB="$PWD/.agent-memory/state.sqlite" \
scripts/memoryctl --actor migration index --init --scan --report
scripts/memoryctl --actor migration check --skip-state-db
scripts/memoryctl --actor human doctor
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

For a stable machine-wide entry point, use the POSIX product entry shown in
Quick start. It plans with source code before changing an old Runtime and keeps
an upgrade non-ready until the strong commit gate succeeds. The lower-level
commands below are for recovery and expert inspection, not a substitute for the
preflight ordering:

```bash
python3 scripts/install_runtime.py --config-root "$HOME/.config/agent-memory"
# New installs only: create the TOML with `cp -n`, then edit its roots/identity.
# Existing installs: never copy over the private TOML; migrate it with backup.
"$HOME/.config/agent-memory/scripts/memoryctl" --actor migration migrate config-plan --json
"$HOME/.config/agent-memory/scripts/memoryctl" --actor migration migrate config-apply \
  --backup-path "$HOME/.config/agent-memory/backups/agent-memory-before-v2.toml" --json
"$HOME/.config/agent-memory/scripts/install_runtime.py" \
  --config-root "$HOME/.config/agent-memory" --verify --json
```

Running the installer again upgrades runtime-owned files without overwriting your private configuration or host adapters. Never repeat the template `cp` on an existing install; use `config-plan` and `config-apply` with a new non-existing backup path.

An upgrade that does not preserve an already verified identical bundle remains in `state_migration_required`. Ordinary commands fail closed until you run `migrate plan`, `migrate apply` with a non-existing backup path (or `migrate init` for a truly missing database), a read-only `migrate verify`, all index/Doctor/Hook checks, and finally `migrate verify --publish-ready`. `apply` never publishes readiness by itself.

## Project status

Agent Memory Vault is actively maintained. Continuous validation is local-only: isolated Python tests cover the shared logic, cross-platform static checks cover platform boundaries, and native Windows behavior is revalidated on a local Windows 10/11 host when required. The public template is intentionally free of personal memory and generated state.

Created and primarily maintained by [Yichen (@mcncarl)](https://github.com/mcncarl).

## Contributing

Issues and pull requests are welcome. Please keep changes cross-platform, add tests for behavior changes, and never include real memory, absolute private paths, credentials, generated databases, or vector indexes.

## License

Released under the [MIT License](./LICENSE). Third-party notices are listed in [ACKNOWLEDGMENTS.md](./ACKNOWLEDGMENTS.md).
