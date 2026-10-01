# Write Gateway v2

## Product claim

Agent Memory Vault is a durable memory layer for long-running and multi-agent work. Its source of truth remains readable Markdown, but supported automatic writers do not edit that Markdown directly. They use one write gateway that binds a proposal to the exact file version it read, serializes ownership by canonical target, and refuses stale or bypassed writes.

The v2 guarantee is deliberately narrow and testable:

- For one canonical Markdown path, only one live write lease exists at a time.
- A lease transfer always receives a strictly larger fencing token.
- A writer can publish only when the target bytes, Git base, session, actor, scope, lease, and proposal hash still match.
- A late or expired writer cannot apply, close out, or finalize a receipt.
- External edits are preserved and reported as a conflict; they are never silently overwritten.
- A successful closeout binds the durable Git commit, immutable receipt, file observation, and claim completion.

This is not an operating-system security boundary. Processes running as the same unrestricted local user can still bypass a CLI and edit a file directly. The gateway detects that divergence and fails closed at apply or closeout. Preventing deliberate bypass requires a broker running under a separate account, a sandbox that makes the Vault read-only to agents, or a mediated filesystem.

## Why claims are not locks

Session claims answer “which task owns the closeout for this file?” They do not grant permission to write. Earlier schemas keyed claims by session and path, which allowed two sessions to claim the same file. v2 treats claims as an audit projection of the current write intent and makes the canonical target exclusive while active.

The authoritative write lease is an active `memory_write_intents` row. The existing active-target unique index prevents two live intents for the same canonical target. `memory_path_fences` supplies a monotonic token that survives expiry and ownership transfer:

```text
read exact target bytes
        |
        v
prepare intent + acquire target lease + allocate fence N
        |
        v
explicit approval where required
        |
        v
apply: assert lease N + compare target/base hashes + atomic conditional write
        |
        v
closeout: assert lease N before validation, Git commit, and finalization
        |
        v
one DB transaction: receipt + observation + claim completion + lease terminal state
```

Every operation carries the target key and fencing token. An old process holding token `N` is rejected after token `N+1` has been issued, even if the old process wakes after a long pause.

## Canonical target identity

Conflict identity is the canonical target, not the actor name and not the spelling supplied by the client. Canonicalization must:

- resolve the path beneath the configured Vault root;
- reject symlinks and containment escapes;
- normalize Unicode consistently;
- account for platform case behavior;
- support a missing final file for safe `ADD` operations;
- produce one stable `target_key` used by intents, claims, fences, receipts, and observations.

Every supported writer competes for the same lease when addressing the same Markdown file. Renaming a client does not authorize an alias or a second conflict domain.

## Client registry

The core writer is actor-neutral. Product-specific policy belongs in a client registry. A client entry declares:

- canonical actor and app identity;
- allowed operations;
- session source;
- allowed project and scope behavior;
- whether an independent confirmation is required;
- minimum writer protocol version.

The supported v2 automatic writers are exactly `codex`, `claude`, and `ailu`; unknown actor input is rejected. Historical terminal receipts keep the actor value that created them, while any active unsupported actor blocks migration generically. Rewriting signed or approval-bound history would invalidate the evidence.

## Temporal, risk, and status gates

Every active non-structural document declares a supported `temporal_policy` and
an explicit review interval. Active project, workflow, and decision documents
also declare exactly one `risk_class`: `ordinary` or `action_sensitive`.
No third state is accepted. Canonical path policy is a floor, so
frontmatter cannot relabel a project, workflow, decision, atomic fact,
`expiring` record, validity-bounded record, or `事实-*.md` file into a less
sensitive class.

An action-sensitive record uses one fact per file and supplies `fact_key`,
`valid_from`, a real `verified_at`, and request-bound `evidence_ref`;
`valid_until` is required only when the evidence proves an actual expiry. The
read path exposes missing, invalid, and downgraded declarations as stable
`METADATA_RISK_CLASS_*` codes. During the seven-day metadata shadow they are
observations; after an attested cutover, they block authorization. An
affirmative canonical-path downgrade is already reference-only in both modes.

Codex and Claude may request the controlled
`operation=status_transition` path from `active` to
`pending_verification`, `outdated`, or `archived`. Reactivation requires a new
verification date and evidence. Ailu cannot transition status. The transition
may change only the permitted temporal/status frontmatter; it cannot smuggle a
body rewrite. `pending_verification` remains discoverable but never authorizes
an action, while `outdated` and `archived` require `--include-inactive`.

Stable failures are decoded with `memoryctl explain <reason_code>` so clients
do not preserve obsolete low-level claim recipes.

## External edits and human adoption

Filesystem watchers are advisory only. Correctness comes from reopening the target and comparing raw bytes, canonical bytes, and the Git base immediately before publication.

If the current file does not match the gateway baseline, the target enters an external-dirty state. Automatic writers stop. The operator then chooses one of two explicit actions:

1. Adopt the current external bytes as the new baseline, run safety and reconciliation, and commit them as a human/manual transaction.
2. Re-read the current file and prepare a new proposal against that version.

The gateway never performs an automatic three-way merge of long-term memory. A merge can alter provenance or turn two qualified statements into one false fact, so it remains an explicit review step.

Sensitive adoption, governance migration, and status transitions require a short-lived capability bound to the exact pending intent, actor, task/session hashes, target, proposal hashes, operation, action, and fencing token. Consumption first creates a private create-once receipt and then marks the journal consumed, so restoring an older `issued` journal cannot accidentally reuse the approval. This is an accidental-misuse and crash-recovery boundary, not cryptographic proof of human presence: until a host UI or operating-system user-presence bridge becomes the issuer, the explicit manual issuer remains inside the current user's local trust domain and must be invoked only against an authorization already present in the user-visible task.

## Single-file and multi-file semantics

v2 guarantees one intent per Markdown file. SQLite lease acquisition, a file replacement, and a Git reference update can each be atomic in their own domain, but ordinary filesystems do not provide a portable atomic replacement of several unrelated files.

A future batch protocol may add a durable transaction journal, acquire all target leases in sorted order, stage all proposals, preserve displaced originals, and recover to a declared state after a crash. Until that protocol exists, the product must not claim that an arbitrary multi-file edit is physically atomic to external editors.

## Ailu client contract

Ailu is a client of Agent Memory Vault, not a renamed memory product. Its canonical v2 identity is:

```text
display name: Ailu
actor/app id: ailu
plugin/package id: ailu
Vault namespace: .ailu
home namespace: ~/.ailu
environment: AILU_HOME
memory project: the actual project, or global
```

All Ailu requests must use these canonical values. The Runtime does not accept aliases or
perform application-identity rewrites. Historical Agent Memory receipts remain immutable,
while all new Ailu Markdown uses `app_id: ailu`.

Runtime release `2.1.0` exposes `write status` and `write list` as session-scoped recovery
queries. They use the same Ailu session identity as prepare/apply, do not create or update
SQLite files, claims, telemetry, or Markdown, and return only intents owned by that actor and
session. A terminal apply or cancel replay returns the original verified receipt; it never
manufactures a replacement outcome. On Windows the write gateway is read-only:
`read-target`, `status`, and `list` remain available, while `prepare`, `apply`, and `cancel`
return `WINDOWS_READ_ONLY` before request or state access.

## Migration gates

### Already committed, expired validated writes

`migrate committed-recovery-plan --json` is a read-only diagnostic for a narrow
crash boundary: Codex/Claude approved and validated exact bytes, Git contains
only that content version, but closeout did not publish the terminal receipt.
Live leases, changed files/history, missing approval, newer fences, and Ailu
writes are not eligible. Generated INDEX completion observations are recovered
separately from the original consumed generation transaction and Git proof.

Save the exact plan in a private reviewed JSON document. Add an `approval`
object containing `approved: true`, reason code
`REPAIR_COMMITTED_CLOSEOUT_LEDGER`, and an `authorization_ref_sha256` referencing
the actual maintenance authorization. Pass it to the POSIX installer using
`--committed-recovery-file`. The installer verifies it before changing Runtime,
then verifies it again inside the online-backed-up state migration. Any Git,
content, approval or claim drift fails closed. Recovery preserves original
approvals and evidence, updates receipt/claim/observation atomically, never
renews a lease, and never invents a live verification. Replaying an applied plan
is idempotent. This is not a way for a new session to impersonate an old writer.

### Legacy state

`migrate plan` reports `ACTIVE_LEGACY_CLAIM`, `UNSUPPORTED_ACTIVE_ACTOR`, and
`TERMINAL_INTENT_ACTIVE_CLAIM` without changing them. Save its exact
`disposition_template` as a private JSON document, review every exact
`session_hash`/`path`/`intent_id`/status/`updated_at` tuple, then pass that
document to the normal backed-up state migration:

```bash
memoryctl --actor migration migrate plan --json
memoryctl --actor migration migrate apply \
  --backup-path /new/private/state-before-v2.sqlite \
  --disposition-file /private/reviewed-dispositions.json --json
```

The online backup, exact disposition compare-and-swap, receipt/Git validation,
and schema upgrade all run under the same locks and `BEGIN IMMEDIATE`. Any
mismatch rolls back everything. Ordinary `claim`/`claims-expire` commands stay
closed on v1 state and can never be used to sneak an upgrade through
`ensure_schema`.

On POSIX systems, `scripts/install-posix.py --plan` performs this inspection
with the source checkout's migrator, not an assumed installed migrator. Its
`--apply` revalidates the reviewed document before installing Runtime files or
touching the Vault. Upgrade never invokes `bootstrap.py`; that command is
fresh-install-only. A TOML-without-state or state-without-TOML combination is
an ambiguous partial install and remains fail-closed.

Production cutover is allowed only after all of these are true:

1. All host writers and Obsidian instances are stopped.
2. State DB, Runtime config, hooks, Vault Git head, Ailu settings, namespaces, and dirty source changes have verified backups.
3. Ambiguous active claims or intents have been resolved; a migrator never chooses a winner silently.
4. Runtime v2 installs and verifies before Ailu v2 is enabled.
5. Derived SQLite/FTS and vector indexes are rebuilt from migrated Markdown.
6. Codex, Claude, and Ailu concurrency tests show one winner for the same target and no lost bytes.
7. Each Vault passes an independent Ailu data-integrity check before the next Vault is enabled.

Rollback is version-aware. Before the first v2 write, the complete snapshot can restore the old runtime and plugin. After a v2 write, an old writable runtime must not be re-enabled directly; recovery must stay read-only or use a forward/explicit reverse migrator so new data is not lost.
