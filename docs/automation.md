# Automation

Agent Memory Vault uses three separate automation layers:

1. Write Gateway `apply` and explicit `closeout` finish the current task's governed writes.
2. Optional Stop hooks retry only files whose current-session claim projects a live intent lease.
3. One weekly scheduler owns content audit plus read-only Doctor. On macOS the canonical LaunchAgent runs Sunday at 10:30; lifecycle hooks never shift that schedule.

Automation should only produce reminders, reports, logs, and local audit decisions. It should not directly rewrite Markdown facts.

Every Host automation command must enter through the authenticated managed
`memoryctl` route shown below. Hooks and schedulers must never execute
`agent_memory_*.py` directly. The installer, Doctor, and publish-ready gate use
one shared classifier and require exactly one canonical scheduler/Stop route,
zero legacy routes, and zero ambiguous wrappers.

## Closeout and weekly audit are independent

Use the managed entrypoint for a manual closeout:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor codex closeout
```

The weekly scheduler uses this canonical route:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor human audit-autorun \
  --reason launchd \
  --notify \
  --json
```

Closeout records `weekly_launchagent_owned` and does not call audit autorun. The weekly job runs content audit first and then Doctor, writes `latest-audit.json` and `latest-doctor.json`, and notifies immediately on failure. A scheduler failure makes Doctor and installation acceptance fail, but it does not disable ordinary Search or Retrieve.

If another tool auto-commits the vault before closeout runs, closeout compares the last successful `git_observed_through` value with current `HEAD` and processes those committed file changes as well. This lets Obsidian Git keep its backup schedule without stealing the memory pipeline's indexing baseline.

## Stop Hook Modes

Stop is turn-scoped in both Claude Code and Codex, so the hook must stay quiet and idempotent.

Reminder mode:

- Remind only when Markdown files under the memory vault changed and the SQLite index is older than those files.
- Stamp each session or day so the same reminder is not repeated constantly.
- Do not let the hook invent or rewrite memory facts.

Automatic closeout mode is a retry/exit safety net after a Write Gateway v2 apply has already created a live intent-backed claim:

- Claude `SessionStart` must use the canonical managed route `python -I -S memoryctl --actor claude session-hook`. The command dispatches the internal adapter after Runtime authentication, writes the hook payload's real `session_id` to `CLAUDE_ENV_FILE`, and keeps `write read-target/prepare/apply` and Stop on the same ownership key. It also clears an inherited `CODEX_THREAD_ID` inside Claude Bash commands.
- Formal Markdown is written only through `memoryctl --actor codex|claude write read-target|prepare|apply --json`. Do not edit first and add a low-level claim later.
- Gate on lease state, not claim age: current-session live lease may close out; another session's live lease stays untouched; expired, fenced, terminal, missing-intent, or legacy claims fail closed. Lease renewal updates the intent TTL without changing its fencing token.
- Treat a historical file as complete only when its current content hash matches `memory_file_observations`; a full SQLite scan alone is not closeout evidence.
- If dirty memory has no live intent-backed claim, block silent completion and ask the Agent to re-read and prepare a new proposal, or explicitly adopt an authorized external edit.
- Any unresolved `memory_closeout_incidents` row globally blocks Stop. It is resolved only by a later exact `ADOPT` of the same target whose current raw bytes, validated final bytes, and committed Git blob match; there is no naked manual-resolve command.
- Pass `--actor codex` or `--actor claude` so logs and commits remain attributable.
- Claude Stop may return `decision: block` when closeout fails. Codex Stop can request continuation by exiting with code `2` and writing a non-empty continuation prompt to stderr.
- Claude SessionEnd can be a short non-blocking fallback. Codex currently has no direct SessionEnd equivalent.
- Set the outer hook timeout slightly above the closeout timeout. For a 300-second closeout, use at least 320 seconds outside.
- Keep one global closeout lock and one Git baseline across both hosts.

Pseudo-flow:

```text
on Claude SessionStart:
  export the payload session_id through CLAUDE_ENV_FILE

on Stop:
  read hook input JSON
  resolve the host session id
  if any unresolved closeout incident exists:
    block globally for Doctor plus exact ADOPT recovery
  else if this session has a claim backed by a live current fence:
    run claimed-only closeout
  else if every pending file belongs to another live lease:
    stay silent
  else if pending memory has an invalid or missing lease:
    block and request read-target/prepare or explicit ADOPT

  never run or reschedule the weekly audit from Stop
```

Claude SessionStart example:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl --actor claude session-hook",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

This uses Claude Code's official `CLAUDE_ENV_FILE` mechanism. Merge it with existing `SessionStart` groups instead of replacing unrelated hooks.

Automatic closeout example:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor claude stop-hook \
  --protocol claude \
  --auto-closeout \
  --timeout 300
```

## Claude Settings Managers

For a managed POSIX runtime, preview and then atomically migrate the live Codex
and Claude JSON entries with the configured Python 3.10+ interpreter:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-host-hooks \
  --host codex --host claude --auto-closeout --json
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-host-hooks \
  --host codex --host claude --auto-closeout \
  --backup-dir "$AGENT_MEMORY_CONFIG_ROOT/backups/hooks-v2" --apply --json
```

The v2 ready policy requires blocking automatic Codex Stop closeout; it is the
installer default and is shown explicitly above. The apply form preserves
unrelated entries, removes duplicate managed entries, makes non-overwriting byte backups,
enables Codex `[features] hooks = true`, and publishes each host file by atomic
replace. It does not update a provider manager's separate database; if such a
manager owns Claude settings, migrate that source of truth before requiring the
Claude hook in the strong ready gate.

Host automation is healthy only when each required lifecycle event has exactly
one active canonical route, zero legacy routes, and zero ambiguous routes.
Putting the managed command inside a disabled entry or disabled hook group is a
failure, not an installed route. Doctor also scans configured and default host
files for references to the retained legacy wrapper. Claude binding uses a
stable semantic projection of the managed `SessionStart`, `Stop`, and
`SessionEnd` routes; unrelated settings, permissions, models, and third-party
hooks do not invalidate that proof.

For product installation on macOS/Linux, prefer `scripts/install-posix.py
--plan` followed by explicit `--apply`. It orchestrates these same hook, config,
state, and strong-publication primitives; it does not add a second migration
implementation. Upgrades require new non-overwriting backup paths and any
plan-generated reviewed claim disposition file. The read-only plan runs the
source checkout's migrator with an existing Python 3.10+, so it can inspect a
live v1 config/state even when the installed v1 Runtime has no migrator. Apply
verifies all blockers and the exact disposition before changing Runtime or
Vault files. A config/state half-install is rejected; fresh alone bootstraps a
Vault, while upgrade never adds template Markdown or initializes Git. After
state and audit readiness, upgrade may perform exactly one governed initial
generated-INDEX closeout transaction. That gate requires all Vault Markdown to
be clean and HEAD-bound, preserves unrelated non-Markdown work, and commits
only the generated `INDEX.md` before Host automation is changed.

On macOS the weekly LaunchAgent is mandatory and independent of lifecycle-hook
policy. Even an installation using `--no-host-hooks` must provide a new,
otherwise unused `--launchagent-backup-dir`; `--hook-backup-dir` remains a
separate input used only when Codex or Claude hooks are selected. Apply stages
the canonical plist before strong publication, then reloads and really
kickstarts it after publication. Installation succeeds only after run count
increases, exit code is 0, the successful audit report is fresh, and the final
strict Doctor passes.

The staged apply and post-publication finalize share the same durable journal
and original backup. Final route classification, singleton discovery, loaded
argument verification, and the real kickstart all remain inside that one
rollback boundary. A failure at any late step restores both the prior plist
bytes and the prior loaded/unloaded state. An interrupted final JSONL record is
sealed on recovery with a hash-bound `journal_tail_recovered` record; malformed
completed records still fail closed.

The whole POSIX apply is additionally serialized by one private total-install
lock and the fixed
`<config-root>/state/install-orchestration.jsonl` journal. Its fingerprint binds
all requested roots, unique backup paths, both Host choices, identities, and
the complete Runtime/template source bundle. A pending transaction resumes
only with that exact fingerprint; a concurrent apply is rejected, and source
drift or failed LaunchAgent compensation becomes `recovery_required` rather
than a warning. Completed mutating stages may be reused only from their durable
stage evidence, while Runtime install, generated INDEX, publish-ready, and the
terminal Doctor are always rerun or independently recovered and revalidated.

An upgrade plan reports the state and audit-ledger schemas separately. Supply
unused `--state-backup` and `--audit-backup` paths when those databases exist;
ordinary search, retrieve, observe, and audit commands never create or alter
schema and instead return a migration-required reason code.

```bash
python3 scripts/install-posix.py --plan \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks --json
python3 scripts/install-posix.py --apply \
  --memory-root "$HOME/agent-memory-vault" --no-host-hooks \
  --launchagent-backup-dir "$HOME/.config/agent-memory/backups/launchagent-NEW" \
  --json
```

Some provider switchers and configuration managers regenerate `~/.claude/settings.json` when they start or change providers. A hook added only to the live file can therefore disappear even though the original installation succeeded.

- Merge Agent Memory hooks into the manager's persistent or common Claude configuration, not only the generated live file.
- If the manager keeps a live rollback copy, update that copy too; otherwise the next recovery can restore a hook-free file.
- Keep unrelated hooks when merging.
- After restarting or switching providers, verify that the live settings still contain exactly one canonical `memoryctl --actor claude stop-hook` route and no legacy wrapper.
- Use Claude debug logs or the `/hooks` browser to confirm that `SessionStart`, `Stop`, and `SessionEnd` are actually loaded. A file existing on disk is not sufficient evidence.

For tools such as CC Switch, the practical source of truth may be the switcher's own database-backed common configuration. Treat the generated `~/.claude/settings.json` as an output of that manager.

Codex reads `~/.codex/hooks.json`. Enable hooks in `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

Reminder-only `Stop` entry (merge it with existing hooks instead of overwriting unrelated entries):

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl --actor codex stop-hook --protocol codex --event stop-hook",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

The managed entrypoint loads the private Runtime configuration after verifying
its manifest and Python identity. It inherits stdin for the event JSON. After
changing a hook command, review the updated hook in Codex if the client asks you
to trust the new hash.

For automatic Codex closeout, add the actor, protocol, and timeout explicitly, and give the outer hook enough time to receive the structured result:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl --actor codex stop-hook --protocol codex --event stop-hook --auto-closeout --timeout 300",
            "timeout": 320
          }
        ]
      }
    ]
  }
}
```

## macOS canonical weekly LaunchAgent

The macOS installation always uses one managed LaunchAgent so the audit runs
even if no Agent session happens. The canonical schedule is Sunday at 10:30
local time; there is no daily retry scheduler.

Preview and apply the managed plist with a new private backup directory. Apply
uses byte CAS, preserves the previous bytes, reloads the job, and requires one
real kickstart run with exit code 0:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-audit-launchagent \
  --plan --runtime-root /path/to/runtime --json
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-audit-launchagent \
  --apply --runtime-root /path/to/runtime \
  --backup-dir /new/private/backup-directory --json
```

The generated plist has this canonical shape:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.agent-memory-vault-audit</string>

  <key>ProgramArguments</key>
  <array>
    <string>/path/to/runtime/.venv/bin/python</string>
    <string>-I</string>
    <string>-S</string>
    <string>/path/to/runtime/scripts/memoryctl</string>
    <string>--actor</string>
    <string>human</string>
    <string>audit-autorun</string>
    <string>--reason</string>
    <string>launchd</string>
    <string>--notify</string>
    <string>--json</string>
  </array>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>0</integer>
    <key>Hour</key>
    <integer>10</integer>
    <key>Minute</key>
    <integer>30</integer>
  </dict>

  <key>StandardOutPath</key>
  <string>/path/to/agent-memory-vault-config/logs/audit-launchd.out.log</string>

  <key>StandardErrorPath</key>
  <string>/path/to/agent-memory-vault-config/logs/audit-launchd.err.log</string>

  <key>WorkingDirectory</key>
  <string>/path/to/user-home</string>
</dict>
</plist>
```

Verify the exact loaded command, run count, and last exit code:

```bash
launchctl print gui/$(id -u)/com.example.agent-memory-vault-audit
```

Rollback uses the durable transaction journal and restores only the exact prior
bytes. A plist created by a failed fresh install is moved into the private
backup directory instead of being deleted:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-audit-launchagent \
  --rollback --runtime-root /path/to/runtime \
  --journal /new/private/backup-directory/audit-launchagent-transaction.jsonl --json
```

For a staged product install, finalize must reuse the journal returned by the
deferred apply rather than starting another transaction:

```bash
/path/to/runtime/.venv/bin/python -I -S /path/to/runtime/scripts/memoryctl \
  --actor migration install-audit-launchagent \
  --finalize --runtime-root /path/to/runtime \
  --journal /new/private/backup-directory/audit-launchagent-transaction.jsonl --json
```

## Windows Task Scheduler Fallback

The Windows Runtime includes a PowerShell management wrapper. It registers a weekly task for the current interactive user with Limited privileges:

```powershell
$runtime = Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'
& (Join-Path $runtime 'scripts\audit-task.ps1') install -RuntimeRoot $runtime
& (Join-Path $runtime 'scripts\audit-task.ps1') status -RuntimeRoot $runtime
```

The task starts the installed Python with UTF-8 mode and routes the audit
through managed `memoryctl audit-autorun`. Repeating `install` updates the same
task. See [windows.md](windows.md) for the complete setup and removal boundary.

## Reading Results

The latest report is local:

```bash
cat "$AGENT_MEMORY_AUDIT_REPORT"
```

Typical findings mean:

- `stale_verified_at`: the memory may need review because its verification date is old.
- `missing_verified_at`: the memory lacks an explicit verification date.
- `open_loop_count`: one file has too many true unresolved items; `next_hint` is navigation and is not mixed into this count.
- `risk_count`: one file has several risks that may need validity review.
- `weak_verification_coverage`: many files only have mtime fallback instead of explicit review evidence.
- `large_memory_file`: current facts and historical change logs may need to be split.
- `duplicate_title`: two or more files may overlap.
- `outdated_status`: a file is intentionally old and should not be treated as current truth.
