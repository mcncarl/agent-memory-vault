# Automation

Agent Memory Vault can run without background automation. The recommended automated setup is layered:

1. `closeout` piggyback: every important task-end closeout checks whether audit is due.
2. Optional Stop hook: shared Claude/Codex setups run full closeout only for files claimed by the current session.
3. Optional macOS `launchd` fallback: runs the due content audit plus a read-only infrastructure Doctor weekly even if no Agent session happens.

Automation should only produce reminders, reports, logs, and local audit decisions. It should not directly rewrite Markdown facts.

## Closeout Piggyback

This is the primary path because it runs when an Agent is already present to read and explain the result.

```bash
python3 scripts/agent_memory_closeout.py --commit
```

By default, closeout calls:

```bash
python3 scripts/agent_memory_audit_autorun.py \
  --reason closeout \
  --min-interval-days 7 \
  --json
```

If the last successful audit is recent, autorun exits with `skipped_recent`. When the interval is due, it runs content audit first and then Doctor, writing `latest-audit.json` and `latest-doctor.json`. A Doctor warning does not rewrite Markdown or invalidate the successful content-audit timestamp, but it is included in the report and notification.

The `closeout` trigger runs Doctor before the scoped Git commit, so autorun passes `--allow-dirty-memory` only for that transient pre-commit check. Manual and `launchd` Doctor runs remain strict; the flag does not suppress index, model, dependency, remote-backup, hook, or other health checks.

If another tool auto-commits the vault before closeout runs, closeout compares the last successful `git_observed_through` value with current `HEAD` and processes those committed file changes as well. This lets Obsidian Git keep its backup schedule without stealing the memory pipeline's indexing baseline.

## Stop Hook Modes

Stop is turn-scoped in both Claude Code and Codex, so the hook must stay quiet and idempotent.

Reminder mode:

- Remind only when Markdown files under the memory vault changed and the SQLite index is older than those files.
- Call `agent_memory_audit_autorun.py`; its interval gate decides whether a real content audit plus read-only Doctor is due.
- Stamp each session or day so the same reminder is not repeated constantly.
- Do not let the hook invent or rewrite memory facts.

Automatic closeout mode is appropriate when the Agent has already written and claimed formal memory before stopping:

- Claude must run `agent_memory_session_hook.py` from `SessionStart`. It writes the hook payload's real `session_id` to `CLAUDE_ENV_FILE`, so later Bash calls to `memoryctl claim` and the Stop payload use the same ownership key. It also clears an inherited `CODEX_THREAD_ID` inside Claude Bash commands.
- After each formal write, run `memoryctl --actor codex|claude claim --file <path>`.
- Gate on active claims for the current session. Dirty files claimed by another session stay untouched.
- Treat claims older than 24 hours as abandoned for Stop-hook ownership checks. `doctor` reports them, and `memoryctl --actor human claims-expire` previews them before an explicit `--apply` changes only the SQLite ledger.
- Treat a historical file as complete only when its current content hash matches `memory_file_observations`; a full SQLite scan alone is not closeout evidence.
- If dirty memory is not claimed by any session, block silent completion and ask the Agent to claim or resolve it.
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
  if this session has active file claims:
    run claimed-only closeout
  else if every pending file belongs to another claim updated within 24 hours:
    stay silent
  else if unclaimed pending memory exists:
    block and request claim/review

  run audit_autorun with a 7-day interval gate
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
            "command": "python3 /path/to/agent-memory-vault/scripts/agent_memory_session_hook.py --actor claude",
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
python3 scripts/agent_memory_stop_hook.py \
  --actor claude \
  --protocol claude \
  --auto-closeout \
  --timeout 300
```

## Claude Settings Managers

Some provider switchers and configuration managers regenerate `~/.claude/settings.json` when they start or change providers. A hook added only to the live file can therefore disappear even though the original installation succeeded.

- Merge Agent Memory hooks into the manager's persistent or common Claude configuration, not only the generated live file.
- If the manager keeps a live rollback copy, update that copy too; otherwise the next recovery can restore a hook-free file.
- Keep unrelated hooks when merging.
- After restarting or switching providers, verify that the live settings still contain `agent_memory_stop_hook.py`.
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
            "command": "/bin/zsh -lc 'set -a; source /path/to/agent-memory-vault/.env; set +a; exec python3 /path/to/agent-memory-vault/scripts/agent_memory_stop_hook.py'",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

The command sources the private `.env` so the hook sees the real vault and state database. It inherits stdin, so `agent_memory_stop_hook.py` can read the event JSON. After changing a hook command, review the updated hook in Codex if the client asks you to trust the new hash.

For automatic Codex closeout, add the actor, protocol, and timeout explicitly, and give the outer hook enough time to receive the structured result:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/bin/zsh -lc 'set -a; source /path/to/agent-memory-vault/.env; set +a; exec python3 /path/to/agent-memory-vault/scripts/agent_memory_stop_hook.py --actor codex --protocol codex --auto-closeout --timeout 300'",
            "timeout": 320
          }
        ]
      }
    ]
  }
}
```

## macOS launchd Fallback

Use `launchd` when you want a weekly audit even if no Agent session happens.

Create `~/Library/LaunchAgents/com.example.agent-memory-vault-audit.plist`:

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
    <string>/usr/bin/python3</string>
    <string>/path/to/agent-memory-vault/scripts/agent_memory_audit_autorun.py</string>
    <string>--reason</string>
    <string>launchd</string>
    <string>--notify</string>
    <string>--json</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENT_MEMORY_ROOT</key>
    <string>/path/to/private-memory-vault</string>
    <key>AGENT_MEMORY_CONFIG_ROOT</key>
    <string>/path/to/agent-memory-vault-config</string>
    <key>AGENT_MEMORY_STATE_DB</key>
    <string>/path/to/agent-memory-vault-config/state.sqlite</string>
  </dict>

  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>1</integer>
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
  <string>/path/to/agent-memory-vault</string>
</dict>
</plist>
```

Load it:

```bash
launchctl load ~/Library/LaunchAgents/com.example.agent-memory-vault-audit.plist
launchctl list | grep agent-memory-vault-audit
```

Unload it:

```bash
launchctl unload ~/Library/LaunchAgents/com.example.agent-memory-vault-audit.plist
```

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
