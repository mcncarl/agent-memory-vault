# Automation

Codex Memory can run without background automation. The recommended automated setup is layered:

1. `closeout` piggyback: every important task-end closeout checks whether audit is due.
2. Optional Stop hook: only reminds when memory files changed and the index is stale; it also lets the seven-day gate run audit when due.
3. Optional macOS `launchd` fallback: runs audit weekly even if no Agent session happens.

Automation should only produce reminders, reports, logs, and local audit decisions. It should not directly rewrite Markdown facts.

## Closeout Piggyback

This is the primary path because it runs when an Agent is already present to read and explain the result.

```bash
python3 scripts/codex_memory_closeout.py --commit
```

By default, closeout calls:

```bash
python3 scripts/codex_memory_audit_autorun.py \
  --reason closeout \
  --min-interval-days 7 \
  --json
```

If the last successful audit is recent, autorun exits with `skipped_recent`.

## Stop Hook Reminder

Codex Stop is turn-scoped, so the hook must stay quiet and idempotent:

- Remind only when Markdown files under the memory vault changed and the SQLite index is older than those files.
- Call `codex_memory_audit_autorun.py`; its interval gate decides whether a real audit is due.
- Stamp each session or day so the same reminder is not repeated constantly.
- Do not write memories, run commits, or edit Markdown from the hook.

Pseudo-flow:

```text
on Stop:
  read hook input JSON
  if memory vault has dirty Markdown files:
    if state.sqlite is older than the changed files:
      if this session was not reminded:
        notify: run codex_memory_closeout.py --dry-run

  run audit_autorun with a 7-day interval gate
```

Codex reads `~/.codex/hooks.json`. Enable hooks in `~/.codex/config.toml`:

```toml
[features]
hooks = true
```

Example `Stop` entry (merge it with existing hooks instead of overwriting unrelated entries):

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/bin/zsh -lc 'set -a; source /path/to/codex-memory/.env; set +a; exec python3 /path/to/codex-memory/scripts/codex_memory_stop_hook.py'",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

The command sources the private `.env` so the hook sees the real vault and state database. It inherits stdin, so `codex_memory_stop_hook.py` can read the event JSON. After changing a hook command, review the updated hook in Codex if the client asks you to trust the new hash.

## macOS launchd Fallback

Use `launchd` when you want a weekly audit even if no Agent session happens.

Create `~/Library/LaunchAgents/com.example.codex-memory-audit.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.codex-memory-audit</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/path/to/codex-memory/scripts/codex_memory_audit_autorun.py</string>
    <string>--reason</string>
    <string>launchd</string>
    <string>--notify</string>
    <string>--json</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>CODEX_MEMORY_ROOT</key>
    <string>/path/to/private-memory-vault</string>
    <key>CODEX_MEMORY_CONFIG_ROOT</key>
    <string>/path/to/codex-memory-config</string>
    <key>CODEX_MEMORY_STATE_DB</key>
    <string>/path/to/codex-memory-config/state.sqlite</string>
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
  <string>/path/to/codex-memory-config/logs/audit-launchd.out.log</string>

  <key>StandardErrorPath</key>
  <string>/path/to/codex-memory-config/logs/audit-launchd.err.log</string>

  <key>WorkingDirectory</key>
  <string>/path/to/codex-memory</string>
</dict>
</plist>
```

Load it:

```bash
launchctl load ~/Library/LaunchAgents/com.example.codex-memory-audit.plist
launchctl list | grep codex-memory-audit
```

Unload it:

```bash
launchctl unload ~/Library/LaunchAgents/com.example.codex-memory-audit.plist
```

## Reading Results

The latest report is local:

```bash
cat "$CODEX_MEMORY_AUDIT_REPORT"
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
