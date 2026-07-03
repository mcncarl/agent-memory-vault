#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONFIG_ROOT = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_CONFIG_ROOT", "$HOME/.config/codex-memory"))
).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_STATE_DB", str(CONFIG_ROOT / "state.sqlite")))
).expanduser().resolve()
AUDIT_DB = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_AUDIT_DB", str(CONFIG_ROOT / "audit_decisions.sqlite")))
).expanduser().resolve()


@dataclass
class Finding:
    id: str
    kind: str
    severity: str
    rel_path: str
    title: str
    message: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": self.severity,
            "rel_path": self.rel_path,
            "title": self.title,
            "message": self.message,
            "detail": self.detail,
        }


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def today() -> dt.date:
    return dt.datetime.now().date()


def stable_id(kind: str, *parts: object) -> str:
    raw = "|".join([kind, *[str(part) for part in parts]])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def connect_state() -> sqlite3.Connection:
    conn = sqlite3.connect(STATE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def connect_audit() -> sqlite3.Connection:
    AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decisions (
          finding_id TEXT PRIMARY KEY,
          decision TEXT NOT NULL,
          note TEXT DEFAULT '',
          snooze_until TEXT DEFAULT '',
          decided_at TEXT NOT NULL
        )
        """
    )
    return conn


def parse_date(value: str) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


def severity_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(value, 0)


def add_stale_findings(conn: sqlite3.Connection, findings: list[Finding], days: int) -> None:
    cutoff = today() - dt.timedelta(days=days)
    rows = conn.execute(
        """
        SELECT rel_path, title, status, verified_at, memory_type, track
        FROM memory_docs
        WHERE status IN ('active', 'candidate')
        ORDER BY rel_path
        """
    ).fetchall()
    for row in rows:
        verified = parse_date(str(row["verified_at"] or ""))
        if verified is None:
            findings.append(
                Finding(
                    id=stable_id("missing_verified_at", row["rel_path"]),
                    kind="missing_verified_at",
                    severity="medium",
                    rel_path=row["rel_path"],
                    title=row["title"],
                    message="没有 verified_at，之后容易把旧事实当成新事实。",
                    detail={"status": row["status"], "memory_type": row["memory_type"], "track": row["track"]},
                )
            )
            continue
        if verified < cutoff:
            findings.append(
                Finding(
                    id=stable_id("stale_verified_at", row["rel_path"], verified.isoformat(), days),
                    kind="stale_verified_at",
                    severity="low",
                    rel_path=row["rel_path"],
                    title=row["title"],
                    message=f"verified_at={verified.isoformat()}，超过 {days} 天未复核。",
                    detail={"verified_at": verified.isoformat(), "days": days, "status": row["status"]},
                )
            )


def add_open_loop_findings(conn: sqlite3.Connection, findings: list[Finding], threshold: int) -> None:
    rows = conn.execute(
        """
        SELECT d.rel_path, d.title, COUNT(*) AS loop_count,
               GROUP_CONCAT(DISTINCT o.kind) AS kinds
        FROM memory_open_loops o
        JOIN memory_docs d ON d.path = o.path
        WHERE o.status='open'
        GROUP BY d.path, d.rel_path, d.title
        HAVING loop_count >= ?
        ORDER BY loop_count DESC, d.rel_path
        """,
        (threshold,),
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("open_loop_count", row["rel_path"], row["loop_count"]),
                kind="open_loop_count",
                severity="medium",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"open-loop/risk/next-hint 合计 {row['loop_count']} 条，建议人工分流或压缩。",
                detail={"count": row["loop_count"], "kinds": row["kinds"] or ""},
            )
        )


def add_duplicate_title_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    rows = conn.execute(
        """
        SELECT lower(title) AS normalized_title,
               COUNT(*) AS item_count,
               GROUP_CONCAT(rel_path, ' || ') AS paths,
               GROUP_CONCAT(title, ' || ') AS titles
        FROM memory_docs
        WHERE title IS NOT NULL AND trim(title) != ''
        GROUP BY normalized_title
        HAVING item_count > 1
        ORDER BY item_count DESC, normalized_title
        """
    ).fetchall()
    for row in rows:
        title = str(row["titles"]).split(" || ", 1)[0]
        findings.append(
            Finding(
                id=stable_id("duplicate_title", row["normalized_title"], row["paths"]),
                kind="duplicate_title",
                severity="low",
                rel_path="",
                title=title,
                message=f"标题重复 {row['item_count']} 次，可能只是 README/模板，也可能是重复事实。",
                detail={"paths": str(row["paths"]).split(" || ")},
            )
        )


def add_outdated_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, status, verified_at
        FROM memory_docs
        WHERE status IN ('outdated', 'deprecated', 'stale')
        ORDER BY rel_path
        """
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("outdated_status", row["rel_path"], row["status"]),
                kind="outdated_status",
                severity="low",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"status={row['status']}，检索时需要避免当成当前事实。",
                detail={"verified_at": row["verified_at"]},
            )
        )


def load_decisions(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    rows = conn.execute("SELECT * FROM audit_decisions").fetchall()
    return {row["finding_id"]: row for row in rows}


def decision_hides(row: sqlite3.Row) -> bool:
    decision = str(row["decision"])
    if decision in {"ignored", "resolved"}:
        return True
    if decision == "snoozed":
        snooze_until = parse_date(str(row["snooze_until"] or ""))
        return bool(snooze_until and snooze_until >= today())
    return False


def apply_decisions(findings: list[Finding], decisions: dict[str, sqlite3.Row], include_acknowledged: bool) -> list[Finding]:
    if include_acknowledged:
        return findings
    visible: list[Finding] = []
    for finding in findings:
        decision = decisions.get(finding.id)
        if decision is not None and decision_hides(decision):
            continue
        visible.append(finding)
    return visible


def collect_findings(args: argparse.Namespace) -> list[Finding]:
    if not STATE_DB.exists():
        raise SystemExit(f"missing state db: {STATE_DB}")
    findings: list[Finding] = []
    with connect_state() as conn:
        add_stale_findings(conn, findings, args.stale_days)
        add_open_loop_findings(conn, findings, args.open_loop_threshold)
        add_duplicate_title_findings(conn, findings)
        add_outdated_findings(conn, findings)
    findings.sort(key=lambda item: (severity_rank(item.severity), item.kind, item.rel_path), reverse=True)
    with connect_audit() as audit_conn:
        decisions = load_decisions(audit_conn)
    return apply_decisions(findings, decisions, args.include_acknowledged)[: args.limit]


def record_decision(args: argparse.Namespace) -> dict[str, Any] | None:
    actions = [
        ("ack", args.ack),
        ("ignored", args.ignore),
        ("resolved", args.resolve),
        ("snoozed", args.snooze),
    ]
    selected = [(decision, finding_id) for decision, finding_id in actions if finding_id]
    if not selected:
        return None
    decision, finding_id = selected[0]
    with connect_audit() as conn:
        conn.execute(
            """
            INSERT INTO audit_decisions(finding_id, decision, note, snooze_until, decided_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
              decision=excluded.decision,
              note=excluded.note,
              snooze_until=excluded.snooze_until,
              decided_at=excluded.decided_at
            """,
            (finding_id, decision, args.note, args.until or "", utc_now()),
        )
    return {"finding_id": finding_id, "decision": decision, "note": args.note, "snooze_until": args.until or ""}


def list_decisions() -> list[dict[str, Any]]:
    with connect_audit() as conn:
        rows = conn.execute(
            "SELECT finding_id, decision, note, snooze_until, decided_at FROM audit_decisions ORDER BY decided_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def print_human(payload: dict[str, Any]) -> None:
    if payload.get("recorded"):
        item = payload["recorded"]
        print(f"recorded={item['finding_id']} decision={item['decision']}")
    if payload.get("decisions") is not None:
        print(f"decisions={len(payload['decisions'])}")
        for item in payload["decisions"]:
            print(f"{item['finding_id']} {item['decision']} until={item.get('snooze_until', '')} note={item.get('note', '')}")
        return
    findings = payload.get("findings", [])
    print(f"audit_findings={len(findings)}")
    print(f"audit_db={AUDIT_DB}")
    for finding in findings:
        print(f"{finding['id']} [{finding['severity']}] {finding['kind']}")
        target = finding.get("rel_path") or finding.get("title")
        print(f"  target: {target}")
        print(f"  message: {finding['message']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Codex memory for stale facts, noisy loops, and duplicates.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum visible findings.")
    parser.add_argument("--stale-days", type=int, default=120, help="Flag active memories older than this many days.")
    parser.add_argument("--open-loop-threshold", type=int, default=4, help="Flag docs with at least this many open-loop indexed items.")
    parser.add_argument("--include-acknowledged", action="store_true", help="Show findings already ignored/resolved/snoozed.")
    parser.add_argument("--list-decisions", action="store_true", help="List audit decisions.")
    parser.add_argument("--ack", default="", help="Mark a finding as acknowledged.")
    parser.add_argument("--ignore", default="", help="Hide a finding as intentionally ignored.")
    parser.add_argument("--resolve", default="", help="Hide a finding as resolved.")
    parser.add_argument("--snooze", default="", help="Hide a finding until --until.")
    parser.add_argument("--until", default="", help="YYYY-MM-DD date for --snooze.")
    parser.add_argument("--note", default="", help="Optional decision note.")
    args = parser.parse_args()
    args.limit = max(args.limit, 1)
    if args.snooze and not parse_date(args.until):
        parser.error("--snooze requires --until YYYY-MM-DD")
    decision_count = sum(bool(value) for value in (args.ack, args.ignore, args.resolve, args.snooze))
    if decision_count > 1:
        parser.error("choose only one decision action")
    return args


def main() -> int:
    args = parse_args()
    recorded = record_decision(args)
    payload: dict[str, Any] = {
        "time": utc_now(),
        "audit_db": str(AUDIT_DB),
        "recorded": recorded,
    }
    if args.list_decisions:
        payload["decisions"] = list_decisions()
    else:
        payload["findings"] = [finding.to_dict() for finding in collect_findings(args)]
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
