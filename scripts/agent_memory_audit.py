#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import env_value, expand_path


CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
AUDIT_DB = expand_path(env_value("AUDIT_DB", str(CONFIG_ROOT / "audit_decisions.sqlite"))).resolve()
INVARIANTS_PATH = expand_path(env_value("INVARIANTS", str(CONFIG_ROOT / "config" / "system-invariants.json"))).resolve()
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(REPO_ROOT / "templates" / "vault"))).resolve()


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
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def connect_audit() -> sqlite3.Connection:
    AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
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


def load_invariants() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "schema_version": 1,
        "system_name": "Agent Memory Vault",
        "memory_root": str(VAULT_ROOT),
        "runtime_root": str(CONFIG_ROOT),
        "canonical_script_prefix": "agent_memory_",
        "shared_tracks": ["user", "project", "workflow", "decision", "routing"],
        "scope_exceptions": [],
        "forbidden_current_summary_patterns": [
            {
                "id": "legacy_codex_script_prefix",
                "pattern": r"codex_memory_",
                "severity": "high",
                "message": "Current summary still references the retired codex_memory_ script prefix.",
            },
            {
                "id": "legacy_codex_runtime_path",
                "pattern": r"\.config/codex-memory",
                "severity": "high",
                "message": "Current summary still references the retired codex-memory runtime path.",
            },
        ],
    }
    try:
        payload = json.loads(INVARIANTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return defaults
    if not isinstance(payload, dict):
        return defaults
    return {**defaults, **payload}


def add_current_fact_invariant_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    invariants = load_invariants()
    configured_roots = {
        "memory_root": str(VAULT_ROOT),
        "runtime_root": str(CONFIG_ROOT),
    }
    for key, actual in configured_roots.items():
        expected = os.path.expandvars(str(invariants.get(key, "")))
        expected = str(Path(expected).expanduser().resolve()) if expected else ""
        if expected and expected != actual:
            findings.append(
                Finding(
                    id=stable_id("invariant_config_conflict", key),
                    kind="invariant_config_conflict",
                    severity="high",
                    rel_path="",
                    title="System invariant configuration",
                    message=f"Configured {key} does not match the active runtime.",
                    detail={"key": key, "expected": expected, "actual": actual, "invariants_file": str(INVARIANTS_PATH)},
                )
            )

    rows = conn.execute(
        """
        SELECT rel_path, title, summary, track, agent_scope, status
        FROM memory_docs
        WHERE status IN ('active', 'candidate')
        ORDER BY rel_path
        """
    ).fetchall()
    shared_tracks = {str(item) for item in invariants.get("shared_tracks", [])}
    scope_exceptions = {str(item) for item in invariants.get("scope_exceptions", [])}
    for row in rows:
        rel_path = str(row["rel_path"])
        track = str(row["track"] or "")
        scope = str(row["agent_scope"] or "shared")
        if track in shared_tracks and scope != "shared" and rel_path not in scope_exceptions:
            findings.append(
                Finding(
                    id=stable_id("agent_scope_invariant", rel_path),
                    kind="agent_scope_invariant",
                    severity="high",
                    rel_path=rel_path,
                    title=str(row["title"]),
                    message=f"Track {track} should be shared but agent_scope={scope}.",
                    detail={"track": track, "agent_scope": scope, "allowed_exceptions": sorted(scope_exceptions)},
                )
            )

    patterns = invariants.get("forbidden_current_summary_patterns", [])
    for rule in patterns if isinstance(patterns, list) else []:
        if not isinstance(rule, dict) or not rule.get("id") or not rule.get("pattern"):
            continue
        try:
            compiled = re.compile(str(rule["pattern"]), re.IGNORECASE)
        except re.error:
            continue
        for row in rows:
            summary = str(row["summary"] or "")
            if compiled.search(summary):
                rule_id = str(rule["id"])
                findings.append(
                    Finding(
                        id=stable_id("current_summary_invariant", rule_id, row["rel_path"]),
                        kind="current_summary_invariant",
                        severity=str(rule.get("severity", "medium")),
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=str(rule.get("message") or f"Current summary violates invariant {rule_id}."),
                        detail={"rule_id": rule_id, "pattern": str(rule["pattern"]), "invariants_file": str(INVARIANTS_PATH)},
                    )
                )

    markdown_docs = int(conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0])
    fts_docs = int(conn.execute("SELECT COUNT(DISTINCT path) FROM memory_fts").fetchone()[0])
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    eligible_vector_docs = 0
    indexed_vector_docs = 0
    vector_chunks = 0
    if {"memory_vector_index_state", "memory_vector_chunks"}.issubset(tables):
        eligible_vector_docs = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM memory_docs
                WHERE memory_type NOT IN ('routing','directory_index','template','agent_case_candidate','skill_candidate')
                  AND status NOT IN ('archived','deleted','obsolete','outdated','deprecated','stale')
                  AND sensitivity NOT IN ('secret','credential')
                  AND rel_path NOT LIKE '%/README.md'
                  AND rel_path NOT GLOB '*/_模板*'
                """
            ).fetchone()[0]
        )
        indexed_vector_docs = int(
            conn.execute("SELECT COUNT(*) FROM memory_vector_index_state WHERE status='indexed'").fetchone()[0]
        )
        vector_chunks = int(conn.execute("SELECT COUNT(*) FROM memory_vector_chunks").fetchone()[0])

    for row in rows:
        summary = str(row["summary"] or "")
        sqlite_match = re.search(r"Markdown/SQLite/FTS[^0-9]{0,20}(\d+)/(\d+)/(\d+)", summary, re.IGNORECASE)
        if sqlite_match:
            stated = tuple(int(value) for value in sqlite_match.groups())
            actual = (markdown_docs, markdown_docs, fts_docs)
            if stated != actual:
                findings.append(
                    Finding(
                        id=stable_id("current_metric_conflict", "markdown_sqlite_fts", row["rel_path"]),
                        kind="current_metric_conflict",
                        severity="medium",
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=f"Current summary says Markdown/SQLite/FTS={stated}, runtime reports {actual}.",
                        detail={"metric": "markdown_sqlite_fts", "stated": stated, "actual": actual},
                    )
                )
        zvec_match = re.search(
            r"Zvec[^0-9]{0,20}(\d+)/(\d+)(?:[^0-9]{0,12}(\d+)\s*(?:个)?(?:当前事实块|事实块|chunks?))?",
            summary,
            re.IGNORECASE,
        )
        if zvec_match and indexed_vector_docs:
            stated_docs = (int(zvec_match.group(1)), int(zvec_match.group(2)))
            stated_chunks = int(zvec_match.group(3)) if zvec_match.group(3) else None
            docs_actual = (indexed_vector_docs, eligible_vector_docs)
            if stated_docs != docs_actual or (stated_chunks is not None and stated_chunks != vector_chunks):
                findings.append(
                    Finding(
                        id=stable_id("current_metric_conflict", "zvec", row["rel_path"]),
                        kind="current_metric_conflict",
                        severity="medium",
                        rel_path=str(row["rel_path"]),
                        title=str(row["title"]),
                        message=f"Current summary says Zvec={stated_docs}, runtime reports {docs_actual} with {vector_chunks} chunks.",
                        detail={
                            "metric": "zvec",
                            "stated_docs": stated_docs,
                            "stated_chunks": stated_chunks,
                            "actual_docs": docs_actual,
                            "actual_chunks": vector_chunks,
                        },
                    )
                )


def add_stale_findings(conn: sqlite3.Connection, findings: list[Finding], fallback_days: int) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, status, verified_at, verified_at_source,
               review_after_days, memory_type, track
        FROM memory_docs
        WHERE status IN ('active', 'candidate')
          AND memory_type NOT IN ('routing', 'directory_index', 'template')
        ORDER BY rel_path
        """
    ).fetchall()
    weak_rows = [
        row
        for row in rows
        if str(row["verified_at_source"] or "") in {"mtime_fallback", "needs_review"}
    ]
    if weak_rows:
        findings.append(
            Finding(
                id=stable_id("weak_verification_coverage"),
                kind="weak_verification_coverage",
                severity="medium",
                rel_path="",
                title="Verification provenance",
                message=f"{len(weak_rows)} memories still need an explicit provenance decision or fact review.",
                detail={"count": len(weak_rows), "total": len(rows), "sample_paths": [str(row["rel_path"]) for row in weak_rows[:10]]},
            )
        )
    for row in rows:
        source = str(row["verified_at_source"] or "mtime_fallback")
        if source in {"mtime_fallback", "needs_review", "structural", "snapshot"}:
            continue
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
        review_days = int(row["review_after_days"] or fallback_days)
        cutoff = today() - dt.timedelta(days=review_days)
        if verified < cutoff:
            findings.append(
                Finding(
                    id=stable_id("stale_verified_at", row["rel_path"]),
                    kind="stale_verified_at",
                    severity="low",
                    rel_path=row["rel_path"],
                    title=row["title"],
                    message=f"Explicit review date {verified.isoformat()} exceeds the {review_days}-day policy.",
                    detail={"verified_at": verified.isoformat(), "verified_at_source": source, "review_after_days": review_days, "status": row["status"]},
                )
            )


def add_open_loop_findings(conn: sqlite3.Connection, findings: list[Finding], threshold: int, risk_threshold: int) -> None:
    rows = conn.execute(
        """
        SELECT d.rel_path, d.title, COUNT(*) AS loop_count
        FROM memory_open_loops o
        JOIN memory_docs d ON d.path = o.path
        WHERE o.status='open' AND o.kind='open_loop'
        GROUP BY d.path, d.rel_path, d.title
        HAVING loop_count >= ?
        ORDER BY loop_count DESC, d.rel_path
        """,
        (threshold,),
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("open_loop_count", row["rel_path"]),
                kind="open_loop_count",
                severity="medium",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"{row['loop_count']} true open-loop items need review.",
                detail={"count": row["loop_count"], "kind": "open_loop"},
            )
        )
    risk_rows = conn.execute(
        """
        SELECT d.rel_path, d.title, COUNT(*) AS risk_count
        FROM memory_open_loops o
        JOIN memory_docs d ON d.path = o.path
        WHERE o.status='open' AND o.kind='risk'
        GROUP BY d.path, d.rel_path, d.title
        HAVING risk_count >= ?
        ORDER BY risk_count DESC, d.rel_path
        """,
        (risk_threshold,),
    ).fetchall()
    for row in risk_rows:
        findings.append(
            Finding(
                id=stable_id("risk_count", row["rel_path"]),
                kind="risk_count",
                severity="medium",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"{row['risk_count']} risk items need validity review.",
                detail={"count": row["risk_count"], "kind": "risk"},
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
          AND memory_type NOT IN ('directory_index', 'template')
          AND rel_path NOT LIKE '%/README.md'
        GROUP BY normalized_title
        HAVING item_count > 1
        ORDER BY item_count DESC, normalized_title
        """
    ).fetchall()
    for row in rows:
        title = str(row["titles"]).split(" || ", 1)[0]
        findings.append(
            Finding(
                id=stable_id("duplicate_title", row["normalized_title"]),
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


def add_large_file_findings(conn: sqlite3.Connection, findings: list[Finding], line_limit: int, byte_limit: int) -> None:
    rows = conn.execute(
        """
        SELECT rel_path, title, line_count, size_bytes
        FROM memory_docs
        WHERE memory_type NOT IN ('template', 'directory_index')
          AND status IN ('active', 'candidate')
          AND (line_count > ? OR size_bytes > ?)
        ORDER BY size_bytes DESC, line_count DESC
        """,
        (line_limit, byte_limit),
    ).fetchall()
    for row in rows:
        findings.append(
            Finding(
                id=stable_id("large_memory_file", row["rel_path"]),
                kind="large_memory_file",
                severity="low",
                rel_path=row["rel_path"],
                title=row["title"],
                message=f"File has {row['line_count']} lines / {row['size_bytes']} bytes; review current facts versus history.",
                detail={"line_count": row["line_count"], "size_bytes": row["size_bytes"]},
            )
        )


def add_index_parity_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    doc_count = int(conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0])
    fts_count = int(conn.execute("SELECT COUNT(DISTINCT path) FROM memory_fts").fetchone()[0])
    if doc_count != fts_count:
        findings.append(
            Finding(
                id=stable_id("sqlite_fts_parity"), kind="sqlite_fts_parity", severity="high",
                rel_path="", title="SQLite/FTS parity",
                message=f"SQLite has {doc_count} docs but FTS has {fts_count}.",
                detail={"memory_docs": doc_count, "fts_docs": fts_count},
            )
        )
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "memory_vector_index_state" not in tables:
        return
    eligible_count = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM memory_docs
            WHERE memory_type NOT IN ('routing','directory_index','template','agent_case_candidate','skill_candidate')
              AND status NOT IN ('archived','deleted','obsolete','outdated','deprecated','stale')
              AND sensitivity NOT IN ('secret','credential')
              AND rel_path NOT LIKE '%/README.md'
              AND rel_path NOT GLOB '*/_模板*'
            """
        ).fetchone()[0]
    )
    vector_count = int(conn.execute("SELECT COUNT(*) FROM memory_vector_index_state WHERE status='indexed'").fetchone()[0])
    state_count = int(conn.execute("SELECT COUNT(*) FROM memory_vector_index_state").fetchone()[0])
    if state_count == 0:
        return
    if eligible_count != vector_count:
        findings.append(
            Finding(
                id=stable_id("zvec_parity"), kind="zvec_parity", severity="high",
                rel_path="", title="Zvec parity",
                message=f"Expected {eligible_count} semantic docs but found {vector_count} indexed docs.",
                detail={"eligible_docs": eligible_count, "indexed_docs": vector_count},
            )
        )
    hash_mismatches = [
        str(row[0])
        for row in conn.execute(
            """
            SELECT d.rel_path
            FROM memory_docs d
            JOIN memory_vector_index_state v ON v.path=d.path
            WHERE v.status='indexed' AND coalesce(v.doc_sha256, '') != d.sha256
            ORDER BY d.rel_path
            """
        ).fetchall()
    ]
    if hash_mismatches:
        findings.append(
            Finding(
                id=stable_id("zvec_hash_parity"),
                kind="zvec_hash_parity",
                severity="high",
                rel_path="",
                title="Zvec hash parity",
                message=f"{len(hash_mismatches)} semantic documents are older than their Markdown source.",
                detail={"hash_mismatch": hash_mismatches},
            )
        )


def load_decisions(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    rows = conn.execute("SELECT * FROM audit_decisions").fetchall()
    return {row["finding_id"]: row for row in rows}


def decision_hides(row: sqlite3.Row) -> bool:
    decision = str(row["decision"])
    if decision in {"ack", "ignored", "resolved"}:
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
    with closing(connect_state()) as conn, conn:
        add_stale_findings(conn, findings, args.stale_days)
        add_open_loop_findings(conn, findings, args.open_loop_threshold, args.risk_threshold)
        add_duplicate_title_findings(conn, findings)
        add_outdated_findings(conn, findings)
        add_large_file_findings(conn, findings, args.large_file_line_limit, args.large_file_byte_limit)
        add_index_parity_findings(conn, findings)
        add_current_fact_invariant_findings(conn, findings)
    findings.sort(key=lambda item: (severity_rank(item.severity), item.kind, item.rel_path), reverse=True)
    with closing(connect_audit()) as audit_conn, audit_conn:
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
    with closing(connect_audit()) as conn, conn:
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
    with closing(connect_audit()) as conn, conn:
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
    parser = argparse.ArgumentParser(description="Audit Agent Memory for stale facts, noisy loops, and duplicates.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--limit", type=int, default=50, help="Maximum visible findings.")
    parser.add_argument("--stale-days", type=int, default=180, help="Fallback review period.")
    parser.add_argument("--open-loop-threshold", type=int, default=4, help="Flag docs with at least this many open-loop indexed items.")
    parser.add_argument("--risk-threshold", type=int, default=3, help="Flag docs with at least this many risk items.")
    parser.add_argument("--large-file-line-limit", type=int, default=180, help="Advisory line threshold.")
    parser.add_argument("--large-file-byte-limit", type=int, default=24576, help="Advisory byte threshold.")
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
    args.stale_days = max(args.stale_days, 1)
    args.open_loop_threshold = max(args.open_loop_threshold, 1)
    args.risk_threshold = max(args.risk_threshold, 1)
    args.large_file_line_limit = max(args.large_file_line_limit, 1)
    args.large_file_byte_limit = max(args.large_file_byte_limit, 1)
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
        findings = collect_findings(args)
        payload["findings"] = [finding.to_dict() for finding in findings]
        payload["summary"] = {
            "total": len(findings),
            "by_severity": {severity: sum(1 for item in findings if item.severity == severity) for severity in ("high", "medium", "low")},
            "by_kind": {kind: sum(1 for item in findings if item.kind == kind) for kind in sorted({item.kind for item in findings})},
        }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
