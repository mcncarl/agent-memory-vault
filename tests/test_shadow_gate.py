from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import sys
from pathlib import Path
from unittest import mock

import tomllib

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_observability as observability
import agent_memory_search as search
import agent_memory_shadow as shadow


class ShadowGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config_root = self.root / "runtime"
        (self.config_root / "config").mkdir(parents=True)
        self.shadow_root = self.config_root / "shadow"
        self.state_db = self.config_root / "state.sqlite"
        self.config_file = self.config_root / "config" / "agent-memory.toml"
        self.config_file.write_text(
            "[observability]\n"
            "enabled = true\n"
            "stale_adoption_enforcement = \"shadow\"\n"
            "metadata_enforcement = \"shadow\"\n\n"
            "[shadow]\nstatus = \"observing\"\n\n"
            "[semantic_retrieval]\nranking_version = \"hybrid-v2-shadow\"\n",
            encoding="utf-8",
        )
        self.config_file.chmod(0o600)
        self.manifest = self.config_root / "config" / "runtime-manifest.json"
        self.manifest.write_text(json.dumps({
            "installed_at": "2026-08-24T04:00:00+00:00",
            "install_id": "a" * 64,
        }, sort_keys=True), encoding="utf-8")
        patches = (
            mock.patch.object(shadow, "CONFIG_ROOT", self.config_root),
            mock.patch.object(shadow, "SHADOW_ROOT", self.shadow_root),
            mock.patch.object(shadow, "STATE_DB", self.state_db),
            mock.patch.object(shadow, "MANIFEST_PATH", self.manifest),
            mock.patch.object(shadow, "config_path", return_value=self.config_file),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        benchmark_root = self.config_root / "benchmarks"
        benchmark_root.mkdir(mode=0o700)
        self.benchmark_file = benchmark_root / "private-quality.json"
        self.benchmark_file.write_text(json.dumps({
            "schema_version": 1,
            "privacy": "private_local",
            "cases": [
                {
                    "id": "auto-closeout",
                    "query": "Codex 每次对话结束怎么自动归档",
                    "expected": ["工作流/Agent记忆收尾决策规则.md"],
                    "required_at": 5,
                },
                *[
                    {
                        "id": f"required-{index}",
                        "query": f"private quality case {index}",
                        "expected": [f"工作流/fixture-{index}.md"],
                        "required_at": 5,
                    }
                    for index in range(2, 6)
                ],
            ],
        }, ensure_ascii=False), encoding="utf-8")
        self.benchmark_file.chmod(0o600)
        self.dataset_binding = shadow.private_benchmark_binding(str(self.benchmark_file))

    @staticmethod
    def shadow_config() -> dict[str, object]:
        return {
            "semantic_retrieval": {"ranking_version": "hybrid-v2-shadow"},
            "observability": {
                "enabled": True,
                "stale_adoption_enforcement": "shadow",
                "metadata_enforcement": "shadow",
            },
        }

    def valid_benchmark_payload(self) -> dict[str, object]:
        return {
            "start_attestation_sha256": "b" * 64,
            "runs": 3,
            **self.dataset_binding,
            "full_required_case_set": True,
            "production_config_sha256": shadow.production_config_sha256(),
            "metrics": {
                name: {"hit_at_5": 1.0, "mrr": 0.95}
                for name in ("sqlite", "vector", "hybrid", "canonical_retrieve")
            },
            "hybrid_cold_ms": 5000,
            "hybrid_warm_p95_ms": 800,
            "degraded_count": 0,
            "worker_cold_status": "started",
            "worker_warm_sample_count": 2,
            "worker_warm_reused_count": 2,
        }

    def load_test_config(self) -> dict[str, object]:
        return tomllib.loads(self.config_file.read_text(encoding="utf-8"))

    def shadow_start_payload(self) -> dict[str, object]:
        return {
            "shadow_started_at": "2026-08-01T00:00:00+00:00",
            "minimum_days": 7,
            "production_config_sha256": shadow.production_config_sha256(),
            **self.dataset_binding,
        }

    def start_shadow_at(self, timestamp: str) -> dict[str, object]:
        with mock.patch.object(shadow, "load_config", return_value=self.shadow_config()), mock.patch.object(
            shadow, "env_value", return_value="7"
        ), mock.patch.object(shadow, "utc_now", return_value=timestamp):
            return shadow.start_shadow(
                actor="migration",
                benchmark_file=str(self.benchmark_file),
            )

    def restart_shadow_at(
        self,
        parent: str,
        timestamp: str,
        *,
        search_high_watermark: int = 0,
        event_high_watermark: int = 0,
    ) -> dict[str, object]:
        current = dt.datetime.fromisoformat(timestamp)
        with mock.patch.object(
            shadow, "_normalized_utc", return_value=current
        ), mock.patch.object(
            shadow,
            "_state_high_watermarks",
            return_value={
                "search_log_high_watermark": search_high_watermark,
                "event_log_high_watermark": event_high_watermark,
            },
        ):
            return shadow.restart_shadow(
                actor="migration",
                benchmark_file=str(self.benchmark_file),
                supersede_epoch=parent,
            )

    @staticmethod
    def healthy_shadow_metrics(**changes: int) -> dict[str, int]:
        payload = {
            "searches": 1,
            "real_searches": 1,
            "real_task_count": 1,
            "required_regressions": 0,
            "privacy_violations": 0,
            "missing_task_denominator": 0,
            "worker_restarts": 0,
            "worker_crash_loops": 0,
            "semantic_failure_streaks": 0,
            "metadata_would_block_count": 0,
            "metadata_observation_invalid": 0,
            "state_privacy_guard_invalid": 0,
            "returned_without_disposition": 0,
            "opened_without_disposition": 0,
            "tasks_with_missing_disposition": 0,
        }
        payload.update(changes)
        return payload

    def write_gate_evidence(
        self,
        *,
        start_digest: str,
        epoch_digest: str,
        epoch_number: int,
        epoch_started_at: str,
    ) -> None:
        binding = shadow.runtime_binding()
        benchmark = {
            "schema_version": 1,
            "kind": "benchmark-success",
            "created_at": epoch_started_at,
            "shadow_started_at": epoch_started_at,
            **self.valid_benchmark_payload(),
            "start_attestation_sha256": start_digest,
            **binding,
        }
        canary = {
            "schema_version": 1,
            "kind": "stale-canary",
            "created_at": epoch_started_at,
            "shadow_started_at": epoch_started_at,
            "start_attestation_sha256": start_digest,
            "identified_before_live_verification": 1,
            "remaining_after_live_verification": 0,
            "task_ref_sha256": "e" * 64,
            "memory_version_fingerprint": "f" * 64,
            **binding,
        }
        if epoch_number > 0:
            epoch_fields = {
                "epoch_attestation_sha256": epoch_digest,
                "epoch_number": epoch_number,
            }
            benchmark.update(epoch_fields)
            canary.update(epoch_fields)
        shadow._exclusive_json("benchmark-success", benchmark)
        shadow._exclusive_json("stale-canary", canary)

    def epoch_payload(
        self,
        *,
        root_digest: str,
        parent_digest: str,
        epoch_number: int,
        timestamp: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "shadow-epoch",
            "created_at": timestamp,
            "epoch_started_at": timestamp,
            "epoch_number": epoch_number,
            "reason_code": shadow.SHADOW_EPOCH_REASON,
            "root_start_attestation_sha256": root_digest,
            "parent_epoch_attestation_sha256": parent_digest,
            "production_config_sha256": shadow.production_config_sha256(),
            **self.dataset_binding,
            "search_log_high_watermark": 0,
            "event_log_high_watermark": 0,
            **shadow.runtime_binding(),
        }

    def activate_cutover_fixture(self) -> tuple[bytes, bytes, Path]:
        original = self.config_file.read_bytes()
        original_sha = hashlib.sha256(original).hexdigest()
        backup = self.config_root / "backups" / "before-cutover.toml"
        backup.parent.mkdir(mode=0o700)
        backup.write_bytes(original)
        backup.chmod(0o600)
        evidence_payload = {
            "schema_version": 1,
            "kind": "cutover-gate",
            "status": "passed",
            "production_config_sha256": original_sha,
            **shadow.runtime_binding(),
        }
        evidence, evidence_sha = shadow._exclusive_json("cutover-gate", evidence_payload)
        migrated = shadow.render_cutover_config(
            original,
            evidence_sha256=evidence_sha,
            evidence_file=str(evidence),
            backup_file=str(backup),
            from_config_sha256=original_sha,
            shadow_started_at="2026-08-01T00:00:00+00:00",
            runtime_installed_at=shadow.runtime_binding()["runtime_installed_at"],
            manifest_sha256=shadow.runtime_binding()["manifest_sha256"],
            cutover_at="2026-08-08T00:00:01+00:00",
        )
        self.config_file.write_bytes(migrated)
        self.config_file.chmod(0o600)
        transition = self.config_root / "config" / "runtime-transition.json"
        transition.write_text(json.dumps({
            "preflight_attestation": {"config_sha256": original_sha}
        }), encoding="utf-8")
        transition.chmod(0o600)
        shadow.reset_config_cache()
        self.assertTrue(shadow.cutover_active())
        return original, migrated, backup

    def test_start_is_unique_idempotent_and_manifest_bound(self) -> None:
        with mock.patch.object(shadow, "load_config", return_value=self.shadow_config()), mock.patch.object(
            shadow, "env_value", return_value="7"
        ):
            first = shadow.start_shadow(
                actor="migration", benchmark_file=str(self.benchmark_file)
            )
            second = shadow.start_shadow(
                actor="migration", benchmark_file=str(self.benchmark_file)
            )

        self.assertEqual(first["status"], "started")
        self.assertEqual(second["status"], "already_started")
        self.assertEqual(first["start_attestation_sha256"], second["start_attestation_sha256"])
        files = list(self.shadow_root.glob("shadow-start-*.json"))
        self.assertEqual(len(files), 1)
        payload = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(payload["runtime_installed_at"], "2026-08-24T04:00:00+00:00")
        for key, value in self.dataset_binding.items():
            self.assertEqual(payload[key], value)
        start_raw = files[0].read_text(encoding="utf-8").casefold()
        for forbidden in ("query", "expected", str(self.benchmark_file).casefold()):
            self.assertNotIn(forbidden, start_raw)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_start_rejects_dataset_change_after_day_one(self) -> None:
        with mock.patch.object(shadow, "load_config", return_value=self.shadow_config()), mock.patch.object(
            shadow, "env_value", return_value="7"
        ):
            shadow.start_shadow(
                actor="migration", benchmark_file=str(self.benchmark_file)
            )
            payload = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
            payload["cases"][-1]["query"] = "changed after shadow start"
            self.benchmark_file.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            self.benchmark_file.chmod(0o600)
            with self.assertRaisesRegex(
                shadow.ShadowGateError, "SHADOW_BENCHMARK_CHANGED_SINCE_START"
            ):
                shadow.start_shadow(
                    actor="migration", benchmark_file=str(self.benchmark_file)
                )

    def test_start_rejects_too_small_required_set(self) -> None:
        payload = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
        payload["cases"] = payload["cases"][:4]
        self.benchmark_file.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        self.benchmark_file.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_PRIVATE_BENCHMARK_REQUIRED_SET_TOO_SMALL"
        ):
            shadow.private_benchmark_binding(str(self.benchmark_file))

    def test_start_rejects_duplicate_normalized_required_queries(self) -> None:
        payload = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
        payload["cases"][2]["query"] = "  PRIVATE   quality case 2  "
        self.benchmark_file.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        self.benchmark_file.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_PRIVATE_BENCHMARK_REQUIRED_QUERIES_NOT_UNIQUE",
        ):
            shadow.private_benchmark_binding(str(self.benchmark_file))

    def test_start_rejects_mandatory_query_with_wrong_expected_target(self) -> None:
        payload = json.loads(self.benchmark_file.read_text(encoding="utf-8"))
        payload["cases"][0]["expected"] = ["工作流/错误目标.md"]
        self.benchmark_file.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        self.benchmark_file.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_PRIVATE_BENCHMARK_MANDATORY_CASE_MISSING"
        ):
            shadow.private_benchmark_binding(str(self.benchmark_file))

    def test_start_lock_fails_closed_under_concurrent_owner(self) -> None:
        with shadow._shadow_start_transaction_lock(), mock.patch.object(
            shadow, "load_config", return_value=self.shadow_config()
        ):
            with self.assertRaisesRegex(
                shadow.ShadowGateError, "SHADOW_START_ALREADY_IN_PROGRESS"
            ):
                shadow.start_shadow(
                    actor="migration", benchmark_file=str(self.benchmark_file)
                )
        self.assertEqual(list(self.shadow_root.glob("shadow-start-*.json")), [])
        self.assertEqual((self.shadow_root / ".shadow-start.lock").stat().st_mode & 0o777, 0o600)

    def test_start_rejects_symlink_even_when_target_stays_inside_runtime(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is privilege-dependent on Windows")
        link = self.benchmark_file.parent / "private-quality-link.json"
        link.symlink_to(self.benchmark_file)
        with self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_PRIVATE_BENCHMARK_UNSAFE"
        ):
            shadow.private_benchmark_binding(str(link))

    def test_restart_at_day_699_resets_window_and_inherits_no_gate_evidence(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                "CREATE TABLE memory_search_log("
                "id INTEGER PRIMARY KEY, query_sha256 TEXT, "
                "metadata_would_block_count INTEGER, "
                "metadata_reason_fingerprint TEXT, created_at TEXT)"
            )
            conn.execute(
                "INSERT INTO memory_search_log VALUES(1, ?, 1, ?, ?)",
                (
                    "a" * 64,
                    "b" * 64,
                    "2026-08-07T23:44:00+00:00",
                ),
            )
            conn.commit()
        self.state_db.chmod(0o600)
        state_before = self.state_db.read_bytes()
        old_metrics = self.healthy_shadow_metrics(
            metadata_would_block_count=1,
            required_regressions=2,
            privacy_violations=1,
            missing_task_denominator=1,
            worker_restarts=3,
            worker_crash_loops=1,
            semantic_failure_streaks=1,
            metadata_observation_invalid=1,
            returned_without_disposition=1,
            opened_without_disposition=1,
            tasks_with_missing_disposition=1,
        )
        with mock.patch.object(shadow, "_shadow_metrics", return_value=old_metrics):
            before = shadow.shadow_status(
                now=dt.datetime(2026, 8, 7, 23, 45, tzinfo=dt.timezone.utc)
            )
        self.assertIn("SHADOW_METADATA_GATE_WOULD_BLOCK", before["gate_failures"])

        restarted = self.restart_shadow_at(
            start_digest,
            "2026-08-07T23:45:00+00:00",
            search_high_watermark=1,
        )
        self.assertEqual(restarted["status"], "restarted")
        self.assertEqual(self.state_db.read_bytes(), state_before)
        epoch_started_at = str(restarted["shadow_started_at"])

        def metrics(since: str, **bounds: int) -> dict[str, int]:
            if bounds.get("search_id_after") == 1:
                return self.healthy_shadow_metrics(
                    searches=0,
                    real_searches=0,
                    real_task_count=0,
                )
            return old_metrics

        with mock.patch.object(shadow, "_shadow_metrics", side_effect=metrics):
            status = shadow.shadow_status(
                now=dt.datetime(2026, 8, 8, 0, 0, tzinfo=dt.timezone.utc)
            )
        self.assertIn("SHADOW_MINIMUM_DURATION_NOT_MET", status["gate_failures"])
        self.assertIn("SHADOW_BENCHMARK_ATTESTATION_MISSING", status["gate_failures"])
        self.assertIn("SHADOW_STALE_CANARY_ATTESTATION_MISSING", status["gate_failures"])
        self.assertIn("SHADOW_REAL_RETRIEVAL_DENOMINATOR_MISSING", status["gate_failures"])
        self.assertNotIn("SHADOW_METADATA_GATE_WOULD_BLOCK", status["gate_failures"])
        self.assertEqual(status["benchmark_attestation_count"], 0)
        self.assertEqual(status["canary_attestation_count"], 0)
        self.assertEqual(status["historical_benchmark_attestation_count"], 1)
        self.assertEqual(status["historical_canary_attestation_count"], 1)
        self.assertEqual(status["metrics"]["historical_metadata_would_block_count"], 1)
        for field, expected in (
            ("required_regressions", 2),
            ("privacy_violations", 1),
            ("missing_task_denominator", 1),
            ("worker_restarts", 3),
            ("worker_crash_loops", 1),
            ("semantic_failure_streaks", 1),
            ("metadata_observation_invalid", 1),
            ("returned_without_disposition", 1),
            ("opened_without_disposition", 1),
            ("tasks_with_missing_disposition", 1),
        ):
            self.assertEqual(status["historical_metrics"][field], expected)
            self.assertEqual(status["metrics"][f"historical_{field}"], expected)
        for historical_only_reason in (
            "SHADOW_REQUIRED_CASE_REGRESSION",
            "SHADOW_PRIVACY_VIOLATION",
            "SHADOW_TASK_DENOMINATOR_MISSING",
            "SHADOW_WORKER_CRASH_LOOP",
            "SHADOW_SEMANTIC_FAILURE_STREAK",
            "SHADOW_METADATA_OBSERVATION_INVALID",
            "SHADOW_CANDIDATE_DISPOSITION_MISSING",
        ):
            self.assertNotIn(historical_only_reason, status["gate_failures"])
        self.assertEqual(status["epoch_number"], 1)

    def test_restart_watermarks_split_same_second_and_late_backdated_rows(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        root_digest = str(started["start_attestation_sha256"])
        old_task = "a" * 64
        new_task = "b" * 64
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.executescript(
                """
                CREATE TABLE memory_search_log(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  query TEXT, used_paths TEXT, task_id TEXT, actor TEXT,
                  sources TEXT, required_case_regression_count INTEGER,
                  worker_status TEXT, worker_restart_count INTEGER,
                  metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                  metadata_reason_fingerprint TEXT, created_at TEXT
                );
                CREATE TABLE memory_use_events(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  task_id TEXT, actor TEXT, event_type TEXT, source TEXT,
                  created_at TEXT
                );
                """
            )
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL,'','',?,'codex','sqlite',0,"
                "'reused',0,'shadow',1,?,?)",
                (old_task, "c" * 64, "2026-08-07T23:45:00+00:00"),
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,?,'codex','task_seen',"
                "'tool_observed',?)",
                (old_task, "2026-08-07T23:45:00+00:00"),
            )
            conn.commit()
        self.state_db.chmod(0o600)

        current = dt.datetime(2026, 8, 7, 23, 45, tzinfo=dt.timezone.utc)
        with mock.patch.object(shadow, "_normalized_utc", return_value=current):
            restarted = shadow.restart_shadow(
                actor="migration",
                benchmark_file=str(self.benchmark_file),
                supersede_epoch=root_digest,
            )
        self.assertEqual(restarted["search_log_high_watermark"], 1)
        self.assertEqual(restarted["event_log_high_watermark"], 1)

        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            # A clean row in the exact restart second belongs to the new epoch.
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL,'','',?,'codex','sqlite',0,"
                "'reused',0,'shadow',0,'',?)",
                (new_task, "2026-08-07T23:45:00+00:00"),
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,?,'codex','task_seen',"
                "'tool_observed',?)",
                (new_task, "2026-08-07T23:45:00+00:00"),
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,?,'codex','source_opened',"
                "'tool_observed',?)",
                (new_task, "2026-08-07T23:45:00+00:00"),
            )
            conn.commit()
        current_metrics = shadow._shadow_metrics(
            str(restarted["shadow_started_at"]),
            search_id_after=1,
            event_id_after=1,
        )
        historical_metrics = shadow._shadow_metrics(
            "2026-08-01T00:00:00+00:00",
            search_id_at_most=1,
            event_id_at_most=1,
        )
        self.assertEqual(current_metrics["searches"], 1)
        self.assertEqual(current_metrics["metadata_would_block_count"], 0)
        self.assertEqual(current_metrics["real_task_count"], 1)
        self.assertEqual(historical_metrics["metadata_would_block_count"], 1)

        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            # Model a writer that captured an old timestamp before restart but
            # committed afterwards. The greater row ID must still be gated.
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL,'','',?,'codex','sqlite',0,"
                "'reused',0,'shadow',1,?,?)",
                (new_task, "d" * 64, "2026-08-07T23:44:59+00:00"),
            )
            conn.commit()
        delayed = shadow._shadow_metrics(
            str(restarted["shadow_started_at"]),
            search_id_after=1,
            event_id_after=1,
        )
        self.assertEqual(delayed["searches"], 2)
        self.assertEqual(delayed["metadata_would_block_count"], 1)

    def test_current_root_requires_owner_only_attestation_permissions(self) -> None:
        if os.name != "posix":
            self.skipTest("owner-only mode bits are a POSIX invariant")
        self.start_shadow_at("2026-08-01T00:00:00+00:00")
        root_file = next(self.shadow_root.glob("shadow-start-*.json"))
        root_file.chmod(0o644)

        with self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_START_ATTESTATION_UNSAFE"
        ):
            shadow.current_shadow_epoch()
        status = shadow.shadow_status(
            now=dt.datetime(2026, 8, 8, tzinfo=dt.timezone.utc)
        )
        self.assertEqual(status["status"], "invalid")
        self.assertEqual(
            status["gate_failures"], ["SHADOW_START_ATTESTATION_UNSAFE"]
        )

    def test_evidence_reader_accepts_current_root_writer_payloads(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )

        binding = shadow.runtime_binding()
        benchmarks = shadow._attestations("benchmark-success", binding)
        canaries = shadow._attestations("stale-canary", binding)

        self.assertEqual(len(benchmarks), 1)
        self.assertEqual(len(canaries), 1)
        self.assertNotIn("epoch_number", benchmarks[0][1])
        self.assertNotIn("epoch_attestation_sha256", canaries[0][1])

    def test_restart_same_second_microsecond_canary_is_readable(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        epoch_time = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
        ).replace(microsecond=654321)
        restarted = self.restart_shadow_at(
            start_digest,
            epoch_time.isoformat(),
        )
        self.assertEqual(restarted["shadow_started_at"], epoch_time.isoformat())
        truncated = epoch_time.replace(microsecond=0).isoformat()

        with mock.patch.object(
            shadow,
            "_normalized_utc",
            return_value=epoch_time,
        ), mock.patch.object(
            shadow,
            "utc_now",
            return_value=truncated,
        ), mock.patch.object(
            observability,
            "record_source_opened_version",
        ), mock.patch.object(
            observability,
            "record_declared_event",
        ), mock.patch.object(
            observability,
            "adopted_stale_without_verification",
            side_effect=(1, 0),
        ):
            shadow.run_stale_canary(actor="migration")
            rows = shadow._attestations(
                "stale-canary",
                shadow.runtime_binding(),
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1]["created_at"], epoch_time.isoformat())
        self.assertEqual(rows[0][1]["shadow_started_at"], epoch_time.isoformat())

    def test_evidence_reader_rejects_non_private_mode_with_stable_reason(self) -> None:
        if os.name != "posix":
            self.skipTest("owner-only mode bits are a POSIX invariant")
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        benchmark = next(self.shadow_root.glob("benchmark-success-*.json"))
        benchmark.chmod(0o644)

        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_ATTESTATION_UNSAFE",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

    def test_evidence_reader_requires_current_user_owner(self) -> None:
        if os.name != "posix" or not hasattr(os, "geteuid"):
            self.skipTest("owner identity is a POSIX invariant")
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        contexts = shadow._attestation_contexts(
            now=dt.datetime.now(dt.timezone.utc)
        )
        with mock.patch.object(
            shadow,
            "_attestation_contexts",
            return_value=contexts,
        ), mock.patch.object(
            shadow.os,
            "geteuid",
            return_value=os.geteuid() + 1,
        ), self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_ATTESTATION_UNSAFE",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

    def test_evidence_reader_rejects_symlink_even_beside_valid_evidence(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation is privilege-dependent on Windows")
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        benchmark = next(self.shadow_root.glob("benchmark-success-*.json"))
        forged = self.shadow_root / "benchmark-success-forged.json"
        forged.symlink_to(benchmark)

        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_ATTESTATION_UNSAFE",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

    def test_evidence_reader_rejects_unknown_fields_and_partial_epoch(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        canary = next(self.shadow_root.glob("stale-canary-*.json"))
        payload = json.loads(canary.read_text(encoding="utf-8"))
        payload["query"] = "must never be accepted"
        forged = self.shadow_root / "stale-canary-forged.json"
        forged.write_text(json.dumps(payload), encoding="utf-8")
        forged.chmod(0o600)

        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_STALE_CANARY_ATTESTATION_MALFORMED",
        ):
            shadow._attestations("stale-canary", shadow.runtime_binding())

        benchmark = next(self.shadow_root.glob("benchmark-success-*.json"))
        partial = json.loads(benchmark.read_text(encoding="utf-8"))
        partial["epoch_number"] = 1
        partial_path = self.shadow_root / "benchmark-success-partial-epoch.json"
        partial_path.write_text(json.dumps(partial), encoding="utf-8")
        partial_path.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_ATTESTATION_MALFORMED",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

    def test_evidence_reader_rejects_duplicate_json_members_and_large_files(self) -> None:
        self.start_shadow_at("2026-08-01T00:00:00+00:00")
        malformed = self.shadow_root / "stale-canary-duplicate-member.json"
        malformed.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        malformed.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_STALE_CANARY_ATTESTATION_MALFORMED",
        ):
            shadow._attestations("stale-canary", shadow.runtime_binding())

        oversized = self.shadow_root / "benchmark-success-oversized.json"
        oversized.write_bytes(b"{" + b" " * shadow.MAX_ATTESTATION_BYTES)
        oversized.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_ATTESTATION_MALFORMED",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

    def test_evidence_reader_rejects_duplicate_and_invalid_binding(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=start_digest,
            epoch_number=0,
            epoch_started_at="2026-08-01T00:00:00+00:00",
        )
        benchmark = next(self.shadow_root.glob("benchmark-success-*.json"))
        duplicate = self.shadow_root / "benchmark-success-exact-copy.json"
        duplicate.write_bytes(benchmark.read_bytes())
        duplicate.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_BENCHMARK_DUPLICATE_ATTESTATION",
        ):
            shadow._attestations("benchmark-success", shadow.runtime_binding())

        canary = next(self.shadow_root.glob("stale-canary-*.json"))
        payload = json.loads(canary.read_text(encoding="utf-8"))
        payload["manifest_sha256"] = "9" * 64
        forged = self.shadow_root / "stale-canary-invalid-binding.json"
        forged.write_text(json.dumps(payload), encoding="utf-8")
        forged.chmod(0o600)
        with self.assertRaisesRegex(
            shadow.ShadowGateError,
            "SHADOW_STALE_CANARY_ATTESTATION_BINDING_INVALID",
        ):
            shadow._attestations("stale-canary", shadow.runtime_binding())

    def test_restart_passes_only_after_new_evidence_and_full_seven_days(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        start_digest = str(started["start_attestation_sha256"])
        restarted = self.restart_shadow_at(
            start_digest,
            "2026-08-07T23:45:00+00:00",
        )
        epoch_digest = str(restarted["epoch_attestation_sha256"])
        epoch_started_at = str(restarted["shadow_started_at"])
        self.write_gate_evidence(
            start_digest=start_digest,
            epoch_digest=epoch_digest,
            epoch_number=1,
            epoch_started_at=epoch_started_at,
        )

        current_metrics = self.healthy_shadow_metrics()
        all_metrics = self.healthy_shadow_metrics(
            searches=2,
            real_searches=2,
            real_task_count=2,
            metadata_would_block_count=1,
        )

        def metrics(since: str, **bounds: int) -> dict[str, int]:
            return current_metrics if "search_id_after" in bounds else all_metrics

        with mock.patch.object(shadow, "_shadow_metrics", side_effect=metrics):
            early = shadow.shadow_status(
                now=dt.datetime(2026, 8, 14, 23, 44, 59, tzinfo=dt.timezone.utc)
            )
            passed = shadow.shadow_status(
                now=dt.datetime(2026, 8, 14, 23, 45, 1, tzinfo=dt.timezone.utc)
            )
        self.assertIn("SHADOW_MINIMUM_DURATION_NOT_MET", early["gate_failures"])
        self.assertTrue(passed["ok"])
        self.assertEqual(passed["gate_failures"], [])
        self.assertEqual(passed["benchmark_attestation_count"], 1)
        self.assertEqual(passed["canary_attestation_count"], 1)
        self.assertEqual(passed["metrics"]["historical_metadata_would_block_count"], 1)

    def test_restart_is_idempotent_but_old_parent_is_fenced_after_later_epoch(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        root_digest = str(started["start_attestation_sha256"])
        first = self.restart_shadow_at(root_digest, "2026-08-02T00:00:00+00:00")
        retry = self.restart_shadow_at(root_digest, "2026-08-03T00:00:00+00:00")
        self.assertEqual(retry["status"], "already_restarted")
        self.assertEqual(
            retry["epoch_attestation_sha256"],
            first["epoch_attestation_sha256"],
        )
        epoch_files = list(self.shadow_root.glob("shadow-epoch-*.json"))
        self.assertEqual(len(epoch_files), 1)
        self.assertEqual(epoch_files[0].stat().st_mode & 0o777, 0o600)
        epoch_payload = json.loads(epoch_files[0].read_text(encoding="utf-8"))
        self.assertEqual(set(epoch_payload), shadow.SHADOW_EPOCH_ATTESTATION_KEYS)
        self.assertEqual(epoch_payload["reason_code"], shadow.SHADOW_EPOCH_REASON)
        self.assertEqual(epoch_payload["parent_epoch_attestation_sha256"], root_digest)
        self.assertNotIn(str(self.benchmark_file), epoch_files[0].read_text(encoding="utf-8"))

        second = self.restart_shadow_at(
            str(first["epoch_attestation_sha256"]),
            "2026-08-04T00:00:00+00:00",
        )
        self.assertEqual(second["epoch_number"], 2)
        with self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_EPOCH_PARENT_STALE"):
            self.restart_shadow_at(root_digest, "2026-08-05T00:00:00+00:00")
        with self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_EPOCH_PARENT_UNKNOWN"):
            self.restart_shadow_at("9" * 64, "2026-08-05T00:00:00+00:00")

    def test_restart_cli_requires_explicit_benchmark_and_parent_epoch(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_shadow.py",
                "--actor",
                "migration",
                "restart",
                "--benchmark-file",
                str(self.benchmark_file),
                "--supersede-epoch",
                "1" * 64,
            ],
        ):
            args = shadow.parse_args()
        self.assertEqual(args.action, "restart")
        self.assertEqual(args.benchmark_file, str(self.benchmark_file))
        self.assertEqual(args.supersede_epoch, "1" * 64)

    def test_epoch_chain_rejects_fork_cross_binding_future_malformed_and_duplicate(self) -> None:
        scenarios = (
            "fork",
            "cross_binding",
            "foreign_root",
            "future",
            "malformed",
            "duplicate",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                shadow_dir = self.config_root / f"shadow-{scenario}"
                with mock.patch.object(shadow, "SHADOW_ROOT", shadow_dir):
                    start_payload = self.shadow_start_payload()
                    start_payload.update(shadow.runtime_binding())
                    root_digest = "1" * 64
                    payload = self.epoch_payload(
                        root_digest=root_digest,
                        parent_digest=root_digest,
                        epoch_number=1,
                        timestamp="2026-08-02T00:00:00+00:00",
                    )
                    if scenario == "fork":
                        shadow._exclusive_json("shadow-epoch", payload)
                        forked = dict(payload)
                        forked["created_at"] = "2026-08-03T00:00:00+00:00"
                        forked["epoch_started_at"] = "2026-08-03T00:00:00+00:00"
                        shadow._exclusive_json("shadow-epoch", forked)
                        reason = "SHADOW_EPOCH_FORK_DETECTED"
                    elif scenario == "cross_binding":
                        payload["manifest_sha256"] = "2" * 64
                        shadow._exclusive_json("shadow-epoch", payload)
                        reason = "SHADOW_EPOCH_CROSS_BINDING"
                    elif scenario == "foreign_root":
                        payload["root_start_attestation_sha256"] = "3" * 64
                        payload["parent_epoch_attestation_sha256"] = "3" * 64
                        shadow._exclusive_json("shadow-epoch", payload)
                        reason = "SHADOW_EPOCH_CROSS_BINDING"
                    elif scenario == "future":
                        payload["created_at"] = "2026-08-05T00:00:00+00:00"
                        payload["epoch_started_at"] = "2026-08-05T00:00:00+00:00"
                        shadow._exclusive_json("shadow-epoch", payload)
                        reason = "SHADOW_EPOCH_FUTURE_TIMESTAMP"
                    elif scenario == "malformed":
                        shadow._exclusive_json("shadow-epoch", {"schema_version": 1})
                        reason = "SHADOW_EPOCH_ATTESTATION_MALFORMED"
                    else:
                        shadow._exclusive_json("shadow-epoch", payload)
                        shadow._exclusive_json("shadow-epoch", payload)
                        reason = "SHADOW_EPOCH_DUPLICATE_ATTESTATION"
                    with self.assertRaisesRegex(shadow.ShadowGateError, reason):
                        shadow._shadow_epoch_state(
                            binding=shadow.runtime_binding(),
                            start_payload=start_payload,
                            start_attestation_sha256=root_digest,
                            now=dt.datetime(2026, 8, 4, tzinfo=dt.timezone.utc),
                        )

    def test_well_formed_epoch_from_prior_runtime_is_historical_not_current(self) -> None:
        isolated_shadow = self.config_root / "shadow-prior-runtime"
        with mock.patch.object(shadow, "SHADOW_ROOT", isolated_shadow):
            old_binding = {
                "manifest_sha256": "2" * 64,
                "runtime_installed_at": "2026-07-01T00:00:00+00:00",
                "install_id_sha256": "3" * 64,
            }
            old_start = {
                "schema_version": 1,
                "kind": "shadow-start",
                "shadow_started_at": "2026-07-01T00:00:00+00:00",
                "minimum_days": 7,
                "production_config_sha256": shadow.production_config_sha256(),
                **self.dataset_binding,
                **old_binding,
            }
            _path, old_root_digest = shadow._exclusive_json("shadow-start", old_start)
            old_epoch = self.epoch_payload(
                root_digest=old_root_digest,
                parent_digest=old_root_digest,
                epoch_number=1,
                timestamp="2026-07-02T00:00:00+00:00",
            )
            old_epoch.update(old_binding)
            shadow._exclusive_json("shadow-epoch", old_epoch)
            state = shadow._shadow_epoch_state(
                binding=shadow.runtime_binding(),
                start_payload=self.shadow_start_payload(),
                start_attestation_sha256="1" * 64,
                now=dt.datetime(2026, 8, 4, tzinfo=dt.timezone.utc),
            )
        self.assertEqual(state["head_number"], 0)
        self.assertEqual(state["head_attestation_sha256"], "1" * 64)

    def test_prior_runtime_epoch_chain_is_still_validated_fail_closed(self) -> None:
        for scenario, reason in (
            ("unknown-parent", "SHADOW_EPOCH_PARENT_INVALID"),
            ("fork", "SHADOW_EPOCH_FORK_DETECTED"),
        ):
            with self.subTest(scenario=scenario):
                isolated_shadow = self.config_root / f"shadow-prior-{scenario}"
                with mock.patch.object(shadow, "SHADOW_ROOT", isolated_shadow):
                    old_binding = {
                        "manifest_sha256": "2" * 64,
                        "runtime_installed_at": "2026-07-01T00:00:00+00:00",
                        "install_id_sha256": "3" * 64,
                    }
                    old_start = {
                        "schema_version": 1,
                        "kind": "shadow-start",
                        "shadow_started_at": "2026-07-01T00:00:00+00:00",
                        "minimum_days": 7,
                        "production_config_sha256": shadow.production_config_sha256(),
                        **self.dataset_binding,
                        **old_binding,
                    }
                    _path, old_root_digest = shadow._exclusive_json(
                        "shadow-start", old_start
                    )
                    first = self.epoch_payload(
                        root_digest=old_root_digest,
                        parent_digest=(
                            "9" * 64
                            if scenario == "unknown-parent"
                            else old_root_digest
                        ),
                        epoch_number=1,
                        timestamp="2026-07-02T00:00:00+00:00",
                    )
                    first.update(old_binding)
                    shadow._exclusive_json("shadow-epoch", first)
                    if scenario == "fork":
                        second = self.epoch_payload(
                            root_digest=old_root_digest,
                            parent_digest=old_root_digest,
                            epoch_number=1,
                            timestamp="2026-07-03T00:00:00+00:00",
                        )
                        second.update(old_binding)
                        shadow._exclusive_json("shadow-epoch", second)
                    with self.assertRaisesRegex(shadow.ShadowGateError, reason):
                        shadow._shadow_epoch_state(
                            binding=shadow.runtime_binding(),
                            start_payload=self.shadow_start_payload(),
                            start_attestation_sha256="1" * 64,
                            now=dt.datetime(
                                2026, 8, 4, tzinfo=dt.timezone.utc
                            ),
                        )

    def test_epoch_chain_cycle_is_rejected(self) -> None:
        isolated_shadow = self.config_root / "shadow-cycle"
        root_digest = "1" * 64
        first_digest = "a" * 64
        second_digest = "b" * 64
        with mock.patch.object(shadow, "SHADOW_ROOT", isolated_shadow):
            first = self.epoch_payload(
                root_digest=root_digest,
                parent_digest=second_digest,
                epoch_number=1,
                timestamp="2026-08-02T00:00:00+00:00",
            )
            second = self.epoch_payload(
                root_digest=root_digest,
                parent_digest=first_digest,
                epoch_number=2,
                timestamp="2026-08-03T00:00:00+00:00",
            )
            shadow._exclusive_json("shadow-epoch", first)
            shadow._exclusive_json("shadow-epoch", second)
            binding = shadow.runtime_binding()
            start_payload = self.shadow_start_payload()

            def digest(raw: bytes) -> str:
                payload = json.loads(raw.decode("utf-8"))
                return first_digest if payload.get("epoch_number") == 1 else second_digest

            with mock.patch.object(shadow, "sha256_bytes", side_effect=digest), self.assertRaisesRegex(
                shadow.ShadowGateError, "SHADOW_EPOCH_CYCLE_DETECTED"
            ):
                shadow._shadow_epoch_state(
                    binding=binding,
                    start_payload=start_payload,
                    start_attestation_sha256=root_digest,
                    now=dt.datetime(2026, 8, 4, tzinfo=dt.timezone.utc),
                )

    def test_status_reports_malformed_epoch_as_fail_closed(self) -> None:
        self.start_shadow_at("2026-08-01T00:00:00+00:00")
        shadow._exclusive_json("shadow-epoch", {"schema_version": 1})
        status = shadow.shadow_status(
            now=dt.datetime(2026, 8, 8, tzinfo=dt.timezone.utc)
        )
        self.assertFalse(status["ok"])
        self.assertEqual(status["status"], "invalid")
        self.assertEqual(
            status["gate_failures"],
            ["SHADOW_EPOCH_ATTESTATION_MALFORMED"],
        )

    def test_restart_lock_contention_fails_without_epoch_file(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        with shadow._shadow_start_transaction_lock(), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_START_ALREADY_IN_PROGRESS"
        ):
            self.restart_shadow_at(
                str(started["start_attestation_sha256"]),
                "2026-08-02T00:00:00+00:00",
            )
        self.assertEqual(list(self.shadow_root.glob("shadow-epoch-*.json")), [])

    def test_cutover_holds_epoch_lock_while_reading_gate_and_writing_config(self) -> None:
        started = self.start_shadow_at("2026-08-01T00:00:00+00:00")
        root_digest = str(started["start_attestation_sha256"])
        restart_reason = ""

        def status_during_cutover() -> dict[str, object]:
            nonlocal restart_reason
            try:
                self.restart_shadow_at(
                    root_digest,
                    "2026-08-08T00:00:01+00:00",
                )
            except shadow.ShadowGateError as exc:
                restart_reason = str(exc)
            return {"ok": False}

        with mock.patch.object(
            shadow, "shadow_status", side_effect=status_during_cutover
        ), self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_GATE_NOT_PASSED"):
            shadow.cutover(
                actor="migration",
                backup_path=str(self.config_root / "backups" / "cutover.toml"),
            )

        self.assertEqual(restart_reason, "SHADOW_START_ALREADY_IN_PROGRESS")
        self.assertEqual(list(self.shadow_root.glob("shadow-epoch-*.json")), [])
        self.assertFalse((self.config_root / "backups" / "cutover.toml").exists())

    def test_cutover_exclusive_activity_lock_blocks_mid_gate_observation_commit(self) -> None:
        if os.name != "posix":
            self.skipTest("shared flock concurrency is validated on POSIX")
        self.start_shadow_at("2026-08-01T00:00:00+00:00")
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                "CREATE TABLE memory_search_log("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "metadata_would_block_count INTEGER)"
            )
            conn.commit()
        self.state_db.chmod(0o600)
        original_config = self.config_file.read_bytes()
        writer_reason = ""

        def status_before_cas() -> dict[str, object]:
            nonlocal writer_reason
            try:
                with shadow._shadow_activity_lock(exclusive=False):
                    with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
                        conn.execute(
                            "INSERT INTO memory_search_log("
                            "metadata_would_block_count) VALUES(1)"
                        )
                        conn.commit()
            except shadow.ShadowGateError as exc:
                writer_reason = str(exc)
            return {"ok": False}

        with mock.patch.dict(
            os.environ,
            {"AGENT_MEMORY_SHADOW_ACTIVITY_LOCK_TIMEOUT_SECONDS": "0"},
        ), mock.patch.object(
            shadow, "shadow_status", side_effect=status_before_cas
        ), self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_GATE_NOT_PASSED"):
            shadow.cutover(
                actor="migration",
                backup_path=str(self.config_root / "backups" / "cutover.toml"),
            )

        self.assertEqual(writer_reason, "SHADOW_ACTIVITY_LOCK_BUSY")
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM memory_search_log").fetchone()[0],
                0,
            )
        self.assertEqual(self.config_file.read_bytes(), original_config)
        self.assertFalse((self.config_root / "backups" / "cutover.toml").exists())

    def test_status_requires_full_window_and_all_evidence(self) -> None:
        binding = shadow.runtime_binding()
        start_payload = self.shadow_start_payload()
        attestations = {
            "benchmark-success": [(Path("benchmark"), self.valid_benchmark_payload(), "c" * 64)],
            "stale-canary": [(Path("canary"), {
                "start_attestation_sha256": "b" * 64,
                "identified_before_live_verification": 1,
                "remaining_after_live_verification": 0,
            }, "d" * 64)],
        }
        with mock.patch.object(shadow, "current_start", return_value=(start_payload, "b" * 64)), mock.patch.object(
            shadow, "_shadow_metrics", return_value={
                "searches": 9,
                "required_regressions": 0,
                "privacy_violations": 0,
                "missing_task_denominator": 0,
                "worker_restarts": 1,
                "worker_crash_loops": 0,
                "real_searches": 9,
                "real_task_count": 2,
                "semantic_failure_streaks": 0,
                "metadata_would_block_count": 0,
                "metadata_observation_invalid": 0,
                "state_privacy_guard_invalid": 0,
            }
        ), mock.patch.object(
            shadow, "_attestations", side_effect=lambda kind, _binding: attestations.get(kind, [])
        ):
            passed = shadow.shadow_status(now=dt.datetime(2026, 8, 8, 0, 0, 1, tzinfo=dt.timezone.utc))
            early = shadow.shadow_status(now=dt.datetime(2026, 8, 7, 23, 59, tzinfo=dt.timezone.utc))

        self.assertTrue(passed["ok"])
        self.assertEqual(passed["manifest_sha256"], binding["manifest_sha256"])
        self.assertIn("SHADOW_MINIMUM_DURATION_NOT_MET", early["gate_failures"])

    def test_status_blocks_completed_task_with_missing_candidate_disposition(self) -> None:
        start_payload = self.shadow_start_payload()
        attestations = {
            "benchmark-success": [(Path("benchmark"), self.valid_benchmark_payload(), "c" * 64)],
            "stale-canary": [(Path("canary"), {
                "start_attestation_sha256": "b" * 64,
                "identified_before_live_verification": 1,
                "remaining_after_live_verification": 0,
            }, "d" * 64)],
        }
        metrics = {
            "searches": 1,
            "required_regressions": 0,
            "privacy_violations": 0,
            "missing_task_denominator": 0,
            "worker_restarts": 0,
            "worker_crash_loops": 0,
            "real_searches": 1,
            "real_task_count": 1,
            "semantic_failure_streaks": 0,
            "metadata_would_block_count": 0,
            "metadata_observation_invalid": 0,
            "state_privacy_guard_invalid": 0,
            "returned_without_disposition": 1,
            "opened_without_disposition": 0,
            "tasks_with_missing_disposition": 1,
        }
        with mock.patch.object(
            shadow, "current_start", return_value=(start_payload, "b" * 64)
        ), mock.patch.object(
            shadow, "_shadow_metrics", return_value=metrics
        ), mock.patch.object(
            shadow, "_attestations", side_effect=lambda kind, _binding: attestations.get(kind, [])
        ):
            status = shadow.shadow_status(
                now=dt.datetime(2026, 8, 8, 0, 0, 1, tzinfo=dt.timezone.utc)
            )

        self.assertFalse(status["ok"])
        self.assertIn(
            "SHADOW_CANDIDATE_DISPOSITION_MISSING",
            status["gate_failures"],
        )

    def test_start_requires_enabled_observability(self) -> None:
        config = self.shadow_config()
        config["observability"]["enabled"] = False  # type: ignore[index]
        with mock.patch.object(shadow, "load_config", return_value=config), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_OBSERVABILITY_MUST_BE_ENABLED"
        ):
            shadow.start_shadow(
                actor="migration", benchmark_file=str(self.benchmark_file)
            )

    def test_start_requires_metadata_gate_shadow_mode(self) -> None:
        config = self.shadow_config()
        config["observability"]["metadata_enforcement"] = "enforce"  # type: ignore[index]
        with mock.patch.object(shadow, "load_config", return_value=config), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_METADATA_MODE_REQUIRED"
        ):
            shadow.start_shadow(
                actor="migration", benchmark_file=str(self.benchmark_file)
            )

    def test_metadata_gate_projection_is_stable_and_cutover_bound(self) -> None:
        complete = {
            "status": "active",
            "memory_type": "workflow",
            "track": "workflow",
            "meta": {
                "memory_id": "a" * 64,
                "temporal_policy": "reviewable",
                "review_after_days": 90,
                "risk_class": "ordinary",
            },
        }
        incomplete = {
            "status": "active",
            "memory_type": "workflow",
            "track": "workflow",
            "meta": {},
        }
        self.assertEqual(shadow.temporal_metadata_gate_reasons(complete), ())
        reasons = shadow.temporal_metadata_gate_reasons(incomplete)
        self.assertEqual(
            set(reasons),
            {
                "METADATA_MEMORY_ID_NOT_EXPLICIT",
                "METADATA_TEMPORAL_POLICY_NOT_EXPLICIT",
                "METADATA_REVIEW_POLICY_NOT_EXPLICIT",
                "METADATA_RISK_CLASS_NOT_EXPLICIT",
            },
        )
        shadow_config = {"observability": {"metadata_enforcement": "shadow"}}
        projected = shadow.metadata_gate_projection([(), reasons], config=shadow_config)
        self.assertEqual(projected["effective_mode"], "shadow")
        self.assertEqual(projected["would_block_count"], 1)
        self.assertRegex(projected["reason_fingerprint"], r"^[0-9a-f]{64}$")
        enforce_config = {"observability": {"metadata_enforcement": "enforce"}}
        self.assertEqual(
            shadow.metadata_gate_projection(
                [reasons], config=enforce_config, cutover_verified=False
            )["effective_mode"],
            "shadow",
        )
        self.assertTrue(shadow.metadata_gate_projection(
            [reasons], config=enforce_config, cutover_verified=True
        )["enforced"])

    def test_canonical_action_sensitive_projection_requires_atomic_tuple_and_exact_receipt(self) -> None:
        raw_sha256 = hashlib.sha256(b"current canonical bytes\n").hexdigest()
        metadata = {
            "status": "active",
            "memory_type": "fact",
            "track": "project",
            "rel_path": "项目/事实-owner.md",
            "meta": {
                "memory_id": "a" * 64,
                "temporal_policy": "reviewable",
                "review_after_days": 90,
                "risk_class": "action_sensitive",
            },
        }
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute(
                """
                CREATE TABLE memory_write_receipts(
                  writer_protocol_version INTEGER,
                  target_rel_path TEXT,
                  outcome TEXT,
                  final_raw_sha256 TEXT,
                  git_commit TEXT,
                  source_class TEXT,
                  knowledge_kind TEXT,
                  asserted_by_sha256 TEXT,
                  safety_decision TEXT,
                  evidence_ref_sha256 TEXT,
                  created_at TEXT
                )
                """
            )
            reasons = shadow.canonical_action_sensitive_gate_reasons(
                metadata,
                rel_path="项目/事实-owner.md",
                raw_sha256=raw_sha256,
                state_conn=conn,
                current_date=dt.date(2026, 8, 25),
            )
            self.assertEqual(
                reasons,
                (
                    "METADATA_ATOMIC_FACT_KEY_INVALID",
                    "METADATA_ATOMIC_VALID_FROM_INVALID",
                    "METADATA_ATOMIC_VERIFIED_AT_INVALID",
                    "METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
                ),
            )
            projected = shadow.metadata_gate_projection(
                [reasons],
                config={"observability": {"metadata_enforcement": "shadow"}},
            )
            self.assertEqual(projected["effective_mode"], "shadow")
            self.assertEqual(projected["reason_codes"], sorted(reasons))

            metadata["meta"] = {
                **metadata["meta"],  # type: ignore[arg-type]
                "fact_key": "project.owner",
                "valid_from": "2026-08-25",
                "verified_at": "2026-08-25",
            }
            conn.execute(
                "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    2,
                    "项目/事实-owner.md",
                    "completed",
                    raw_sha256,
                    "b" * 40,
                    "user_direct",
                    "fact",
                    "c" * 64,
                    "ALLOW",
                    "d" * 64,
                    "2026-08-25T00:00:00+00:00",
                ),
            )
            self.assertEqual(
                shadow.canonical_action_sensitive_gate_reasons(
                    metadata,
                    rel_path="项目/事实-owner.md",
                    raw_sha256=raw_sha256,
                    state_conn=conn,
                    current_date=dt.date(2026, 8, 25),
                ),
                (),
            )

    def test_risk_metadata_gate_matches_write_time_classification(self) -> None:
        def metadata(**changes: object) -> dict[str, object]:
            payload: dict[str, object] = {
                "status": "active",
                "memory_type": "workflow",
                "track": "workflow",
                "rel_path": "工作流/example.md",
                "meta": {
                    "memory_id": "a" * 64,
                    "temporal_policy": "reviewable",
                    "review_after_days": 90,
                    "risk_class": "ordinary",
                },
            }
            payload.update(changes)
            return payload

        self.assertEqual(shadow.temporal_metadata_gate_reasons(metadata()), ())

        missing = metadata()
        missing["meta"] = {
            "memory_id": "a" * 64,
            "temporal_policy": "reviewable",
            "review_after_days": 90,
        }
        self.assertEqual(
            shadow.temporal_metadata_gate_reasons(missing),
            ("METADATA_RISK_CLASS_NOT_EXPLICIT",),
        )

        invalid = metadata()
        invalid["meta"] = {
            **invalid["meta"],  # type: ignore[arg-type]
            "risk_class": "legacy_sensitive",
        }
        self.assertEqual(
            shadow.temporal_metadata_gate_reasons(invalid),
            ("METADATA_RISK_CLASS_INVALID",),
        )

        decision = metadata(
            memory_type="decision",
            track="decision",
            rel_path="决策/example.md",
        )
        self.assertEqual(
            shadow.temporal_metadata_gate_reasons(decision),
            ("METADATA_RISK_CLASS_DOWNGRADE",),
        )

        atomic = metadata(
            memory_type="fact",
            rel_path="项目/事实-owner.md",
        )
        atomic["meta"] = {
            **atomic["meta"],  # type: ignore[arg-type]
            "fact_key": "project.owner",
            "valid_from": "2026-08-01",
        }
        self.assertEqual(
            shadow.temporal_metadata_gate_reasons(atomic),
            ("METADATA_RISK_CLASS_DOWNGRADE",),
        )
        atomic["meta"] = {
            **atomic["meta"],  # type: ignore[arg-type]
            "risk_class": "action_sensitive",
        }
        self.assertEqual(shadow.temporal_metadata_gate_reasons(atomic), ())

        successor = metadata()
        successor["meta"] = {
            **successor["meta"],  # type: ignore[arg-type]
            "supersedes": ["项目/旧事实.md"],
        }
        self.assertEqual(
            shadow.temporal_metadata_gate_reasons(successor),
            ("METADATA_RISK_CLASS_DOWNGRADE",),
        )

        unscoped_user = metadata(memory_type="user_profile", track="user")
        unscoped_user["meta"] = {
            key: value
            for key, value in unscoped_user["meta"].items()  # type: ignore[union-attr]
            if key != "risk_class"
        }
        self.assertEqual(shadow.temporal_metadata_gate_reasons(unscoped_user), ())

        pending = metadata(status="pending_verification")
        pending["meta"] = {}
        self.assertEqual(shadow.temporal_metadata_gate_reasons(pending), ())
        self.assertEqual(
            shadow.canonical_action_sensitive_gate_reasons(
                pending,
                rel_path="工作流/example.md",
                raw_sha256="f" * 64,
            ),
            (),
        )

    def test_risk_path_reasons_are_normalized_into_shadow_codes(self) -> None:
        base = {
            "status": "active",
            "memory_type": "fact",
            "track": "project",
            "risk_class": "ordinary",
            "risk_class_source": "frontmatter",
            "memory_id": "a" * 64,
            "memory_id_source": "frontmatter",
            "temporal_policy": "reviewable",
            "temporal_policy_source": "frontmatter",
            "review_after_days": 90,
            "review_after_source": "frontmatter",
            "fact_key": "project.owner",
            "path_policy_reason_codes": ("RISK_CLASS_DOWNGRADE",),
        }
        reasons = shadow.temporal_metadata_gate_reasons(base)
        self.assertEqual(reasons, ("METADATA_RISK_CLASS_DOWNGRADE",))
        projected = shadow.metadata_gate_projection(
            [reasons],
            config={"observability": {"metadata_enforcement": "shadow"}},
        )
        self.assertEqual(projected["reason_codes"], ["METADATA_RISK_CLASS_DOWNGRADE"])

    def test_status_requires_at_least_one_real_search_observation(self) -> None:
        start_payload = self.shadow_start_payload()
        evidence = {
            "benchmark-success": [(Path("b"), self.valid_benchmark_payload(), "c" * 64)],
            "stale-canary": [(Path("c"), {
                "start_attestation_sha256": "b" * 64,
                "identified_before_live_verification": 1,
                "remaining_after_live_verification": 0,
            }, "d" * 64)],
        }
        with mock.patch.object(shadow, "current_start", return_value=(start_payload, "b" * 64)), mock.patch.object(
            shadow, "_shadow_metrics", return_value={
                "searches": 0, "required_regressions": 0, "privacy_violations": 0,
                "missing_task_denominator": 0, "worker_restarts": 0, "worker_crash_loops": 0,
                "real_searches": 0, "real_task_count": 0, "semantic_failure_streaks": 0,
                "metadata_would_block_count": 0, "metadata_observation_invalid": 0,
                "state_privacy_guard_invalid": 0,
            }
        ), mock.patch.object(shadow, "_attestations", side_effect=lambda kind, _binding: evidence.get(kind, [])):
            status = shadow.shadow_status(now=dt.datetime(2026, 8, 9, tzinfo=dt.timezone.utc))
        self.assertIn("SHADOW_REAL_RETRIEVAL_DENOMINATOR_MISSING", status["gate_failures"])

    def test_status_rejects_missing_or_drifted_state_privacy_guards(self) -> None:
        evidence = {
            "benchmark-success": [(Path("b"), self.valid_benchmark_payload(), "c" * 64)],
            "stale-canary": [(Path("c"), {
                "start_attestation_sha256": "b" * 64,
                "identified_before_live_verification": 1,
                "remaining_after_live_verification": 0,
            }, "d" * 64)],
        }
        metrics = {
            "searches": 1, "required_regressions": 0, "privacy_violations": 0,
            "missing_task_denominator": 0, "worker_restarts": 0,
            "worker_crash_loops": 0, "real_searches": 1, "real_task_count": 1,
            "semantic_failure_streaks": 0, "metadata_would_block_count": 0,
            "metadata_observation_invalid": 0, "state_privacy_guard_invalid": 1,
        }
        with mock.patch.object(
            shadow, "current_start", return_value=(self.shadow_start_payload(), "b" * 64)
        ), mock.patch.object(
            shadow, "_shadow_metrics", return_value=metrics
        ), mock.patch.object(
            shadow, "_attestations", side_effect=lambda kind, _binding: evidence.get(kind, [])
        ):
            status = shadow.shadow_status(now=dt.datetime(2026, 8, 9, tzinfo=dt.timezone.utc))
        self.assertIn("SHADOW_STATE_PRIVACY_GUARD_INVALID", status["gate_failures"])

    def test_private_benchmark_attestation_contains_metrics_not_content(self) -> None:
        binding = shadow.runtime_binding()
        output = {
            "status": "ok",
            "gate_failures": [],
            "runs": 3,
            "case_count": self.dataset_binding["case_count"],
            "required_case_count": self.dataset_binding["required_case_count"],
            "full_required_case_set": True,
            "required_case_set_sha256": self.dataset_binding["required_case_set_sha256"],
            "mandatory_auto_archive_case_count": self.dataset_binding["mandatory_auto_archive_case_count"],
            "mandatory_auto_archive_passed": True,
            "required": {
                name: {"hit@5": 1.0, "mrr": 0.95}
                for name in ("sqlite", "vector", "hybrid", "canonical_retrieve")
            },
            "latency_ms": {"hybrid": {"cold": 5000.0, "warm_p95": 800.0}},
            "worker_lifecycle": {
                "cold_status": "started", "warm_sample_count": 2,
                "warm_reused_count": 2, "restart_count": 0,
                "failed_or_degraded_count": 0,
            },
        }
        with mock.patch.dict(os.environ, {"MEMORY_ACTOR": "migration"}), mock.patch.object(
            shadow, "current_start", return_value=(self.shadow_start_payload(), "b" * 64)
        ):
            result = shadow.write_benchmark_attestation(
                output,
                dataset_sha256=str(self.dataset_binding["dataset_sha256"]),
                production_config_digest=shadow.production_config_sha256(),
            )

        self.assertTrue(result["ok"])
        path = next(self.shadow_root.glob("benchmark-success-*.json"))
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        self.assertEqual(payload["manifest_sha256"], binding["manifest_sha256"])
        for forbidden in ("query", "expected", "path", "url", "excerpt", "正文"):
            self.assertNotIn(forbidden, raw.casefold())

    def test_benchmark_attestation_rejects_non_hash_and_nonfinite_metrics(self) -> None:
        output = {
            "status": "ok",
            "gate_failures": [],
            "runs": 3,
            "case_count": self.dataset_binding["case_count"],
            "required_case_count": self.dataset_binding["required_case_count"],
            "full_required_case_set": True,
            "required_case_set_sha256": self.dataset_binding["required_case_set_sha256"],
            "mandatory_auto_archive_case_count": self.dataset_binding["mandatory_auto_archive_case_count"],
            "mandatory_auto_archive_passed": True,
            "required": {
                name: {"hit@5": 1.0, "mrr": 0.95}
                for name in ("sqlite", "vector", "hybrid", "canonical_retrieve")
            },
            "latency_ms": {"hybrid": {"cold": 5000.0, "warm_p95": 800.0}},
            "worker_lifecycle": {
                "cold_status": "started", "warm_sample_count": 2,
                "warm_reused_count": 2, "restart_count": 0,
                "failed_or_degraded_count": 0,
            },
        }
        with mock.patch.dict(os.environ, {"MEMORY_ACTOR": "migration"}), mock.patch.object(
            shadow,
            "current_start",
            return_value=(self.shadow_start_payload(), "b" * 64),
        ):
            with self.assertRaisesRegex(shadow.ShadowGateError, "BENCHMARK_DATASET_DIGEST_INVALID"):
                shadow.write_benchmark_attestation(
                    output, dataset_sha256="private-query",
                    production_config_digest=shadow.production_config_sha256(),
                )
            with self.assertRaisesRegex(
                shadow.ShadowGateError, "BENCHMARK_DOES_NOT_MATCH_SHADOW_START"
            ):
                shadow.write_benchmark_attestation(
                    output, dataset_sha256="d" * 64,
                    production_config_digest=shadow.production_config_sha256(),
                )
            output["required"]["hybrid"]["mrr"] = float("nan")  # type: ignore[index]
            with self.assertRaisesRegex(shadow.ShadowGateError, "BENCHMARK_QUALITY_THRESHOLD_FAILED"):
                shadow.write_benchmark_attestation(
                    output, dataset_sha256=str(self.dataset_binding["dataset_sha256"]),
                    production_config_digest=shadow.production_config_sha256(),
                )
            output["required"]["hybrid"]["mrr"] = 0.95  # type: ignore[index]
            output["latency_ms"]["hybrid"]["warm_p95"] = float("nan")  # type: ignore[index]
            with self.assertRaisesRegex(shadow.ShadowGateError, "BENCHMARK_LATENCY_THRESHOLD_FAILED"):
                shadow.write_benchmark_attestation(
                    output, dataset_sha256=str(self.dataset_binding["dataset_sha256"]),
                    production_config_digest=shadow.production_config_sha256(),
                )
        self.assertEqual(list(self.shadow_root.glob("benchmark-success-*.json")), [])

    def test_canary_proves_detection_then_version_bound_clear(self) -> None:
        with mock.patch.object(
            shadow, "current_start", return_value=({"shadow_started_at": "2026-08-01T00:00:00+00:00"}, "b" * 64)
        ), mock.patch.object(observability, "record_source_opened_version") as opened, mock.patch.object(
            observability, "record_declared_event"
        ) as declared, mock.patch.object(
            observability, "adopted_stale_without_verification", side_effect=(1, 0)
        ):
            result = shadow.run_stale_canary(actor="migration")

        self.assertTrue(result["ok"])
        opened.assert_called_once()
        self.assertEqual(declared.call_count, 2)
        payload = json.loads(next(self.shadow_root.glob("stale-canary-*.json")).read_text(encoding="utf-8"))
        self.assertEqual(payload["identified_before_live_verification"], 1)
        self.assertEqual(payload["remaining_after_live_verification"], 0)
        self.assertNotIn("shadow-canary-", json.dumps(payload))

    def test_cutover_config_is_exactly_reconstructable_and_tamper_evident(self) -> None:
        original = b"""[observability]\nstale_adoption_enforcement = \"shadow\"\nmetadata_enforcement = \"shadow\"\n\n[semantic_retrieval]\nranking_version = \"hybrid-v2-shadow\"\n"""
        backup = self.config_root / "backups" / "before-cutover.toml"
        backup.parent.mkdir(mode=0o700)
        backup.write_bytes(original)
        evidence_payload = {
            "schema_version": 1,
            "kind": "cutover-gate",
            "status": "passed",
            "production_config_sha256": hashlib.sha256(original).hexdigest(),
            **shadow.runtime_binding(),
        }
        evidence, evidence_sha = shadow._exclusive_json("cutover-gate", evidence_payload)
        fields = {
            "evidence_sha256": evidence_sha,
            "evidence_file": str(evidence),
            "backup_file": str(backup),
            "from_config_sha256": hashlib.sha256(original).hexdigest(),
            "shadow_started_at": "2026-08-01T00:00:00+00:00",
            "runtime_installed_at": shadow.runtime_binding()["runtime_installed_at"],
            "manifest_sha256": shadow.runtime_binding()["manifest_sha256"],
            "cutover_at": "2026-08-08T00:00:01+00:00",
        }
        migrated = shadow.render_cutover_config(original, **fields)
        payload = tomllib.loads(migrated.decode("utf-8"))
        verified = shadow.verify_cutover_config(
            migrated,
            payload,
            expected_config_sha256=hashlib.sha256(original).hexdigest(),
        )
        self.assertTrue(verified["ok"])
        self.assertFalse(shadow.verify_cutover_config(
            migrated.replace(b'hybrid-v2"', b'hybrid-v1"'),
            payload,
            expected_config_sha256=hashlib.sha256(original).hexdigest(),
        )["ok"])

    def test_search_hybrid_v2_requires_cutover_or_internal_benchmark_capability(self) -> None:
        args = argparse.Namespace(
            query="fixture", limit=5, semantic_mode="off", no_zvec=True, force_rg=False,
            ranking_version="hybrid-v2", no_log=True, agent_scope="", track="",
            memory_type="", user_id="", agent_id="", app_id="", session_id="",
            project_id="", current_project="", status="", has_open_loop=False,
            include_inactive=False, include_superseded=False, include_supporting=False,
            cross_project=False,
        )
        with mock.patch.object(search, "sqlite_search", return_value=([], [])), mock.patch.object(
            search.shadow_gate, "cutover_active", return_value=False
        ):
            with self.assertRaisesRegex(shadow.ShadowGateError, "HYBRID_V2_CUTOVER"):
                search.run_search(args)
            args._shadow_benchmark_bypass = True
            rows, _warnings, _failed = search.run_search(args)
        self.assertEqual(rows, [])

    def test_config_cas_rejects_race_without_overwriting(self) -> None:
        target = self.config_root / "config" / "agent-memory.toml"
        target.write_bytes(b"concurrent\n")
        target.chmod(0o600)
        with mock.patch.object(shadow, "config_path", return_value=target), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_CONFIG_CAS_MISMATCH"
        ):
            shadow._atomic_config(b"migrated\n", expected=b"original\n")
        self.assertEqual(target.read_bytes(), b"concurrent\n")

    def test_rollback_restores_only_exact_published_private_backup(self) -> None:
        with mock.patch.object(shadow, "load_config", side_effect=self.load_test_config):
            original, migrated, _backup = self.activate_cutover_fixture()
            rollback_copy = self.config_root / "backups" / "before-rollback.toml"
            result = shadow.rollback(actor="migration", backup_path=str(rollback_copy))

        self.assertTrue(result["ok"])
        self.assertEqual(self.config_file.read_bytes(), original)
        self.assertEqual(rollback_copy.read_bytes(), migrated)
        self.assertEqual(rollback_copy.stat().st_mode & 0o777, 0o600)
        with mock.patch.object(shadow, "load_config", side_effect=self.load_test_config):
            self.assertFalse(shadow.cutover_active())
        self.assertEqual(len(list(self.shadow_root.glob("cutover-rollback-*.json"))), 1)

    def test_rollback_rejects_tampered_source_backup_without_writing(self) -> None:
        with mock.patch.object(shadow, "load_config", side_effect=self.load_test_config):
            _original, migrated, backup = self.activate_cutover_fixture()
            backup.write_bytes(b"tampered\n")
            backup.chmod(0o600)
            shadow.reset_config_cache()

            with self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_CUTOVER_NOT_ACTIVE"):
                shadow.rollback(
                    actor="migration",
                    backup_path=str(self.config_root / "backups" / "unused.toml"),
                )

        self.assertEqual(self.config_file.read_bytes(), migrated)
        self.assertFalse((self.config_root / "backups" / "unused.toml").exists())

    def test_rollback_reverts_cutover_if_post_restore_validation_fails(self) -> None:
        with mock.patch.object(shadow, "load_config", side_effect=self.load_test_config):
            _original, migrated, _backup = self.activate_cutover_fixture()
        rollback_copy = self.config_root / "backups" / "before-failed-rollback.toml"
        calls = 0

        def drift_after_restore() -> dict[str, object]:
            nonlocal calls
            calls += 1
            payload = self.load_test_config()
            if calls >= 3:
                payload = dict(payload)
                payload["semantic_retrieval"] = {"ranking_version": "hybrid-v1"}
            return payload

        with mock.patch.object(shadow, "load_config", side_effect=drift_after_restore), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_ROLLBACK_REVERTED"
        ):
            shadow.rollback(actor="migration", backup_path=str(rollback_copy))

        self.assertEqual(self.config_file.read_bytes(), migrated)
        shadow.reset_config_cache()
        with mock.patch.object(shadow, "load_config", side_effect=self.load_test_config):
            self.assertTrue(shadow.cutover_active())

    def test_shadow_metrics_rejects_symlink_state_db(self) -> None:
        target = self.config_root / "actual.sqlite"
        target.write_bytes(b"not-a-db")
        target.chmod(0o600)
        self.state_db.symlink_to(target)
        with self.assertRaisesRegex(shadow.ShadowGateError, "SHADOW_STATE_DB_UNSAFE"):
            shadow._shadow_metrics("2026-08-01T00:00:00+00:00")

    def test_configured_shadow_directory_cannot_escape_private_runtime(self) -> None:
        outside = self.root / "outside-shadow"
        with mock.patch.object(shadow, "SHADOW_ROOT", outside), self.assertRaisesRegex(
            shadow.ShadowGateError, "SHADOW_DIRECTORY_OUTSIDE_PRIVATE_RUNTIME"
        ):
            shadow._exclusive_json("shadow-start", {"schema_version": 1})
        self.assertFalse(outside.exists())

    def test_shadow_metrics_counts_each_regression_once_from_private_read_only_db(self) -> None:
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                """CREATE TABLE memory_search_log(
                id INTEGER PRIMARY KEY, query TEXT, used_paths TEXT, task_id TEXT,
                actor TEXT, sources TEXT, required_case_regression_count INTEGER,
                worker_status TEXT, worker_restart_count INTEGER,
                metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                metadata_reason_fingerprint TEXT, created_at TEXT)"""
            )
            conn.executemany(
                "INSERT INTO memory_search_log VALUES(NULL, '', '', ?, 'codex', 'sqlite', ?, "
                "'reused', 0, 'shadow', 0, '', ?)",
                (("a" * 64, 1, "2026-08-02T00:00:00+00:00"), ("b" * 64, 2, "2026-08-03T00:00:00+00:00")),
            )
            conn.execute(
                "CREATE TABLE memory_use_events(id INTEGER PRIMARY KEY, task_id TEXT, actor TEXT, "
                "event_type TEXT, source TEXT, created_at TEXT)"
            )
            conn.executemany(
                "INSERT INTO memory_use_events VALUES(NULL, ?, 'codex', 'task_seen', 'tool_observed', ?)",
                (
                    ("a" * 64, "2026-08-02T00:00:00+00:00"),
                    ("b" * 64, "2026-08-03T00:00:00+00:00"),
                ),
            )
            conn.commit()
        self.state_db.chmod(0o600)
        result = shadow._shadow_metrics("2026-08-01T00:00:00+00:00")
        self.assertEqual(result["searches"], 2)
        self.assertEqual(result["required_regressions"], 3)
        self.assertEqual(result["missing_task_denominator"], 0)
        self.assertEqual(result["real_task_count"], 2)

    def test_candidate_disposition_metrics_are_prospective_and_completion_bound(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            conn.executescript(
                """
                CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO meta VALUES(
                  'disposition_tracking_enabled_at',
                  '2026-08-01T00:00:00+00:00'
                );
                CREATE TABLE memory_use_events(
                  id INTEGER PRIMARY KEY,
                  actor TEXT,
                  task_id TEXT,
                  event_type TEXT,
                  source TEXT,
                  value TEXT,
                  memory_ids_json TEXT,
                  memory_versions_json TEXT,
                  created_at TEXT
                );
                """
            )
            task_id = "a" * 64
            memory_id = "b" * 64
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'search_completed',"
                "'tool_observed','success',?,'[]','2026-08-02T00:00:00+00:00')",
                (task_id, json.dumps([memory_id])),
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'task_completed',"
                "'tool_observed','success','[]','[]','2026-08-02T00:01:00+00:00')",
                (task_id,),
            )
            missing = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'adoption_declared',"
                "'agent_declared','rejected',?,'[]','2026-08-02T00:02:00+00:00')",
                (task_id, json.dumps([memory_id])),
            )
            resolved = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )

            # Reusing one host task/session creates a later lifecycle. Neither
            # the old completion nor the old disposition can cover it.
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'search_completed',"
                "'tool_observed','success',?,'[]','2026-08-02T00:03:00+00:00')",
                (task_id, json.dumps([memory_id])),
            )
            in_flight = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'task_completed',"
                "'tool_observed','failure','[]','[]','2026-08-02T00:04:00+00:00')",
                (task_id,),
            )
            failed_cycle = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'task_completed',"
                "'tool_observed','success','[]','[]','2026-08-02T00:05:00+00:00')",
                (task_id,),
            )
            later_missing = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'adoption_declared',"
                "'agent_declared','rejected',?,'[]','2026-08-02T00:06:00+00:00')",
                (task_id, json.dumps([memory_id])),
            )
            later_resolved = shadow._candidate_disposition_metrics(
                conn,
                started_at="2026-08-01T00:00:00+00:00",
            )

        self.assertEqual(missing["returned_without_disposition"], 1)
        self.assertEqual(missing["tasks_with_missing_disposition"], 1)
        self.assertEqual(resolved["returned_without_disposition"], 0)
        self.assertEqual(resolved["tasks_with_missing_disposition"], 0)
        self.assertEqual(in_flight["returned_without_disposition"], 0)
        self.assertEqual(failed_cycle["returned_without_disposition"], 0)
        self.assertEqual(later_missing["returned_without_disposition"], 1)
        self.assertEqual(later_resolved["returned_without_disposition"], 0)

    def test_declared_success_does_not_close_shadow_candidate_cycle(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as conn:
            conn.row_factory = sqlite3.Row
            conn.executescript(
                """
                CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO meta VALUES(
                  'disposition_tracking_enabled_at',
                  '2026-08-01T00:00:00+00:00'
                );
                CREATE TABLE memory_use_events(
                  id INTEGER PRIMARY KEY, actor TEXT, task_id TEXT,
                  event_type TEXT, source TEXT, value TEXT,
                  memory_ids_json TEXT, memory_versions_json TEXT,
                  created_at TEXT
                );
                """
            )
            task_id = "c" * 64
            memory_id = "d" * 64
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'search_completed',"
                "'tool_observed','success',?,'[]','2026-08-02T00:00:00+00:00')",
                (task_id, json.dumps([memory_id])),
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'task_completed',"
                "'agent_declared','success','[]','[]','2026-08-02T00:01:00+00:00')",
                (task_id,),
            )
            declared = shadow._candidate_disposition_metrics(
                conn, started_at="2026-08-01T00:00:00+00:00"
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL,'codex',?,'task_completed',"
                "'tool_observed','success','[]','[]','2026-08-02T00:02:00+00:00')",
                (task_id,),
            )
            stopped = shadow._candidate_disposition_metrics(
                conn, started_at="2026-08-01T00:00:00+00:00"
            )

        self.assertEqual(declared["returned_without_disposition"], 0)
        self.assertEqual(stopped["returned_without_disposition"], 1)

    def test_shadow_metrics_rejects_even_redacted_query_placeholders(self) -> None:
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                """CREATE TABLE memory_search_log(
                id INTEGER PRIMARY KEY, query TEXT, used_paths TEXT, task_id TEXT,
                actor TEXT, sources TEXT, required_case_regression_count INTEGER,
                worker_status TEXT, worker_restart_count INTEGER,
                metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                metadata_reason_fingerprint TEXT, created_at TEXT)"""
            )
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL, ?, '', ?, 'codex', 'sqlite', 0, "
                "'reused', 0, 'shadow', 0, '', ?)",
                ("[redacted:0123456789ab]", "a" * 64, "2026-08-02T00:00:00+00:00"),
            )
            conn.execute(
                "CREATE TABLE memory_use_events(id INTEGER PRIMARY KEY, task_id TEXT, actor TEXT, "
                "event_type TEXT, source TEXT, created_at TEXT)"
            )
            conn.commit()
        self.state_db.chmod(0o600)
        result = shadow._shadow_metrics("2026-08-01T00:00:00+00:00")
        self.assertEqual(result["privacy_violations"], 1)

    def test_shadow_metrics_excludes_synthetic_and_detects_semantic_streak_without_restart(self) -> None:
        fingerprint = "f" * 64
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                """CREATE TABLE memory_search_log(
                id INTEGER PRIMARY KEY, query TEXT, used_paths TEXT, task_id TEXT,
                actor TEXT, sources TEXT, required_case_regression_count INTEGER,
                worker_status TEXT, worker_restart_count INTEGER,
                metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                metadata_reason_fingerprint TEXT, created_at TEXT)"""
            )
            conn.executemany(
                "INSERT INTO memory_search_log VALUES(NULL, '', '', ?, ?, ?, 0, ?, 0, 'shadow', ?, ?, ?)",
                (
                    ("a" * 64, "migration", "hybrid_benchmark", "failed", 9, fingerprint, "2026-08-02T00:00:00+00:00"),
                    ("b" * 64, "codex", "sqlite,zvec", "failed", 0, "", "2026-08-03T00:00:00+00:00"),
                    ("b" * 64, "codex", "sqlite,zvec", "degraded", 1, fingerprint, "2026-08-04T00:00:00+00:00"),
                ),
            )
            conn.execute(
                "CREATE TABLE memory_use_events(id INTEGER PRIMARY KEY, task_id TEXT, actor TEXT, "
                "event_type TEXT, source TEXT, created_at TEXT)"
            )
            conn.executemany(
                "INSERT INTO memory_use_events VALUES(NULL, ?, ?, 'source_opened', 'tool_observed', ?)",
                (
                    ("c" * 64, "codex", "2026-08-05T00:00:00+00:00"),
                    ("d" * 64, "test", "2026-08-05T00:00:00+00:00"),
                ),
            )
            conn.executemany(
                "INSERT INTO memory_use_events VALUES(NULL, ?, 'codex', 'task_seen', 'tool_observed', ?)",
                (
                    ("b" * 64, "2026-08-03T00:00:00+00:00"),
                    ("c" * 64, "2026-08-05T00:00:00+00:00"),
                ),
            )
            conn.commit()
        self.state_db.chmod(0o600)
        result = shadow._shadow_metrics("2026-08-01T00:00:00+00:00")
        self.assertEqual(result["real_searches"], 2)
        self.assertEqual(result["real_task_count"], 2)
        self.assertEqual(result["semantic_failure_streaks"], 1)
        self.assertEqual(result["metadata_would_block_count"], 1)

    def test_shadow_metrics_requires_task_seen_for_same_actor_and_task_hash(self) -> None:
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                """CREATE TABLE memory_search_log(
                id INTEGER PRIMARY KEY, query TEXT, used_paths TEXT, task_id TEXT,
                actor TEXT, sources TEXT, required_case_regression_count INTEGER,
                worker_status TEXT, worker_restart_count INTEGER,
                metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                metadata_reason_fingerprint TEXT, created_at TEXT)"""
            )
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL, '', '', ?, 'codex', 'sqlite', 0, "
                "'reused', 0, 'shadow', 0, '', ?)",
                ("a" * 64, "2026-08-02T00:00:00+00:00"),
            )
            conn.execute(
                "CREATE TABLE memory_use_events(id INTEGER PRIMARY KEY, task_id TEXT, actor TEXT, "
                "event_type TEXT, source TEXT, created_at TEXT)"
            )
            # Same opaque task hash under another actor is not this task's
            # denominator and must not make the Codex search look healthy.
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL, ?, 'claude', 'task_seen', "
                "'tool_observed', ?)",
                ("a" * 64, "2026-08-02T00:00:00+00:00"),
            )
            conn.commit()
        self.state_db.chmod(0o600)
        result = shadow._shadow_metrics("2026-08-01T00:00:00+00:00")
        self.assertEqual(result["missing_task_denominator"], 1)
        self.assertEqual(result["real_searches"], 0)
        self.assertEqual(result["real_task_count"], 0)

    def test_shadow_metrics_accepts_pre_window_task_seen_for_in_window_search(self) -> None:
        with contextlib.closing(sqlite3.connect(self.state_db)) as conn:
            conn.execute(
                """CREATE TABLE memory_search_log(
                id INTEGER PRIMARY KEY, query TEXT, used_paths TEXT, task_id TEXT,
                actor TEXT, sources TEXT, required_case_regression_count INTEGER,
                worker_status TEXT, worker_restart_count INTEGER,
                metadata_gate_mode TEXT, metadata_would_block_count INTEGER,
                metadata_reason_fingerprint TEXT, created_at TEXT)"""
            )
            conn.execute(
                "INSERT INTO memory_search_log VALUES(NULL, '', '', ?, 'codex', 'sqlite', 0, "
                "'reused', 0, 'shadow', 0, '', ?)",
                ("a" * 64, "2026-08-02T00:00:00+00:00"),
            )
            conn.execute(
                "CREATE TABLE memory_use_events(id INTEGER PRIMARY KEY, task_id TEXT, actor TEXT, "
                "event_type TEXT, source TEXT, created_at TEXT)"
            )
            conn.execute(
                "INSERT INTO memory_use_events VALUES(NULL, ?, 'codex', 'task_seen', "
                "'tool_observed', ?)",
                ("a" * 64, "2026-07-31T00:00:00+00:00"),
            )
            conn.commit()
        self.state_db.chmod(0o600)

        result = shadow._shadow_metrics("2026-08-01T00:00:00+00:00")

        self.assertEqual(result["missing_task_denominator"], 0)
        self.assertEqual(result["real_searches"], 1)
        self.assertEqual(result["real_task_count"], 1)


if __name__ == "__main__":
    unittest.main()
