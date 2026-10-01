#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import time
import unicodedata
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any


SCRIPT_ROOT = Path(__file__).resolve().parents[0]
RUNTIME_ROOT = SCRIPT_ROOT.parent
DEFAULT_LIMIT = 5
DEFAULT_LOCK_TIMEOUT = 2.0
DEFAULT_BENCHMARK_FILE = RUNTIME_ROOT / "benchmarks" / "public-sample.json"
MAX_DATASET_BYTES = 2 * 1024 * 1024
MAX_CASES = 200
MAX_QUERY_CHARS = 20_000
MANDATORY_AUTO_ARCHIVE_QUERY = "Codex 每次对话结束怎么自动归档"
MANDATORY_AUTO_ARCHIVE_EXPECTED = "工作流/Agent记忆收尾决策规则.md"


class DatasetError(ValueError):
    """A stable, content-free benchmark input error."""


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot_load_module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_expected_path(raw: object) -> str:
    if not isinstance(raw, str):
        raise DatasetError("case_expected_paths_must_be_strings")
    value = str(raw).strip()
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or path.suffix.lower() != ".md":
        raise DatasetError("case_expected_must_be_safe_relative_markdown_path")
    return path.as_posix()


def load_dataset(path: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        selected = Path(path).expanduser().resolve() if path else DEFAULT_BENCHMARK_FILE.resolve()
        raw_data = selected.read_bytes()
    except (OSError, RuntimeError, ValueError) as exc:
        raise DatasetError("dataset_unreadable") from exc
    if len(raw_data) > MAX_DATASET_BYTES:
        raise DatasetError("dataset_too_large")
    try:
        data = json.loads(raw_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetError("dataset_invalid_json") from exc
    if isinstance(data, list):
        metadata: dict[str, object] = {
            "schema_version": 0,
            "name": selected.stem,
            "privacy": "private_local" if path else "public_sample",
            "legacy_array": True,
        }
        raw_cases = data
    elif isinstance(data, dict) and isinstance(data.get("cases"), list):
        declared_privacy = str(data.get("privacy") or "private_local")
        if declared_privacy not in {"public_sample", "private_local"}:
            raise DatasetError("dataset_privacy_is_unsupported")
        try:
            schema_version = int(data.get("schema_version") or 1)
        except (TypeError, ValueError) as exc:
            raise DatasetError("dataset_schema_version_is_invalid") from exc
        metadata = {
            "schema_version": schema_version,
            "name": str(data.get("name") or selected.stem),
            # An explicitly supplied file is outside the bundled trust
            # boundary.  It cannot opt itself into public output merely by
            # declaring `privacy: public_sample` inside its own contents.
            "privacy": "private_local" if path else declared_privacy,
            "declared_privacy": declared_privacy,
            "legacy_array": False,
        }
        raw_cases = data["cases"]
    else:
        raise DatasetError("dataset_requires_array_or_object_with_cases")
    if metadata["privacy"] not in {"public_sample", "private_local"}:
        raise DatasetError("dataset_privacy_is_unsupported")
    if not raw_cases or len(raw_cases) > MAX_CASES:
        raise DatasetError("dataset_case_count_is_invalid")
    cases: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for item in raw_cases:
        if not isinstance(item, dict) or "id" not in item or "query" not in item or "expected" not in item:
            raise DatasetError("case_requires_id_query_expected")
        if not isinstance(item["id"], str) or not isinstance(item["query"], str):
            raise DatasetError("case_id_and_query_must_be_strings")
        case_id = item["id"].strip()
        query = item["query"].strip()
        expected_raw = item["expected"]
        if not case_id or case_id in seen_ids:
            raise DatasetError("case_ids_must_be_unique_and_nonempty")
        if not query or not isinstance(expected_raw, list) or not expected_raw:
            raise DatasetError("case_query_and_expected_must_be_nonempty")
        if len(query) > MAX_QUERY_CHARS:
            raise DatasetError("case_query_too_large")
        required_at_raw = item.get("required_at")
        try:
            required_at = int(required_at_raw) if required_at_raw not in (None, "") else 0
        except (TypeError, ValueError) as exc:
            raise DatasetError("case_required_at_is_invalid") from exc
        if required_at < 0 or required_at > 100:
            raise DatasetError("case_required_at_must_be_between_0_and_100")
        current_project = str(item.get("current_project") or "").strip()
        if len(current_project) > 160 or "\x00" in current_project:
            raise DatasetError("case_current_project_is_invalid")
        seen_ids.add(case_id)
        cases.append(
            {
                "id": case_id,
                "query": query,
                "expected": [validate_expected_path(value) for value in expected_raw],
                "required_at": required_at,
                "current_project": current_project,
                "tags": [str(value) for value in item.get("tags", [])] if isinstance(item.get("tags", []), list) else [],
            }
        )
    metadata["path"] = (
        str(selected)
        if path
        else selected.relative_to(RUNTIME_ROOT.resolve()).as_posix()
    )
    metadata["sha256"] = hashlib.sha256(raw_data).hexdigest()
    return metadata, cases


def output_dataset_metadata(dataset: dict[str, object], *, private_redacted: bool) -> dict[str, object]:
    if not private_redacted:
        return dict(dataset)
    # Do not emit a user-selected absolute path or self-declared dataset name.
    # A content hash is sufficient to identify the exact private fixture run.
    return {
        "schema_version": dataset.get("schema_version", 0),
        "privacy": "private_local",
        "legacy_array": bool(dataset.get("legacy_array", False)),
        "sha256": dataset.get("sha256", ""),
    }


def redacted_case_ref(case_id: object, ordinal: int) -> str:
    digest = hashlib.sha256(str(case_id).encode("utf-8")).hexdigest()[:12]
    return f"case-{ordinal:03d}-{digest}"


def normalized_query(value: object) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).split()).casefold()


def required_case_set_sha256(cases: list[dict[str, object]]) -> str:
    """Bind the complete required set without persisting ids, queries, or paths."""

    rows: list[dict[str, object]] = []
    for case in cases:
        required_at = int(case.get("required_at") or 0)
        if required_at <= 0:
            continue
        rows.append({
            "id_sha256": hashlib.sha256(str(case["id"]).encode("utf-8")).hexdigest(),
            "query_sha256": hashlib.sha256(str(case["query"]).encode("utf-8")).hexdigest(),
            "expected_sha256": [
                hashlib.sha256(str(value).encode("utf-8")).hexdigest()
                for value in sorted(str(value) for value in case["expected"])  # type: ignore[index]
            ],
            "required_at": required_at,
        })
    raw = json.dumps(
        sorted(rows, key=lambda row: (str(row["id_sha256"]), str(row["query_sha256"]))),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def is_mandatory_auto_archive_case(case: dict[str, object]) -> bool:
    expected = {
        str(value) for value in case.get("expected", [])
    } if isinstance(case.get("expected"), list) else set()
    return (
        int(case.get("required_at") or 0) in range(1, 6)
        and normalized_query(case.get("query")) == normalized_query(MANDATORY_AUTO_ARCHIVE_QUERY)
        and MANDATORY_AUTO_ARCHIVE_EXPECTED in expected
    )


def first_hit_rank(results: list[str], expected: list[str]) -> int | None:
    expected_set = set(expected)
    for index, rel_path in enumerate(results, 1):
        if rel_path in expected_set:
            return index
    return None


def metrics(ranks: list[int | None]) -> dict[str, float]:
    total = len(ranks) or 1
    return {
        "cases": len(ranks),
        "hit@1": sum(1 for rank in ranks if rank is not None and rank <= 1) / total,
        "hit@3": sum(1 for rank in ranks if rank is not None and rank <= 3) / total,
        "hit@5": sum(1 for rank in ranks if rank is not None and rank <= 5) / total,
        "mrr": sum((1 / rank) for rank in ranks if rank is not None) / total,
    }


def worst_rank(ranks: list[int | None]) -> int | None:
    return None if not ranks or any(rank is None for rank in ranks) else max(int(rank) for rank in ranks)


def p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) * 0.95) + 0.999999) - 1))
    return round(ordered[index], 3)


def format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def readonly_sqlite_connection(sqlite_index: Any) -> sqlite3.Connection:
    """Open the derived state without WAL setup, schema writes, or creation."""

    return sqlite_index.secure_sqlite_connect(
        Path(sqlite_index.STATE_DB).expanduser().resolve(),
        create=False,
        read_only=True,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )


def run_sqlite(sqlite_index: Any, query: str, limit: int) -> list[str]:
    with readonly_sqlite_connection(sqlite_index) as conn:
        sqlite_index.assert_schema_ready(conn)
        rows = sqlite_index.search(conn, query, limit)
    return [str(row["rel_path"]) for row in rows]


def runtime_semantic_binding(zvec_index: Any) -> tuple[argparse.Namespace, dict[str, object]]:
    """Resolve the exact configured model/revision/manifest identity."""

    binding_args = argparse.Namespace(
        model=str(zvec_index.DEFAULT_MODEL),
        model_revision=str(zvec_index.DEFAULT_MODEL_REVISION),
        model_manifest=str(Path(zvec_index.DEFAULT_MODEL_MANIFEST).expanduser().resolve()),
        embedding_dim=int(zvec_index.DEFAULT_EMBEDDING_DIM),
        require_local_model=bool(zvec_index.DEFAULT_REQUIRE_LOCAL_MODEL),
        device=str(zvec_index.DEFAULT_DEVICE),
        cache_folder="",
    )
    binding = zvec_index.resolve_embedding_binding(binding_args)
    if not isinstance(binding, dict) or not str(binding.get("binding_id") or ""):
        raise RuntimeError("BENCHMARK_MODEL_BINDING_INVALID")
    snapshot = {
        "model": binding_args.model,
        "model_revision": binding_args.model_revision,
        "model_manifest": binding_args.model_manifest,
        "model_manifest_sha256": str(binding.get("model_manifest_sha256") or ""),
        "embedding_dim": int(binding_args.embedding_dim),
        "require_local_model": bool(binding_args.require_local_model),
        "binding_id": str(binding["binding_id"]),
    }
    return binding_args, snapshot


def isolated_worker_socket_base() -> Path:
    """Return a fresh socket namespace that cannot select the live Worker."""

    import agent_memory_embedding_worker as embedding_worker

    production_base = Path(embedding_worker.DEFAULT_SOCKET_BASE).expanduser().resolve()
    suffix = production_base.suffix or ".sock"
    return production_base.with_name(
        f"{production_base.stem}-bench-{uuid.uuid4().hex[:12]}{suffix}"
    )


@contextmanager
def isolated_worker_environment(socket_base: Path):
    """Route benchmark subprocesses to one private, invocation-scoped Worker."""

    key = "AGENT_MEMORY_EMBEDDING_WORKER_SOCKET"
    previous = os.environ.get(key)
    os.environ[key] = str(Path(socket_base).expanduser().resolve())
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def shutdown_isolated_worker(
    binding_args: argparse.Namespace,
    socket_base: Path,
) -> bool:
    """Stop only the benchmark namespace; never inspect the live socket."""

    import agent_memory_embedding_worker as embedding_worker

    return embedding_worker.shutdown_worker(
        model=str(binding_args.model),
        revision=str(binding_args.model_revision),
        embedding_dim=int(binding_args.embedding_dim),
        socket_base=Path(socket_base).expanduser().resolve(),
        model_manifest=Path(binding_args.model_manifest).expanduser().resolve(),
        timeout=2.0,
    )


def run_vector(
    zvec_index: Any,
    vector_conn: Any,
    store: Any,
    embedder: Any,
    query: str,
    limit: int,
    *,
    lock_timeout: float,
    binding_id: str,
) -> list[str]:
    # Model loading and query embedding can take seconds on a cold start. It
    # must never hold the native collection lock or block an index writer.
    query_embedding = embedder.embed_query(query)
    with zvec_index.zvec_lock(
        exclusive=False,
        timeout=max(float(lock_timeout), 0.0),
    ):
        try:
            store.open_existing()
            scored_ids = store.search(query_embedding, max(limit * 12, limit))
        finally:
            # The native collection owns its own process-level directory lock.
            # Its lifetime must be strictly contained by the shared lock so a
            # following Hybrid subprocess can open the same collection.
            store.close()
    rows = zvec_index.vector_rows(
        vector_conn,
        scored_ids,
        query,
        expected_embedding_binding=binding_id,
    )[:limit]
    return [str(row["rel_path"]) for row in rows]


def _production_search_namespace(
    query: str,
    limit: int,
    *,
    semantic_mode: str,
) -> argparse.Namespace:
    import agent_memory_search as production_search

    return argparse.Namespace(
        query=query,
        limit=max(limit, 1),
        ranking_version="hybrid-v2",
        semantic_mode=semantic_mode,
        no_zvec=semantic_mode == "off",
        no_log=True,
        force_rg=False,
        zvec_timeout=14.0,
        zvec_lock_timeout=production_search.DEFAULT_ZVEC_LOCK_TIMEOUT,
        worker_cold_timeout=production_search.DEFAULT_WORKER_COLD_TIMEOUT,
        worker_warm_timeout=production_search.DEFAULT_WORKER_WARM_TIMEOUT,
        worker_idle_seconds=production_search.DEFAULT_WORKER_IDLE_SECONDS,
        zvec_max_distance=production_search.DEFAULT_ZVEC_MAX_DISTANCE,
        candidate_pool_min=production_search.DEFAULT_CANDIDATE_POOL_MIN,
        candidate_pool_factor=production_search.DEFAULT_CANDIDATE_POOL_FACTOR,
        candidate_pool_scope_min=production_search.DEFAULT_CANDIDATE_POOL_SCOPE_MIN,
        candidate_pool_max=production_search.DEFAULT_CANDIDATE_POOL_MAX,
        rg_timeout=15,
        track="",
        memory_type="",
        project_id="",
        current_project="",
        cross_project=False,
        as_of="",
        user_id="",
        agent_id="",
        agent_scope="",
        app_id="",
        session_id="",
        status="",
        has_open_loop=False,
        include_inactive=False,
        include_supporting=False,
        include_superseded=False,
        _shadow_benchmark_bypass=True,
    )


def run_hybrid(query: str, limit: int, *, current_project: str = "") -> tuple[list[str], dict[str, Any]]:
    import agent_memory_search as production_search

    args = _production_search_namespace(
        query,
        limit,
        semantic_mode=production_search.DEFAULT_SEMANTIC_MODE,
    )
    args.current_project = current_project
    rows, warnings, all_failed = production_search.run_search(args)
    return [row.rel_path for row in rows], {
        "ranking_version": getattr(args, "_effective_ranking_version", "hybrid-v2"),
        "backend_status": dict(getattr(args, "_backend_status", {})),
        "degraded": bool(getattr(args, "_degraded", False)),
        "all_failed": bool(all_failed),
        "warning_count": len(warnings),
        "v1_result_memory_ids": list(getattr(args, "_v1_result_memory_ids", [])),
        "v2_result_memory_ids": list(getattr(args, "_shadow_result_memory_ids", [])),
        "worker_status": str(getattr(args, "_worker_status", "not_used")),
        "worker_restart_count": int(getattr(args, "_worker_restart_count", 0) or 0),
    }


def run_canonical(query: str, limit: int, *, current_project: str = "") -> tuple[list[str], dict[str, Any]]:
    import agent_memory_retrieve as canonical_retrieve

    # Canonical Retrieve intentionally follows the production config. During
    # the benchmark only, bind its in-process search namespace to the exact v2
    # candidate implementation. There is no CLI/environment bypass to reuse.
    original_namespace = canonical_retrieve._search_namespace

    def benchmark_namespace(*args: Any, **kwargs: Any) -> argparse.Namespace:
        namespace = original_namespace(*args, **kwargs)
        namespace.ranking_version = "hybrid-v2"
        namespace._shadow_benchmark_bypass = True
        return namespace

    canonical_retrieve._search_namespace = benchmark_namespace
    try:
        payload = canonical_retrieve.retrieve(
            # Exercise the real Codex scope while an in-process identity-only
            # capability suppresses ordinary task/adoption observations.  The
            # public Retrieve CLI cannot construct or submit this capability.
            actor="codex",
            app_id="",
            project_id="",
            current_project=current_project,
            query=query,
            max_results=max(limit, 1),
            max_file_bytes=canonical_retrieve.DEFAULT_MAX_FILE_BYTES,
            max_total_bytes=canonical_retrieve.DEFAULT_MAX_TOTAL_BYTES,
            max_excerpt_bytes=canonical_retrieve.DEFAULT_MAX_EXCERPT_BYTES,
            semantic_mode=canonical_retrieve.memory_search.DEFAULT_SEMANTIC_MODE,
            _observation_capability=(
                canonical_retrieve._SYNTHETIC_BENCHMARK_CAPABILITY
            ),
        )
    finally:
        canonical_retrieve._search_namespace = original_namespace
    return [str(row["relative_path"]) for row in payload.get("results", [])], {
        "ranking_version": payload.get("ranking_version", ""),
        "backend_status": payload.get("backend_status", {}),
        "degraded": bool(payload.get("degraded", False)),
        "warning_count": len(payload.get("warnings", [])),
    }


def record_required_shadow_observation(
    query: str,
    rel_paths: list[str],
    metadata: dict[str, Any],
    *,
    duration_ms: int,
    regression_count: int,
) -> bool:
    """Persist only fingerprints/counters for one benchmark Hybrid run."""

    if "v1_result_memory_ids" not in metadata or "v2_result_memory_ids" not in metadata:
        return False
    try:
        import agent_memory_search as production_search

        v1_ids = [str(value) for value in metadata.get("v1_result_memory_ids", [])]
        v2_ids = [str(value) for value in metadata.get("v2_result_memory_ids", [])]
        with production_search.connect() as conn:
            # A benchmark is an ordinary production read/observation, never a
            # schema migration route.  Index schema 13 (including explicit
            # risk metadata) must already have been installed under the
            # backed-up migration capability.
            production_search.memory_index.assert_schema_ready(conn)
            production_search.observability.record_benchmark_search(
                conn,
                query=query,
                rel_paths=rel_paths,
                memory_ids=v2_ids,
                duration_ms=max(int(duration_ms), 0),
                search_status="success" if not metadata.get("degraded") else "partial",
                v1_result_fingerprint=hashlib.sha256("\0".join(v1_ids).encode("utf-8")).hexdigest(),
                v2_result_fingerprint=hashlib.sha256("\0".join(v2_ids).encode("utf-8")).hexdigest(),
                required_case_regression_count=max(int(regression_count), 0),
                worker_status=str(metadata.get("worker_status") or "not_used"),
                worker_restart_count=min(max(int(metadata.get("worker_restart_count", 0) or 0), 0), 1),
            )
        return True
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare SQLite/FTS retrieval with optional Zvec semantic retrieval.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Top K used for hit@K and result display.")
    parser.add_argument("--json", action="store_true", help="Print JSON.")
    parser.add_argument("--no-vector", action="store_true", help="Only run SQLite baseline.")
    parser.add_argument("--case-id", action="append", default=[], help="Run only this benchmark case id. Repeatable.")
    parser.add_argument("--benchmark-file", default="", help="Optional JSON array of benchmark cases.")
    parser.add_argument("--runs", type=int, default=3, help="Consecutive repetitions required for stability evidence.")
    parser.add_argument(
        "--legacy-backends-only",
        action="store_false",
        dest="production_chain",
        default=True,
        help="Compatibility mode: skip Hybrid and Canonical Retrieve production-chain checks.",
    )
    parser.add_argument(
        "--lock-timeout",
        type=float,
        default=DEFAULT_LOCK_TIMEOUT,
        help="Seconds to wait for the serialized Zvec collection lock.",
    )
    parser.add_argument(
        "--show-private-details",
        action="store_true",
        help="Explicitly show private query text and paths. Private datasets are redacted by default.",
    )
    parser.add_argument(
        "--attest-success",
        action="store_true",
        help="Write a private manifest-bound success attestation (migration actor only).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if bool(getattr(args, "attest_success", False)) and list(getattr(args, "case_id", []) or []):
        payload = {"status": "error", "error": "success_attestation_forbids_case_selection"}
        print(
            json.dumps(payload, ensure_ascii=True, indent=2)
            if bool(getattr(args, "json", False))
            else "retrieval-benchmark=error success_attestation_forbids_case_selection"
        )
        return 2
    if not any(
        os.environ.get(name, "").strip()
        for name in (
            "AGENT_MEMORY_TASK_ID", "AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID",
            "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID",
        )
    ):
        # The raw nonce exists only in this process. Observability persists its
        # purpose-bound hash, giving maintenance benchmarks a task denominator
        # without retaining a session identifier.
        os.environ["AGENT_MEMORY_TASK_ID"] = "retrieval-benchmark-" + uuid.uuid4().hex
    limit = max(args.limit, 1)
    runs = min(max(int(getattr(args, "runs", 1) or 1), 1), 10)
    production_chain = bool(getattr(args, "production_chain", False)) and not bool(args.no_vector)
    try:
        dataset, loaded_cases = load_dataset(args.benchmark_file)
    except DatasetError as exc:
        payload = {"status": "error", "error": str(exc)}
        print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"retrieval-benchmark=error {exc}")
        return 2
    private_redacted = bool(args.benchmark_file) and not args.show_private_details
    if dataset.get("privacy") == "private_local" and not args.show_private_details:
        private_redacted = True
    case_ids = set(args.case_id)
    cases = [case for case in loaded_cases if not case_ids or str(case["id"]) in case_ids]
    if not cases:
        print("no_cases_selected", file=sys.stderr)
        return 1

    sqlite_index = load_module("agent_memory_index_module", SCRIPT_ROOT / "agent_memory_index.py")
    records: list[dict[str, object]] = []
    sqlite_ranks: list[int | None] = []
    vector_ranks: list[int | None] = []
    hybrid_ranks: list[int | None] = []
    canonical_ranks: list[int | None] = []
    latency_samples: dict[str, list[float]] = {
        "sqlite": [],
        "vector": [],
        "hybrid": [],
        "canonical_retrieve": [],
    }
    hybrid_worker_statuses: list[str] = []
    hybrid_worker_restart_count = 0

    for ordinal, case in enumerate(cases, 1):
        query = str(case["query"])
        expected = [str(item) for item in case["expected"]]  # type: ignore[index]
        sqlite_run_ranks: list[int | None] = []
        sqlite_results: list[str] = []
        for _run in range(runs):
            started = time.monotonic()
            sqlite_results = run_sqlite(sqlite_index, query, limit)
            latency_samples["sqlite"].append((time.monotonic() - started) * 1000)
            sqlite_run_ranks.append(first_hit_rank(sqlite_results, expected))
        sqlite_rank = worst_rank(sqlite_run_ranks)
        sqlite_ranks.append(sqlite_rank)
        records.append({
            "id": case["id"],
            "case_ref": redacted_case_ref(case["id"], ordinal),
            "query": query,
            "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "query_length": len(query),
            "expected": expected,
            "required_at": int(case.get("required_at") or 0),
            "sqlite_rank": sqlite_rank,
            "sqlite_results": sqlite_results,
            "sqlite_run_ranks": sqlite_run_ranks,
            "vector_rank": None,
            "vector_results": [],
            "vector_run_ranks": [],
            "hybrid_rank": None,
            "hybrid_results": [],
            "hybrid_run_ranks": [],
            "canonical_rank": None,
            "canonical_results": [],
            "canonical_run_ranks": [],
            "hybrid_degraded": False,
            "canonical_degraded": False,
            "shadow_observation_recorded": 0,
            "current_project": str(case.get("current_project") or ""),
        })

    vector_error = ""
    semantic_binding_args: argparse.Namespace | None = None
    if not args.no_vector:
        try:
            zvec_index = load_module("agent_memory_zvec_index_module", SCRIPT_ROOT / "agent_memory_zvec_index.py")
            vector_conn = zvec_index.connect(read_only=True)
            store: Any | None = None
            embedder: Any | None = None
            try:
                # Benchmarks are ordinary consumers of an installed index.
                # Schema creation and migration remain installer-only.
                zvec_index.assert_schema_ready(vector_conn)
                binding_args, binding_before = runtime_semantic_binding(zvec_index)
                semantic_binding_args = binding_args
                zvec_index.assert_index_binding(
                    vector_conn,
                    str(binding_before["binding_id"]),
                )
                store = zvec_index.ZvecStore(
                    zvec_index.DEFAULT_COLLECTION_PATH,
                    zvec_index.DEFAULT_EMBEDDING_DIM,
                )
                embedder = zvec_index.EmbeddingGemmaEmbedder(
                    binding_args.model,
                    binding_args.embedding_dim,
                    binding_args.device,
                    binding_args.cache_folder,
                    binding_args.require_local_model,
                    binding_args.model_revision,
                )
                for record in records:
                    vector_run_ranks: list[int | None] = []
                    vector_results: list[str] = []
                    for _run in range(runs):
                        started = time.monotonic()
                        vector_results = run_vector(
                            zvec_index,
                            vector_conn,
                            store,
                            embedder,
                            str(record["query"]),
                            limit,
                            lock_timeout=float(args.lock_timeout),
                            binding_id=str(binding_before["binding_id"]),
                        )
                        latency_samples["vector"].append((time.monotonic() - started) * 1000)
                        vector_run_ranks.append(
                            first_hit_rank(vector_results, list(record["expected"]))
                        )
                    vector_rank = worst_rank(vector_run_ranks)
                    vector_ranks.append(vector_rank)
                    record["vector_rank"] = vector_rank
                    record["vector_results"] = vector_results
                    record["vector_run_ranks"] = vector_run_ranks

                # Re-resolve the manifest and configured model after all model
                # work. A mid-run revision/manifest/config drift invalidates the
                # quality evidence instead of silently mixing identities.
                _final_args, binding_after = runtime_semantic_binding(zvec_index)
                if binding_after != binding_before:
                    raise RuntimeError("BENCHMARK_MODEL_BINDING_CHANGED")
                zvec_index.assert_index_binding(
                    vector_conn,
                    str(binding_after["binding_id"]),
                )
            finally:
                # Per-query cleanup happens inside run_vector's shared lock.
                # Keep an idempotent outer close for setup failures and future
                # control-flow changes before the real Hybrid subprocess runs.
                try:
                    if store is not None:
                        store.close()
                finally:
                    vector_conn.close()
                    # The independent Vector baseline has finished. Keeping
                    # its full model alive while cold-starting the real Worker
                    # doubles model residency and measures avoidable benchmark
                    # memory pressure rather than the production query path.
                    # Do not reuse its vectors/model to prewarm the Worker.
                    embedder = None
                    gc.collect()
        except Exception as exc:
            vector_error = str(exc)

    production_error = ""
    isolated_socket_base: Path | None = None
    isolated_worker_cleanup = "not_started"
    if production_chain and not vector_error:
        isolated_socket_base = isolated_worker_socket_base()
        try:
            with isolated_worker_environment(isolated_socket_base):
                for record in records:
                    hybrid_run_ranks: list[int | None] = []
                    canonical_run_ranks: list[int | None] = []
                    hybrid_results: list[str] = []
                    canonical_results: list[str] = []
                    for _run in range(runs):
                        started = time.monotonic()
                        hybrid_results, hybrid_metadata = run_hybrid(
                            str(record["query"]),
                            limit,
                            current_project=str(record["current_project"]),
                        )
                        latency_samples["hybrid"].append((time.monotonic() - started) * 1000)
                        hybrid_duration_ms = int((time.monotonic() - started) * 1000)
                        hybrid_rank = first_hit_rank(hybrid_results, list(record["expected"]))
                        hybrid_run_ranks.append(hybrid_rank)
                        required_at = int(record["required_at"] or 0)
                        regression_count = int(
                            bool(required_at and (hybrid_rank is None or int(hybrid_rank) > required_at))
                        )
                        if record_required_shadow_observation(
                            str(record["query"]),
                            hybrid_results,
                            hybrid_metadata,
                            duration_ms=hybrid_duration_ms,
                            regression_count=regression_count,
                        ):
                            record["shadow_observation_recorded"] = int(
                                record["shadow_observation_recorded"]
                            ) + 1
                        record["hybrid_degraded"] = bool(record["hybrid_degraded"]) or bool(
                            hybrid_metadata.get("degraded") or hybrid_metadata.get("all_failed")
                        )
                        hybrid_worker_statuses.append(
                            str(hybrid_metadata.get("worker_status") or "not_used").strip().casefold()
                        )
                        hybrid_worker_restart_count += max(
                            0,
                            int(hybrid_metadata.get("worker_restart_count") or 0),
                        )

                        started = time.monotonic()
                        canonical_results, canonical_metadata = run_canonical(
                            str(record["query"]),
                            limit,
                            current_project=str(record["current_project"]),
                        )
                        latency_samples["canonical_retrieve"].append(
                            (time.monotonic() - started) * 1000
                        )
                        canonical_run_ranks.append(
                            first_hit_rank(canonical_results, list(record["expected"]))
                        )
                        record["canonical_degraded"] = bool(record["canonical_degraded"]) or bool(
                            canonical_metadata.get("degraded")
                        )
                    record["hybrid_results"] = hybrid_results
                    record["hybrid_run_ranks"] = hybrid_run_ranks
                    record["hybrid_rank"] = worst_rank(hybrid_run_ranks)
                    record["canonical_results"] = canonical_results
                    record["canonical_run_ranks"] = canonical_run_ranks
                    record["canonical_rank"] = worst_rank(canonical_run_ranks)
                    hybrid_ranks.append(record["hybrid_rank"])  # type: ignore[arg-type]
                    canonical_ranks.append(record["canonical_rank"])  # type: ignore[arg-type]
        except Exception as exc:
            production_error = str(exc)
        finally:
            if semantic_binding_args is not None and isolated_socket_base is not None:
                try:
                    isolated_worker_cleanup = (
                        "stopped"
                        if shutdown_isolated_worker(
                            semantic_binding_args,
                            isolated_socket_base,
                        )
                        else "failed"
                    )
                except Exception:
                    # No path, query, model name, or arbitrary exception text is
                    # persisted.  A Worker that never launched is distinct from
                    # a live isolated Worker that failed graceful shutdown.
                    isolated_worker_cleanup = (
                        "not_started" if not hybrid_worker_statuses else "failed"
                    )

    gate_failures: list[dict[str, object]] = []
    for record in records:
        required_at = int(record["required_at"] or 0)
        if not required_at:
            continue
        sqlite_rank = record["sqlite_rank"]
        if sqlite_rank is None or int(sqlite_rank) > required_at:
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    record["case_ref"] if private_redacted else record["id"]
                ),
                "backend": "sqlite",
                "required_at": required_at,
                "rank": sqlite_rank,
            })
        vector_rank = record["vector_rank"]
        if not args.no_vector and not vector_error and (vector_rank is None or int(vector_rank) > required_at):
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    record["case_ref"] if private_redacted else record["id"]
                ),
                "backend": "vector",
                "required_at": required_at,
                "rank": vector_rank,
            })
        if production_chain and not production_error:
            for backend, key in (("hybrid", "hybrid_rank"), ("canonical_retrieve", "canonical_rank")):
                rank = record[key]
                if rank is None or int(rank) > required_at:
                    gate_failures.append({
                        ("case_ref" if private_redacted else "id"): (
                            record["case_ref"] if private_redacted else record["id"]
                        ),
                        "backend": backend,
                        "required_at": required_at,
                        "rank": rank,
                    })

    if production_chain and not production_error:
        if isolated_worker_cleanup != "stopped":
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    redacted_case_ref("worker-isolation-cleanup", 0)
                    if private_redacted
                    else "worker-isolation-cleanup"
                ),
                "backend": "hybrid",
                "required_at": 1,
                "rank": 0,
                "reason_code": "ISOLATED_WORKER_CLEANUP_FAILED",
            })
        for record in records:
            for backend, degraded_key in (
                ("hybrid", "hybrid_degraded"),
                ("canonical_retrieve", "canonical_degraded"),
            ):
                if bool(record[degraded_key]):
                    gate_failures.append({
                        ("case_ref" if private_redacted else "id"): (
                            record["case_ref"] if private_redacted else record["id"]
                        ),
                        "backend": backend,
                        "required_at": int(record["required_at"] or limit),
                        "rank": record[f"{backend.replace('_retrieve', '')}_rank"],
                        "reason_code": "QUALITY_RUN_DEGRADED",
                    })
            if int(record["shadow_observation_recorded"] or 0) != runs:
                gate_failures.append({
                    ("case_ref" if private_redacted else "id"): (
                        record["case_ref"] if private_redacted else record["id"]
                    ),
                    "backend": "hybrid",
                    "required_at": runs,
                    "rank": int(record["shadow_observation_recorded"] or 0),
                    "reason_code": "SHADOW_OBSERVATION_MISSING",
                })
        required_records = [record for record in records if int(record["required_at"] or 0) > 0]
        if required_records:
            for backend, key in (
                ("sqlite", "sqlite_rank"),
                ("vector", "vector_rank"),
                ("hybrid", "hybrid_rank"),
                ("canonical_retrieve", "canonical_rank"),
            ):
                required_metrics = metrics([record[key] for record in required_records])
                if required_metrics["hit@5"] < 1.0 or required_metrics["mrr"] < 0.90:
                    gate_failures.append({
                        ("case_ref" if private_redacted else "id"): (
                            "aggregate-required"
                            if not private_redacted
                            else redacted_case_ref("aggregate-required", 0)
                        ),
                        "backend": backend,
                        "required_at": 5,
                        "rank": None,
                        "reason_code": "REQUIRED_QUALITY_THRESHOLD_FAILED",
                    })
        cold_ms = latency_samples["hybrid"][0] if latency_samples["hybrid"] else None
        warm_ms = p95(latency_samples["hybrid"][1:])
        if cold_ms is None or cold_ms > 8000:
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    "latency-cold" if not private_redacted else redacted_case_ref("latency-cold", 0)
                ),
                "backend": "hybrid",
                "required_at": 8000,
                "rank": round(cold_ms, 3) if cold_ms is not None else None,
                "reason_code": "COLD_START_LATENCY_FAILED",
            })
        if warm_ms is None or warm_ms > 1000:
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    "latency-warm" if not private_redacted else redacted_case_ref("latency-warm", 0)
                ),
                "backend": "hybrid",
                "required_at": 1000,
                "rank": warm_ms,
                "reason_code": "WARM_P95_LATENCY_FAILED",
            })
        cold_status = hybrid_worker_statuses[0] if hybrid_worker_statuses else "missing"
        warm_statuses = hybrid_worker_statuses[1:]
        if cold_status != "started":
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    redacted_case_ref("worker-cold", 0) if private_redacted else "worker-cold"
                ),
                "backend": "hybrid",
                "required_at": 1,
                "rank": None,
                "reason_code": "COLD_WORKER_NOT_STARTED",
            })
        if not warm_statuses or any(status != "reused" for status in warm_statuses):
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    redacted_case_ref("worker-warm", 0) if private_redacted else "worker-warm"
                ),
                "backend": "hybrid",
                "required_at": len(warm_statuses) or 1,
                "rank": sum(1 for status in warm_statuses if status == "reused"),
                "reason_code": "WARM_WORKER_NOT_REUSED",
            })
        if hybrid_worker_restart_count:
            gate_failures.append({
                ("case_ref" if private_redacted else "id"): (
                    redacted_case_ref("worker-restart", 0) if private_redacted else "worker-restart"
                ),
                "backend": "hybrid",
                "required_at": 0,
                "rank": hybrid_worker_restart_count,
                "reason_code": "QUALITY_RUN_WORKER_RESTARTED",
            })

    output_records: list[dict[str, object]] = []
    for record in records:
        if private_redacted:
            output_records.append({
                "case_ref": record["case_ref"],
                "query_sha256": record["query_sha256"],
                "query_length": record["query_length"],
                "required_at": record["required_at"],
                "sqlite_rank": record["sqlite_rank"],
                "vector_rank": record["vector_rank"],
                "hybrid_rank": record["hybrid_rank"],
                "canonical_rank": record["canonical_rank"],
            })
        else:
            output_records.append(record)

    required_records = [record for record in records if int(record["required_at"] or 0) > 0]
    mandatory_records = [
        record
        for record, case in zip(records, cases)
        if is_mandatory_auto_archive_case(case)
    ]
    mandatory_passed = bool(mandatory_records) and all(
        all(
            record[key] is not None and int(record[key]) <= 5
            for key in ("sqlite_rank", "vector_rank", "hybrid_rank", "canonical_rank")
        )
        for record in mandatory_records
    )
    worker_lifecycle = {
        "isolated": bool(production_chain),
        "cleanup_status": isolated_worker_cleanup,
        "cold_status": hybrid_worker_statuses[0] if hybrid_worker_statuses else "missing",
        "warm_sample_count": max(len(hybrid_worker_statuses) - 1, 0),
        "warm_reused_count": sum(1 for status in hybrid_worker_statuses[1:] if status == "reused"),
        "restart_count": hybrid_worker_restart_count,
        "failed_or_degraded_count": sum(
            1 for status in hybrid_worker_statuses if status in {"failed", "degraded"}
        ),
    }
    required_metrics = {
        backend: metrics([record[key] for record in required_records])
        for backend, key in (
            ("sqlite", "sqlite_rank"),
            ("vector", "vector_rank"),
            ("hybrid", "hybrid_rank"),
            ("canonical_retrieve", "canonical_rank"),
        )
    } if required_records else {}
    output: dict[str, object] = {
        "status": "error" if (vector_error or production_error) else ("failed_gate" if gate_failures else "ok"),
        "dataset": output_dataset_metadata(dataset, private_redacted=private_redacted),
        "limit": limit,
        "case_count": len(cases),
        "required_case_count": len(required_records),
        "full_required_case_set": not bool(case_ids) and len(cases) == len(loaded_cases),
        "required_case_set_sha256": required_case_set_sha256(loaded_cases),
        "mandatory_auto_archive_case_count": len(mandatory_records),
        "mandatory_auto_archive_passed": mandatory_passed,
        "runs": runs,
        "sqlite": metrics(sqlite_ranks),
        "vector": metrics(vector_ranks) if vector_ranks else None,
        "hybrid": metrics(hybrid_ranks) if hybrid_ranks else None,
        "canonical_retrieve": metrics(canonical_ranks) if canonical_ranks else None,
        "latency_ms": {
            backend: {
                "cold": round(values[0], 3) if values else None,
                "warm_p95": p95(values[1:]),
            }
            for backend, values in latency_samples.items()
        },
        "vector_error": (
            {
                "redacted": True,
                "sha256": hashlib.sha256(vector_error.encode("utf-8")).hexdigest(),
                "length": len(vector_error),
            }
            if private_redacted and vector_error
            else vector_error
        ),
        "production_error": (
            {
                "redacted": True,
                "sha256": hashlib.sha256(production_error.encode("utf-8")).hexdigest(),
                "length": len(production_error),
            }
            if private_redacted and production_error
            else production_error
        ),
        "gate_failures": gate_failures,
        "required": required_metrics,
        "private_details_redacted": private_redacted,
        "worker_lifecycle": worker_lifecycle,
        "records": output_records,
    }
    if bool(getattr(args, "attest_success", False)):
        import agent_memory_shadow

        try:
            if not private_redacted or args.show_private_details:
                raise DatasetError("success_attestation_requires_redacted_private_dataset")
            if args.no_vector or not production_chain:
                raise DatasetError("success_attestation_requires_full_production_chain")
            if limit < 5 or not required_records or any(
                int(record["required_at"] or 0) > 5 for record in required_records
            ):
                raise DatasetError("success_attestation_requires_required_hit_at_5_cases")
            if not bool(output["full_required_case_set"]):
                raise DatasetError("success_attestation_requires_full_required_case_set")
            if not mandatory_passed:
                raise DatasetError("success_attestation_requires_mandatory_auto_archive_case")
            config_digest = agent_memory_shadow.production_config_sha256()
            output["success_attestation"] = agent_memory_shadow.write_benchmark_attestation(
                output,
                dataset_sha256=str(dataset.get("sha256") or ""),
                production_config_digest=config_digest,
            )
        except (DatasetError, RuntimeError, OSError, ValueError) as exc:
            output["status"] = "error"
            output["attestation_error"] = {
                "reason_code": (
                    str(exc)
                    if isinstance(exc, (DatasetError, agent_memory_shadow.ShadowGateError))
                    else "SUCCESS_ATTESTATION_INTERNAL_ERROR"
                ),
            }
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0 if output.get("status") == "ok" else (
            2 if vector_error or production_error else 3
        )

    sqlite_metrics = output["sqlite"]
    vector_metrics = output["vector"]
    print(f"cases={len(cases)} limit={limit}")
    print(
        "sqlite "
        f"hit@1={format_pct(sqlite_metrics['hit@1'])} "
        f"hit@3={format_pct(sqlite_metrics['hit@3'])} "
        f"hit@5={format_pct(sqlite_metrics['hit@5'])} "
        f"mrr={sqlite_metrics['mrr']:.3f}"
    )
    if vector_metrics:
        print(
            "vector "
            f"hit@1={format_pct(vector_metrics['hit@1'])} "
            f"hit@3={format_pct(vector_metrics['hit@3'])} "
            f"hit@5={format_pct(vector_metrics['hit@5'])} "
            f"mrr={vector_metrics['mrr']:.3f}"
        )
    else:
        safe_vector_error = output["vector_error"]
        if isinstance(safe_vector_error, dict):
            print(
                "vector error="
                f"[redacted:{str(safe_vector_error.get('sha256', ''))[:12]} "
                f"len={safe_vector_error.get('length', 0)}]"
            )
        else:
            print(f"vector error={safe_vector_error or 'not_run'}")
    for backend, label in (("hybrid", "hybrid"), ("canonical_retrieve", "canonical")):
        backend_metrics = output.get(backend)
        if isinstance(backend_metrics, dict):
            print(
                f"{label} "
                f"hit@1={format_pct(float(backend_metrics['hit@1']))} "
                f"hit@3={format_pct(float(backend_metrics['hit@3']))} "
                f"hit@5={format_pct(float(backend_metrics['hit@5']))} "
                f"mrr={float(backend_metrics['mrr']):.3f}"
            )
    print("")
    for record in output_records:
        query_label = record.get("query") or f"[redacted:{str(record['query_sha256'])[:12]} len={record['query_length']}]"
        identity = record.get("id") or record.get("case_ref")
        print(f"[{identity}] {query_label}")
        if record.get("expected"):
            print(f"  expected: {', '.join(record['expected'])}")
        print(f"  sqlite_rank={record['sqlite_rank']} top={record.get('sqlite_results', [])[:3]}")
        if vector_metrics:
            print(f"  vector_rank={record['vector_rank']} top={record['vector_results'][:3]}")
    return 0 if output.get("status") == "ok" else (
        2 if vector_error or production_error else 3
    )


if __name__ == "__main__":
    raise SystemExit(main())
