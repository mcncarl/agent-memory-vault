#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


SCRIPT_ROOT = Path(__file__).resolve().parents[0]
DEFAULT_LIMIT = 5


DEFAULT_BENCHMARK_CASES = [
    {
        "id": "field_rules",
        "query": "frontmatter user_id agent_id project_id fields",
        "expected": ["工作流/Agent记忆字段规范.md"],
    },
    {
        "id": "closeout_rules",
        "query": "important conversation closeout write memory",
        "expected": ["工作流/Agent记忆收尾决策规则.md"],
    },
    {
        "id": "sqlite_index",
        "query": "full vault SQLite FTS search and open loops",
        "expected": ["工作流/Agent记忆SQLite全库索引设计.md"],
    },
    {
        "id": "semantic_index",
        "query": "semantic retrieval embedding zvec vector search",
        "expected": ["工作流/Agent记忆语义检索设计.md"],
    },
    {
        "id": "user_profile",
        "query": "long term user preference and boundaries",
        "expected": ["用户记忆/长期画像.md", "用户记忆/偏好与边界.md"],
    },
    {
        "id": "agent_open_loops",
        "query": "agent unresolved tasks open loops",
        "expected": ["agent/open-loops.md"],
    },
]


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot_load_module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_cases(path: str) -> list[dict[str, object]]:
    if not path:
        return DEFAULT_BENCHMARK_CASES
    data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("benchmark_file_must_be_json_array")
    cases: list[dict[str, object]] = []
    for item in data:
        if not isinstance(item, dict) or "id" not in item or "query" not in item or "expected" not in item:
            raise SystemExit("each_case_requires_id_query_expected")
        cases.append(item)
    return cases


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


def format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def run_sqlite(sqlite_index: Any, query: str, limit: int) -> list[str]:
    with sqlite_index.connect() as conn:
        rows = sqlite_index.search(conn, query, limit)
    return [str(row["rel_path"]) for row in rows]


def run_vector(zvec_index: Any, vector_conn: Any, store: Any, embedder: Any, query: str, limit: int) -> list[str]:
    query_embedding = embedder.embed_query(query)
    scored_ids = store.search(query_embedding, max(limit * 12, limit))
    rows = zvec_index.vector_rows(vector_conn, scored_ids, query)[:limit]
    return [str(row["rel_path"]) for row in rows]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare SQLite/FTS retrieval with optional Zvec semantic retrieval.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Top K used for hit@K and result display.")
    parser.add_argument("--json", action="store_true", help="Print JSON.")
    parser.add_argument("--no-vector", action="store_true", help="Only run SQLite baseline.")
    parser.add_argument("--case-id", action="append", default=[], help="Run only this benchmark case id. Repeatable.")
    parser.add_argument("--benchmark-file", default="", help="Optional JSON array of benchmark cases.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    limit = max(args.limit, 1)
    case_ids = set(args.case_id)
    cases = [case for case in load_cases(args.benchmark_file) if not case_ids or str(case["id"]) in case_ids]
    if not cases:
        print("no_cases_selected", file=sys.stderr)
        return 1

    sqlite_index = load_module("agent_memory_index_module", SCRIPT_ROOT / "agent_memory_index.py")
    records: list[dict[str, object]] = []
    sqlite_ranks: list[int | None] = []
    vector_ranks: list[int | None] = []

    for case in cases:
        query = str(case["query"])
        expected = [str(item) for item in case["expected"]]  # type: ignore[index]
        sqlite_results = run_sqlite(sqlite_index, query, limit)
        sqlite_rank = first_hit_rank(sqlite_results, expected)
        sqlite_ranks.append(sqlite_rank)
        records.append(
            {
                "id": case["id"],
                "query": query,
                "expected": expected,
                "sqlite_rank": sqlite_rank,
                "sqlite_results": sqlite_results,
                "vector_rank": None,
                "vector_results": [],
            }
        )

    vector_error = ""
    if not args.no_vector:
        try:
            zvec_index = load_module("agent_memory_zvec_index_module", SCRIPT_ROOT / "agent_memory_zvec_index.py")
            vector_conn = zvec_index.connect()
            zvec_index.init_db(vector_conn)
            store = zvec_index.ZvecStore(zvec_index.DEFAULT_COLLECTION_PATH, zvec_index.DEFAULT_EMBEDDING_DIM)
            store.init()
            embedder = zvec_index.EmbeddingGemmaEmbedder(
                zvec_index.DEFAULT_MODEL,
                zvec_index.DEFAULT_EMBEDDING_DIM,
                zvec_index.DEFAULT_DEVICE,
                "",
            )
            embedder.embed_query("benchmark preflight")
            for record in records:
                vector_results = run_vector(zvec_index, vector_conn, store, embedder, str(record["query"]), limit)
                vector_rank = first_hit_rank(vector_results, list(record["expected"]))
                vector_ranks.append(vector_rank)
                record["vector_rank"] = vector_rank
                record["vector_results"] = vector_results
            vector_conn.close()
        except Exception as exc:
            vector_error = str(exc)

    output: dict[str, object] = {
        "limit": limit,
        "case_count": len(cases),
        "sqlite": metrics(sqlite_ranks),
        "vector": metrics(vector_ranks) if vector_ranks else None,
        "vector_error": vector_error,
        "records": records,
    }
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0 if not vector_error else 2

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
        print(f"vector error={vector_error or 'not_run'}")
    print("")
    for record in records:
        print(f"[{record['id']}] {record['query']}")
        print(f"  expected: {', '.join(record['expected'])}")
        print(f"  sqlite_rank={record['sqlite_rank']} top={record['sqlite_results'][:3]}")
        if vector_metrics:
            print(f"  vector_rank={record['vector_rank']} top={record['vector_results'][:3]}")
    return 0 if not vector_error else 2


if __name__ == "__main__":
    raise SystemExit(main())
