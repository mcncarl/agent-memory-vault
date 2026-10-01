"""Explicit full-schema initializer for disposable test databases only."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import agent_memory_evolution
import agent_memory_index
import agent_memory_intent
import agent_memory_claim
from agent_memory_state import install_search_log_privacy_guards


def initialize_full_state(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        agent_memory_intent.ensure_schema(connection)
        agent_memory_claim.ensure_schema(connection)
        agent_memory_evolution.init_db(connection)
        agent_memory_index.init_db(connection)
        install_search_log_privacy_guards(connection)
        connection.commit()
