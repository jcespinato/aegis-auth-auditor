from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import AuditResult


class AuditStorage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    login_url TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    risk TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def save(self, result: AuditResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audits (target_url, login_url, score, risk, started_at, finished_at, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.target_url,
                    result.login_url,
                    result.score,
                    result.risk,
                    result.started_at,
                    result.finished_at,
                    payload,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, target_url, login_url, score, risk, started_at, finished_at
                FROM audits
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, audit_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM audits WHERE id = ?",
                (audit_id,),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["payload"])
