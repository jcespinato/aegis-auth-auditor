from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import ActiveAuthResult, AuditResult, HashBenchmarkResult, LabSimulationResult, PasswordAnalysisResult


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
            connection.execute("CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY AUTOINCREMENT, target_url TEXT NOT NULL, login_url TEXT NOT NULL, score INTEGER NOT NULL, risk TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS active_tests (id INTEGER PRIMARY KEY AUTOINCREMENT, login_url TEXT NOT NULL, account_hint TEXT NOT NULL, score INTEGER NOT NULL, risk TEXT NOT NULL, verdict TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS password_analyses (id INTEGER PRIMARY KEY AUTOINCREMENT, score INTEGER NOT NULL, rating TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS hash_benchmarks (id INTEGER PRIMARY KEY AUTOINCREMENT, algorithm TEXT NOT NULL, median_ms REAL NOT NULL, rating TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS lab_simulations (id INTEGER PRIMARY KEY AUTOINCREMENT, login_url TEXT NOT NULL, account_hint TEXT NOT NULL, verdict TEXT NOT NULL, risk TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, payload TEXT NOT NULL)")
            connection.commit()

    def save_audit(self, result: AuditResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute("INSERT INTO audits (target_url, login_url, score, risk, started_at, finished_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?)", (result.target_url, result.login_url, result.score, result.risk, result.started_at, result.finished_at, payload))
            connection.commit()
            return int(cursor.lastrowid)

    def save_active(self, result: ActiveAuthResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute("INSERT INTO active_tests (login_url, account_hint, score, risk, verdict, started_at, finished_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (result.login_url, result.account_hint, result.score, result.risk, result.verdict, result.started_at, result.finished_at, payload))
            connection.commit()
            return int(cursor.lastrowid)

    def save_password(self, result: PasswordAnalysisResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute("INSERT INTO password_analyses (score, rating, created_at, payload) VALUES (?, ?, ?, ?)", (result.score, result.rating, result.created_at, payload))
            connection.commit()
            return int(cursor.lastrowid)

    def save_hash(self, result: HashBenchmarkResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute("INSERT INTO hash_benchmarks (algorithm, median_ms, rating, created_at, payload) VALUES (?, ?, ?, ?, ?)", (result.algorithm, result.median_ms, result.rating, result.created_at, payload))
            connection.commit()
            return int(cursor.lastrowid)

    def save_lab(self, result: LabSimulationResult) -> int:
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute("INSERT INTO lab_simulations (login_url, account_hint, verdict, risk, started_at, finished_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?)", (result.login_url, result.account_hint, result.verdict, result.risk, result.started_at, result.finished_at, payload))
            connection.commit()
            return int(cursor.lastrowid)

    def _recent(self, table: str, columns: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(f"SELECT {columns} FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def recent_audits(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._recent("audits", "id, target_url, login_url, score, risk, started_at, finished_at", limit)

    def recent_active(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._recent("active_tests", "id, login_url, account_hint, score, risk, verdict, started_at, finished_at", limit)

    def recent_passwords(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._recent("password_analyses", "id, score, rating, created_at", limit)

    def recent_hashes(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._recent("hash_benchmarks", "id, algorithm, median_ms, rating, created_at", limit)

    def recent_labs(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._recent("lab_simulations", "id, login_url, account_hint, verdict, risk, started_at, finished_at", limit)

    def _get(self, table: str, row_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(f"SELECT payload FROM {table} WHERE id = ?", (row_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def get_audit(self, row_id: int) -> dict[str, Any] | None:
        return self._get("audits", row_id)

    def get_active(self, row_id: int) -> dict[str, Any] | None:
        return self._get("active_tests", row_id)

    def get_password(self, row_id: int) -> dict[str, Any] | None:
        return self._get("password_analyses", row_id)

    def get_hash(self, row_id: int) -> dict[str, Any] | None:
        return self._get("hash_benchmarks", row_id)

    def get_lab(self, row_id: int) -> dict[str, Any] | None:
        return self._get("lab_simulations", row_id)

    def latest_audit(self) -> dict[str, Any] | None:
        rows = self.recent_audits(1)
        return self.get_audit(rows[0]["id"]) if rows else None

    def latest_active(self) -> dict[str, Any] | None:
        rows = self.recent_active(1)
        return self.get_active(rows[0]["id"]) if rows else None

    def latest_password(self) -> dict[str, Any] | None:
        rows = self.recent_passwords(1)
        return self.get_password(rows[0]["id"]) if rows else None

    def latest_hash(self) -> dict[str, Any] | None:
        rows = self.recent_hashes(1)
        return self.get_hash(rows[0]["id"]) if rows else None

    def latest_lab(self) -> dict[str, Any] | None:
        rows = self.recent_labs(1)
        return self.get_lab(rows[0]["id"]) if rows else None
