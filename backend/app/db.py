"""SQLite storage for reports. Owner: P1.

Reports are stored as their full JSON so the schema can evolve without migrations.
"""
import sqlite3
from contextlib import contextmanager
from typing import Iterator, Optional

from app.config import settings
from app.schemas import AnalysisReport


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                input_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)")


def save_report(report: AnalysisReport) -> None:
    """Insert or update (e.g. after on-chain registration fills `chain`)."""
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO reports (id, created_at, input_type, risk_level, json) VALUES (?, ?, ?, ?, ?)",
            (
                report.id,
                report.created_at.isoformat(),
                report.input_type,
                report.risk_level.value,
                report.model_dump_json(),
            ),
        )


def get_report(report_id: str) -> Optional[AnalysisReport]:
    with _connect() as conn:
        row = conn.execute("SELECT json FROM reports WHERE id = ?", (report_id,)).fetchone()
    return AnalysisReport.model_validate_json(row[0]) if row else None


def list_reports(limit: int = 50) -> list[AnalysisReport]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT json FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [AnalysisReport.model_validate_json(r[0]) for r in rows]
