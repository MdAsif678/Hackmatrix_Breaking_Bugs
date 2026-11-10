"""Report storage. Owner: P1.

Two tables: `reports` (each report as its full JSON, so the schema can evolve without migrations) and
`indicators` (one row per domain / IP / certificate / email / phone / UPI ID per report, for correlation).

Where the data lives:
- DATABASE_URL set (postgresql://...): a hosted Postgres database, e.g. Neon. Used in production, because
  Render's free plan wipes the server's disk whenever it restarts, sleeps or redeploys.
- otherwise: the SQLite file backend/data/app.db (local development and tests).
The SQL below is written to run unchanged on both (ON CONFLICT upserts); only the placeholder differs.
"""
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from app.config import settings
from app.schemas import AnalysisReport


def _postgres() -> bool:
    return settings.database_url.startswith(("postgres://", "postgresql://"))


@contextmanager
def _connect() -> Iterator[Any]:
    if _postgres():
        import psycopg  # only needed in production

        conn = psycopg.connect(settings.database_url, connect_timeout=10)
    else:
        settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(settings.db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _run(conn: Any, sql: str, params: tuple = (), many: list[tuple] | None = None) -> Any:
    """Execute on either database: SQLite uses ? placeholders, Postgres (psycopg) uses %s."""
    if _postgres():
        sql = sql.replace("?", "%s")
    cur = conn.cursor()
    if many is not None:
        cur.executemany(sql, many)
    else:
        cur.execute(sql, params)
    return cur


def init_db() -> None:
    with _connect() as conn:
        _run(
            conn,
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
        _run(conn, "CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)")
        # Correlation index: one row per indicator (domain, ip, cert, email, phone, upi) per report.
        _run(
            conn,
            """
            CREATE TABLE IF NOT EXISTS indicators (
                report_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (report_id, kind, value)
            )
            """
        )
        _run(conn, "CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(kind, value)")


def save_report(report: AnalysisReport) -> None:
    """Insert or update (e.g. after on-chain registration fills `chain`)."""
    with _connect() as conn:
        _run(
            conn,
            "INSERT INTO reports (id, created_at, input_type, risk_level, json) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET created_at = excluded.created_at, input_type = excluded.input_type, "
            "risk_level = excluded.risk_level, json = excluded.json",
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
        row = _run(conn, "SELECT json FROM reports WHERE id = ?", (report_id,)).fetchone()
    return AnalysisReport.model_validate_json(row[0]) if row else None


def list_reports(limit: int = 50) -> list[AnalysisReport]:
    with _connect() as conn:
        rows = _run(conn, "SELECT json FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [AnalysisReport.model_validate_json(r[0]) for r in rows]


# ---------------------------------------------------------------- correlation index


def save_indicators(report_id: str, items: set[tuple[str, str]]) -> None:
    with _connect() as conn:
        _run(
            conn,
            "INSERT INTO indicators (report_id, kind, value) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            many=[(report_id, kind, value) for kind, value in items],
        )


def reports_sharing(items: set[tuple[str, str]], exclude_id: str) -> dict[str, list[tuple[str, str]]]:
    """{report_id: [(kind, value), ...]} for other reports that share any of the given indicators."""
    out: dict[str, list[tuple[str, str]]] = {}
    if not items:
        return out
    with _connect() as conn:
        for kind, value in items:
            rows = _run(
                conn,
                "SELECT report_id FROM indicators WHERE kind = ? AND value = ? AND report_id != ?",
                (kind, value, exclude_id),
            ).fetchall()
            for (rid,) in rows:
                out.setdefault(rid, []).append((kind, value))
    return out


def domains_on_ip(ip: str) -> int:
    """How many different domains we have seen on this IP (many = shared hosting / CDN)."""
    with _connect() as conn:
        row = _run(
            conn,
            """
            SELECT COUNT(DISTINCT d.value) FROM indicators i
            JOIN indicators d ON d.report_id = i.report_id AND d.kind = 'domain'
            WHERE i.kind = 'ip' AND i.value = ?
            """,
            (ip,),
        ).fetchone()
    return row[0] if row else 0


def recent_messages(limit: int = 200) -> list[tuple[str, str]]:
    """[(report_id, message_text)] for the most recent message reports."""
    with _connect() as conn:
        rows = _run(
            conn,
            "SELECT id, json FROM reports WHERE input_type = 'message' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [(rid, AnalysisReport.model_validate_json(j).input) for rid, j in rows]
