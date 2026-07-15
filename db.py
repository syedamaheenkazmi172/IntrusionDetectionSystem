#SQLite storage for the IDS alert dashboard.

import sqlite3
import threading
import time
from pathlib import Path

DB_PATH = Path("ids_alerts.db")

# every write goes through this -- cheap at this app's alert volume, and
# removes any chance of a "database is locked" error from two request
# threads writing at once, even though WAL mode already makes that unlikely.
WRITE_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    rule     TEXT NOT NULL,
    src      TEXT,
    sensor   TEXT,
    severity INTEGER,
    detail   TEXT,
    os_guess TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts(src);
CREATE INDEX IF NOT EXISTS idx_alerts_sensor   ON alerts(sensor);
"""


def get_conn():
    # short-lived connection per call. sqlite3 connections can't be shared
    # across threads, and FastAPI's sync def endpoints each run in a
    # threadpool worker -- opening one per call is simpler (and safe) than
    # pooling, and cheap enough at this app's request volume.
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with WRITE_LOCK:
        conn = get_conn()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


def insert_alert(data):
    """data: dict with rule/src/sensor/severity/detail/os_guess/ts keys."""
    with WRITE_LOCK:
        conn = get_conn()
        try:
            cur = conn.execute(
                "INSERT INTO alerts (ts, rule, src, sensor, severity, detail, os_guess) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    data.get("ts", time.time()),
                    data.get("rule"),
                    data.get("src"),
                    data.get("sensor"),
                    data.get("severity"),
                    data.get("detail"),
                    data.get("os_guess"),
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def _row_to_dict(row):
    return {
        "ts": row["ts"],
        "rule": row["rule"],
        "src": row["src"],
        "sensor": row["sensor"],
        "severity": row["severity"],
        "detail": row["detail"],
        "os_guess": row["os_guess"],
    }


def recent_alerts(limit=500):
    """Newest first -- backs /api/alerts, the live-feed view."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def stats():
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        by_rule = {
            r["rule"]: r["c"]
            for r in conn.execute("SELECT rule, COUNT(*) c FROM alerts GROUP BY rule")
        }
        by_severity = {
            str(r["severity"]): r["c"]
            for r in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")
        }
        return {"total": total, "by_rule": by_rule, "by_severity": by_severity}
    finally:
        conn.close()


def blocked_events():
    """All IP_BLOCKED/IP_UNBLOCKED events, oldest first -- used at startup to
    rebuild the in-memory blocked_state panel by replaying history."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE rule IN ('IP_BLOCKED', 'IP_UNBLOCKED') "
            "ORDER BY ts ASC"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def _build_where(start=None, end=None, rule=None, severity=None, src=None,
                  sensor=None, q=None):
    clauses = []
    params = []
    if start is not None:
        clauses.append("ts >= ?")
        params.append(start)
    if end is not None:
        clauses.append("ts <= ?")
        params.append(end)
    if rule:
        clauses.append("rule = ?")
        params.append(rule)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)
    if src:
        clauses.append("src LIKE ?")
        params.append(f"%{src}%")
    if sensor:
        clauses.append("sensor = ?")
        params.append(sensor)
    if q:
        clauses.append(
            "(rule LIKE ? OR src LIKE ? OR detail LIKE ? OR sensor LIKE ? OR os_guess LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def query_alerts(start=None, end=None, rule=None, severity=None, src=None,
                  sensor=None, q=None, limit=500):
    """Indexed search over the full audit trail -- backs /api/logs. Returns
    (total_matched, rows) so the endpoint can report the true match count
    even when it's capped by limit."""
    where, params = _build_where(start, end, rule, severity, src, sensor, q)
    conn = get_conn()
    try:
        total = conn.execute(f"SELECT COUNT(*) c FROM alerts {where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return total, [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def query_alerts_for_export(start=None, end=None, rule=None, severity=None,
                             src=None, sensor=None, q=None):
    """Same filters, no cap, chronological order -- backs /api/logs/export."""
    where, params = _build_where(start, end, rule, severity, src, sensor, q)
    conn = get_conn()
    try:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY ts ASC", params
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def timeseries(hours=6, bucket_seconds=60):
    """Bucketed counts by severity -- backs the traffic-volume chart. Bucket
    math happens in SQL so this stays one indexed query regardless of how
    much history has piled up."""
    bucket_seconds = max(10, bucket_seconds)
    cutoff = time.time() - hours * 3600
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT (CAST(ts / ? AS INTEGER) * ?) AS bucket, severity, COUNT(*) c "
            "FROM alerts WHERE ts >= ? GROUP BY bucket, severity ORDER BY bucket",
            (bucket_seconds, bucket_seconds, cutoff),
        ).fetchall()
    finally:
        conn.close()

    buckets = {}
    for r in rows:
        entry = buckets.setdefault(r["bucket"], {1: 0, 2: 0, 3: 0})
        if r["severity"] in entry:
            entry[r["severity"]] = r["c"]

    points = [
        {"t": t, "info": v[1], "warn": v[2], "crit": v[3]}
        for t, v in sorted(buckets.items())
    ]
    return bucket_seconds, points
