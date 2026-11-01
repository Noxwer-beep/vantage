"""SQLite persistence: scan history, findings, and the audit trail."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable

from . import config

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    profile      TEXT NOT NULL,
    scope        TEXT,
    scope_fp     TEXT,
    operator     TEXT,
    statement    TEXT,
    started      TEXT,
    finished     TEXT,
    duration_s   REAL,
    status       TEXT,
    score        INTEGER,
    grade        TEXT,
    hosts        INTEGER,
    open_ports   INTEGER,
    n_findings   INTEGER,
    counts_json  TEXT,
    result_json  TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id     TEXT NOT NULL,
    key         TEXT NOT NULL,
    title       TEXT,
    severity    TEXT,
    category    TEXT,
    host        TEXT,
    port        INTEGER,
    confidence  TEXT,
    service     TEXT,
    source      TEXT,
    remediation TEXT,
    evidence    TEXT,
    json        TEXT,
    PRIMARY KEY (scan_id, key),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started DESC);
"""


@contextmanager
def connect():
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def save_scan(result) -> None:
    """Upsert a ScanResult. Safe to call more than once per scan."""
    init_db()
    data = result.to_dict()
    s = data["summary"]
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, target, profile, scope, scope_fp, operator, statement,
                               started, finished, duration_s, status, score, grade, hosts,
                               open_ports, n_findings, counts_json, result_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                finished=excluded.finished, duration_s=excluded.duration_s,
                status=excluded.status, score=excluded.score, grade=excluded.grade,
                hosts=excluded.hosts, open_ports=excluded.open_ports,
                n_findings=excluded.n_findings, counts_json=excluded.counts_json,
                result_json=excluded.result_json
            """,
            (
                data["scan_id"], data["target"], data["profile"],
                data["guard"]["scope"]["name"], data["guard"]["scope"].get("fingerprint", ""),
                data["guard"]["operator"], data["guard"]["statement"],
                data["started"], data["finished"], data["duration_s"], data["status"],
                s["score"], s["grade"], len(data["hosts"]),
                sum(len(h["ports"]) for h in data["hosts"]),
                s["total"], json.dumps(s["counts"]), json.dumps(data),
            ),
        )
        conn.execute("DELETE FROM findings WHERE scan_id=?", (data["scan_id"],))
        conn.executemany(
            """
            INSERT OR REPLACE INTO findings
                (scan_id, key, title, severity, category, host, port, confidence,
                 service, source, remediation, evidence, json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    data["scan_id"], f["key"], f["title"], f["severity"], f["category"],
                    f["host"], f["port"], f["confidence"], f["service"], f["source"],
                    f["remediation"], f["evidence"][:2000], json.dumps(f),
                )
                for f in data["findings"]
            ],
        )


def list_scans(limit: int = 25) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            """SELECT id, target, profile, scope, started, status, score, grade,
                      hosts, open_ports, n_findings, counts_json, duration_s
               FROM scans ORDER BY started DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["counts"] = json.loads(item.pop("counts_json") or "{}")
        except json.JSONDecodeError:
            item["counts"] = {}
            item.pop("counts_json", None)
        out.append(item)
    return out


def get_scan(scan_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["result_json"])
    except json.JSONDecodeError:
        return None


def get_meta(scan_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def query_findings(
    severity: str | None = None,
    host: str | None = None,
    limit: int = 200,
    scan_id: str | None = None,
) -> list[dict[str, Any]]:
    init_db()
    clauses, params = [], []
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if host:
        clauses.append("host=?")
        params.append(host)
    if scan_id:
        clauses.append("scan_id=?")
        params.append(scan_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM findings {where} ORDER BY scan_id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_scan(scan_id: str) -> bool:
    init_db()
    with connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return cur.rowcount > 0


def stats() -> dict[str, Any]:
    init_db()
    with connect() as conn:
        scans = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        findings = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        by_sev = {
            r["severity"]: r["c"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
            ).fetchall()
        }
        last = conn.execute("SELECT MAX(started) s FROM scans").fetchone()["s"]
    return {"scans": scans, "findings": findings, "by_severity": by_sev, "last_scan": last}
