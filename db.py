"""Database layer for the Web Server Log Analyzer.

* One DuckDB file (logs.duckdb), opened once per process: DuckDB allows a
  single writer process, so the Streamlit app keeps one cached connection
  and hands each page run a cursor on it.
* Every query is parameterized ($name placeholders). The SQL text lives in
  schema.sql and queries.sql and is never assembled from user input.
* DuckDB has no triggers, stored procedures or ON DELETE CASCADE. The logic
  those would normally hold lives here, in the functions marked "trigger-like".
"""
from __future__ import annotations

import ipaddress
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("LOGLENS_DB", ROOT / "logs.duckdb"))   # override for a second copy
SCHEMA_PATH = ROOT / "schema.sql"
QUERIES_PATH = ROOT / "queries.sql"
SAMPLE_DIR = ROOT / "sample_logs"

SEVERITIES = ("low", "medium", "high", "critical")
METRICS = {
    "status_5xx_per_min": "5xx responses per minute on one path (average over the window)",
    "requests_per_ip_per_min": "requests per minute from one IP (average over the window)",
    "status_4xx_per_ip": "4xx responses to one IP within the window (count)",
}
IP_METRICS = {"requests_per_ip_per_min", "status_4xx_per_ip"}


# ---------------------------------------------------------------------------
# Named queries from queries.sql
# ---------------------------------------------------------------------------

def _load_named_queries(path: Path) -> dict[str, str]:
    """Split queries.sql on '-- name: x' markers. Trailing comment lines
    (the next section's banner) are dropped from each query."""
    blocks: dict[str, list[str]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^--\s*name:\s*(\w+)\s*$", line)
        if m:
            current = m.group(1)
            blocks[current] = []
        elif current:
            blocks[current].append(line)
    queries = {}
    for name, lines in blocks.items():
        while lines and (not lines[-1].strip() or lines[-1].lstrip().startswith("--")):
            lines.pop()
        queries[name] = "\n".join(lines).strip().rstrip(";")
    return queries


QUERIES = _load_named_queries(QUERIES_PATH)


def df(con: duckdb.DuckDBPyConnection, name: str, params: dict | None = None) -> pd.DataFrame:
    """Run a named query and return a DataFrame (elapsed time in .attrs)."""
    t0 = time.perf_counter()
    out = con.execute(QUERIES[name], params or {}).df()
    out.attrs["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return out


def one(con: duckdb.DuckDBPyConnection, name: str, params: dict | None = None):
    return con.execute(QUERIES[name], params or {}).fetchone()


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def open_db(path: Path | str = DB_PATH) -> duckdb.DuckDBPyConnection:
    """Open (or create) the database and apply schema.sql idempotently."""
    con = duckdb.connect(str(path))
    con.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
    purge_deleted_files(con)
    return con


@st.cache_resource(show_spinner="Opening logs.duckdb ...")
def get_conn() -> duckdb.DuckDBPyConnection:
    """The single process-wide connection (Streamlit caches it across reruns and sessions)."""
    return open_db()


def cursor() -> duckdb.DuckDBPyConnection:
    """A cursor is a separate handle onto the same database. Streamlit runs every
    session in its own thread and a DuckDB connection must not be shared across
    threads, so each page run works through its own cursor."""
    return get_conn().cursor()


@contextmanager
def transaction(con: duckdb.DuckDBPyConnection):
    con.execute("BEGIN TRANSACTION")
    try:
        yield con
    except BaseException:
        con.execute("ROLLBACK")
        raise
    con.execute("COMMIT")


def _friendly(e: duckdb.Error) -> str:
    """Strip DuckDB's error-class prefix and hint lines for display."""
    msg = str(e).split("\n")[0]
    return re.sub(r"^\w+ Error: ", "", msg)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

@dataclass
class IngestResult:
    file_id: int
    name: str
    line_count: int
    parsed: int
    failed: int
    seconds: float

    @property
    def rows_per_sec(self) -> float:
        return self.line_count / self.seconds if self.seconds else 0.0


def ingest_file(con: duckdb.DuckDBPyConnection, path: Path | str, name: str | None = None) -> IngestResult:
    """Load one access log. Parsing happens inside DuckDB (read_csv ->
    regexp_extract -> strptime); everything is one transaction, so a failure
    leaves no trace."""
    name = name or Path(path).name
    t0 = time.perf_counter()
    try:
        with transaction(con):
            file_id = one(con, "insert_log_file", {"name": name})[0]
            line_count, parsed, failed = _parse_into(con, file_id, path, line_offset=0)
            seconds = time.perf_counter() - t0
            con.execute(QUERIES["finish_log_file"], {"file_id": file_id, "line_count": line_count,
                                                     "parsed": parsed, "failed": failed, "seconds": seconds})
    except duckdb.ConstraintException as e:
        if "Duplicate key" in str(e) and "name" in str(e):
            raise ValueError(f"'{name}' is already loaded. Delete it first to load it again.") from e
        raise ValueError(_friendly(e)) from e
    except duckdb.Error as e:
        raise ValueError(f"Could not read '{name}': {_friendly(e)}") from e
    return IngestResult(file_id, name, line_count, parsed, failed, time.perf_counter() - t0)


def _parse_into(con, file_id: int, path: Path | str, line_offset: int) -> tuple[int, int, int]:
    """The shared parsing pipeline: stage the raw lines, then one INSERT ...
    SELECT for the good lines and one for the rest. Runs inside the caller's
    transaction; returns (lines, parsed, failed)."""
    con.execute(QUERIES["stage_raw_lines"], {"path": str(path), "line_offset": line_offset})
    line_count = con.execute("SELECT count(*) FROM raw_lines").fetchone()[0]
    parsed = con.execute(QUERIES["ingest_requests"], {"file_id": file_id}).fetchone()[0]
    failed = con.execute(QUERIES["ingest_parse_errors"], {"file_id": file_id}).fetchone()[0]
    con.execute("DROP TABLE raw_lines")
    return line_count, parsed, failed


def ensure_log_file(con, name: str) -> int:
    """Id of the log_files row called `name`, creating it if needed (live feed)."""
    row = con.execute("SELECT id FROM log_files WHERE name = $name AND status = 'active'",
                      {"name": name}).fetchone()
    return row[0] if row else one(con, "insert_log_file", {"name": name})[0]


def append_lines(con, file_id: int, path: Path | str) -> tuple[int, int, int]:
    """Append a batch of lines to an existing log file record, through the same
    parsing pipeline as an upload, in one transaction."""
    t0 = time.perf_counter()
    with transaction(con):
        offset = con.execute("SELECT line_count FROM log_files WHERE id = $id", {"id": file_id}).fetchone()
        if offset is None:
            raise ValueError(f"log file {file_id} no longer exists")
        counts = _parse_into(con, file_id, path, line_offset=offset[0])
        con.execute(QUERIES["append_log_file_counts"],
                    {"file_id": file_id, "line_count": counts[0], "parsed": counts[1], "failed": counts[2],
                     "seconds": time.perf_counter() - t0})
    return counts


def delete_log_file(con: duckdb.DuckDBPyConnection, file_id: int) -> None:
    """Trigger-like: emulates ON DELETE CASCADE, which DuckDB does not have.

    Step 1, one transaction: flag the parent 'deleting' and delete every child
    row (parse_errors, requests). Either all children go or none do.
    Step 2: delete the parent. It can't share step 1's transaction because
    DuckDB checks the foreign key against index entries that still hold the
    transaction's own deleted children (its "over-eager constraint checking"
    limitation). If the process dies between the steps, the row is left
    childless with status 'deleting', hidden from the app, and
    purge_deleted_files() finishes the job on the next start.
    """
    params = {"id": file_id}
    with transaction(con):
        con.execute("UPDATE log_files SET status = 'deleting' WHERE id = $id", params)
        con.execute("DELETE FROM parse_errors WHERE file_id = $id", params)
        con.execute("DELETE FROM requests WHERE file_id = $id", params)
    with transaction(con):
        con.execute("DELETE FROM log_files WHERE id = $id", params)


def purge_deleted_files(con: duckdb.DuckDBPyConnection) -> None:
    for (file_id,) in con.execute("SELECT id FROM log_files WHERE status = 'deleting'").fetchall():
        delete_log_file(con, file_id)


def loaded_file_names(con: duckdb.DuckDBPyConnection) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM log_files").fetchall()}


# ---------------------------------------------------------------------------
# Watchlist CRUD
# ---------------------------------------------------------------------------

def normalize_ip(raw: str) -> str:
    """Trigger-like (BEFORE INSERT/UPDATE on watchlist): validate the address
    and store it in canonical form, so '010.0.0.1 ' can't sneak past UNIQUE."""
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        raise ValueError(f"'{raw.strip()}' is not a valid IPv4 or IPv6 address") from None


def _validate_watch(ip: str, reason: str, severity: str) -> dict:
    reason = reason.strip()
    if not reason:
        raise ValueError("A reason is required")
    if len(reason) > 500:
        raise ValueError("Reason must be 500 characters or fewer")
    if severity not in SEVERITIES:
        raise ValueError(f"Severity must be one of {', '.join(SEVERITIES)}")
    return {"ip": normalize_ip(ip), "reason": reason, "severity": severity}


def add_watchlist(con, ip: str, reason: str, severity: str) -> int:
    values = _validate_watch(ip, reason, severity)
    try:
        return con.execute("INSERT INTO watchlist (ip, reason, severity) VALUES ($ip, $reason, $severity) "
                           "RETURNING id", values).fetchone()[0]
    except duckdb.ConstraintException as e:
        if "Duplicate key" in str(e):
            raise ValueError(f"{values['ip']} is already on the watchlist") from e
        raise ValueError(_friendly(e)) from e


def update_watchlist(con, entry_id: int, ip: str, reason: str, severity: str) -> None:
    values = _validate_watch(ip, reason, severity) | {"id": entry_id}
    try:
        con.execute("UPDATE watchlist SET ip = $ip, reason = $reason, severity = $severity WHERE id = $id", values)
    except duckdb.ConstraintException as e:
        if "Duplicate key" in str(e):
            raise ValueError(f"{values['ip']} is already on the watchlist") from e
        raise ValueError(_friendly(e)) from e


def delete_watchlist(con, entry_id: int) -> None:
    con.execute("DELETE FROM watchlist WHERE id = $id", {"id": entry_id})


# ---------------------------------------------------------------------------
# Alert rules CRUD
# ---------------------------------------------------------------------------

def _validate_rule(name: str, metric: str, threshold: float, window_minutes: int) -> dict:
    name = name.strip()
    if not name:
        raise ValueError("A rule name is required")
    if len(name) > 80:
        raise ValueError("Rule name must be 80 characters or fewer")
    if metric not in METRICS:
        raise ValueError(f"Unknown metric '{metric}'")
    if not threshold or threshold <= 0:
        raise ValueError("Threshold must be greater than 0")
    if not 1 <= int(window_minutes) <= 1440:
        raise ValueError("Window must be between 1 and 1440 minutes")
    return {"name": name, "metric": metric, "threshold": float(threshold), "window": int(window_minutes)}


def add_rule(con, name, metric, threshold, window_minutes, enabled=True, auto_watchlist=False) -> int:
    values = _validate_rule(name, metric, threshold, window_minutes) | {"enabled": enabled, "auto": auto_watchlist}
    try:
        return con.execute(
            "INSERT INTO alert_rules (name, metric, threshold, window_minutes, enabled, auto_watchlist) "
            "VALUES ($name, $metric, $threshold, $window, $enabled, $auto) RETURNING id", values).fetchone()[0]
    except duckdb.ConstraintException as e:
        if "Duplicate key" in str(e):
            raise ValueError(f"A rule named '{values['name']}' already exists") from e
        raise ValueError(_friendly(e)) from e


def update_rule(con, rule_id, name, metric, threshold, window_minutes, enabled, auto_watchlist) -> None:
    values = (_validate_rule(name, metric, threshold, window_minutes)
              | {"id": rule_id, "enabled": enabled, "auto": auto_watchlist})
    try:
        con.execute("UPDATE alert_rules SET name = $name, metric = $metric, threshold = $threshold, "
                    "window_minutes = $window, enabled = $enabled, auto_watchlist = $auto WHERE id = $id", values)
    except duckdb.ConstraintException as e:
        if "Duplicate key" in str(e):
            raise ValueError(f"A rule named '{values['name']}' already exists") from e
        raise ValueError(_friendly(e)) from e


def delete_rule(con, rule_id: int) -> None:
    """Trigger-like cascade, same two steps as delete_log_file(): disable the
    rule and drop its alerts atomically, then delete the rule itself."""
    params = {"id": rule_id}
    with transaction(con):
        con.execute("UPDATE alert_rules SET enabled = false WHERE id = $id", params)
        con.execute("DELETE FROM alerts WHERE rule_id = $id", params)
    with transaction(con):
        con.execute("DELETE FROM alert_rules WHERE id = $id", params)


def clear_alerts(con) -> None:
    con.execute("DELETE FROM alerts")


# ---------------------------------------------------------------------------
# Alert evaluation
# ---------------------------------------------------------------------------

ALERT_QUERY = {
    "status_5xx_per_min": "alert_status_5xx_per_min",
    "requests_per_ip_per_min": "alert_requests_per_ip_per_min",
    "status_4xx_per_ip": "alert_status_4xx_per_ip",
}


def alert_insert_sql(metric: str) -> str:
    """INSERT wrapper around a metric's candidate query. Both pieces are
    constants from this module and queries.sql (the metric is checked against
    ALERT_QUERY), and every value is still a bound parameter."""
    return ("INSERT INTO alerts (rule_id, triggered_at, ended_at, subject, observed_value)\n"
            "SELECT $rule_id, triggered_at, ended_at, subject, observed_value\n"
            f"FROM (\n{QUERIES[ALERT_QUERY[metric]]}\n) AS candidates\n"
            "ON CONFLICT DO NOTHING          -- UNIQUE (rule_id, subject, triggered_at)\n"
            "RETURNING subject, observed_value")


def run_alert_check(con) -> list[dict]:
    """Evaluate every enabled rule in one transaction and record new alerts."""
    rules = con.execute("SELECT id, name, metric, threshold, window_minutes, auto_watchlist "
                        "FROM alert_rules WHERE enabled ORDER BY id").fetchall()
    report = []
    try:
        with transaction(con):
            for rule_id, name, metric, threshold, window, auto in rules:
                t0 = time.perf_counter()
                params = {"rule_id": rule_id, "threshold": threshold, "window": window}
                new = con.execute(alert_insert_sql(metric), params).fetchall()
                added = _auto_watchlist(con, name, new) if auto and metric in IP_METRICS else []
                report.append({"rule": name, "metric": metric, "new_alerts": len(new),
                               "subjects": ", ".join(sorted({s for s, _ in new})[:8]),
                               "auto_watchlisted": ", ".join(added),
                               "ms": round((time.perf_counter() - t0) * 1000, 1)})
    except duckdb.TransactionException as e:
        # Optimistic concurrency: the live feed's own check wrote the same rows first.
        raise ValueError("Another alert check was writing at the same moment. Try again.") from e
    return report


def _auto_watchlist(con, rule_name: str, new_alerts: list[tuple]) -> list[str]:
    """Trigger-like (AFTER INSERT on alerts): a rule with auto_watchlist set
    puts each offending IP on the watchlist. ON CONFLICT DO NOTHING keeps an
    existing entry (and the admin's own severity) untouched."""
    added = []
    for subject, value in new_alerts:
        try:
            ip = normalize_ip(subject)
        except ValueError:
            continue
        row = con.execute(
            "INSERT INTO watchlist (ip, reason, severity) VALUES ($ip, $reason, 'high') "
            "ON CONFLICT (ip) DO NOTHING RETURNING ip",
            {"ip": ip, "reason": f"Auto: alert rule '{rule_name}' (peak {value:g})"}).fetchone()
        if row:
            added.append(row[0])
    return added


# ---------------------------------------------------------------------------
# Read-only SQL console
# ---------------------------------------------------------------------------

CONSOLE_KEYWORDS = ("SELECT", "WITH", "DESCRIBE", "SUMMARIZE")
# Things a SELECT can still do that a read-only console must not: advance
# sequences, read arbitrary files from disk, or run SQL held in a string.
_BLOCKED = re.compile(
    r"\b(nextval|setval|read_\w+|parquet_scan|parquet_metadata|glob|sniff_csv|getenv|query|query_table"
    r"|sqlite_scan|postgres_scan|mysql_scan|iceberg_scan|delta_scan)\s*\("
    r"|\b(from|join)\s+'",          # FROM 'some/file.csv' replacement scans
    re.IGNORECASE)


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", text)


def check_read_only(con, text: str) -> str:
    """Raise ValueError unless `text` is one read-only statement."""
    body = _strip_comments(text).strip().rstrip(";").strip()
    if not body:
        raise ValueError("Enter a query")
    first = re.match(r"[\s(]*(\w+)", body)
    if not first or first.group(1).upper() not in CONSOLE_KEYWORDS:
        raise ValueError(f"Only {', '.join(CONSOLE_KEYWORDS)} statements are allowed")
    try:
        statements = con.extract_statements(body)
    except duckdb.Error as e:
        raise ValueError(_friendly(e)) from e
    if len(statements) != 1:
        raise ValueError("Run one statement at a time")
    if statements[0].type != duckdb.StatementType.SELECT:
        raise ValueError(f"{statements[0].type.name} statements are not allowed")
    blocked = _BLOCKED.search(body)
    if blocked:
        raise ValueError(f"'{blocked.group(0).strip()}' is not allowed in the console")
    return body


def run_console(con, text: str, max_rows: int = 5000, explain: bool = False):
    """Validate and run a console query inside a transaction that is always
    rolled back. Returns (DataFrame, elapsed_ms, truncated, plan_text)."""
    body = check_read_only(con, text)
    con.execute("BEGIN TRANSACTION")
    try:
        t0 = time.perf_counter()
        res = con.execute(body)
        cols = [d[0] for d in res.description]
        rows = res.fetchmany(max_rows + 1)
        elapsed = (time.perf_counter() - t0) * 1000
        plan = None
        if explain:
            plan = "\n".join(r[1] for r in con.execute("EXPLAIN " + body).fetchall())
    except duckdb.Error as e:
        raise ValueError(_friendly(e)) from e
    finally:
        con.execute("ROLLBACK")
    truncated = len(rows) > max_rows
    return pd.DataFrame(rows[:max_rows], columns=cols), elapsed, truncated, plan
