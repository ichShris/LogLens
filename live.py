"""Live traffic simulator.

Appends fresh access-log lines every couple of seconds so the statistics and
charts keep moving during a demo, and injects an attack on demand.

It runs as a background thread inside the Streamlit process rather than as a
separate script, because DuckDB allows only one process to write to
logs.duckdb. The thread works through its own cursor, and every batch goes
through the same read_csv -> regexp_extract -> INSERT ... SELECT pipeline as
an uploaded file (db.append_lines), recorded under one log_files row.
"""
from __future__ import annotations

import random
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import duckdb
import streamlit as st

import db
from scripts.generate_logs import Generator

LIVE_FILE = "live-feed"
TICK_SECONDS = 2
ALERT_EVERY_SECONDS = 30
REFRESH_SECONDS = 5          # how often the open pages re-query while live

# Each incident is short but intense enough to cross the seeded alert rules.
INCIDENTS = {
    "Brute-force login": (3, "203.0.113.", lambda gen, t, ip: gen.brute_force(t, 3, ip=ip)),
    "Vulnerability scan": (3, "198.51.100.", lambda gen, t, ip: gen.scanner(t, 3, ip=ip, per_min=45)),
    "500 errors on /api/checkout": (4, None, lambda gen, t, ip: gen.error_spike(t, 4)),
    "Bot surge": (4, "192.0.2.", lambda gen, t, ip: gen.bot_surge(t, 4, ip=ip)),
}


class LiveFeed:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._gen = Generator(datetime.now(), 1, random.Random())
        self.rate = 5                 # requests per second (the sample data averages ~1/s)
        self.auto_alerts = True
        self.rows = 0
        self.alerts = 0
        self.last_batch: datetime | None = None
        self.error: str | None = None
        self.events: list[str] = []   # injected incidents, newest first

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, conn: duckdb.DuckDBPyConnection) -> None:
        if self.running:
            return
        self._stop.clear()
        self.error = None
        self._thread = threading.Thread(target=self._run, args=(conn.cursor(),), name="live-feed", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        self._thread = None

    def inject(self, kind: str) -> str:
        """Queue an incident starting now; its lines are released as time passes."""
        minutes, ip_range, make = INCIDENTS[kind]
        ip = f"{ip_range}{random.randint(2, 254)}" if ip_range else None
        now = datetime.now()
        with self._lock:
            make(self._gen, now, ip)
        message = f"{now:%H:%M:%S} {kind}" + (f" from {ip}" if ip else "") + f" for {minutes} min"
        self.events.insert(0, message)
        del self.events[5:]
        return message

    def _run(self, cur: duckdb.DuckDBPyConnection) -> None:
        file_id = None
        last = datetime.now()
        last_alert = time.monotonic()
        with tempfile.TemporaryDirectory() as tmp:
            batch = Path(tmp) / "batch.log"
            while not self._stop.is_set():
                now = datetime.now()
                try:
                    if file_id is None:
                        file_id = db.ensure_log_file(cur, LIVE_FILE)
                    with self._lock:
                        self._gen.live_traffic(last, now, self.rate)
                        lines = self._gen.take_until(now)   # future-stamped lines wait
                    last = now
                    if lines:
                        batch.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        self.rows += db.append_lines(cur, file_id, batch)[1]
                        self.last_batch = now
                    if self.auto_alerts and time.monotonic() - last_alert >= ALERT_EVERY_SECONDS:
                        last_alert = time.monotonic()
                        self.alerts += sum(r["new_alerts"] for r in db.run_alert_check(cur))
                    self.error = None
                except (duckdb.Error, ValueError, OSError) as e:
                    self.error = str(e).split("\n")[0]
                    file_id = None   # the live file may have been deleted: recreate it next tick
                self._stop.wait(TICK_SECONDS)
        cur.close()


@st.cache_resource
def get_feed() -> LiveFeed:
    """One simulator per server process, shared by every browser session."""
    return LiveFeed()


def refresh_every() -> int | None:
    """run_every for auto-refreshing fragments: on only while the feed runs."""
    return REFRESH_SECONDS if get_feed().running else None
