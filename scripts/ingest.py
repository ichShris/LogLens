"""Command-line ingestion (and a quick health check) without the UI.

  python scripts/ingest.py                         # load sample_logs/*.log
  python scripts/ingest.py my.log other.log --alerts
  python scripts/ingest.py --reset --alerts        # fresh database, sample logs, run alert rules

Stop the Streamlit app first: DuckDB allows only one process to open
logs.duckdb for writing.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

import db  # noqa: E402

pd.set_option("display.width", 200)
pd.set_option("display.max_columns", 20)
pd.set_option("display.max_colwidth", 40)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path, help="log files (default: sample_logs/*.log)")
    ap.add_argument("--db", type=Path, default=db.DB_PATH, help="database file (default: logs.duckdb)")
    ap.add_argument("--reset", action="store_true", help="delete the database file first")
    ap.add_argument("--alerts", action="store_true", help="run the enabled alert rules afterwards")
    args = ap.parse_args()

    if args.reset:
        for p in (args.db, Path(str(args.db) + ".wal")):
            p.unlink(missing_ok=True)
    con = db.open_db(args.db)
    files = args.files or sorted(db.SAMPLE_DIR.glob("*.log"))
    if not files:
        sys.exit("No log files given and none in sample_logs/ - run scripts/generate_logs.py first")

    for path in files:
        try:
            r = db.ingest_file(con, path)
        except ValueError as e:
            print(f"skip {path.name}: {e}")
            continue
        print(f"{r.name}: {r.line_count:,} lines, {r.parsed:,} parsed, {r.failed:,} failed "
              f"in {r.seconds:.2f}s ({r.rows_per_sec:,.0f} rows/s)")

    print("\nTop suspicious IPs (suspicious_ips view):")
    print(db.df(con, "suspicious_ranked", {"min_score": 0, "limit": 8}).to_string(index=False))

    if args.alerts:
        print("\nAlert check:")
        print(pd.DataFrame(db.run_alert_check(con)).to_string(index=False))
        print("\nAlerts:")
        print(db.df(con, "alerts_list", {"rule_id": None}).to_string(index=False))
        print("\nWatchlist:")
        print(db.df(con, "watchlist_with_activity").to_string(index=False))
    con.close()


if __name__ == "__main__":
    main()
