"""LogLens: Web Server Log Analyzer - Streamlit entry point.

    streamlit run app.py
"""
import duckdb
import streamlit as st

import db

st.set_page_config(page_title="LogLens", page_icon=":material/monitoring:", layout="wide")

pages = {
    "Data": [
        st.Page("pages/upload.py", title="Upload & Files", icon=":material/upload_file:"),
        st.Page("pages/dashboard.py", title="Dashboard", icon=":material/dashboard:", default=True),
        st.Page("pages/explorer.py", title="Explorer", icon=":material/table_view:"),
    ],
    "Security": [
        st.Page("pages/security.py", title="Security", icon=":material/shield:"),
        st.Page("pages/watchlist.py", title="Watchlist", icon=":material/visibility:"),
        st.Page("pages/alert_rules.py", title="Alert Rules", icon=":material/notifications_active:"),
    ],
    "SQL": [
        st.Page("pages/sql_console.py", title="SQL Console", icon=":material/terminal:"),
    ],
}
nav = st.navigation(pages)

with st.sidebar:
    con = db.cursor()
    files, rows, alerts, watched = con.execute(
        "SELECT (SELECT count(*) FROM log_files WHERE status = 'active'), (SELECT count(*) FROM requests), "
        "(SELECT count(*) FROM alerts), (SELECT count(*) FROM watchlist)").fetchone()
    st.caption(f"**{db.DB_PATH.name}** · DuckDB {duckdb.__version__}")
    st.caption(f"{files} files · {rows:,} requests · {alerts} alerts · {watched} watched IPs")

nav.run()
