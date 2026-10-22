"""LogLens: Web Server Log Analyzer - Streamlit entry point.

    streamlit run app.py
"""
from datetime import datetime

import duckdb
import streamlit as st

import db
import live

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
feed = live.get_feed()


def toggle_feed() -> None:
    if feed.running:
        feed.stop()
    else:
        feed.start(db.get_conn())


def set_rate() -> None:
    feed.rate = st.session_state["live_rate"]


@st.fragment(run_every=live.refresh_every())
def database_status() -> None:
    con = db.cursor()
    files, rows, alerts, watched = con.execute(
        "SELECT (SELECT count(*) FROM log_files WHERE status = 'active'), (SELECT count(*) FROM requests), "
        "(SELECT count(*) FROM alerts), (SELECT count(*) FROM watchlist)").fetchone()
    st.caption(f"**{db.DB_PATH.name}** · DuckDB {duckdb.__version__}")
    st.caption(f"{files} files · {rows:,} requests · {alerts} alerts · {watched} watched IPs")
    if feed.running:
        ago = f"{(datetime.now() - feed.last_batch).seconds}s ago" if feed.last_batch else "starting"
        st.caption(f":green[● Live] +{feed.rows:,} requests · {feed.alerts} alerts raised · last batch {ago}")
    if feed.error:
        st.warning(f"Live feed: {feed.error}", icon=":material/warning:")


with st.sidebar:
    database_status()
    st.divider()
    st.markdown("**Live traffic**")
    st.button("Stop live traffic" if feed.running else "Start live traffic", on_click=toggle_feed,
              type="secondary" if feed.running else "primary",
              icon=":material/stop:" if feed.running else ":material/play_arrow:", width="stretch")
    st.slider("Requests per second", 1, 100, value=feed.rate, key="live_rate", on_change=set_rate)
    kind = st.selectbox("Incident", list(live.INCIDENTS), key="live_incident")
    if st.button("Inject incident", disabled=not feed.running, icon=":material/bug_report:", width="stretch"):
        st.toast(feed.inject(kind))
    for event in feed.events:
        st.caption(event)
    if feed.running:
        st.caption(f"Pages refresh every {live.REFRESH_SECONDS}s; alert rules run every "
                   f"{live.ALERT_EVERY_SECONDS}s.")

nav.run()
