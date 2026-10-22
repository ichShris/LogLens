import io
import math

import pyarrow.csv as pa_csv
import pyarrow.parquet as pq
import streamlit as st

import db
import ui

con = db.cursor()
st.title("Explorer")

bounds = ui.require_data(con)
if bounds is None:
    st.stop()

statuses = db.df(con, "distinct_statuses")["status"].tolist()
methods = db.df(con, "distinct_methods")["method"].tolist()

with st.container(border=True):
    c1, c2, c3 = st.columns([2, 2, 2])
    with c1:
        start, end = ui.date_range_filter(bounds, key="explorer_range")
    with c2:
        picked_status = st.multiselect("Status", statuses, placeholder="Any status")
    with c3:
        picked_methods = st.multiselect("Method", methods, placeholder="Any method")
    c4, c5, c6 = st.columns([2, 2, 2])
    ip_prefix = c4.text_input("IP (exact or prefix)", placeholder="e.g. 203.0.113.").strip()
    path_part = c5.text_input("Path contains", placeholder="e.g. /api/").strip()
    page_size = c6.selectbox("Rows per page", [25, 50, 100, 250], index=1)

params = {"start": start, "end": end, "statuses": [int(s) for s in picked_status],
          "methods": picked_methods, "ip_prefix": ip_prefix, "path_part": path_part}

# Reset to page 1 whenever a filter changes.
signature = repr(sorted((k, str(v)) for k, v in params.items())) + str(page_size)
if st.session_state.get("explorer_sig") != signature:
    st.session_state["explorer_sig"] = signature
    st.session_state["explorer_page"] = 1

total = int(db.one(con, "explorer_count", params)[0])
pages = max(1, math.ceil(total / page_size))

page = min(st.session_state["explorer_page"], pages)


def go_to(n: int) -> None:
    # on_click callbacks run before the rerun, so the page label is never stale
    st.session_state["explorer_page"] = n


nav = st.columns([2, 1, 1, 1, 1])
nav[0].markdown(f"**{total:,}** matching requests · page **{page:,}** of {pages:,}")
nav[1].button("First", on_click=go_to, args=(1,), disabled=page == 1, width="stretch")
nav[2].button("Previous", on_click=go_to, args=(page - 1,), disabled=page == 1, width="stretch")
nav[3].button("Next", on_click=go_to, args=(page + 1,), disabled=page >= pages, width="stretch")
nav[4].button("Last", on_click=go_to, args=(pages,), disabled=page >= pages, width="stretch")

page_params = params | {"limit": page_size, "offset": (page - 1) * page_size}
rows = ui.report(con, "explorer_page", page_params)
st.dataframe(rows, hide_index=True, height=min(38 + 35 * len(rows), 700), column_config={
    "ts": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
    "bytes": st.column_config.NumberColumn("Bytes", format="%,d"),
    "user_agent": st.column_config.TextColumn("User agent", width="medium"),
})
ui.show_sql("explorer_page", page_params, rows)
with st.expander("Show SQL: the filtered_requests() table macro", icon=":material/code:"):
    st.code(con.execute("SELECT macro_definition FROM duckdb_functions() "
                        "WHERE function_name = 'filtered_requests'").fetchone()[0], language="sql")
    st.code(db.QUERIES["explorer_count"], language="sql")


# --- Export ------------------------------------------------------------------------
def export_table():
    return con.execute(db.QUERIES["explorer_export"], params).fetch_arrow_table()


def to_csv() -> bytes:
    buf = io.BytesIO()
    pa_csv.write_csv(export_table(), buf)
    return buf.getvalue()


def to_parquet() -> bytes:
    buf = io.BytesIO()
    pq.write_table(export_table(), buf, compression="zstd")
    return buf.getvalue()


st.subheader("Export")
st.caption(f"Exports all {total:,} filtered rows, not just this page. The file is built when you click.")
e1, e2, _ = st.columns([1, 1, 3])
# Callables: the query runs only when the button is clicked.
e1.download_button("Download CSV", to_csv, file_name="requests.csv", mime="text/csv",
                   icon=":material/download:", disabled=total == 0, on_click="ignore")
e2.download_button("Download Parquet", to_parquet, file_name="requests.parquet",
                   mime="application/vnd.apache.parquet", icon=":material/download:",
                   disabled=total == 0, on_click="ignore")
ui.show_sql("explorer_export", params, label="Show SQL (export)")
