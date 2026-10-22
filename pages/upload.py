import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

import db
import ui

con = db.cursor()
st.title("Upload & Files")
st.caption("Log files are parsed inside DuckDB: read_csv → regexp_extract → strptime, "
           "one INSERT … SELECT per file, wrapped in a transaction.")


def show_results(results: list[db.IngestResult]) -> None:
    for r in results:
        with st.container(border=True):
            st.markdown(f"**{r.name}**")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Lines", f"{r.line_count:,}")
            c2.metric("Parsed", f"{r.parsed:,}")
            c3.metric("Failed", f"{r.failed:,}")
            c4.metric("Parse time", f"{r.seconds:.2f} s", f"{r.rows_per_sec:,.0f} rows/s", delta_color="off")


# --- Upload ------------------------------------------------------------------
upload_col, sample_col = st.columns([3, 2], gap="large")
with upload_col:
    st.subheader("Upload log files")
    uploads = st.file_uploader("Apache/Nginx combined-format access logs", accept_multiple_files=True,
                               type=["log", "txt"])
    if st.button("Ingest uploaded files", type="primary", disabled=not uploads, icon=":material/database_upload:"):
        results = []
        with tempfile.TemporaryDirectory() as tmp, st.status("Ingesting ...", expanded=True) as status:
            for up in uploads:
                st.write(f"Parsing {up.name} ...")
                path = Path(tmp) / Path(up.name).name
                path.write_bytes(up.getbuffer())
                try:
                    results.append(db.ingest_file(con, path, up.name))
                except ValueError as e:
                    st.error(str(e))
            status.update(label=f"Ingested {len(results)} of {len(uploads)} files", state="complete")
        st.session_state["ingest_results"] = results

with sample_col:
    st.subheader("Bundled sample logs")
    samples = sorted(db.SAMPLE_DIR.glob("*.log"))
    loaded = db.loaded_file_names(con)
    pending = [p for p in samples if p.name not in loaded]
    if not samples:
        st.info("No sample logs found. Generate them with `python scripts/generate_logs.py`.")
    else:
        for p in samples:
            mark = "loaded" if p.name in loaded else "not loaded"
            st.markdown(f"- `{p.name}` · {p.stat().st_size / 1e6:,.1f} MB · {mark}")
        if st.button("Load sample logs", disabled=not pending, icon=":material/folder_open:"):
            results = []
            with st.spinner(f"Ingesting {len(pending)} file(s) ..."):
                for p in pending:
                    try:
                        results.append(db.ingest_file(con, p))
                    except ValueError as e:
                        st.error(str(e))
            st.session_state["ingest_results"] = results

if st.session_state.get("ingest_results"):
    show_results(st.session_state["ingest_results"])

with st.expander("Show SQL: ingestion pipeline", icon=":material/code:"):
    for name in ("insert_log_file", "stage_raw_lines", "ingest_requests", "ingest_parse_errors", "finish_log_file"):
        st.caption(name)
        st.code(db.QUERIES[name], language="sql")
    st.caption("parse_log_line() macro (schema.sql)")
    st.code(con.execute("SELECT macro_definition FROM duckdb_functions() "
                        "WHERE function_name = 'parse_log_line'").fetchone()[0], language="sql")

st.divider()

# --- Files -------------------------------------------------------------------
st.subheader("Loaded files")
files = ui.report(con, "files_list")
if files.empty:
    st.info("No files loaded yet.")
else:
    st.dataframe(files, hide_index=True, column_config={
        "id": st.column_config.NumberColumn("ID", width="small"),
        "uploaded_at": st.column_config.DatetimeColumn("Uploaded", format="YYYY-MM-DD HH:mm"),
        "failed_pct": st.column_config.NumberColumn("Failed %", format="%.3f"),
        "rows_per_sec": st.column_config.NumberColumn("Rows/s", format="%,d"),
        "first_request": st.column_config.DatetimeColumn("First request", format="YYYY-MM-DD HH:mm"),
        "last_request": st.column_config.DatetimeColumn("Last request", format="YYYY-MM-DD HH:mm"),
    })
    ui.show_sql("files_list", result=files)

    errors_col, delete_col = st.columns([3, 2], gap="large")
    options = dict(zip(files["name"], files["id"]))
    with errors_col:
        st.markdown("**Parse errors**")
        name = st.selectbox("File", list(options), key="errors_file")
        params = {"file_id": int(options[name])}
        errors = ui.report(con, "file_parse_errors", params)
        if errors.empty:
            st.success("Every line parsed.")
        else:
            st.dataframe(errors, hide_index=True, height=240)
        ui.show_sql("file_parse_errors", params, errors)

    with delete_col:
        st.markdown("**Delete a file**")
        with st.form("delete_file"):
            target = st.selectbox("File to delete", list(options))
            confirm = st.checkbox("Also deletes its requests and parse errors")
            if st.form_submit_button("Delete file", icon=":material/delete:"):
                if not confirm:
                    st.warning("Tick the confirmation box first.")
                else:
                    db.delete_log_file(con, int(options[target]))
                    st.session_state.pop("ingest_results", None)
                    st.toast(f"Deleted {target}")
                    st.rerun()
        st.caption("No ON DELETE CASCADE in DuckDB: db.delete_log_file() deletes the children first.")
        ui.show_sql("-- step 1: one transaction\nBEGIN TRANSACTION;\n"
                    "UPDATE log_files SET status = 'deleting' WHERE id = $id;\n"
                    "DELETE FROM parse_errors WHERE file_id = $id;\n"
                    "DELETE FROM requests     WHERE file_id = $id;\nCOMMIT;\n\n"
                    "-- step 2: the parent row\nBEGIN TRANSACTION;\n"
                    "DELETE FROM log_files WHERE id = $id;\nCOMMIT;")

    st.subheader("Status codes across all data")
    summary = ui.report(con, "status_summary_all")
    st.dataframe(summary, hide_index=True, width="content")
    ui.show_sql("status_summary_all", result=summary)
