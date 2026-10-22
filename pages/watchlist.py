import streamlit as st

import db
import ui

con = db.cursor()
st.title("Watchlist")
st.caption("IPs flagged by an admin, from the Security page, or automatically by an alert rule.")

# --- Read ------------------------------------------------------------------------------
entries = ui.report(con, "watchlist_with_activity")
if entries.empty:
    st.info("The watchlist is empty.")
else:
    st.dataframe(entries, hide_index=True, column_config={
        "id": st.column_config.NumberColumn("ID", width="small"),
        "reason": st.column_config.TextColumn("Reason", width="large"),
        "added_at": st.column_config.DatetimeColumn("Added", format="YYYY-MM-DD HH:mm"),
        "last_seen": st.column_config.DatetimeColumn("Last seen in logs", format="YYYY-MM-DD HH:mm"),
    })
ui.show_sql("watchlist_with_activity", result=entries)

create_col, edit_col = st.columns(2, gap="large")

# --- Create ----------------------------------------------------------------------------
with create_col:
    st.subheader("Add an IP")
    with st.form("add_watch", clear_on_submit=True):
        ip = st.text_input("IP address", placeholder="203.0.113.45")
        severity = st.selectbox("Severity", db.SEVERITIES, index=1)
        reason = st.text_area("Reason", max_chars=500)
        if st.form_submit_button("Add to watchlist", type="primary", icon=":material/add:"):
            try:
                db.add_watchlist(con, ip, reason, severity)
                st.toast(f"Added {ip.strip()}")
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    ui.show_sql("INSERT INTO watchlist (ip, reason, severity)\nVALUES ($ip, $reason, $severity)\nRETURNING id",
                label="Show SQL (insert)")

# --- Update / delete -------------------------------------------------------------------------
with edit_col:
    st.subheader("Edit or remove")
    if entries.empty:
        st.caption("Nothing to edit yet.")
    else:
        by_id = {int(r.id): r for r in entries.itertuples()}
        entry_id = st.selectbox("Entry", list(by_id), format_func=lambda i: f"{by_id[i].ip} ({by_id[i].severity})")
        entry = by_id[entry_id]
        with st.form(f"edit_watch_{entry_id}"):
            new_ip = st.text_input("IP address", value=entry.ip)
            new_sev = st.selectbox("Severity", db.SEVERITIES, index=db.SEVERITIES.index(entry.severity))
            new_reason = st.text_area("Reason", value=entry.reason, max_chars=500)
            save, delete = st.columns(2)
            if save.form_submit_button("Save changes", type="primary", icon=":material/save:"):
                try:
                    db.update_watchlist(con, entry_id, new_ip, new_reason, new_sev)
                    st.toast("Saved")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
            if delete.form_submit_button("Remove from watchlist", icon=":material/delete:"):
                db.delete_watchlist(con, entry_id)
                st.toast(f"Removed {entry.ip}")
                st.rerun()
        ui.show_sql("UPDATE watchlist SET ip = $ip, reason = $reason, severity = $severity WHERE id = $id;\n\n"
                    "DELETE FROM watchlist WHERE id = $id;", label="Show SQL (update / delete)")

st.caption("Validation runs twice: db.py checks and normalises the input first (the job a BEFORE "
           "trigger would do), then the table's NOT NULL, UNIQUE and CHECK constraints enforce it in the database.")
