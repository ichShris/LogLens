import pandas as pd
import streamlit as st

import db
import live
import ui

con = db.cursor()
st.title("Alert Rules")
st.caption("Each rule is evaluated over the logs with window functions; every breach "
           "episode becomes one row in the alerts table.")

# --- Rules (read) ------------------------------------------------------------------------
rules = ui.report(con, "rules_with_counts")
st.dataframe(rules, hide_index=True, column_config={
    "id": st.column_config.NumberColumn("ID", width="small"),
    "window_minutes": st.column_config.NumberColumn("Window (min)"),
    "enabled": st.column_config.CheckboxColumn("Enabled"),
    "auto_watchlist": st.column_config.CheckboxColumn("Auto-watchlist"),
    "last_triggered": st.column_config.DatetimeColumn("Last triggered", format="YYYY-MM-DD HH:mm"),
})
ui.show_sql("rules_with_counts", result=rules)
with st.expander("What the metrics mean", icon=":material/help:"):
    for metric, text in db.METRICS.items():
        st.markdown(f"- `{metric}`: {text}")
    st.markdown("- **Auto-watchlist** puts the offending IP on the watchlist when an IP-based rule fires.")

# --- Run the check -------------------------------------------------------------------------
st.subheader("Run alert check")
run_col, clear_col, _ = st.columns([1, 1, 3])
if run_col.button("Run alert check", type="primary", icon=":material/play_arrow:"):
    with st.spinner("Evaluating enabled rules ..."):
        try:
            st.session_state["alert_report"] = db.run_alert_check(con)
        except ValueError as e:
            st.warning(str(e))
if clear_col.button("Clear all alerts", icon=":material/delete_sweep:"):
    db.clear_alerts(con)
    st.session_state.pop("alert_report", None)
    st.toast("All alerts deleted")
    st.rerun()
if "alert_report" in st.session_state:
    report = pd.DataFrame(st.session_state["alert_report"])
    if report.empty:
        st.warning("No enabled rules.")
    else:
        total = int(report["new_alerts"].sum())
        if total:
            st.success(f"{total} new alert(s) from {len(report)} rule(s).")
        else:
            st.info("No new alerts (repeats are ignored by the UNIQUE constraint).")
        st.dataframe(report, hide_index=True)
with st.expander("Show SQL: alert evaluation (one INSERT per metric)", icon=":material/code:"):
    st.caption("Parameters per rule: $rule_id, $threshold, $window (minutes)")
    for metric in db.ALERT_QUERY:
        st.markdown(f"**{metric}**")
        st.code(db.alert_insert_sql(metric), language="sql")

# --- Alerts ------------------------------------------------------------------------------------
rule_names = dict(zip(rules["name"], rules["id"]))


@st.fragment(run_every=live.refresh_every())   # new alerts appear while live traffic runs
def alerts_section() -> None:
    con = db.cursor()
    st.subheader("Alerts")
    pick = st.selectbox("Rule", ["All rules", *rule_names])
    params = {"rule_id": None if pick == "All rules" else int(rule_names[pick])}
    alerts = ui.report(con, "alerts_list", params)
    if alerts.empty:
        st.info("No alerts yet. Press **Run alert check**.")
    else:
        st.dataframe(alerts, hide_index=True, column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "observed_value": st.column_config.NumberColumn("Peak value", format="%.1f"),
            "triggered_at": st.column_config.DatetimeColumn("Triggered", format="YYYY-MM-DD HH:mm"),
            "ended_at": st.column_config.DatetimeColumn("Ended", format="YYYY-MM-DD HH:mm"),
            "watchlist_severity": st.column_config.TextColumn("Watchlist"),
        })
    ui.show_sql("alerts_list", params, alerts)


alerts_section()

st.divider()
create_col, edit_col = st.columns(2, gap="large")
metrics = list(db.METRICS)

# --- Create ---------------------------------------------------------------------------------------
with create_col:
    st.subheader("New rule")
    with st.form("add_rule", clear_on_submit=True):
        name = st.text_input("Name", max_chars=80)
        metric = st.selectbox("Metric", metrics, help="\n".join(f"- {m}: {t}" for m, t in db.METRICS.items()))
        threshold = st.number_input("Threshold", min_value=0.0, value=10.0, step=1.0)
        window = st.number_input("Window (minutes)", min_value=1, max_value=1440, value=5, step=1)
        enabled = st.checkbox("Enabled", value=True)
        auto = st.checkbox("Auto-watchlist offending IPs", value=False)
        if st.form_submit_button("Create rule", type="primary", icon=":material/add:"):
            try:
                db.add_rule(con, name, metric, threshold, window, enabled, auto)
                st.toast(f"Created '{name.strip()}'")
                st.rerun()
            except ValueError as e:
                st.error(str(e))

# --- Update / delete ----------------------------------------------------------------------------------
with edit_col:
    st.subheader("Edit or delete a rule")
    if rules.empty:
        st.caption("No rules yet.")
    else:
        by_id = {int(r.id): r for r in rules.itertuples()}
        rule_id = st.selectbox("Rule to edit", list(by_id), format_func=lambda i: by_id[i].name)
        r = by_id[rule_id]
        with st.form(f"edit_rule_{rule_id}"):
            new_name = st.text_input("Name", value=r.name, max_chars=80)
            new_metric = st.selectbox("Metric", metrics, index=metrics.index(r.metric))
            new_threshold = st.number_input("Threshold", min_value=0.0, value=float(r.threshold), step=1.0)
            new_window = st.number_input("Window (minutes)", min_value=1, max_value=1440,
                                         value=int(r.window_minutes), step=1)
            new_enabled = st.checkbox("Enabled", value=bool(r.enabled))
            new_auto = st.checkbox("Auto-watchlist offending IPs", value=bool(r.auto_watchlist))
            confirm = st.checkbox(f"Confirm delete (also deletes its {int(r.alerts)} alert(s))")
            save, delete = st.columns(2)
            if save.form_submit_button("Save changes", type="primary", icon=":material/save:"):
                try:
                    db.update_rule(con, rule_id, new_name, new_metric, new_threshold, new_window,
                                   new_enabled, new_auto)
                    st.toast("Saved")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
            if delete.form_submit_button("Delete rule", icon=":material/delete:"):
                if not confirm:
                    st.warning("Tick the confirmation box first.")
                else:
                    db.delete_rule(con, rule_id)
                    st.toast(f"Deleted '{r.name}'")
                    st.rerun()
