import plotly.express as px
import streamlit as st

import db
import live
import ui

con = db.cursor()
st.title("Security")

if ui.require_data(con) is None:
    st.stop()


@st.fragment(run_every=live.refresh_every())
def security() -> None:
    con = db.cursor()   # fresh handle per refresh

    # --- Suspicious IPs ----------------------------------------------------------------
    st.subheader("Suspicious IPs")
    st.caption("The suspicious_ips view scores every IP 0–100: 4xx volume (40 points), distinct "
               "scanner-like paths (30) and peak requests per minute (30).")
    min_score = st.slider("Minimum score", 0, 100, 20, step=5)
    params = {"min_score": min_score, "limit": 100}
    suspects = ui.report(con, "suspicious_ranked", params)
    st.dataframe(suspects, hide_index=True, column_config={
        "rank": st.column_config.NumberColumn("#", width="small"),
        "score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.1f"),
        "watchlist_severity": st.column_config.TextColumn("Watchlist"),
        "n_4xx": st.column_config.NumberColumn("4xx"),
        "n_401": st.column_config.NumberColumn("401"),
        "peak_rpm": st.column_config.NumberColumn("Peak req/min"),
        "first_seen": st.column_config.DatetimeColumn("First seen", format="MM-DD HH:mm"),
        "last_seen": st.column_config.DatetimeColumn("Last seen", format="MM-DD HH:mm"),
    })
    ui.show_sql("suspicious_ranked", params, suspects)
    with st.expander("Show SQL: the suspicious_ips view definition", icon=":material/code:"):
        st.code(con.execute("SELECT sql FROM duckdb_views() WHERE view_name = 'suspicious_ips'").fetchone()[0],
                language="sql")

    st.divider()

    # --- Single IP drill-down ------------------------------------------------------------
    st.subheader("Investigate an IP")
    pick_col, type_col = st.columns(2)
    choices = suspects["ip"].tolist()
    picked = pick_col.selectbox("From the list above", choices, index=0 if choices else None,
                                placeholder="No IPs above the score")
    typed = type_col.text_input("…or type any IP").strip()
    ip = typed or picked

    if ip:
        profile = db.df(con, "ip_profile", {"ip": ip}).iloc[0]
        if not profile["requests"]:
            st.warning(f"No requests from {ip}.")
        else:
            listed = con.execute("SELECT severity FROM watchlist WHERE ip = $ip", {"ip": ip}).fetchone()
            row = suspects[suspects["ip"] == ip]
            score = float(row["score"].iloc[0]) if not row.empty else None
            risk = row["risk"].iloc[0] if not row.empty else "low"

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Requests", f"{int(profile['requests']):,}", border=True)
            c2.metric("4xx responses", f"{int(profile['n_4xx']):,}", border=True)
            c3.metric("Scanner paths", int(profile["scanner_paths"]), border=True)
            c4.metric("Score", f"{score:.1f}" if score is not None else "below filter", border=True)
            st.caption(f"Active {profile['first_seen']:%d %b %H:%M} → {profile['last_seen']:%d %b %H:%M} · "
                       f"User agent: `{profile['user_agent']}`")

            # One-click watchlisting with a suggested severity and reason.
            if listed:
                st.info(f"{ip} is on the watchlist (severity **{listed[0]}**).", icon=":material/visibility:")
            else:
                severity = {"high": "high", "medium": "medium"}.get(risk, "low")
                reason = (f"Security page: score {score:.1f}, " if score is not None else "Security page: ") + \
                          f"{int(profile['n_4xx'])} 4xx, {int(profile['scanner_paths'])} scanner paths"
                if st.button(f"Add {ip} to watchlist ({severity})", type="primary", icon=":material/add_moderator:"):
                    try:
                        db.add_watchlist(con, ip, reason, severity)
                        st.toast(f"{ip} added to the watchlist")
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))

            timeline_params = {"ip": ip}
            timeline = ui.report(con, "ip_timeline", timeline_params)
            timeline["status_class"] = timeline["status_class"].fillna("2xx")  # gap-filled zero rows
            fig = px.bar(timeline, x="minute", y="requests", color="status_class",
                         color_discrete_map=ui.STATUS_COLORS,
                         category_orders={"status_class": ["2xx", "3xx", "4xx", "5xx"]})
            fig.update_traces(hovertemplate="%{x|%d %b %H:%M}: %{y} requests<extra>%{fullData.name}</extra>")
            st.caption(f"Requests per minute from {ip} (gap-filled with range() + LEFT JOIN)")
            st.plotly_chart(ui.style(fig, height=280).update_layout(bargap=0, hovermode="x unified"))
            ui.show_sql("ip_timeline", timeline_params, timeline)

            top_paths = ui.report(con, "ip_top_paths", timeline_params)
            st.dataframe(top_paths, hide_index=True, height=250)
            ui.show_sql("ip_top_paths", timeline_params, top_paths)

    st.divider()

    # --- Attack evidence -------------------------------------------------------------------
    left, right = st.columns(2, gap="large")
    with left:
        st.subheader("Scanner path hits")
        scanner = ui.report(con, "scanner_hits")
        st.dataframe(scanner, hide_index=True, height=320, column_config={
            "first_seen": st.column_config.DatetimeColumn(format="MM-DD HH:mm"),
            "last_seen": st.column_config.DatetimeColumn(format="MM-DD HH:mm"),
        })
        ui.show_sql("scanner_hits", result=scanner)

    with right:
        st.subheader("Failed logins")
        params = {"min_failures": 20}
        logins = ui.report(con, "failed_logins", params)
        if logins.empty:
            st.success("No IP with 20 or more failed logins.")
        else:
            st.dataframe(logins, hide_index=True)
        ui.show_sql("failed_logins", params, logins)

        st.subheader("Error-prone endpoints")
        params = {"min_hits": 100}
        endpoints = ui.report(con, "error_prone_endpoints", params)
        st.dataframe(endpoints, hide_index=True, column_config={
            "error_rate_pct": st.column_config.NumberColumn("Error %", format="%.2f"),
        })
        ui.show_sql("error_prone_endpoints", params, endpoints)


security()
