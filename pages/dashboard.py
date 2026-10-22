from datetime import timedelta

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import db
import ui

con = db.cursor()
st.title("Dashboard")

bounds = ui.require_data(con)
if bounds is None:
    st.stop()

filter_col, _ = st.columns([2, 3])
with filter_col:
    start, end = ui.date_range_filter(bounds, key="dash_range")
span = {"start": start, "end": end}
st.caption(f"Every chart below covers {ui.fmt_date(start)} – {ui.fmt_date(end - timedelta(days=1))}, "
           "through the `requests_between($start, $end)` table macro or the `hourly_traffic` view.")

# --- KPI cards -----------------------------------------------------------------
kpis = ui.report(con, "kpis", span)
k = kpis.iloc[0]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total requests", f"{int(k.total_requests):,}", border=True)
c2.metric("Unique IPs", f"{int(k.unique_ips):,}", border=True)
c3.metric("Error rate (4xx + 5xx)", f"{k.error_rate_pct or 0:.2f}%", border=True)
c4.metric("Total bandwidth", ui.fmt_bytes(k.total_bytes), border=True,
          help=f"Median response {ui.fmt_bytes(k.median_bytes)} · p95 {ui.fmt_bytes(k.p95_bytes)} (quantile_cont)")
ui.show_sql("kpis", span, kpis)

# --- Requests over time ----------------------------------------------------------
st.subheader("Requests over time")
traffic = ui.report(con, "traffic_over_time", span)
fig = go.Figure()
fig.add_bar(x=traffic["hour"], y=traffic["requests"], name="Requests per hour", marker_color=ui.SEQUENTIAL[2],
            hovertemplate="%{x|%a %d %b %H:00}<br>%{y:,} requests<extra></extra>")
fig.add_scatter(x=traffic["hour"], y=traffic["moving_avg_24h"], name="24 h moving average", mode="lines",
                line_color=ui.SERIES[1], hovertemplate="%{y:,.0f} avg<extra></extra>")
st.plotly_chart(ui.style(fig, height=330).update_layout(hovermode="x unified", bargap=0.05))

err = traffic.melt(id_vars="hour", value_vars=["errors_4xx", "errors_5xx"], var_name="class", value_name="n")
err["class"] = err["class"].map({"errors_4xx": "4xx", "errors_5xx": "5xx"})
fig = px.line(err, x="hour", y="n", color="class", color_discrete_map=ui.STATUS_COLORS,
              labels={"n": "Errors per hour", "hour": ""})
fig.update_traces(hovertemplate="%{y:,}")
st.caption("Errors per hour (a separate chart, so the error scale isn't flattened by total traffic)")
st.plotly_chart(ui.style(fig, height=220).update_layout(hovermode="x unified"))
ui.show_sql("traffic_over_time", span, traffic)

# --- Status classes + bots ---------------------------------------------------------
left, right = st.columns(2, gap="large")
with left:
    st.subheader("Status classes")
    status = ui.report(con, "status_breakdown", span)
    fig = px.bar(status, x="hits", y="status_class", orientation="h", color="status_class",
                 color_discrete_map=ui.STATUS_COLORS, text=status["pct"].map(lambda p: f"{p:.2f}%"),
                 custom_data=["pct"])
    fig.update_traces(textposition="outside", cliponaxis=False, marker_cornerradius=4,
                      hovertemplate="%{y}: %{x:,} requests (%{customdata[0]:.2f}%)<extra></extra>")
    fig.update_yaxes(categoryorder="category descending")
    fig.update_xaxes(range=[0, status["hits"].max() * 1.18])  # room for the outside labels
    st.plotly_chart(ui.style(fig, height=260, legend=False))
    ui.show_sql("status_breakdown", span, status)

with right:
    st.subheader("Bot vs human traffic")
    bots = ui.report(con, "bot_vs_human", span)
    daily = ui.report(con, "bot_vs_human_daily", span)
    cols = st.columns(len(bots))
    for col, row in zip(cols, bots.itertuples()):
        col.metric(row.client, f"{row.hits:,}", f"{row.pct:.1f}% of requests · {ui.fmt_bytes(row.bytes)}",
                   delta_color="off", delta_arrow="off")
    fig = px.bar(daily, x="day", y="hits", color="client", color_discrete_map=ui.CLIENT_COLORS,
                 category_orders={"client": ["Human", "Bot"]})
    fig.update_traces(marker_cornerradius=4, hovertemplate="%{x|%a %d %b}: %{y:,}<extra>%{fullData.name}</extra>")
    st.plotly_chart(ui.style(fig, height=200))
    ui.show_sql("bot_vs_human", span, bots)
    ui.show_sql("bot_vs_human_daily", span, daily, label="Show SQL (daily)")

# --- Top endpoints / IPs --------------------------------------------------------------
left, right = st.columns(2, gap="large")
with left:
    st.subheader("Top endpoints")
    include_static = st.toggle("Include static assets", value=False)
    params = span | {"include_static": include_static, "limit": 15}
    endpoints = ui.report(con, "top_endpoints", params)
    st.dataframe(endpoints, hide_index=True, column_config={
        "hits": st.column_config.ProgressColumn("Hits", format="%d", min_value=0,
                                                max_value=int(endpoints["hits"].max() or 1)),
        "error_rate_pct": st.column_config.NumberColumn("Error %", format="%.2f"),
        "avg_bytes": st.column_config.NumberColumn("Avg bytes", format="%,d"),
        "p95_bytes": st.column_config.NumberColumn("p95 bytes", format="%,d"),
    })
    ui.show_sql("top_endpoints", params, endpoints)

with right:
    st.subheader("Top IPs")
    params = span | {"limit": 15}
    ips = ui.report(con, "top_ips", params)
    st.dataframe(ips, hide_index=True, column_config={
        "watchlist_severity": st.column_config.TextColumn("Watchlist"),
        "hits": st.column_config.ProgressColumn("Hits", format="%d", min_value=0,
                                                max_value=int(ips["hits"].max() or 1)),
        "bytes": st.column_config.NumberColumn("Bytes", format="%,d"),
        "error_rate_pct": st.column_config.NumberColumn("Error %", format="%.2f"),
    })
    ui.show_sql("top_ips", params, ips)

# --- Weekly pattern + busiest hours ------------------------------------------------------
left, right = st.columns([3, 2], gap="large")
with left:
    st.subheader("Traffic by weekday and hour")
    heat = ui.report(con, "weekly_heatmap", span)
    grid = heat.pivot_table(index=["dow", "weekday"], columns="hour", values="avg_requests").droplevel("dow")
    # No explicit colour scale: Streamlit's theme supplies a sequential one
    # stepped for whichever light/dark theme is active.
    fig = px.imshow(grid, aspect="auto",
                    labels={"x": "Hour of day", "y": "", "color": "Avg requests"})
    fig.update_traces(xgap=2, ygap=2, hovertemplate="%{y} %{x}:00 · %{z:,.0f} requests/hour<extra></extra>")
    st.plotly_chart(ui.style(fig, height=280, legend=False).update_xaxes(title_text="Hour of day", dtick=2))
    ui.show_sql("weekly_heatmap", span, heat)

with right:
    st.subheader("Busiest hour per day")
    busiest = ui.report(con, "busiest_hour_per_day", span)
    st.dataframe(busiest, hide_index=True, column_config={
        "day": st.column_config.DateColumn("Day", format="ddd DD MMM"),
        "busiest_hour": st.column_config.TextColumn("Busiest hour"),
    })
    ui.show_sql("busiest_hour_per_day", span, busiest)
