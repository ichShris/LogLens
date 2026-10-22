"""Shared Streamlit helpers: the "Show SQL" expander, filters, chart styling."""
from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import db

# Colour-blind-safe reference palette: categorical slots in fixed
# order, a single-hue sequential ramp, and reserved status colours.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SEQUENTIAL = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
STATUS_COLORS = {"1xx": "#898781", "2xx": "#0ca30c", "3xx": "#2a78d6", "4xx": "#ec835a", "5xx": "#d03b3b"}
CLIENT_COLORS = {"Human": SERIES[0], "Bot": SERIES[1]}


def show_sql(name_or_sql: str, params: dict | None = None, result: pd.DataFrame | None = None,
             label: str = "Show SQL") -> None:
    """Expander with the exact query text (from queries.sql when given a
    query name) and the parameter values bound to it."""
    text = db.QUERIES.get(name_or_sql, name_or_sql)
    with st.expander(label, icon=":material/code:"):
        st.code(text, language="sql")
        if params:
            st.caption("Bound parameters")
            st.code(json.dumps(params, default=str, indent=2), language="json")
        if result is not None and "elapsed_ms" in result.attrs:
            st.caption(f"{len(result):,} rows in {result.attrs['elapsed_ms']:.1f} ms")


def report(con, name: str, params: dict | None = None) -> pd.DataFrame:
    """Run a named query; call show_sql(name, params, df) after rendering it."""
    return db.df(con, name, params)


def require_data(con) -> tuple[datetime, datetime] | None:
    """Return (first_ts, last_ts), or show a hint and return None when empty."""
    first, last, n = db.one(con, "data_range")
    if not n:
        st.info("No log data yet. Load some files first.", icon=":material/info:")
        st.page_link("pages/upload.py", label="Go to Upload & Files", icon=":material/upload:")
        return None
    return first, last


def date_range_filter(bounds: tuple[datetime, datetime], key: str) -> tuple[datetime, datetime]:
    """A date range over the data, returned as a half-open [start, end) of datetimes."""
    lo, hi = bounds[0].date(), bounds[1].date()
    picked = st.date_input("Date range", value=(lo, hi), min_value=lo, max_value=hi, key=key)
    if isinstance(picked, (tuple, list)):
        start = picked[0] if picked else lo
        end = picked[1] if len(picked) > 1 else start   # the user is mid-selection
    else:
        start = end = picked
    return datetime.combine(start, time.min), datetime.combine(end + timedelta(days=1), time.min)


def style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    """Thin marks, recessive axes, legend in one row above the plot."""
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=8 if not legend else 36, b=8),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, title_text=""),
        showlegend=legend, bargap=0.15,
    )
    fig.update_xaxes(showgrid=False, title_text="")
    fig.update_yaxes(title_text="", zeroline=False)
    fig.update_traces(selector=dict(type="scatter"), line_width=2)
    return fig


def fmt_bytes(n: float | int | None) -> str:
    if n is None or pd.isna(n):
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_date(d: date | datetime) -> str:
    return d.strftime("%d %b %Y")
