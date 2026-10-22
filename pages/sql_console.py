import streamlit as st

import db
import ui

con = db.cursor()
st.title("SQL Console")
st.caption("Read-only: one SELECT, WITH, DESCRIBE or SUMMARIZE statement at a time. It runs inside a "
           "transaction that is always rolled back.")

EXAMPLES = {
    "Top 10 IPs by 4xx": "SELECT ip, count(*) AS n_4xx\nFROM requests\nWHERE status BETWEEN 400 AND 499\n"
                         "GROUP BY ALL\nORDER BY n_4xx DESC\nLIMIT 10",
    "Suspicious IPs (view)": "SELECT rank, ip, score, risk, n_4xx, scanner_paths, peak_rpm\n"
                             "FROM suspicious_ips\nORDER BY rank\nLIMIT 10",
    "Response size percentiles per status class":
        "SELECT status_class(status) AS class,\n       count(*) AS hits,\n"
        "       quantile_cont(bytes, [0.5, 0.9, 0.99]) AS p50_p90_p99\nFROM requests\nGROUP BY ALL\nORDER BY class",
    "Each IP's busiest minute (QUALIFY)":
        "WITH per_minute AS (\n    SELECT ip, date_trunc('minute', ts) AS minute, count(*) AS n\n"
        "    FROM requests GROUP BY ALL\n)\nSELECT *\nFROM per_minute\n"
        "QUALIFY row_number() OVER (PARTITION BY ip ORDER BY n DESC) = 1\nORDER BY n DESC\nLIMIT 10",
    "Hour-over-hour change (LAG)":
        "SELECT hour, requests,\n       requests - lag(requests) OVER (ORDER BY hour) AS change\n"
        "FROM hourly_traffic\nORDER BY abs(change) DESC NULLS LAST\nLIMIT 10",
    "Describe the requests table": "DESCRIBE requests",
    "Summarize the requests table": "SUMMARIZE requests",
}


def load_example() -> None:
    st.session_state["console_sql"] = EXAMPLES[st.session_state["console_example"]]


console_tab, schema_tab = st.tabs(["Console", "Schema browser"])

with console_tab:
    st.selectbox("Examples", list(EXAMPLES), key="console_example", on_change=load_example, index=None,
                 placeholder="Load an example query ...")
    st.session_state.setdefault("console_sql", EXAMPLES["Top 10 IPs by 4xx"])
    sql = st.text_area("Query", key="console_sql", height=220)
    c1, c2, _ = st.columns([1, 1, 3])
    run = c1.button("Run", type="primary", icon=":material/play_arrow:")
    explain = c2.checkbox("Show query plan")
    if run:
        try:
            result, ms, truncated, plan = db.run_console(con, sql, explain=explain)
        except ValueError as e:
            st.error(str(e), icon=":material/block:")
        else:
            note = " (first 5,000 shown)" if truncated else ""
            st.success(f"{len(result):,} rows{note} in {ms:.1f} ms", icon=":material/check:")
            st.dataframe(result, hide_index=True)
            if plan:
                st.code(plan, language="text")

with schema_tab:
    objects = ui.report(con, "catalog_objects")
    st.dataframe(objects, hide_index=True)
    ui.show_sql("catalog_objects", result=objects)

    st.markdown("**Constraints**")
    constraints = ui.report(con, "catalog_constraints")
    st.dataframe(constraints, hide_index=True)
    ui.show_sql("catalog_constraints", result=constraints)

    st.markdown("**View definitions**")
    for view_name, view_sql in db.df(con, "catalog_view_sql").itertuples(index=False):
        with st.expander(view_name):
            st.code(view_sql, language="sql")
