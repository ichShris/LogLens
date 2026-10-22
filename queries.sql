-- =====================================================================
-- Web Server Log Analyzer - analytical and ingestion queries
--
-- db.py loads this file at startup: every block that starts with
-- "-- name: <query_name>" becomes one named query, and the app runs
-- exactly this text (the "Show SQL" expanders display it unchanged).
--
-- All inputs are bound parameters written as $name - nothing is ever
-- formatted into the SQL string.
-- =====================================================================


-- =====================================================================
-- 1. INGESTION  (run inside one transaction per file, see db.ingest_file)
-- =====================================================================

-- name: insert_log_file
-- Parent row first, so the child rows below can reference it (FK).
INSERT INTO log_files (name) VALUES ($name) RETURNING id;

-- name: stage_raw_lines
-- Read the whole file as ONE VARCHAR column: the delimiter is the ASCII
-- unit separator (never present in logs) and quoting is switched off, so
-- every physical line arrives verbatim. row_number() keeps line numbers;
-- $line_offset continues the numbering when the live feed appends a batch.
CREATE OR REPLACE TEMP TABLE raw_lines AS
SELECT line_no, rtrim(line, chr(13)) AS line
FROM (
    SELECT row_number() OVER () + $line_offset AS line_no, line
    FROM read_csv($path,
                  columns = {'line': 'VARCHAR'},
                  header = false, delim = chr(31), quote = '', escape = '',
                  auto_detect = false)
)
WHERE line IS NOT NULL AND line <> '';

-- name: ingest_requests
-- The parser: one INSERT ... SELECT. parse_log_line() (a macro around
-- regexp_extract with named groups) splits the line into a STRUCT, and
-- strptime turns the Apache timestamp into a TIMESTAMP.
INSERT INTO requests (file_id, ip, ts, method, path, query_string, protocol,
                      status, bytes, referrer, user_agent, is_bot)
SELECT $file_id,
       f.ip,
       strptime(f.ts, '%d/%b/%Y:%H:%M:%S'),
       f.method,
       split_part(f.target, '?', 1),
       nullif(regexp_extract(f.target, '\?(.*)$', 1), ''),
       f.protocol,
       CAST(f.status AS SMALLINT),
       CASE WHEN f.bytes = '-' THEN 0 ELSE CAST(f.bytes AS BIGINT) END,
       nullif(f.referrer, '-'),
       nullif(f.ua, '-'),
       is_bot_ua(f.ua)
FROM (SELECT line_no, parse_log_line(line) AS f FROM raw_lines) AS parsed
WHERE f.ip <> ''                                              -- regex matched
  AND try_strptime(f.ts, '%d/%b/%Y:%H:%M:%S') IS NOT NULL     -- and the date is real
ORDER BY line_no;

-- name: ingest_parse_errors
-- Exactly the complement of the WHERE clause above.
INSERT INTO parse_errors (file_id, line_no, raw_line)
SELECT $file_id, line_no, line
FROM (SELECT line_no, line, parse_log_line(line) AS f FROM raw_lines) AS parsed
WHERE f.ip = ''
   OR try_strptime(f.ts, '%d/%b/%Y:%H:%M:%S') IS NULL;

-- name: finish_log_file
-- The table-level CHECK (parsed + failed = line_count) doubles as an
-- integrity assertion: if the two inserts ever disagree, the whole
-- transaction rolls back.
UPDATE log_files
SET line_count = $line_count, parsed_count = $parsed, failed_count = $failed,
    parse_seconds = $seconds
WHERE id = $file_id;

-- name: append_log_file_counts
-- Live feed: each appended batch adds to the running totals.
UPDATE log_files
SET line_count    = line_count + $line_count,
    parsed_count  = parsed_count + $parsed,
    failed_count  = failed_count + $failed,
    parse_seconds = coalesce(parse_seconds, 0) + $seconds
WHERE id = $file_id;


-- =====================================================================
-- 2. FILES PAGE
-- =====================================================================

-- name: files_list
-- LEFT JOIN so a file whose every line failed still shows up.
SELECT f.id, f.name, f.uploaded_at, f.line_count, f.parsed_count, f.failed_count,
       round(100.0 * f.failed_count / nullif(f.line_count, 0), 3) AS failed_pct,
       round(f.parse_seconds, 2)                                  AS parse_seconds,
       round(f.line_count / nullif(f.parse_seconds, 0))           AS rows_per_sec,
       min(r.ts) AS first_request,
       max(r.ts) AS last_request
FROM log_files f
LEFT JOIN requests r ON r.file_id = f.id
WHERE f.status = 'active'
GROUP BY ALL
ORDER BY f.id;

-- name: file_parse_errors
SELECT line_no, raw_line
FROM parse_errors
WHERE file_id = $file_id
ORDER BY line_no
LIMIT 200;

-- name: status_summary_all
-- The status_summary view, rolled up to classes with ROLLUP for a total row.
SELECT coalesce(status_class, 'TOTAL') AS status_class,
       CAST(sum(hits) AS BIGINT)       AS hits,
       round(sum(pct), 2)              AS pct
FROM status_summary
GROUP BY ROLLUP (status_class)
ORDER BY status_class NULLS LAST;


-- =====================================================================
-- 3. DASHBOARD  (every query takes $start / $end and goes through the
--    requests_between() table macro or filters the hourly_traffic view)
-- =====================================================================

-- name: data_range
SELECT min(ts) AS first_ts, max(ts) AS last_ts, count(*) AS n FROM requests;

-- name: kpis
SELECT count(*)                                                          AS total_requests,
       count(DISTINCT ip)                                                AS unique_ips,
       round(100.0 * count(*) FILTER (WHERE status >= 400) / nullif(count(*), 0), 2) AS error_rate_pct,
       coalesce(sum(bytes), 0)                                           AS total_bytes,
       quantile_cont(bytes, 0.5)                                         AS median_bytes,
       quantile_cont(bytes, 0.95)                                        AS p95_bytes
FROM requests_between($start, $end);

-- name: traffic_over_time
-- Window function: a trailing 24-hour moving average. RANGE (not ROWS)
-- measures the frame in time, so hours with no traffic don't skew it.
SELECT hour,
       requests,
       round(avg(requests) OVER (ORDER BY hour
                                 RANGE BETWEEN INTERVAL 23 HOURS PRECEDING AND CURRENT ROW)) AS moving_avg_24h,
       errors_4xx,
       errors_5xx
FROM hourly_traffic
WHERE hour >= $start AND hour < $end
ORDER BY hour;

-- name: status_breakdown
-- count(*) / sum(count(*)) OVER () = share of the total, in one pass.
SELECT status_class(status)                                 AS status_class,
       count(*)                                             AS hits,
       round(100.0 * count(*) / sum(count(*)) OVER (), 2)   AS pct
FROM requests_between($start, $end)
GROUP BY ALL
ORDER BY status_class;

-- name: top_endpoints
SELECT normalize_path(path)                                               AS endpoint,
       count(*)                                                           AS hits,
       count(DISTINCT ip)                                                 AS unique_ips,
       round(100.0 * count(*) FILTER (WHERE status >= 400) / count(*), 2) AS error_rate_pct,
       round(avg(bytes))                                                  AS avg_bytes,
       quantile_cont(bytes, 0.95)                                         AS p95_bytes
FROM requests_between($start, $end)
WHERE $include_static OR NOT regexp_matches(path, '^/(static/|favicon\.ico)')
GROUP BY ALL
ORDER BY hits DESC
LIMIT $limit;

-- name: top_ips
-- LEFT JOIN watchlist: every IP is kept, flagged ones get their severity.
SELECT r.ip,
       w.severity                                                             AS watchlist_severity,
       count(*)                                                               AS hits,
       count(DISTINCT r.path)                                                 AS distinct_paths,
       sum(r.bytes)                                                           AS bytes,
       round(100.0 * count(*) FILTER (WHERE r.status >= 400) / count(*), 2)   AS error_rate_pct,
       bool_or(r.is_bot)                                                      AS is_bot
FROM requests_between($start, $end) AS r
LEFT JOIN watchlist w ON w.ip = r.ip
GROUP BY ALL
ORDER BY hits DESC
LIMIT $limit;

-- name: bot_vs_human
SELECT CASE WHEN is_bot THEN 'Bot' ELSE 'Human' END        AS client,
       count(*)                                             AS hits,
       sum(bytes)                                           AS bytes,
       count(DISTINCT ip)                                   AS unique_ips,
       round(100.0 * count(*) / sum(count(*)) OVER (), 2)   AS pct
FROM requests_between($start, $end)
GROUP BY ALL
ORDER BY client;

-- name: bot_vs_human_daily
SELECT date_trunc('day', ts)                         AS day,
       CASE WHEN is_bot THEN 'Bot' ELSE 'Human' END AS client,
       count(*)                                      AS hits
FROM requests_between($start, $end)
GROUP BY ALL
ORDER BY day, client;

-- name: weekly_heatmap
-- Average requests per (weekday, hour): total hits divided by how many
-- distinct days of that weekday are in the range.
SELECT isodow(ts)                                    AS dow,
       dayname(ts)                                   AS weekday,
       hour(ts)                                      AS hour,
       round(count(*) / count(DISTINCT CAST(ts AS DATE))) AS avg_requests
FROM requests_between($start, $end)
GROUP BY ALL
ORDER BY dow, hour;

-- name: recent_kpis
-- Live view: activity since $since (the last few minutes), shown as KPI deltas.
SELECT count(*)                                                          AS requests,
       count(DISTINCT ip)                                                AS unique_ips,
       round(100.0 * count(*) FILTER (WHERE status >= 400) / nullif(count(*), 0), 2) AS error_rate_pct,
       coalesce(sum(bytes), 0)                                           AS bytes
FROM requests
WHERE ts >= $since;

-- name: live_last_hour
-- Live view: requests per minute over the last hour, gap-filled so the
-- chart scrolls smoothly even through silent minutes.
WITH minutes AS (
    SELECT unnest(range(date_trunc('minute', CAST($since AS TIMESTAMP)),
                        date_trunc('minute', CAST($now AS TIMESTAMP)) + INTERVAL 1 MINUTE,
                        INTERVAL 1 MINUTE)) AS minute
),
hits AS (
    SELECT date_trunc('minute', ts)                     AS minute,
           count(*) FILTER (WHERE status < 400)         AS ok,
           count(*) FILTER (WHERE status >= 400)        AS errors
    FROM requests
    WHERE ts >= $since
    GROUP BY ALL
)
SELECT m.minute, coalesce(h.ok, 0) AS ok, coalesce(h.errors, 0) AS errors
FROM minutes m
LEFT JOIN hits h USING (minute)
ORDER BY m.minute;

-- name: busiest_hour_per_day
-- QUALIFY filters on a window function, like HAVING does for aggregates:
-- keep only the top-ranked hour of each day.
SELECT CAST(hour AS DATE)  AS day,
       strftime(hour, '%H:00') AS busiest_hour,
       requests,
       unique_ips,
       errors_5xx
FROM hourly_traffic
WHERE hour >= $start AND hour < $end
QUALIFY row_number() OVER (PARTITION BY CAST(hour AS DATE) ORDER BY requests DESC) = 1
ORDER BY day;


-- =====================================================================
-- 4. EXPLORER  (the filtered_requests() table macro holds the WHERE)
-- =====================================================================

-- name: explorer_count
SELECT count(*) AS n
FROM filtered_requests($start, $end, CAST($statuses AS INTEGER[]), CAST($methods AS VARCHAR[]),
                       $ip_prefix, $path_part);

-- name: explorer_page
-- Pagination with LIMIT / OFFSET; id breaks ties so pages never overlap.
SELECT ts, ip, method, path, query_string, status, bytes, referrer, user_agent, is_bot
FROM filtered_requests($start, $end, CAST($statuses AS INTEGER[]), CAST($methods AS VARCHAR[]),
                       $ip_prefix, $path_part)
ORDER BY ts, id
LIMIT $limit OFFSET $offset;

-- name: explorer_export
SELECT ts, ip, method, path, query_string, status, bytes, referrer, user_agent, is_bot
FROM filtered_requests($start, $end, CAST($statuses AS INTEGER[]), CAST($methods AS VARCHAR[]),
                       $ip_prefix, $path_part)
ORDER BY ts, id;

-- name: distinct_statuses
SELECT DISTINCT status FROM requests ORDER BY status;

-- name: distinct_methods
SELECT method FROM requests GROUP BY method ORDER BY count(*) DESC;


-- =====================================================================
-- 5. SECURITY
-- =====================================================================

-- name: suspicious_ranked
SELECT rank, ip, score, risk, watchlist_severity, total_requests, n_4xx, n_401,
       scanner_paths, peak_rpm, is_bot, first_seen, last_seen
FROM suspicious_ips
WHERE score >= $min_score
ORDER BY rank
LIMIT $limit;

-- name: ip_profile
SELECT count(*)                                                AS requests,
       count(*) FILTER (WHERE status BETWEEN 400 AND 499)      AS n_4xx,
       count(DISTINCT path) FILTER (WHERE is_scanner_path(path)) AS scanner_paths,
       min(ts)                                                 AS first_seen,
       max(ts)                                                 AS last_seen,
       mode(user_agent)                                        AS user_agent
FROM requests
WHERE ip = $ip;

-- name: ip_timeline
-- Per-minute activity of one IP, gap-filled: range() generates every
-- minute between its first and last request, and the LEFT JOIN turns
-- silent minutes into zeros instead of dropping them.
WITH bounds AS (
    SELECT date_trunc('minute', min(ts)) AS lo, date_trunc('minute', max(ts)) AS hi
    FROM requests WHERE ip = $ip
),
minutes AS (
    SELECT unnest(range(lo, hi + INTERVAL 1 MINUTE, INTERVAL 1 MINUTE)) AS minute
    FROM bounds
),
hits AS (
    SELECT date_trunc('minute', ts) AS minute, status_class(status) AS status_class, count(*) AS n
    FROM requests
    WHERE ip = $ip
    GROUP BY ALL
)
SELECT m.minute, h.status_class, coalesce(h.n, 0) AS requests
FROM minutes m
LEFT JOIN hits h USING (minute)
ORDER BY m.minute, h.status_class;

-- name: ip_top_paths
SELECT path, method, status, count(*) AS hits, max(ts) AS last_seen
FROM requests
WHERE ip = $ip
GROUP BY ALL
ORDER BY hits DESC
LIMIT 25;

-- name: scanner_hits
-- list(DISTINCT ...) aggregates into a LIST value - handy for summaries.
SELECT path,
       count(*)                     AS hits,
       count(DISTINCT ip)           AS ips,
       list(DISTINCT status ORDER BY status) AS statuses,
       min(ts)                      AS first_seen,
       max(ts)                      AS last_seen
FROM requests
WHERE is_scanner_path(path)
GROUP BY ALL
ORDER BY hits DESC
LIMIT 50;

-- name: failed_logins
-- Brute-force evidence: failed POST /login per IP, with the attack rate.
SELECT ip,
       count(*)                                                  AS failures,
       min(ts)                                                   AS first_attempt,
       max(ts)                                                   AS last_attempt,
       round(count(*) / greatest(date_diff('minute', min(ts), max(ts)), 1), 1) AS per_minute
FROM requests
WHERE method = 'POST' AND path = '/login' AND status = 401
GROUP BY ip
HAVING count(*) >= $min_failures
ORDER BY failures DESC;

-- name: error_prone_endpoints
-- The endpoint_stats view: endpoints with real traffic, worst first.
SELECT endpoint, hits, unique_ips, error_rate_pct, avg_bytes, p95_bytes
FROM endpoint_stats
WHERE hits >= $min_hits
ORDER BY error_rate_pct DESC, hits DESC
LIMIT 15;


-- =====================================================================
-- 6. ALERT RULES
--
-- Each metric has one candidate query with the same shape:
--   per_minute  bucket the relevant requests per subject per minute
--   windowed    sliding window: sum over the last $window minutes.
--               RANGE frames are measured in time, so missing minutes
--               count as zero instead of stretching the window.
--   breaches    windows at or over $threshold
--   episodes    "gaps and islands": lag() finds where a new run of
--               breaches starts, a running sum() numbers the runs
-- and returns one row per episode (first minute, last minute, peak).
-- db.run_alert_check() wraps it in INSERT ... ON CONFLICT DO NOTHING.
-- =====================================================================

-- name: alert_status_5xx_per_min
-- Subject = path. Value = average 5xx per minute over the window.
WITH per_minute AS (
    SELECT path AS subject, date_trunc('minute', ts) AS minute, count(*) AS n
    FROM requests
    WHERE status >= 500
    GROUP BY ALL
),
windowed AS (
    SELECT subject, minute,
           sum(n) OVER (PARTITION BY subject ORDER BY minute
                        RANGE BETWEEN to_minutes(CAST($window AS BIGINT) - 1) PRECEDING
                                  AND CURRENT ROW) / $window AS value
    FROM per_minute
),
breaches AS (
    SELECT subject, minute, value,
           lag(minute) OVER (PARTITION BY subject ORDER BY minute) AS prev_minute
    FROM windowed
    WHERE value >= $threshold
),
episodes AS (
    SELECT *,
           sum(CASE WHEN prev_minute IS NULL
                      OR minute - prev_minute > to_minutes(CAST($window AS BIGINT))
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY subject ORDER BY minute) AS episode
    FROM breaches
)
SELECT subject, min(minute) AS triggered_at, max(minute) AS ended_at,
       round(max(value), 2) AS observed_value
FROM episodes
GROUP BY subject, episode;

-- name: alert_requests_per_ip_per_min
-- Subject = IP. Value = average requests per minute over the window.
WITH per_minute AS (
    SELECT ip AS subject, date_trunc('minute', ts) AS minute, count(*) AS n
    FROM requests
    GROUP BY ALL
),
windowed AS (
    SELECT subject, minute,
           sum(n) OVER (PARTITION BY subject ORDER BY minute
                        RANGE BETWEEN to_minutes(CAST($window AS BIGINT) - 1) PRECEDING
                                  AND CURRENT ROW) / $window AS value
    FROM per_minute
),
breaches AS (
    SELECT subject, minute, value,
           lag(minute) OVER (PARTITION BY subject ORDER BY minute) AS prev_minute
    FROM windowed
    WHERE value >= $threshold
),
episodes AS (
    SELECT *,
           sum(CASE WHEN prev_minute IS NULL
                      OR minute - prev_minute > to_minutes(CAST($window AS BIGINT))
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY subject ORDER BY minute) AS episode
    FROM breaches
)
SELECT subject, min(minute) AS triggered_at, max(minute) AS ended_at,
       round(max(value), 2) AS observed_value
FROM episodes
GROUP BY subject, episode;

-- name: alert_status_4xx_per_ip
-- Subject = IP. Value = number of 4xx responses inside the window.
WITH per_minute AS (
    SELECT ip AS subject, date_trunc('minute', ts) AS minute, count(*) AS n
    FROM requests
    WHERE status BETWEEN 400 AND 499
    GROUP BY ALL
),
windowed AS (
    SELECT subject, minute,
           sum(n) OVER (PARTITION BY subject ORDER BY minute
                        RANGE BETWEEN to_minutes(CAST($window AS BIGINT) - 1) PRECEDING
                                  AND CURRENT ROW) AS value
    FROM per_minute
),
breaches AS (
    SELECT subject, minute, value,
           lag(minute) OVER (PARTITION BY subject ORDER BY minute) AS prev_minute
    FROM windowed
    WHERE value >= $threshold
),
episodes AS (
    SELECT *,
           sum(CASE WHEN prev_minute IS NULL
                      OR minute - prev_minute > to_minutes(CAST($window AS BIGINT))
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY subject ORDER BY minute) AS episode
    FROM breaches
)
SELECT subject, min(minute) AS triggered_at, max(minute) AS ended_at,
       max(value) AS observed_value
FROM episodes
GROUP BY subject, episode;

-- name: rules_with_counts
SELECT r.id, r.name, r.metric, r.threshold, r.window_minutes, r.enabled, r.auto_watchlist,
       count(a.id)         AS alerts,
       max(a.triggered_at) AS last_triggered
FROM alert_rules r
LEFT JOIN alerts a ON a.rule_id = r.id
GROUP BY ALL
ORDER BY r.id;

-- name: alerts_list
-- INNER JOIN to the rule for its name and metric; a LEFT JOIN to the
-- watchlist shows whether the subject (if it is an IP) is already listed.
SELECT a.id, r.name AS rule, r.metric, a.subject, a.observed_value, r.threshold,
       a.triggered_at, a.ended_at,
       date_diff('minute', a.triggered_at, a.ended_at) + 1 AS minutes,
       w.severity AS watchlist_severity
FROM alerts a
JOIN alert_rules r ON r.id = a.rule_id
LEFT JOIN watchlist w ON w.ip = a.subject
WHERE $rule_id IS NULL OR a.rule_id = $rule_id
ORDER BY a.triggered_at DESC;


-- =====================================================================
-- 7. WATCHLIST
-- =====================================================================

-- name: watchlist_with_activity
-- Two pre-aggregated CTEs joined back to the watchlist (LEFT JOINs keep
-- IPs that never appear in the logs).
WITH activity AS (
    SELECT ip,
           count(*)                                  AS requests,
           count(*) FILTER (WHERE status >= 400)     AS errors,
           max(ts)                                   AS last_seen
    FROM requests
    WHERE ip IN (SELECT ip FROM watchlist)
    GROUP BY ip
),
alert_counts AS (
    SELECT subject AS ip, count(*) AS alerts FROM alerts GROUP BY subject
)
SELECT w.id, w.ip, w.severity, w.reason, w.added_at,
       coalesce(a.requests, 0) AS requests,
       coalesce(a.errors, 0)   AS errors,
       a.last_seen,
       coalesce(c.alerts, 0)   AS alerts
FROM watchlist w
LEFT JOIN activity a     USING (ip)
LEFT JOIN alert_counts c USING (ip)
ORDER BY list_position(['critical', 'high', 'medium', 'low'], w.severity), w.added_at DESC;


-- =====================================================================
-- 8. CATALOG  (DuckDB's own metadata, for the SQL console)
-- =====================================================================

-- name: catalog_objects
SELECT 'table' AS kind, table_name AS name, estimated_size AS approx_rows, column_count AS columns
FROM duckdb_tables() WHERE schema_name = 'main' AND NOT internal
UNION ALL
SELECT 'view', view_name, NULL, column_count
FROM duckdb_views() WHERE schema_name = 'main' AND NOT internal
UNION ALL
SELECT DISTINCT function_type, function_name, NULL, NULL
FROM duckdb_functions() WHERE schema_name = 'main' AND function_type IN ('macro', 'table_macro') AND NOT internal
UNION ALL
SELECT 'sequence', sequence_name, NULL, NULL
FROM duckdb_sequences() WHERE schema_name = 'main'
ORDER BY kind, name;

-- name: catalog_constraints
SELECT table_name, constraint_type, constraint_text
FROM duckdb_constraints()
WHERE schema_name = 'main'
ORDER BY table_name, constraint_type;

-- name: catalog_view_sql
SELECT view_name, sql FROM duckdb_views() WHERE schema_name = 'main' AND NOT internal ORDER BY view_name;
