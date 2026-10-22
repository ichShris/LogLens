-- =====================================================================
-- Web Server Log Analyzer - DuckDB schema
--
-- Applied by db.open_db() on every startup. Every statement is
-- idempotent (IF NOT EXISTS / OR REPLACE), so re-running it never
-- touches existing data; views and macros are always refreshed.
--
-- DuckDB notes that shape this design:
--   * No ON DELETE CASCADE: child rows are deleted explicitly, in a
--     transaction, by db.delete_log_file() / db.delete_rule(). DuckDB
--     also rejects deleting a parent in the same transaction as its
--     children (over-eager FK check), so the parent goes in a 2nd step.
--   * No triggers or stored procedures: "trigger-like" behaviour
--     (input normalisation, auto-watchlisting on alerts) lives in db.py.
--   * Macros are DuckDB's reusable SQL functions (scalar and table).
-- =====================================================================

-- ---------------------------------------------------------------------
-- Sequences (surrogate key generators)
-- ---------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS seq_log_files    START 1;
CREATE SEQUENCE IF NOT EXISTS seq_requests     START 1;
CREATE SEQUENCE IF NOT EXISTS seq_parse_errors START 1;
CREATE SEQUENCE IF NOT EXISTS seq_watchlist    START 1;
CREATE SEQUENCE IF NOT EXISTS seq_alert_rules  START 1;
CREATE SEQUENCE IF NOT EXISTS seq_alerts       START 1;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------

-- One row per ingested log file.
CREATE TABLE IF NOT EXISTS log_files (
    id            INTEGER   PRIMARY KEY DEFAULT nextval('seq_log_files'),
    name          VARCHAR   NOT NULL UNIQUE,          -- same file can't be loaded twice
    uploaded_at   TIMESTAMP NOT NULL DEFAULT CAST(current_timestamp AS TIMESTAMP),
    line_count    INTEGER   NOT NULL DEFAULT 0 CHECK (line_count   >= 0),
    parsed_count  INTEGER   NOT NULL DEFAULT 0 CHECK (parsed_count >= 0),
    failed_count  INTEGER   NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    parse_seconds DOUBLE             CHECK (parse_seconds >= 0),
    -- 'deleting' = children already removed, parent row awaiting purge (see db.delete_log_file)
    status        VARCHAR   NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleting')),
    CHECK (parsed_count + failed_count = line_count)  -- table-level CHECK across columns
);

-- One row per successfully parsed access-log line (the fact table).
CREATE TABLE IF NOT EXISTS requests (
    id           BIGINT    PRIMARY KEY DEFAULT nextval('seq_requests'),
    file_id      INTEGER   NOT NULL REFERENCES log_files (id),
    ip           VARCHAR   NOT NULL,
    ts           TIMESTAMP NOT NULL,
    method       VARCHAR   NOT NULL,
    path         VARCHAR   NOT NULL,
    query_string VARCHAR,
    protocol     VARCHAR,
    status       SMALLINT  NOT NULL CHECK (status BETWEEN 100 AND 599),
    bytes        BIGINT    NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    referrer     VARCHAR,
    user_agent   VARCHAR,
    is_bot       BOOLEAN   NOT NULL DEFAULT false
);

-- Lines that did not match the combined log format.
CREATE TABLE IF NOT EXISTS parse_errors (
    id       BIGINT  PRIMARY KEY DEFAULT nextval('seq_parse_errors'),
    file_id  INTEGER NOT NULL REFERENCES log_files (id),
    line_no  INTEGER NOT NULL CHECK (line_no > 0),
    raw_line VARCHAR NOT NULL,
    UNIQUE (file_id, line_no)
);

-- IPs flagged by the admin (or automatically by an alert rule).
CREATE TABLE IF NOT EXISTS watchlist (
    id       INTEGER   PRIMARY KEY DEFAULT nextval('seq_watchlist'),
    ip       VARCHAR   NOT NULL UNIQUE,
    reason   VARCHAR   NOT NULL CHECK (length(trim(reason)) > 0),
    severity VARCHAR   NOT NULL DEFAULT 'medium'
                       CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    added_at TIMESTAMP NOT NULL DEFAULT CAST(current_timestamp AS TIMESTAMP)
);

-- User-defined alert thresholds.
CREATE TABLE IF NOT EXISTS alert_rules (
    id             INTEGER   PRIMARY KEY DEFAULT nextval('seq_alert_rules'),
    name           VARCHAR   NOT NULL UNIQUE,
    metric         VARCHAR   NOT NULL CHECK (metric IN ('status_5xx_per_min',
                                                        'requests_per_ip_per_min',
                                                        'status_4xx_per_ip')),
    threshold      DOUBLE    NOT NULL CHECK (threshold > 0),
    window_minutes INTEGER   NOT NULL CHECK (window_minutes BETWEEN 1 AND 1440),
    enabled        BOOLEAN   NOT NULL DEFAULT true,
    auto_watchlist BOOLEAN   NOT NULL DEFAULT false,  -- emulated AFTER INSERT trigger on alerts
    created_at     TIMESTAMP NOT NULL DEFAULT CAST(current_timestamp AS TIMESTAMP)
);

-- Alerts produced by evaluating the enabled rules.
CREATE TABLE IF NOT EXISTS alerts (
    id             BIGINT    PRIMARY KEY DEFAULT nextval('seq_alerts'),
    rule_id        INTEGER   NOT NULL REFERENCES alert_rules (id),
    triggered_at   TIMESTAMP NOT NULL,                -- first minute the threshold was breached (log time)
    ended_at       TIMESTAMP NOT NULL,                -- last breaching minute of the same episode
    subject        VARCHAR   NOT NULL,                -- the IP or the path
    observed_value DOUBLE    NOT NULL,                -- peak value during the episode
    CHECK (ended_at >= triggered_at),
    created_at     TIMESTAMP NOT NULL DEFAULT CAST(current_timestamp AS TIMESTAMP),
    UNIQUE (rule_id, subject, triggered_at)           -- re-running a check never duplicates
);

-- Seed alert rules, inserted only into an empty table.
INSERT INTO alert_rules (name, metric, threshold, window_minutes, auto_watchlist)
SELECT * FROM (VALUES
    ('4xx flood per IP',        'status_4xx_per_ip',       100, 10, true),
    ('Request flood per IP',    'requests_per_ip_per_min',  60,  5, false),
    ('5xx spike per endpoint',  'status_5xx_per_min',        5,  5, false)
) AS seed (name, metric, threshold, window_minutes, auto_watchlist)
WHERE NOT EXISTS (SELECT 1 FROM alert_rules);

-- ---------------------------------------------------------------------
-- Macros (DuckDB's user-defined functions)
-- ---------------------------------------------------------------------

-- 404 -> '4xx'
CREATE OR REPLACE MACRO status_class(s) AS (s // 100)::VARCHAR || 'xx';

-- Paths that only vulnerability scanners ask for.
CREATE OR REPLACE MACRO is_scanner_path(p) AS regexp_matches(lower(p),
    '(wp-admin|wp-login|wp-content|wp-includes|xmlrpc|phpmyadmin|/pma|\.env|\.git|\.svn|\.htaccess|\.htpasswd|\.ds_store|cgi-bin|\.php$|/config\.|/backup|\.sql$|\.bak$|/etc/passwd|actuator|server-status|/vendor/|/shell|/console|/solr|/manager/html|/boaform|/hnap1)');

-- Crawlers, scripts and headless clients.
CREATE OR REPLACE MACRO is_bot_ua(ua) AS regexp_matches(lower(coalesce(ua, '')),
    'bot|crawl|spider|slurp|curl|wget|python-requests|scrapy|httpclient|go-http-client|headless|java/');

-- /products/123/reviews -> /products/:id/reviews  (groups REST paths into endpoints)
CREATE OR REPLACE MACRO normalize_path(p) AS regexp_replace(p, '/[0-9]+(/|$)', '/:id\1', 'g');

-- Parses one "combined" log line into a STRUCT of named capture groups.
-- Returns all-empty fields when the line does not match.
--   203.0.113.9 - - [14/Oct/2026:01:02:03 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0 ..."
CREATE OR REPLACE MACRO parse_log_line(line) AS regexp_extract(line,
    '^(\S+) \S+ \S+ \[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\] "([A-Z]+) (\S+) (HTTP/[0-9.]+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$',
    ['ip', 'ts', 'method', 'target', 'protocol', 'status', 'bytes', 'referrer', 'ua']);

-- Table macro: the requests inside [start_ts, end_ts). The dashboard's
-- date filter goes through this, so every chart filters the same way.
CREATE OR REPLACE MACRO requests_between(start_ts, end_ts) AS TABLE
    SELECT * FROM requests WHERE ts >= start_ts AND ts < end_ts;

-- Table macro behind the Explorer. Every filter is optional: an empty
-- list / empty string disables it, so the SQL text never changes with the
-- filters and all user input stays a bound parameter.
CREATE OR REPLACE MACRO filtered_requests(start_ts, end_ts, statuses, methods, ip_prefix, path_part) AS TABLE
    SELECT id, ts, ip, method, path, query_string, status, bytes, referrer, user_agent, is_bot, file_id
    FROM requests
    WHERE ts >= start_ts AND ts < end_ts
      AND (len(statuses) = 0 OR list_contains(statuses, status))
      AND (len(methods)  = 0 OR list_contains(methods, method))
      AND (ip_prefix = '' OR starts_with(ip, ip_prefix))
      AND (path_part = '' OR contains(lower(path), lower(path_part)));

-- ---------------------------------------------------------------------
-- Views
-- ---------------------------------------------------------------------

-- Traffic per hour.
CREATE OR REPLACE VIEW hourly_traffic AS
SELECT date_trunc('hour', ts)                                 AS hour,
       count(*)                                               AS requests,
       count(DISTINCT ip)                                     AS unique_ips,
       sum(bytes)                                             AS bytes,
       count(*) FILTER (WHERE status BETWEEN 400 AND 499)     AS errors_4xx,
       count(*) FILTER (WHERE status >= 500)                  AS errors_5xx,
       count(*) FILTER (WHERE is_bot)                         AS bot_requests
FROM requests
GROUP BY ALL;

-- Per-endpoint health: hits, error rate and response sizes.
CREATE OR REPLACE VIEW endpoint_stats AS
SELECT normalize_path(path)                                            AS endpoint,
       count(*)                                                        AS hits,
       count(DISTINCT ip)                                              AS unique_ips,
       round(100.0 * count(*) FILTER (WHERE status >= 400) / count(*), 2) AS error_rate_pct,
       round(avg(bytes))                                               AS avg_bytes,
       quantile_cont(bytes, 0.5)                                       AS median_bytes,
       quantile_cont(bytes, 0.95)                                      AS p95_bytes,
       min(ts)                                                         AS first_seen,
       max(ts)                                                         AS last_seen
FROM requests
GROUP BY ALL;

-- Hits per status code, with each code's share of all traffic.
CREATE OR REPLACE VIEW status_summary AS
SELECT status,
       status_class(status)                                AS status_class,
       count(*)                                            AS hits,
       round(100.0 * count(*) / sum(count(*)) OVER (), 2)  AS pct
FROM requests
GROUP BY ALL;

-- Scores every IP 0-100 from three signals:
--   4xx volume        (up to 40 points, saturates at 500 errors)
--   scanner paths     (up to 30 points, saturates at 20 distinct paths)
--   peak request rate (up to 30 points, saturates at 120 requests/minute)
CREATE OR REPLACE VIEW suspicious_ips AS
WITH per_ip AS (
    SELECT ip,
           count(*)                                                   AS total_requests,
           count(*) FILTER (WHERE status BETWEEN 400 AND 499)         AS n_4xx,
           count(*) FILTER (WHERE status = 401)                       AS n_401,
           count(DISTINCT path) FILTER (WHERE is_scanner_path(path))  AS scanner_paths,
           bool_or(is_bot)                                            AS is_bot,
           min(ts)                                                    AS first_seen,
           max(ts)                                                    AS last_seen
    FROM requests
    GROUP BY ip
),
per_minute AS (
    SELECT ip, date_trunc('minute', ts) AS minute, count(*) AS n
    FROM requests
    GROUP BY ALL
),
peak AS (
    SELECT ip, max(n) AS peak_rpm FROM per_minute GROUP BY ip
),
scored AS (
    SELECT p.*,
           k.peak_rpm,
           round(40 * least(p.n_4xx, 500) / 500.0
               + 30 * least(p.scanner_paths, 20) / 20.0
               + 30 * least(k.peak_rpm, 120) / 120.0, 1)              AS score
    FROM per_ip p
    JOIN peak k USING (ip)
)
SELECT rank() OVER (ORDER BY s.score DESC)                             AS rank,
       s.*,
       CASE WHEN s.score >= 50 THEN 'high'
            WHEN s.score >= 25 THEN 'medium'
            ELSE 'low' END                                             AS risk,
       w.severity                                                      AS watchlist_severity
FROM scored s
LEFT JOIN watchlist w USING (ip);
