"""Generate realistic Apache/Nginx "combined" format access logs.

Writes two files into sample_logs/:
  access.log        ~750,000 lines over the 10 days before today, with injected incidents
  access_small.log  today from midnight until now (for the multi-file demo); the
                    app's live traffic simulator carries on from there

Traffic follows a daily curve (quiet nights, afternoon peak, evening bump), dips at
weekends, grows ~3% a day, varies from day to day, and has one "sale day" at 1.6x.

Injected incidents (all attacker IPs come from the RFC 5737 documentation ranges):
  * brute force   203.0.113.45   POST /login -> 401, ~50/min for 2.5 hours
  * bot surge     192.0.2.99     "AggressiveCrawler" at ~150 requests/min for an hour
  * scanner       198.51.100.23  /wp-admin, /.env, /phpmyadmin ... -> 404, 15 minutes
  * 500 spike     /api/checkout  returns 500 for 20 minutes
  * 502 spike     /api/search    returns 502 for 15 minutes
  * brute force   203.0.113.77   a slower second attack, ~30/min for 1.5 hours
  * bot surge     192.0.2.150    "DataHarvester" crawler, 45 minutes
  * scanner       198.51.100.77  a short scan today (access_small.log)
A small fraction of malformed lines is mixed in to exercise parse_errors.

Usage:
  python scripts/generate_logs.py                      # defaults below
  python scripts/generate_logs.py --lines 200000 --days 4 --seed 7
"""
from __future__ import annotations

import argparse
import math
import random
from datetime import datetime, time, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
# Timestamps are local wall-clock time, so the offset written is the local one.
TZ_OFFSET = datetime.now().astimezone().strftime("%z")

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
]
BROWSER_UA_WEIGHTS = [30, 10, 14, 8, 20, 15, 3]

GOOD_BOTS = [
    ("66.249.66.%d", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("157.55.39.%d", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("17.241.75.%d", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1)"),
]
SCRIPT_UAS = ["curl/8.9.1", "python-requests/2.32.3", "Go-http-client/2.0"]

CATEGORIES = ["laptops", "phones", "audio", "cameras", "accessories", "gaming", "wearables"]
BLOG_SLUGS = ["best-laptops-2026", "how-to-choose-headphones", "camera-buying-guide",
              "black-friday-preview", "smartwatch-review", "gaming-setup-tips"]
SEARCH_TERMS = ["laptop", "usb-c+cable", "headphones", "iphone+case", "4k+monitor", "keyboard", "ssd"]
REFERRERS = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
             "https://t.co/xyz", "https://www.facebook.com/", "-"]

SCANNER_PATHS = [
    "/wp-admin/", "/wp-login.php", "/wp-admin/admin-ajax.php", "/wp-content/plugins/revslider/",
    "/wp-includes/wlwmanifest.xml", "/xmlrpc.php", "/.env", "/.env.backup", "/.env.production",
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.htaccess", "/.htpasswd", "/.DS_Store",
    "/phpmyadmin/", "/phpMyAdmin/index.php", "/pma/", "/admin.php", "/config.php", "/config.json",
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/site.bak", "/cgi-bin/test.cgi",
    "/cgi-bin/luci", "/actuator/env", "/actuator/health", "/server-status",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/shell.php", "/console",
    "/solr/admin/info/system", "/manager/html", "/boaform/admin/formLogin", "/HNAP1/",
    "/index.php?s=/Index/think/app/invokefunction", "/info.php", "/test.php", "/phpinfo.php",
    "/etc/passwd", "/../../../../etc/passwd", "/wp-config.php.bak", "/config.yml",
    "/administrator/index.php", "/user/login.php", "/setup.php", "/install.php",
]


def fmt_ts(dt: datetime) -> str:
    # Avoids strftime("%b"), which is locale dependent.
    return (f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:"
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {TZ_OFFSET}")


def log_line(ip, dt, method, target, status, size, referrer, ua) -> str:
    return f'{ip} - - [{fmt_ts(dt)}] "{method} {target} HTTP/1.1" {status} {size} "{referrer}" "{ua}"'


def lognormal_bytes(rng: random.Random, median: float, sigma: float = 0.6) -> int:
    return max(1, int(rng.lognormvariate(math.log(median), sigma)))


def diurnal_weight(dt: datetime) -> float:
    """Traffic shape: quiet nights, a broad afternoon peak and a smaller evening bump."""
    h = dt.hour + dt.minute / 60
    day = math.exp(-((h - 14) ** 2) / (2 * 3.8 ** 2))
    evening = 0.45 * math.exp(-((h - 20.5) ** 2) / (2 * 1.5 ** 2))
    weekend = 0.8 if dt.weekday() >= 5 else 1.0
    return (0.07 + day + evening) * weekend


class Generator:
    def __init__(self, start: datetime, days: int, rng: random.Random):
        self.start = start
        self.days = days
        self.rng = rng
        self.events: list[tuple[float, str]] = []    # (unix time, line), sorted on write
        self.spikes: list[tuple[datetime, datetime, str, int]] = []  # (from, to, path, status)
        # Human client pool: Zipf-like weights, so a few IPs (offices, NAT) are heavy users.
        self.clients = []
        for i in range(6000):
            ip = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            ua = rng.choices(BROWSER_UAS, BROWSER_UA_WEIGHTS)[0]
            self.clients.append((ip, ua))
        self.client_weights = [1 / (i + 10) ** 0.9 for i in range(len(self.clients))]
        self.bots = [(pat % rng.randint(1, 254), ua) for pat, ua in GOOD_BOTS for _ in range(3)]
        self.scripts = [(f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}", ua)
                        for ua in SCRIPT_UAS for _ in range(4)]

    # -- helpers -----------------------------------------------------------
    def add(self, dt: datetime, line: str) -> None:
        self.events.append((dt.timestamp(), line))

    def spike_status(self, path: str, dt: datetime) -> int | None:
        """The forced error status if `path` is inside an injected error spike."""
        for begin, end, spike_path, status in self.spikes:
            if path == spike_path and begin <= dt < end:
                return status
        return None

    def page_target(self) -> tuple[str, int]:
        r = self.rng
        kind = r.choices(["home", "list", "product", "category", "search", "cart", "checkout",
                          "login", "account", "about", "contact", "blog", "bloglist"],
                         [20, 10, 25, 8, 8, 5, 2, 3, 3, 1, 1, 5, 2])[0]
        if kind == "home":
            return "/", lognormal_bytes(r, 42000, 0.2)
        if kind == "list":
            return f"/products?page={r.randint(1, 12)}", lognormal_bytes(r, 38000, 0.3)
        if kind == "product":
            return f"/products/{r.randint(1000, 1600)}", lognormal_bytes(r, 31000, 0.35)
        if kind == "category":
            return f"/category/{r.choice(CATEGORIES)}", lognormal_bytes(r, 36000, 0.3)
        if kind == "search":
            return f"/search?q={r.choice(SEARCH_TERMS)}", lognormal_bytes(r, 28000, 0.4)
        if kind == "blog":
            return f"/blog/{r.choice(BLOG_SLUGS)}", lognormal_bytes(r, 52000, 0.25)
        return {"cart": "/cart", "checkout": "/checkout", "login": "/login", "account": "/account",
                "about": "/about", "contact": "/contact", "bloglist": "/blog"}[kind], lognormal_bytes(r, 24000, 0.3)

    # -- normal traffic ----------------------------------------------------
    def pageview(self, dt: datetime) -> int:
        """Emit one human page view (page + assets + API calls). Returns lines written."""
        r = self.rng
        ip, ua = r.choices(self.clients, self.client_weights)[0]
        target, size = self.page_target()
        status = r.choices([200, 304, 404, 500], [95.3, 3.5, 1.0, 0.2])[0]
        if status == 404:
            target, size = f"/products/{r.randint(9000, 9999)}", 4100
        elif status == 500:
            size = 520
        elif status == 304:
            size = "-"
        ref = r.choice(REFERRERS)
        written = 1
        self.add(dt, log_line(ip, dt, "GET", target, status, size, ref, ua))
        if status != 200:
            return written
        page_url = "https://shop.example.com" + target
        t = dt
        # Static assets, often cached (304).
        if r.random() < 0.75:
            assets = [("/static/css/main.css", 48000), ("/static/js/app.js", 210000),
                      ("/static/js/vendor.js", 380000), ("/static/img/logo.png", 12000),
                      ("/favicon.ico", 5400), ("/static/fonts/inter.woff2", 98000)]
            for path, median in r.sample(assets, r.randint(2, 5)):
                t += timedelta(milliseconds=r.randint(20, 400))
                cached = r.random() < 0.45
                self.add(t, log_line(ip, t, "GET", path, 304 if cached else 200,
                                     "-" if cached else lognormal_bytes(r, median, 0.1), page_url, ua))
                written += 1
            if target.startswith("/products/"):
                t += timedelta(milliseconds=r.randint(50, 500))
                self.add(t, log_line(ip, t, "GET", f"/static/img/products/{r.randint(1000, 1600)}.jpg",
                                     200, lognormal_bytes(r, 85000, 0.5), page_url, ua))
                written += 1
        # Front-end API calls.
        if r.random() < 0.55:
            t += timedelta(milliseconds=r.randint(100, 2000))
            method, path, median, st = r.choices([
                ("GET", f"/api/products?page={r.randint(1, 12)}", 9000, 200),
                ("GET", f"/api/products/{r.randint(1000, 1600)}", 2400, 200),
                ("GET", "/api/cart", 900, 200),
                ("POST", "/api/cart", 600, 201),
                ("GET", f"/api/search?q={r.choice(SEARCH_TERMS)}", 6000, 200),
                ("GET", "/api/recommendations", 4500, 200),
                ("POST", "/api/auth/refresh", 400, 200),
                ("POST", "/api/checkout", 1200, 200),
            ], [18, 18, 14, 10, 12, 14, 8, 6])[0]
            forced = self.spike_status(path.split("?")[0], t)
            if forced:
                st, median = forced, 230
            elif r.random() < 0.004:
                st = r.choice([400, 404, 502, 503])
            self.add(t, log_line(ip, t, method, path, st, lognormal_bytes(r, median, 0.4), page_url, ua))
            written += 1
        # Logins: mostly successful, the odd typo.
        if target == "/login" and r.random() < 0.6:
            t += timedelta(seconds=r.randint(3, 20))
            ok = r.random() < 0.9
            self.add(t, log_line(ip, t, "POST", "/login", 302 if ok else 401, 0 if ok else 512, page_url, ua))
            written += 1
        return written

    def bot_hit(self, dt: datetime) -> int:
        r = self.rng
        ip, ua = r.choice(self.bots)
        target = r.choice(["/robots.txt", "/sitemap.xml", f"/products/{r.randint(1000, 1600)}",
                           f"/category/{r.choice(CATEGORIES)}", f"/blog/{r.choice(BLOG_SLUGS)}"])
        self.add(dt, log_line(ip, dt, "GET", target, 200, lognormal_bytes(r, 30000, 0.5), "-", ua))
        return 1

    def script_hit(self, dt: datetime) -> int:
        r = self.rng
        ip, ua = r.choice(self.scripts)
        target = r.choice(["/api/products?page=1", "/api/products/1200", "/sitemap.xml", "/"])
        self.add(dt, log_line(ip, dt, "GET", target, 200, lognormal_bytes(r, 8000, 0.5), "-", ua))
        return 1

    def visit(self, dt: datetime) -> int:
        """One unit of normal traffic: mostly human page views, some crawlers and scripts."""
        roll = self.rng.random()
        if roll < 0.04:
            return self.bot_hit(dt)
        if roll < 0.05:
            return self.script_hit(dt)
        return self.pageview(dt)

    def normal_traffic(self, total_lines: int, minutes: int | None = None,
                       day_factors: list[float] | None = None) -> None:
        """Spread ~total_lines over the period (default: all days) following the
        daily curve, scaled per day by day_factors (trend, sale day, noise)."""
        minutes = minutes if minutes is not None else self.days * 1440
        day_factors = day_factors or [1.0] * (minutes // 1440 + 1)
        weights = [diurnal_weight(self.start + timedelta(minutes=m)) * day_factors[m // 1440]
                   for m in range(minutes)]
        scale = total_lines / sum(weights)
        r = self.rng
        carry = 0.0
        for m, w in enumerate(weights):
            minute_start = self.start + timedelta(minutes=m)
            # Uptime monitor: one health check per minute.
            self.add(minute_start + timedelta(seconds=7),
                     log_line("192.0.2.10", minute_start + timedelta(seconds=7), "GET", "/health", 200, 2,
                              "-", "UptimeRobot/2.0 (+http://www.uptimerobot.com/)"))
            target = w * scale * r.uniform(0.85, 1.15) + carry - 1
            written = 0
            while written < target:
                written += self.visit(minute_start + timedelta(seconds=r.uniform(0, 59.9)))
            carry = target - written

    def live_traffic(self, t0: datetime, t1: datetime, per_second: float) -> None:
        """Normal traffic for the interval [t0, t1) at roughly per_second lines/s
        (used by the app's live simulator). Assets of a page view may land a
        moment after t1; the caller holds those back until their time comes."""
        secs = (t1 - t0).total_seconds()
        target = per_second * secs * self.rng.uniform(0.6, 1.4)
        written = 0
        while written < target:
            written += self.visit(t0 + timedelta(seconds=self.rng.uniform(0, secs)))


    # -- incidents ---------------------------------------------------------
    def brute_force(self, begin: datetime, minutes: int, ip="203.0.113.45", per_min=(42, 62)) -> None:
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        r = self.rng
        for m in range(minutes):
            for _ in range(r.randint(*per_min)):
                dt = begin + timedelta(minutes=m, seconds=r.uniform(0, 59.9))
                self.add(dt, log_line(ip, dt, "POST", "/login", 401, 512, "https://shop.example.com/login", ua))
        dt = begin + timedelta(minutes=minutes, seconds=5)  # ...and finally one password works
        self.add(dt, log_line(ip, dt, "POST", "/login", 302, 0, "https://shop.example.com/login", ua))

    def scanner(self, begin: datetime, minutes: int, ip="198.51.100.23", paths=SCANNER_PATHS,
                per_min=40) -> None:
        ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
        r = self.rng
        n = minutes * per_min
        for i in range(n):
            dt = begin + timedelta(seconds=i * minutes * 60 / n + r.uniform(0, 1))
            path = paths[i % len(paths)]
            status = 403 if path.startswith(("/.git", "/.ht")) else 404
            method = r.choices(["GET", "POST", "HEAD"], [80, 12, 8])[0]
            self.add(dt, log_line(ip, dt, method, path, status, r.randint(150, 600), "-", ua))

    def error_spike(self, begin: datetime, minutes: int, path="/api/checkout", status=500,
                    method="POST", per_min=(10, 16)) -> None:
        """`path` fails with `status` for the window: normal requests to it get
        the error, and clients retrying add extra failing requests."""
        self.spikes.append((begin, begin + timedelta(minutes=minutes), path, status))
        r = self.rng
        for m in range(minutes):
            for _ in range(r.randint(*per_min)):
                ip, ua = r.choices(self.clients, self.client_weights)[0]
                dt = begin + timedelta(minutes=m, seconds=r.uniform(0, 59.9))
                self.add(dt, log_line(ip, dt, method, path, status, r.randint(180, 260),
                                      "https://shop.example.com/", ua))

    def bot_surge(self, begin: datetime, minutes: int, ip="192.0.2.99",
                  ua="AggressiveCrawler/2.1 (+http://crawler.example.com/bot.html)", per_min=(130, 170)) -> None:
        r = self.rng
        for m in range(minutes):
            for _ in range(r.randint(*per_min)):
                dt = begin + timedelta(minutes=m, seconds=r.uniform(0, 59.9))
                if r.random() < 0.03:
                    target, status, size = f"/products/{r.randint(9000, 9999)}", 404, 4100
                else:
                    target = r.choice([f"/products/{r.randint(1000, 1600)}", f"/category/{r.choice(CATEGORIES)}",
                                       f"/search?q={r.choice(SEARCH_TERMS)}", f"/products?page={r.randint(1, 40)}"])
                    status, size = 200, lognormal_bytes(r, 33000, 0.3)
                self.add(dt, log_line(ip, dt, "GET", target, status, size, "-", ua))

    def malformed(self, count: int, minutes: int | None = None) -> None:
        r = self.rng
        minutes = minutes or self.days * 1440
        for _ in range(count):
            dt = self.start + timedelta(minutes=r.randrange(minutes), seconds=r.randint(0, 59))
            ip = f"{r.randint(11, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
            good = log_line(ip, dt, "GET", "/", 200, 1234, "-", BROWSER_UAS[0])
            kind = r.randrange(5)
            if kind == 0:     # truncated write
                bad = good[: r.randint(10, len(good) - 10)]
            elif kind == 1:   # Apache "-" request line (client closed connection)
                bad = f'{ip} - - [{fmt_ts(dt)}] "-" 408 0 "-" "-"'
            elif kind == 2:   # TLS handshake sent to the plain-HTTP port
                bad = f'{ip} - - [{fmt_ts(dt)}] "\\x16\\x03\\x01\\x00\\xa5" 400 166 "-" "-"'
            elif kind == 3:   # impossible date: matches the regex, fails strptime
                bad = good.replace(fmt_ts(dt)[:11], f"31/Feb/{dt.year}")
            else:             # stray application output in the access log
                bad = f"[warn] worker {r.randint(1000, 9999)} exited on signal 11"
            self.add(dt, bad)

    def take_until(self, until: datetime) -> list[str]:
        """Remove and return (in time order) every line stamped before `until`."""
        cutoff = until.timestamp()
        self.events.sort(key=lambda e: e[0])
        i = next((k for k, (ts, _) in enumerate(self.events) if ts >= cutoff), len(self.events))
        due, self.events = self.events[:i], self.events[i:]
        return [line for _, line in due]

    def write(self, path: Path) -> int:
        self.events.sort(key=lambda e: e[0])
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for _, line in self.events:
                f.write(line + "\n")
        return len(self.events)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lines", type=int, default=750_000, help="approximate lines in access.log")
    ap.add_argument("--days", type=int, default=10, help="days covered by access.log")
    ap.add_argument("--start", default=None,
                    help="first day, YYYY-MM-DD (default: --days before today, so the data ends today)")
    ap.add_argument("--no-today", action="store_true", help="skip access_small.log (today until now)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "sample_logs")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    today = datetime.combine(datetime.now().date(), time.min)
    start = datetime.fromisoformat(args.start) if args.start else today - timedelta(days=args.days)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    def day(n: int, hh: int, mm: int) -> datetime:
        # Incident days are clamped so a short --days run still contains them.
        return start + timedelta(days=min(n, args.days - 1), hours=hh, minutes=mm)

    # Per-day volume: ~3% daily growth, +/-12% noise, and a sale day at 1.6x,
    # so totals and charts really differ from one date range to another.
    sale_day = max(0, args.days - 4)
    day_factors = [(1 + 0.03 * d) * rng.uniform(0.88, 1.12) * (1.6 if d == sale_day else 1.0)
                   for d in range(args.days)]

    gen = Generator(start, args.days, rng)
    incidents = [
        # (label, start, minutes, generator call, approximate lines)
        ("brute force 203.0.113.45 -> POST /login 401", day(2, 1, 10), 150,
         lambda t, m: gen.brute_force(t, m), 52),
        ("bot surge   192.0.2.99 AggressiveCrawler", day(3, 10, 0), 60,
         lambda t, m: gen.bot_surge(t, m), 150),
        ("scanner     198.51.100.23 -> 404s", day(4, 14, 10), 15,
         lambda t, m: gen.scanner(t, m), 40),
        ("500 spike   /api/checkout", day(5, 19, 0), 20,
         lambda t, m: gen.error_spike(t, m), 13),
        ("502 spike   /api/search", day(7, 13, 30), 15,
         lambda t, m: gen.error_spike(t, m, path="/api/search", status=502, method="GET"), 13),
        ("brute force 203.0.113.77 (slower)", day(8, 22, 0), 90,
         lambda t, m: gen.brute_force(t, m, ip="203.0.113.77", per_min=(25, 35)), 30),
        ("bot surge   192.0.2.150 DataHarvester", day(9, 15, 0), 45,
         lambda t, m: gen.bot_surge(t, m, ip="192.0.2.150", per_min=(100, 140),
                                    ua="DataHarvester/1.0 (crawler; +http://harvest.example.net)"), 120),
    ]
    # Incident volume counts toward --lines, so normal traffic gets the rest.
    incident_lines = sum(m * per_min for _, _, m, _, per_min in incidents)
    malformed = max(5, args.lines // 4000)
    # Error spikes must be registered before normal traffic, which consults them.
    for _, when, minutes, make, _ in incidents:
        make(when, minutes)
    gen.normal_traffic(max(1000, args.lines - incident_lines - malformed - args.days * 1440),
                       day_factors=day_factors)
    gen.malformed(malformed)
    big = args.out_dir / "access.log"
    n = gen.write(big)
    print(f"wrote {n:,} lines to {big} ({start:%Y-%m-%d} to {start + timedelta(days=args.days - 1):%Y-%m-%d})")
    print(f"  sale day: {start + timedelta(days=sale_day):%Y-%m-%d}")
    for label, when, minutes, _, _ in incidents:
        print(f"  incident {label}: {when:%Y-%m-%d %H:%M} for {minutes} min")

    small = args.out_dir / "access_small.log"
    now = datetime.now().replace(microsecond=0)
    elapsed = int((now - today).total_seconds() // 60)
    if args.no_today or args.start or elapsed < 15:
        small.unlink(missing_ok=True)
        print("skipped access_small.log (needs default dates and at least 15 minutes of today)")
        return
    # Today, midnight until now, at the level the trend reached.
    full_day = [diurnal_weight(today + timedelta(minutes=m)) for m in range(1440)]
    today_lines = int(args.lines / args.days * (1 + 0.03 * args.days) * sum(full_day[:elapsed]) / sum(full_day))
    gen2 = Generator(today, 1, rng)
    gen2.normal_traffic(max(100, today_lines - elapsed), minutes=elapsed)
    # A second, smaller scan from another IP, so the second file adds a new finding.
    scan_at = now - timedelta(hours=2)
    if scan_at >= today:
        gen2.scanner(scan_at, 5, ip="198.51.100.77", paths=SCANNER_PATHS[::2])
    gen2.malformed(10, minutes=elapsed)
    n2 = gen2.write(small)
    print(f"wrote {n2:,} lines to {small} (today until {now:%H:%M})")


if __name__ == "__main__":
    main()
