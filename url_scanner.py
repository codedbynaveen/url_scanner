#!/usr/bin/env python3
"""
Advanced interactive URL scanner (non-destructive by default).

This fully fixed version resolves previous syntax issues and improves detection
accuracy for SQLi, XSS, and suspicious/webshell detection. It also includes a
robust main launcher that works when an asyncio event loop is already running.

Usage: python3 url_scanner_fixed_full.py

WARNING: Only run against targets you own or have permission to test.
"""

import sys
import os
import re
import asyncio
import aiohttp
import importlib
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse, parse_qsl, urlencode
from collections import defaultdict
from datetime import datetime, timezone
import json
import csv
import time
from colorama import init as colorama_init, Fore, Style

# Ensure required packages
REQUIRED = ["aiohttp", "bs4", "colorama"]

def ensure_packages(pkgs):
    missing = []
    for p in pkgs:
        try:
            importlib.import_module(p)
        except Exception:
            missing.append(p)
    if not missing:
        return
    print("\nInstalling missing packages:", ", ".join(missing))
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade"] + missing)
    os.execv(sys.executable, [sys.executable] + sys.argv)

ensure_packages(REQUIRED)

# initialize colorama
colorama_init(autoreset=True)

# ---------------- Banner ----------------
def show_banner():
    banner = [
        "              _,.-------.,_",
        "            ,;~'          '~;,",
        "          ,;                ;,",
        "          ;                   ;",
        "        ,'                    ',",
        "       ,;                      ;,",
        "       ; ;      .        .      ; ;",
        "       | ;    ______      ______    ; |",
        "       |  `/~\"      \" . \"      \"~\\'  |",
        "       |  ~ ,-~~~^~, | ,~^~~~-, ~  |",
        "        |  |        }:{        |  |",
        "        |  l        / | \\        !  |",
        "        .~ (__,.--\" .^. \"--.,__) ~.",
        "        |     ---;' / | \\ `;---      |",
        "          \\__.        \\/^\\/        .__/",
        "           V| \\                  / |V",
        "            | |T~\\___!___!___/~T| |",
        "            | |`IIII_I_I_I_IIII'| |",
        "            |  \\,III I I I III,/  |",
        "             \\    `~~~~~~~~~~'    /",
        "              \\    .        .    /",
        "               \\.    ^    .  /",
        "                 ^~._____.~^",
        "================================================================================",
        "              â˜ ï¸   A M A L I C I O U S   M I N D   â˜ ï¸",
        "--------------------------------------------------------------------------------",
        "                            coded by naveen",
        "================================================================================"
    ]
    print("\n".join(banner))
# ==========================================================

# ---------------- Config & signatures ----------------
USER_AGENT = "Mozilla/5.0 (compatible; url-scanner/1.0; +https://example.local/)"

# Improved SQL error signatures
SQL_ERRORS_RE = re.compile(r"(" + r"|".join([
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"pg_query\(",
    r"sql syntax.*mysql",
    r"native client",
    r"sql error",
    r"mysql_fetch",
    r"ORA-01756",
    r"quoted string not properly terminated",
    r"syntax error at or near",
    r"unterminated string constant",
]) + r")", re.IGNORECASE)

# Broader set of suspicious markers and regexes for webshells
SHELL_MARKERS = [
    "cmd.exe",
    "shell_exec",
    "passthru(",
    "exec(",
    "system(",
    "popen(",
    "r57",
    "webshell",
    "c99shell",
    "phpinfo(",
    "eval(",
    "base64_decode",
    "preg_replace(.,'/e')",
    "assert(",
]

SHELL_REGEXES = [
    re.compile(r"base64_decode\(|eval\(|assert\(|shell_exec\(|passthru\(|popen\(|proc_open\(", re.IGNORECASE),
    re.compile(r"(\$\w+\s*=\s*\$_(GET|POST|REQUEST)\[)", re.IGNORECASE),
]

DIR_MARKERS = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
    re.compile(r"Directory listing for", re.IGNORECASE),
]

suspicious_filenames = [
    "shell.php", "cmd.php", "r57.php", "c99.php", "upload.php",
    "backdoor.php", "adminer.php", "phpinfo.php"
]

suspicious_param_names = {"cmd", "command", "exec", "shell", "upload", "file", "path", "dir", "cmdshell"}
REDIRECT_PARAM_NAMES = {"url", "next", "redirect", "goto", "return", "continue", "target", "dest", "destination", "to"}

COMMON_PATHS = [
    "admin", "administrator", "login", "uploads", "backup", "backup.zip",
    "backup.tar.gz", "old", "test", "dev", "staging", "phpinfo.php", "adminer.php"
]

# XSS payload templates
XSS_MARKER_TEMPLATE = "XSS_TEST_{}"
XSS_PAYLOADS = ['\"<{marker}>\"', "'<{marker}>'", "<{marker}>"]
OPENREDIRECT_TEST_TARGET = "https://example.com/redirect-test"

# ---------------- Utilities ----------------
def now_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def save_results_json(results, fname):
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def save_results_csv(rows, fname):
    if not rows:
        return
    with open(fname, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def short_url(u):
    return u if len(u) < 120 else u[:117] + "..."

# ---------------- HTTP helper ----------------
async def fetch(session, url, method="GET", data=None, headers=None, allow_redirects=True, timeout=15):
    try:
        start = time.time()
        async with session.request(method, url, data=data, headers=headers, timeout=timeout, allow_redirects=allow_redirects) as resp:
            elapsed = time.time() - start
            ct = resp.headers.get("Content-Type", "")
            body = None
            if resp.status and ("text/html" in ct or "application/xhtml+xml" in ct or ct == "" or "text/" in ct):
                body = await resp.text(errors="ignore")
            return resp.status, resp.headers, body, elapsed
    except asyncio.TimeoutError:
        return "timeout", {}, None, None
    except Exception:
        return None, {}, None, None

# ---------------- robots.txt ----------------
async def respects_robots(session, seed):
    try:
        parsed = urlparse(seed)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        status, headers, body, _ = await fetch(session, robots_url)
        disallows = []
        if body:
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("user-agent:"):
                    curr_agent = line.split(":", 1)[1].strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallows.append(path)
        return disallows
    except Exception:
        return []

# ---------------- Crawler ----------------
class Crawler:
    def __init__(self, seed, max_depth=2, concurrency=6, rate_limit=0.12, same_domain=True, respect_robots=True, session=None):
        self.seed = seed
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.same_domain = same_domain
        self.respect_robots = respect_robots
        self.visited = set()
        self.found_forms = defaultdict(list)
        self.queue = asyncio.Queue()
        self.base_netloc = urlparse(seed).netloc
        self.session = session
        self.robots_disallows = []

    def extract_links(self, base_url, html):
        soup = BeautifulSoup(html or "", "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            try:
                joined = urljoin(base_url, href)
                joined, _ = urldefrag(joined)
                if joined.startswith("http"):
                    links.add(joined)
            except Exception:
                continue
        return links

    def discover_forms(self, base_url, html):
        soup = BeautifulSoup(html or "", "html.parser")
        for form in soup.find_all("form"):
            try:
                method = (form.get("method") or "GET").upper()
                action = form.get("action") or base_url
                action = urljoin(base_url, action)
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    itype = inp.get("type", "text")
                    if not name:
                        continue
                    inputs.append({"name": name, "type": itype})
                enctype = form.get("enctype", "")
                self.found_forms[action].append({"method": method, "inputs": inputs, "enctype": enctype, "source": base_url})
            except Exception:
                continue

    async def worker(self, sem):
        while True:
            try:
                url, depth = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                return
            if url in self.visited:
                self.queue.task_done()
                continue
            if depth > self.max_depth:
                self.queue.task_done()
                continue
            if self.respect_robots:
                path = urlparse(url).path or "/"
                for dis in self.robots_disallows:
                    if dis and path.startswith(dis):
                        self.queue.task_done()
                        break
            async with sem:
                self.visited.add(url)
                print(Fore.CYAN + "[Crawl] " + short_url(url))
                status, headers, body, _ = await fetch(self.session, url, headers={"User-Agent": USER_AGENT})
                if body:
                    self.discover_forms(url, body)
                    for link in self.extract_links(url, body):
                        if self.same_domain and urlparse(link).netloc != self.base_netloc:
                            continue
                        if link not in self.visited:
                            await self.queue.put((link, depth + 1))
                await asyncio.sleep(self.rate_limit)
                self.queue.task_done()

    async def run(self):
        if self.respect_robots:
            self.robots_disallows = await respects_robots(self.session, self.seed)
        await self.queue.put((self.seed, 0))
        sem = asyncio.Semaphore(self.concurrency)
        workers = [asyncio.create_task(self.worker(sem)) for _ in range(self.concurrency)]
        await self.queue.join()
        for w in workers:
            w.cancel()
        return self.visited, self.found_forms

# ---------------- Vulnerability checks (improved) ----------------
async def check_directory_listing(body):
    if not body:
        return False
    for rx in DIR_MARKERS:
        if rx.search(body):
            return True
    return False

async def check_sqli_for_url(session, url, enable_time=False, time_delay=3, time_threshold=1.5):
    """Improved SQLi checks:
    - Error-based: look for DB error patterns in the response body
    - Content-change: compare normalized bodies and use ratio threshold
    - Time-based: issue SLEEP payloads and measure response time difference
    """
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not qs:
        return None
    base = parsed._replace(query="").geturl()
    findings = []

    # baseline
    status0, _, body0, elapsed0 = await fetch(session, url, headers={"User-Agent": USER_AGENT})
    norm0 = (body0 or "")[:20000]

    # candidate payloads
    payloads = ["'", '"', "' OR '1'='1'", '" OR "1"="1"', "%27"]
    tailers = ["", "-- ", "/*", "#"]

    for param in qs:
        orig_val = qs.get(param, "")
        for payload in payloads:
            for tail in tailers:
                test_val = orig_val + payload + tail
                new_qs = qs.copy(); new_qs[param] = test_val
                test_url = base + "?" + urlencode(list(new_qs.items()))
                status, _, body, _ = await fetch(session, test_url, headers={"User-Agent": USER_AGENT})
                if body and SQL_ERRORS_RE.search(body):
                    findings.append({"param": param, "payload": test_val, "reason": "error-signature", "test_url": test_url})
                elif body and body0:
                    try:
                        l0 = len(norm0)
                        l1 = len((body or "")[:20000])
                        if l0 > 0 and abs(l1 - l0) / l0 > 0.20:
                            findings.append({"param": param, "payload": test_val, "reason": "content-length-diff", "test_url": test_url, "len0": l0, "len1": l1})
                    except Exception:
                        pass
        # time-based check (optional): send a sleep payload and measure elapsed
        if enable_time:
            sleep_payloads = [f"' OR SLEEP({time_delay})-- ", f'" OR SLEEP({time_delay})-- ']
            for sp in sleep_payloads:
                new_qs = qs.copy(); new_qs[param] = qs.get(param, "") + sp
                test_url = base + "?" + urlencode(list(new_qs.items()))
                status_t, _, body_t, elapsed_t = await fetch(session, test_url, headers={"User-Agent": USER_AGENT}, allow_redirects=True, timeout=10)
                if elapsed_t is not None and elapsed0 is not None:
                    try:
                        if elapsed_t - elapsed0 > (time_delay * 0.6) and elapsed_t - elapsed0 > time_threshold:
                            findings.append({"param": param, "payload": sp.strip(), "reason": "time-delay", "test_url": test_url, "delta_secs": elapsed_t - elapsed0})
                    except Exception:
                        pass
    return findings if findings else None

async def boolean_based_sqli(session, url, diff_threshold=0.12):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not qs:
        return None
    base = parsed._replace(query="").geturl()
    findings = []
    status_base, _, body_base, _ = await fetch(session, url, headers={"User-Agent": USER_AGENT})
    for param in qs:
        orig = qs.get(param, "")
        true_payload = orig + "' AND '1'='1'"
        false_payload = orig + "' AND '1'='2'"
        new_qs = qs.copy(); new_qs[param] = true_payload
        t_url = base + "?" + urlencode(list(new_qs.items()))
        status_t, _, true_body, _ = await fetch(session, t_url, headers={"User-Agent": USER_AGENT})
        new_qs = qs.copy(); new_qs[param] = false_payload
        f_url = base + "?" + urlencode(list(new_qs.items()))
        status_f, _, false_body, _ = await fetch(session, f_url, headers={"User-Agent": USER_AGENT})
        try:
            if true_body and false_body:
                ltrue = len(true_body)
                lfalse = len(false_body)
                if max(ltrue, lfalse) > 0 and abs(ltrue - lfalse) / max(ltrue, lfalse) > diff_threshold:
                    findings.append({"param": param, "reason": "boolean-diff", "true_url": t_url, "false_url": f_url, "ltrue": ltrue, "lfalse": lfalse})
                else:
                    if body_base and (abs(len(body_base) - ltrue) / max(1, len(body_base)) > diff_threshold or abs(len(body_base) - lfalse) / max(1, len(body_base)) > diff_threshold):
                        findings.append({"param": param, "reason": "baseline-content-diff", "true_url": t_url, "false_url": f_url})
        except Exception:
            pass
    return findings if findings else None


def looks_suspicious_filename_in_url(url):
    for name in suspicious_filenames:
        if name in url.lower():
            return True
    return False

async def check_suspicious_shell(session, url, body):
    findings = []
    parsed = urlparse(url)
    qs_items = list(parse_qsl(parsed.query, keep_blank_values=True))
    for k, v in qs_items:
        if k.lower() in suspicious_param_names:
            findings.append({"type": "suspicious-param", "param": k})
    if looks_suspicious_filename_in_url(url):
        findings.append({"type": "suspicious-filename", "match": url})
    if body:
        lower = body.lower()
        for marker in SHELL_MARKERS:
            if marker.lower() in lower:
                findings.append({"type": "marker", "marker": marker})
        for rx in SHELL_REGEXES:
            if rx.search(body):
                findings.append({"type": "regex-marker", "pattern": rx.pattern})
        try:
            soup = BeautifulSoup(body, 'html.parser')
            for form in soup.find_all('form'):
                enctype = (form.get('enctype') or '').lower()
                if 'multipart/form-data' in enctype:
                    findings.append({"type": "upload-form", "note": "multipart form found (may accept file uploads)"})
                for inp in form.find_all('input'):
                    if inp.get('type', '').lower() == 'file' or inp.get('name', '').lower() in ['file', 'upload']:
                        findings.append({"type": "file-input", "input": str(inp)})
        except Exception:
            pass
    if findings:
        unique = []
        seen = set()
        for f in findings:
            key = json.dumps(f, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
    return None

# XSS - reflected (improved)
async def check_reflected_xss(session, url, marker):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not qs:
        return None
    base = parsed._replace(query="").geturl()
    findings = []
    payloads = [p.format(marker=marker) for p in XSS_PAYLOADS]

    def appears_in_html(body, marker):
        if not body:
            return False, []
        found_places = []
        low = body.lower()
        if marker.lower() in low:
            found_places.append('raw')
        esc = marker.replace('<', '&lt;').replace('>', '&gt;')
        if esc.lower() in low:
            found_places.append('escaped')
        try:
            soup = BeautifulSoup(body, 'html.parser')
            if soup.find(string=lambda s: s and marker in s):
                found_places.append('text-node')
            for tag in soup.find_all(True):
                for v in tag.attrs.values():
                    if isinstance(v, (list, tuple)):
                        vs = ' '.join(v)
                    else:
                        vs = str(v)
                    if marker in vs:
                        found_places.append('attr:'+tag.name)
        except Exception:
            pass
        # deduplicate
        return (len(found_places) > 0), list(dict.fromkeys(found_places))

    for param in qs:
        for payload in payloads:
            new_qs = qs.copy()
            new_qs[param] = qs.get(param, "") + payload
            test_url = base + "?" + urlencode(list(new_qs.items()))
            status, headers, body, _ = await fetch(session, test_url, headers={"User-Agent": USER_AGENT})
            found, places = appears_in_html(body, marker)
            if found:
                findings.append({"param": param, "payload": payload, "test_url": test_url, "reason": "reflected", "places": places})
    return findings if findings else None

# DOM static hints
DOM_SINKS = ["innerHTML", "document.write", "eval(", "setAttribute(", "location.hash", "location.search", "window.location", "document.location"]

def detect_dom_xss_hints(body, params):
    findings = []
    if not body:
        return None
    lower = body.lower()
    for sink in DOM_SINKS:
        if sink in lower:
            for p in params:
                if p.lower() in lower:
                    findings.append({"sink": sink, "param": p, "note": "param name and sink present in page; investigate DOM-XSS"})
    return findings if findings else None

# Persistent XSS (ADVANCED) - submit marker to forms (skip multipart)
async def submit_marker_to_form(session, action, form, marker):
    if form.get("enctype", "").lower().startswith("multipart"):
        return None
    data = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
        itype = inp.get('type', 'text')
        if itype.lower() in ['hidden', 'text', 'search', 'textarea']:
            data[name] = marker
        else:
            data[name] = 'test'
    try:
        status, headers, body, _ = await fetch(session, action, method=form.get("method", "POST"), data=data, headers={"User-Agent": USER_AGENT})
        return {"action": action, "status": status}
    except Exception:
        return None

# Open redirect check
async def check_open_redirect(session, url):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    candidates = [k for k in qs if k.lower() in REDIRECT_PARAM_NAMES]
    if not candidates:
        return None
    findings = []
    base = parsed._replace(query="").geturl()
    for param in candidates:
        new_qs = qs.copy()
        new_qs[param] = OPENREDIRECT_TEST_TARGET
        test_url = base + "?" + urlencode(list(new_qs.items()))
        status, headers, body, _ = await fetch(session, test_url, headers={"User-Agent": USER_AGENT}, allow_redirects=False)
        loc = None
        try:
            for k in headers:
                if k.lower() == 'location':
                    loc = headers.get(k)
                    break
        except Exception:
            loc = None
        if loc and OPENREDIRECT_TEST_TARGET in loc:
            findings.append({"param": param, "test_url": test_url, "redirect_location": loc, "reason": "location-header-redirect"})
        if body and OPENREDIRECT_TEST_TARGET in body:
            findings.append({"param": param, "test_url": test_url, "reason": "reflected-url-in-body"})
    return findings if findings else None

# small path fuzzing (non-invasive)
async def path_fuzz(session, seed, small_list, rate_limit, concurrency):
    parsed = urlparse(seed)
    base = f"{parsed.scheme}://{parsed.netloc}"
    sem = asyncio.Semaphore(concurrency)
    found = []
    async def worker(path):
        async with sem:
            full = base.rstrip("/") + "/" + path.lstrip("/")
            status, headers, body, _ = await fetch(session, full, headers={"User-Agent": USER_AGENT})
            if status and status != 404 and status != "timeout" and status is not None:
                found.append({"path": full, "status": status})
            await asyncio.sleep(rate_limit)
    tasks = [asyncio.create_task(worker(p)) for p in small_list]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found

# ---------------- Orchestration ----------------
async def run_full_scan(seed, max_depth=2, concurrency=6, rate_limit=0.12, respect_robots=True,
                        enable_fuzz=False, enable_advanced=False, path_list=None):
    results = {
        "seed": seed,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "urls": [],
        "forms": {},
        "findings": {
            "possible_sqli": [], "boolean_sqli": [], "directory_listing": [],
            "suspicious": [], "fuzz_hits": [], "xss_reflected": [], "xss_dom": [],
            "xss_persistent": [], "open_redirect": []
        },
        "stats": {}
    }
    timeout = aiohttp.ClientTimeout(total=25)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {"User-Agent": USER_AGENT}

    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
        crawler = Crawler(seed, max_depth=max_depth, concurrency=concurrency, rate_limit=rate_limit,
                          same_domain=True, respect_robots=respect_robots, session=session)
        visited, found_forms = await crawler.run()
        results["urls"] = list(visited)
        results["forms"] = {k: v for k, v in found_forms.items()}

        print(Fore.GREEN + f"\\n[Crawl complete] {len(visited)} URLs discovered, {sum(len(v) for v in found_forms.values())} forms found.")

        if enable_fuzz and path_list:
            print(Fore.MAGENTA + "[Fuzz] running small path fuzzing (non-invasive)...")
            fuzz_hits = await path_fuzz(session, seed, path_list, rate_limit, concurrency)
            results["findings"]["fuzz_hits"] = fuzz_hits
            for h in fuzz_hits:
                print(Fore.MAGENTA + f" [FuzzHit] {h['path']} (status {h['status']})")

        run_marker = XSS_MARKER_TEMPLATE.format(now_ts())
        persistent_submissions = []

        sem = asyncio.Semaphore(concurrency)

        async def analyze_url(u):
            async with sem:
                status, headers, body, elapsed = await fetch(session, u, headers={"User-Agent": USER_AGENT})
                try:
                    if await check_directory_listing(body):
                        results["findings"]["directory_listing"].append(u)
                except Exception:
                    pass
                try:
                    sqli = await check_sqli_for_url(session, u, enable_time=enable_advanced, time_delay=4)
                    if sqli:
                        results["findings"]["possible_sqli"].append({"url": u, "details": sqli})
                except Exception:
                    pass
                try:
                    bsqli = await boolean_based_sqli(session, u)
                    if bsqli:
                        results["findings"]["boolean_sqli"].append({"url": u, "details": bsqli})
                except Exception:
                    pass
                try:
                    susp = await check_suspicious_shell(session, u, body)
                    if susp:
                        results["findings"]["suspicious"].append({"url": u, "details": susp})
                except Exception:
                    pass
                try:
                    rx = await check_reflected_xss(session, u, run_marker)
                    if rx:
                        results["findings"]["xss_reflected"].append({"url": u, "details": rx})
                except Exception:
                    pass
                try:
                    params = [k for k, v in parse_qsl(urlparse(u).query, keep_blank_values=True)]
                    domh = detect_dom_xss_hints(body, params)
                    if domh:
                        results["findings"]["xss_dom"].append({"url": u, "details": domh})
                except Exception:
                    pass
                try:
                    ord = await check_open_redirect(session, u)
                    if ord:
                        results["findings"]["open_redirect"].append({"url": u, "details": ord})
                except Exception:
                    pass

        tasks = [asyncio.create_task(analyze_url(u)) for u in visited]
        await asyncio.gather(*tasks, return_exceptions=True)

        if enable_advanced:
            for action, forms in results["forms"].items():
                for form in forms:
                    if form.get("method", "GET").upper() == "POST" and not form.get("enctype", "").lower().startswith("multipart"):
                        print(Fore.MAGENTA + f"[Advanced] Submitting persistent XSS marker to form at {action} (from {form.get('source')})")
                        sub = await submit_marker_to_form(session, action, form, run_marker)
                        if sub:
                            persistent_submissions.append({"action": action, "form": form, "result": sub})
            if persistent_submissions:
                await asyncio.sleep(2)
                for u in list(visited):
                    status, headers, body, _ = await fetch(session, u, headers={"User-Agent": USER_AGENT})
                    if body and run_marker.lower() in body.lower():
                        results["findings"]["xss_persistent"].append({"url": u, "marker": run_marker})

    results["stats"]["num_urls"] = len(results["urls"])
    results["stats"]["num_forms"] = sum(len(v) for v in results["forms"].values())
    return results

# ---------------- Reporting ----------------
def print_clean_report(results, json_file):
    print("\\n" + "="*55)
    print(Fore.CYAN + "================== SCAN REPORT ==================")
    print(Fore.CYAN + f"Target: {results['seed']}")
    print(Fore.CYAN + f"Scan time (UTC): {results['scanned_at_utc']}")
    print(Fore.CYAN + f"Total URLs Scanned: {results['stats'].get('num_urls', 0)}")
    print(Fore.CYAN + f"Forms Discovered: {results['stats'].get('num_forms', 0)}\\n")

    xr = results["findings"].get("xss_reflected", [])
    if xr:
        print(Fore.RED + "âš ï¸  Reflected XSS candidates:")
        for item in xr:
            print(Fore.RED + f"   -> {item['url']}")
            payloads = []
            for d in item.get("details", []):
                p = d.get("payload")
                param = d.get("param")
                payloads.append(f"{param}={p}")
            for p in sorted(set(payloads)):
                print(Fore.RED + f"      Payload: {p}")
    else:
        print(Fore.GREEN + "âœ…  No reflected XSS detected (quick scan).")

    xd = results["findings"].get("xss_dom", [])
    if xd:
        print(Fore.YELLOW + "\\nðŸ§©  DOM XSS hints (static analysis):")
        for item in xd:
            print(Fore.YELLOW + f"   -> {item['url']}")
            for d in item.get("details", []):
                print(Fore.YELLOW + f"      - Sink: {d.get('sink')} ; Param: {d.get('param')} ; Note: {d.get('note')}")
    else:
        print(Fore.GREEN + "\\nâœ…  No DOM-XSS hints found.")

    xp = results["findings"].get("xss_persistent", [])
    if xp:
        print(Fore.MAGENTA + "\\nðŸ’¥  Persistent (stored) XSS discovered (ADVANCED):")
        for p in xp:
            print(Fore.MAGENTA + f"   -> {p['url']} (marker: {p['marker']})")
    else:
        print(Fore.GREEN + "\\nâœ…  No persistent XSS detected (or ADVANCED not enabled).")

    orr = results["findings"].get("open_redirect", [])
    if orr:
        print(Fore.RED + "\\nðŸ”€  Open redirect candidates:")
        for item in orr:
            print(Fore.RED + f"   -> {item['url']}")
            for d in item.get("details", []):
                print(Fore.RED + f"      - param: {d.get('param')} ; reason: {d.get('reason')} ; test_url: {d.get('test_url')}")
    else:
        print(Fore.GREEN + "\\nâœ…  No open redirect indicators found.")

    sqli = results["findings"].get("possible_sqli", [])
    if sqli:
        print(Fore.RED + "\\nâš ï¸  SQL Injection candidates:")
        for item in sqli:
            print(Fore.RED + f"   -> {item['url']}")
            payloads = set()
            for d in item.get("details", []):
                if d.get("payload"):
                    payloads.add(d.get("payload"))
                else:
                    payloads.add(str(d))
            for p in sorted(payloads):
                print(Fore.RED + f"      Payload/issue: {p}")
    else:
        print(Fore.GREEN + "\\nâœ…  No likely SQLi findings (quick scan).")

    dlist = results["findings"].get("directory_listing", [])
    if dlist:
        print(Fore.YELLOW + "\\nðŸ•µï¸  Directory listings found:")
        for u in dlist:
            print(Fore.YELLOW + f"   -> {u}")
    else:
        print(Fore.GREEN + "\\nâœ…  No directory listings found.")

    susp = results["findings"].get("suspicious", [])
    if susp:
        print(Fore.YELLOW + "\\nðŸ’€  Suspicious endpoints (possible webshells / upload forms):")
        for item in susp:
            print(Fore.YELLOW + f"   -> {item['url']}")
            for d in item.get("details", []):
                if d.get("type") == "upload-form":
                    print(Fore.YELLOW + f"      - Reason: Form uses multipart/form-data (upload endpoint).")
                elif d.get("type") == "suspicious-param":
                    print(Fore.YELLOW + f"      - Reason: Suspicious parameter name: {d.get('param')}")
                elif d.get("type") == "suspicious-filename":
                    print(Fore.YELLOW + f"      - Reason: Suspicious filename in URL: {d.get('match')}")
                elif d.get("type") == "marker":
                    print(Fore.YELLOW + f"      - Reason: Response contains shell marker: {d.get('marker')}")
                elif d.get("type") == "regex-marker":
                    print(Fore.YELLOW + f"      - Reason: Regex marker matched: {d.get('pattern')}")
                elif d.get("type") == "file-input":
                    print(Fore.YELLOW + f"      - Reason: File input detected in form: {d.get('input')}" )
                else:
                    print(Fore.YELLOW + f"      - {d}")
    else:
        print(Fore.GREEN + "\\nâœ…  No suspicious endpoints found.")

    fuzz = results["findings"].get("fuzz_hits", [])
    if fuzz:
        print(Fore.MAGENTA + "\\nðŸ”  Fuzz Hits:")
        for h in fuzz:
            print(Fore.MAGENTA + f"   -> {h['path']} (status {h['status']})")
    else:
        print(Fore.GREEN + "\\nâœ…  No fuzz hits.")

    print(Fore.BLUE + f"\\nReport saved: {json_file}")
    print(Fore.CYAN + "="*55 + "\\n")

def build_and_save_summary(results):
    ts = now_ts()
    json_file = f"scan_results_{ts}.json"
    csv_file = f"scan_summary_{ts}.csv"
    save_results_json(results, json_file)

    rows = []
    for item in results["findings"].get("xss_reflected", []):
        rows.append({"type":"xss_reflected", "url": item["url"], "detail": json.dumps(item["details"], ensure_ascii=False)})
    for item in results["findings"].get("xss_dom", []):
        rows.append({"type":"xss_dom", "url": item["url"], "detail": json.dumps(item["details"], ensure_ascii=False)})
    for item in results["findings"].get("xss_persistent", []):
        rows.append({"type":"xss_persistent", "url": item["url"], "detail": json.dumps(item, ensure_ascii=False)})
    for item in results["findings"].get("open_redirect", []):
        rows.append({"type":"open_redirect", "url": item["url"], "detail": json.dumps(item["details"], ensure_ascii=False)})
    for item in results["findings"].get("possible_sqli", []):
        rows.append({"type":"possible_sqli", "url": item["url"], "detail": json.dumps(item["details"], ensure_ascii=False)})
    for u in results["findings"].get("directory_listing", []):
        rows.append({"type":"directory_listing", "url": u, "detail": ""})
    for item in results["findings"].get("suspicious", []):
        rows.append({"type":"suspicious", "url": item["url"], "detail": json.dumps(item["details"], ensure_ascii=False)})
    for item in results["findings"].get("fuzz_hits", []):
        rows.append({"type":"fuzz_hit", "url": item["path"], "detail": f"status:{item['status']}"})
    if not rows:
        rows = [{"type":"none", "url":"", "detail":"no findings"}]
    save_results_csv(rows, csv_file)
    return json_file, csv_file

# ---------------- Interactive flow ----------------
async def interactive_main():
    show_banner()
    seed = input("\nEnter URL (e.g. https://example.com): ").strip()
    if not seed.startswith("http"):
        print(Fore.RED + "Please include scheme, e.g. https://example.com")
        return
    try:
        depth = int(input("Max depth (default 2): ") or 2)
    except Exception:
        depth = 2
    try:
        concurrency = int(input("Concurrency (default 6): ") or 6)
    except Exception:
        concurrency = 6
    try:
        rate_limit = float(input("Rate limit per request in seconds (default 0.12): ") or 0.12)
    except Exception:
        rate_limit = 0.12

    respect_robots = True
    resp = input("Respect robots.txt? (Y/n) [default Y]: ").strip().lower()
    if resp == "n":
        respect_robots = False

    enable_fuzz = False
    resp = input("Enable small path fuzzing (non-invasive)? (y/N): ").strip().lower()
    if resp == "y":
        enable_fuzz = True

    print(Fore.YELLOW + "\nWARNING: This tool will perform active requests to the target. Only scan targets you own or have explicit permission to test.")
    consent = input("Type YES to confirm you have permission to scan: ").strip()
    if consent != "YES":
        print(Fore.RED + "Permission not granted. Exiting.")
        return

    print(Fore.YELLOW + "\nAdvanced checks include persistent XSS submissions and time-based tests which are more intrusive.")
    advance_consent = input("Type ADVANCED to enable persistent/time-based checks and additional probes, or press Enter to skip: ").strip()
    enable_advanced = (advance_consent == "ADVANCED")
    if enable_advanced:
        print(Fore.MAGENTA + "Advanced checks ENABLED. Proceeding carefully.")

    print(Fore.BLUE + f"\nStarting scan of {seed} with depth {depth}, concurrency {concurrency}, rate_limit {rate_limit} ...")
    start = time.time()
    results = await run_full_scan(seed, max_depth=depth, concurrency=concurrency, rate_limit=rate_limit,
                                  respect_robots=respect_robots, enable_fuzz=enable_fuzz,
                                  enable_advanced=enable_advanced, path_list=COMMON_PATHS if enable_fuzz else None)
    duration = time.time() - start
    results["stats"]["scan_duration_secs"] = duration

    json_file, csv_file = build_and_save_summary(results)
    globals()["json_file"] = json_file
    print_clean_report(results, json_file)

# ---------------- Safe launcher ----------------
def main():
    """Run the async entrypoint in a safe way across environments.

    - If running in a normal Python process, use asyncio.run()
    - If an event loop is already running (embedded REPL or certain hosts), try to apply
      nest_asyncio so asyncio.run() can be nested. If nest_asyncio isn't available we
      attempt to install it automatically.
    - As a final fallback, schedule the coroutine on the existing loop.
    """
    try:
        import nest_asyncio
    except Exception:
        try:
            print("Installing nest_asyncio to allow nested event loop (if needed)...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "nest_asyncio"])
            import nest_asyncio
        except Exception:
            nest_asyncio = None

    try:
        if nest_asyncio:
            try:
                nest_asyncio.apply()
            except Exception:
                pass
        asyncio.run(interactive_main())
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    except RuntimeError:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                print("Detected a running event loop. Scheduling interactive_main() on it.")
                asyncio.ensure_future(interactive_main())
                print("interactive_main() scheduled â€” it will run on the existing event loop.")
            else:
                raise
        except Exception:
            raise


if __name__ == "__main__":
    main()
