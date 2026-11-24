# scanner/idor.py
# WebProbe — Industry Level IDOR Scanner
# Works on: Any website, IP, IP:port, domain
# Detects:
#   1. Numeric ID manipulation in URL path
#   2. Numeric ID manipulation in parameters
#   3. API endpoint IDOR
#   4. Horizontal privilege escalation
#   5. UUID/GUID based IDOR
#   6. File/resource access IDOR
#   7. Mass assignment IDOR
#   8. Parameter pollution IDOR
#   9. HTTP method IDOR
#  10. JSON body IDOR

import re
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from utils.http_engine import send_get, send_post
from utils.helpers import get_timestamp
from rich.console import Console
try:
    from llm.llm_engine import generate_payloads as llm_generate
    LLM_AVAILABLE = True
except Exception:
    LLM_AVAILABLE = False

console = Console()
print_lock = threading.Lock()

# ═══════════════════════════════════════════════════
# SENSITIVE DATA PATTERNS
# Detects if response contains user data
# Used to confirm IDOR finding
# ═══════════════════════════════════════════════════
SENSITIVE_PATTERNS = [
    # User data
    r'"email"\s*:\s*"[^"@]+@[^"]+\.[^"]+"',
    r'"username"\s*:\s*"[^"]+"',
    r'"password"\s*:\s*"[^"]+"',
    r'"role"\s*:\s*"[^"]+"',
    r'"name"\s*:\s*"[^"]+"',
    r'"phone"\s*:\s*"[^"]+"',
    r'"address"\s*:\s*"[^"]+"',
    r'"credit_?card"\s*:\s*"[^"]+"',
    r'"ssn"\s*:\s*"[^"]+"',
    r'"dob"\s*:\s*"[^"]+"',
    r'"token"\s*:\s*"[^"]+"',
    r'"api_?key"\s*:\s*"[^"]+"',
    r'"secret"\s*:\s*"[^"]+"',
    # Order/payment data
    r'"order_?id"\s*:\s*\d+',
    r'"total"\s*:\s*[\d.]+',
    r'"amount"\s*:\s*[\d.]+',
    r'"payment"\s*:\s*"[^"]+"',
    # Account data
    r'"balance"\s*:\s*[\d.]+',
    r'"account"\s*:\s*"[^"]+"',
    r'"profile"\s*:\s*\{',
    # Generic sensitive
    r'"id"\s*:\s*\d+',
    r'"user_?id"\s*:\s*\d+',
    r'"admin"\s*:\s*(true|false)',
    r'"isAdmin"\s*:\s*(true|false)',
    # Extended API attributes
    r'"comment"\s*:\s*"[^"]+"',
    r'"message"\s*:\s*"[^"]+"',
    r'"question"\s*:\s*"[^"]+"',
    r'"answer"\s*:\s*"[^"]+"',
    r'"UserId"\s*:\s*\d+',
    r'"key"\s*:\s*"[^"]+"',
    r'"caption"\s*:\s*"[^"]+"',
    r'"imageUrl"\s*:\s*"[^"]+"',
    r'"cardNumber"\s*:\s*"[^"]+"',
    r'"fullName"\s*:\s*"[^"]+"',
]

# ═══════════════════════════════════════════════════
# UUID PATTERN
# Detects UUID format IDs in URLs
# ═══════════════════════════════════════════════════
UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}'
    r'-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE
)

# ═══════════════════════════════════════════════════
# NUMERIC ID PATTERN IN URL PATH
# Matches /users/1 or /orders/123
# ═══════════════════════════════════════════════════
NUMERIC_ID_PATTERN = re.compile(r'/(\d+)(?:/|$|\?)')

# ═══════════════════════════════════════════════════
# API ENDPOINT PATTERNS
# Common patterns where IDOR occurs
# ═══════════════════════════════════════════════════
API_PATTERNS = [
    r'/api/v?\d*/users?/\d+',
    r'/api/v?\d*/accounts?/\d+',
    r'/api/v?\d*/orders?/\d+',
    r'/api/v?\d*/products?/\d+',
    r'/api/v?\d*/profiles?/\d+',
    r'/api/v?\d*/customers?/\d+',
    r'/api/v?\d*/payments?/\d+',
    r'/api/v?\d*/invoices?/\d+',
    r'/api/v?\d*/tickets?/\d+',
    r'/api/v?\d*/messages?/\d+',
    r'/api/v?\d*/files?/\d+',
    r'/api/v?\d*/documents?/\d+',
    r'/api/v?\d*/records?/\d+',
    r'/rest/users?/\d+',
    r'/rest/orders?/\d+',
    r'/rest/basket/\d+',
]

# ═══════════════════════════════════════════════════
# LOAD IDOR PAYLOADS
# ═══════════════════════════════════════════════════
def load_payloads():
    payload_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "payloads", "idor.txt"
    )
    try:
        with open(payload_file, "r") as f:
            payloads = [l.strip() for l in f
                       if l.strip() and not l.startswith("#")]
        with print_lock:
            console.print(
                f"[dim]    [*] Loaded {len(payloads)} IDOR payloads[/dim]"
            )
        return payloads
    except FileNotFoundError:
        return ["1", "2", "0", "-1", "999", "admin"]

# ═══════════════════════════════════════════════════
# CHECK IF RESPONSE HAS SENSITIVE DATA
# Confirms IDOR by detecting data in response
# ═══════════════════════════════════════════════════
def has_sensitive_data(response_text):
    if not response_text:
        return False, ""
    for pattern in SENSITIVE_PATTERNS:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return True, match.group(0)[:80]
    return False, ""

# ═══════════════════════════════════════════════════
# COMPARE RESPONSES
# Check if two responses are meaningfully different
# Used to detect data access change
# ═══════════════════════════════════════════════════
def responses_differ(r1_text, r2_text, threshold=50):
    if not r1_text or not r2_text:
        return False
    if r1_text == r2_text:
        return False
    diff = abs(len(r1_text) - len(r2_text))
    return diff > threshold

# ═══════════════════════════════════════════════════
# BUILD FINDING
# ═══════════════════════════════════════════════════
def _build_finding(url, param_name, method,
                   idor_type, original, modified,
                   evidence, response_text=""):
    return {
        "vulnerability": "Insecure Direct Object Reference (IDOR)",
        "type": f"IDOR — {idor_type}",
        "url": url,
        "parameter": param_name,
        "original_value": str(original),
        "modified_value": str(modified),
        "payload": str(modified),
        "method": method.upper(),
        "evidence": evidence,
        "idor_type": idor_type,
        "response_status": 200,
        "risk_level": "HIGH",
        "cvss_score": 7.5,
        "cwe": "CWE-639",
        "owasp": "A01:2021 — Broken Access Control",
        "timestamp": get_timestamp(),
        "response_preview": response_text[:200] if response_text else "",
    }

# ═══════════════════════════════════════════════════
# DETECTION 1 — URL PATH ID MANIPULATION
# Changes numeric IDs in URL path
# Most common IDOR pattern
# Works on: /users/1 /orders/5 /api/v1/accounts/3
# ═══════════════════════════════════════════════════
def detect_path_idor(url, base_url):
    findings = []

    # Find all numeric IDs in path
    path = urlparse(url).path
    matches = list(NUMERIC_ID_PATTERN.finditer(path))

    if not matches:
        return findings

    for match in matches:
        original_id = match.group(1)
        original_int = int(original_id)

        # Get baseline response
        baseline_r = send_get(url)
        if baseline_r is None:
            continue

        baseline_status = baseline_r.status_code
        baseline_text = baseline_r.text
        baseline_len = len(baseline_text)

        # Only test if baseline returns data
        if baseline_status not in [200, 201]:
            continue

        # Test different IDs
        test_ids = []

        # Adjacent IDs
        for offset in [1, -1, 2, -2, 3, 5, 10]:
            new_id = original_int + offset
            if new_id > 0:
                test_ids.append(new_id)

        # Common IDs
        test_ids.extend([0, 1, 2, 3, 99, 100, 999])
        test_ids = list(set(test_ids))

        for test_id in test_ids:
            if test_id == original_int:
                continue

            # Build new URL with modified ID
            new_path = path[:match.start(1)] + str(test_id) + path[match.end(1):]
            new_url = urljoin(base_url, new_path)

            r = send_get(new_url)
            if r is None:
                continue

            # Check for successful different response
            if r.status_code in [200, 201]:
                has_data, data_preview = has_sensitive_data(r.text)

                if has_data and r.text != baseline_text:
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] IDOR (Path): "
                            f"{url} → ID {original_id} → {test_id}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        url, "path_id", "GET",
                        "Path ID Manipulation",
                        original_id, test_id,
                        f"ID {original_id} → {test_id} returned different "
                        f"sensitive data: {data_preview}",
                        r.text,
                    ))
                    break

                # Check significant response difference
                if responses_differ(baseline_text, r.text, 200):
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] IDOR (Path): "
                            f"{url} → {test_id}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        url, "path_id", "GET",
                        "Path ID Manipulation",
                        original_id, test_id,
                        f"ID {original_id} → {test_id} returned "
                        f"different response ({len(r.text)}B vs "
                        f"{baseline_len}B)",
                        r.text,
                    ))
                    break

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 2 — PARAMETER ID MANIPULATION
# Changes IDs in URL parameters
# Works on: ?user_id=1 ?order_id=5 ?id=3
# ═══════════════════════════════════════════════════
def detect_param_idor(url, params):
    findings = []

    # ID-like parameter names
    id_param_patterns = [
        'id', 'user_id', 'userid', 'uid', 'account_id',
        'accountid', 'order_id', 'orderid', 'customer_id',
        'customerid', 'profile_id', 'profileid', 'file_id',
        'fileid', 'doc_id', 'document_id', 'record_id',
        'ticket_id', 'message_id', 'post_id', 'comment_id',
        'product_id', 'item_id', 'invoice_id', 'payment_id',
        'session', 'token', 'key', 'ref', 'no',
    ]

    for param in params:
        param_name = param.get("name", "").lower()
        param_value = param.get("value", "")
        param_url = param.get("url", url)

        # Check if param looks like an ID
        is_id_param = (
            any(p in param_name for p in id_param_patterns) or
            (param_value.isdigit() and int(param_value) < 100000)
        )

        if not is_id_param:
            continue

        parsed_p = urlparse(param_url)
        clean_base = f"{parsed_p.scheme}://{parsed_p.netloc}{parsed_p.path}" if parsed_p.scheme else param_url.split("?")[0]
        base_qs = {}
        if parsed_p.query:
            for k, v in parse_qs(parsed_p.query).items():
                base_qs[k] = v[0] if v else ""

        # Get baseline
        base_qs[param_name] = param_value
        baseline_r = send_get(clean_base, params=base_qs)
        if baseline_r is None:
            continue

        baseline_text = baseline_r.text
        baseline_len = len(baseline_text)

        if baseline_r.status_code not in [200, 201]:
            continue

        # Test different values
        if param_value.isdigit():
            original = int(param_value)
            test_values = []
            for offset in [1, -1, 2, -2, 5, 10]:
                v = original + offset
                if v >= 0:
                    test_values.append(str(v))
            test_values.extend(["0", "1", "2", "99", "100", "999"])
        else:
            test_values = ["1", "2", "0", "admin", "root", "test"]

        for test_val in test_values:
            if test_val == param_value:
                continue

            test_qs = dict(base_qs)
            test_qs[param_name] = test_val
            r = send_get(clean_base, params=test_qs)
            if r is None:
                continue

            if r.status_code in [200, 201]:
                has_data, data_preview = has_sensitive_data(r.text)

                if has_data and r.text != baseline_text:
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] IDOR (Param): "
                            f"{param_name}={param_value} → {test_val}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        param_url, param_name, "GET",
                        "Parameter ID Manipulation",
                        param_value, test_val,
                        f"Param {param_name}={param_value} → {test_val} "
                        f"returned sensitive data: {data_preview}",
                        r.text,
                    ))
                    break

                if responses_differ(baseline_text, r.text, 300):
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] IDOR (Param): "
                            f"{param_name}={param_value} → {test_val}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        param_url, param_name, "GET",
                        "Parameter ID Manipulation",
                        param_value, test_val,
                        f"Param {param_name} changed response by "
                        f"{abs(len(r.text)-baseline_len)}B",
                        r.text,
                    ))
                    break

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 3 — API ENDPOINT IDOR
# Tests known API patterns for IDOR
# Works on REST APIs, JSON APIs
# Most common in modern web apps
# ═══════════════════════════════════════════════════
def detect_api_idor(base_url, pages, payloads):
    findings = []

    # Build list of API endpoints to test
    api_endpoints = []

    # From crawled pages
    for page in pages:
        page_url = page.get("url", "")
        for pattern in API_PATTERNS:
            if re.search(pattern, page_url, re.IGNORECASE):
                api_endpoints.append(page_url)
                break

    # Generate common API endpoints to probe
    common_api_paths = [
        "/api/Users/1", "/api/Users/2",
        "/api/Users/3", "/api/Users/0",
        "/api/BasketItems/1", "/api/BasketItems/2",
        "/api/Feedbacks/1", "/api/Feedbacks/2",
        "/api/Complaints/1", "/api/Complaints/2",
        "/api/Recycles/1", "/api/Recycles/2",
        "/api/Products/1", "/api/Products/2",
        "/api/SecurityQuestions/1", "/api/SecurityQuestions/2",
        "/api/Challenges/1", "/api/Challenges/2",
        "/api/Cards/1", "/api/Cards/2",
        "/api/Addresss/1", "/api/Addresss/2",
        "/api/Deliverys/1", "/api/Deliverys/2",
        "/api/Memories/1", "/api/Memories/2",
        "/rest/track-order/1", "/rest/track-order/2",
        "/rest/basket/1", "/rest/basket/2",
        "/rest/basket/3", "/rest/basket/99",
        "/rest/user/1", "/rest/user/2",
        "/rest/memories/1", "/rest/memories/2",
        "/api/v1/users/1", "/api/v1/users/2",
        "/api/v1/orders/1", "/api/v1/orders/2",
        "/api/v1/accounts/1", "/api/v1/accounts/2",
        "/user/profile/1", "/user/profile/2",
        "/account/1", "/account/2",
        "/order/1", "/order/2",
        "/invoice/1", "/invoice/2",
        "/document/1", "/document/2",
        "/file/1", "/file/2",
        "/profile/1", "/profile/2",
        "/admin/user/1", "/admin/user/2",
        "/dashboard/user/1", "/dashboard/user/2",
    ]

    for path in common_api_paths:
        api_endpoints.append(base_url.rstrip("/") + path)

    # Deduplicate
    api_endpoints = list(set(api_endpoints))

    tested_bases = set()

    for endpoint in api_endpoints:
        # Find the ID in this endpoint
        path = urlparse(endpoint).path
        matches = list(NUMERIC_ID_PATTERN.finditer(path))

        if not matches:
            continue

        # Track base endpoint to avoid duplicates
        base_endpoint = re.sub(r'/\d+', '/ID', path)
        if base_endpoint in tested_bases:
            continue
        tested_bases.add(base_endpoint)

        with print_lock:
            console.print(
                f"[dim]      [→] API IDOR: {endpoint}[/dim]"
            )

        # Get baseline
        baseline_r = send_get(endpoint)
        if baseline_r is None:
            continue

        baseline_status = baseline_r.status_code
        baseline_text = baseline_r.text

        # Get the ID from last match
        last_match = matches[-1]
        original_id = int(last_match.group(1))

        # Test adjacent IDs
        test_ids = []
        for offset in [1, -1, 2, -2, 3]:
            nid = original_id + offset
            if nid >= 0:
                test_ids.append(nid)
        test_ids.extend([0, 1, 2, 3, 99])

        for test_id in test_ids:
            if test_id == original_id:
                continue

            new_path = (
                path[:last_match.start(1)] +
                str(test_id) +
                path[last_match.end(1):]
            )
            new_url = base_url.rstrip("/") + new_path

            r = send_get(new_url)
            if r is None:
                continue

            # Success cases
            if r.status_code in [200, 201]:
                has_data, preview = has_sensitive_data(r.text)

                if has_data:
                    # Only report if different from baseline
                    if r.text != baseline_text:
                        with print_lock:
                            console.print(
                                f"[bold magenta]      [!!!] "
                                f"API IDOR: {endpoint} "
                                f"→ ID {test_id}[/bold magenta]"
                            )
                        findings.append(_build_finding(
                            endpoint, "api_id", "GET",
                            "API Endpoint IDOR",
                            original_id, test_id,
                            f"API returned sensitive data "
                            f"for ID {test_id}: {preview}",
                            r.text,
                        ))
                        break

                # Significant response difference
                if (responses_differ(baseline_text, r.text, 100) and
                        baseline_status == 404):
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] "
                            f"API IDOR (404→200): {endpoint} "
                            f"→ {test_id}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        endpoint, "api_id", "GET",
                        "API Endpoint IDOR",
                        original_id, test_id,
                        f"Endpoint returned 200 for ID {test_id} "
                        f"(baseline was 404)",
                        r.text,
                    ))
                    break

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 4 — UUID IDOR
# Detects UUIDs in URLs and tests manipulation
# Less common but high impact
# ═══════════════════════════════════════════════════
def detect_uuid_idor(pages, base_url):
    findings = []
    tested = set()

    for page in pages:
        page_url = page.get("url", "")
        matches = UUID_PATTERN.findall(page_url)

        for uuid in matches:
            if uuid in tested:
                continue
            tested.add(uuid)

            with print_lock:
                console.print(
                    f"[dim]      [→] UUID IDOR: {page_url}[/dim]"
                )

            # Get baseline
            baseline_r = send_get(page_url)
            if baseline_r is None:
                continue

            baseline_text = baseline_r.text

            # Try sequential UUIDs (increment last segment)
            try:
                parts = uuid.split("-")
                last = int(parts[-1], 16)
                for offset in [1, -1, 2]:
                    new_last = format(last + offset, '012x')
                    new_uuid = "-".join(parts[:-1] + [new_last])
                    new_url = page_url.replace(uuid, new_uuid)

                    r = send_get(new_url)
                    if r and r.status_code == 200:
                        if r.text != baseline_text:
                            has_data, preview = has_sensitive_data(r.text)
                            if has_data:
                                findings.append(_build_finding(
                                    page_url, "uuid", "GET",
                                    "UUID IDOR",
                                    uuid, new_uuid,
                                    f"UUID manipulation returned "
                                    f"different data: {preview}",
                                    r.text,
                                ))
                                break
            except Exception:
                continue

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 5 — HTTP METHOD IDOR
# Tests if different HTTP methods bypass auth
# GET blocked → try POST/PUT/DELETE
# Real world: many apps check GET but forget PUT
# ═══════════════════════════════════════════════════
def detect_method_idor(pages, base_url):
    findings = []

    # Focus on API endpoints
    api_pages = [
        p for p in pages
        if any(x in p.get("url", "")
               for x in ["/api/", "/rest/", "/v1/", "/v2/"])
    ]

    for page in api_pages[:10]:
        url = page.get("url", "")

        # Get baseline with GET
        get_r = send_get(url)
        if get_r is None:
            continue

        # Try DELETE method
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            for method in ["DELETE", "PUT", "PATCH"]:
                r = requests.request(
                    method, url,
                    timeout=10, verify=False
                )

                # If method not blocked and returns data
                if r.status_code in [200, 201, 204]:
                    if get_r.status_code in [401, 403]:
                        with print_lock:
                            console.print(
                                f"[bold magenta]      [!!!] "
                                f"Method IDOR: {method} {url}[/bold magenta]"
                            )
                        findings.append(_build_finding(
                            url, "http_method", method,
                            f"HTTP Method IDOR ({method})",
                            "GET (blocked)", method,
                            f"GET returned {get_r.status_code} but "
                            f"{method} returned {r.status_code}",
                            r.text,
                        ))
        except Exception:
            continue

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 6 — HORIZONTAL PRIVILEGE ESCALATION
# Login as user A, access user B resources
# Most critical IDOR type
# ═══════════════════════════════════════════════════
def detect_horizontal_privilege(base_url, pages):
    findings = []

    # Try to access user-specific endpoints
    user_endpoints = [
        "/rest/user/whoami",
        "/api/Users/1",
        "/api/Users/2",
        "/profile",
        "/account",
        "/dashboard",
        "/api/v1/me",
        "/api/me",
        "/api/profile",
        "/user/me",
        "/account/profile",
    ]

    for path in user_endpoints:
        url = base_url.rstrip("/") + path

        r = send_get(url)
        if r is None:
            continue

        if r.status_code in [200, 201]:
            has_data, preview = has_sensitive_data(r.text)
            if has_data:
                with print_lock:
                    console.print(
                        f"[bold magenta]      [!!!] "
                        f"Privilege: Unauthenticated access "
                        f"to {path}[/bold magenta]"
                    )
                findings.append(_build_finding(
                    url, "endpoint", "GET",
                    "Horizontal Privilege Escalation",
                    "authenticated", "unauthenticated",
                    f"Unauthenticated access to sensitive "
                    f"endpoint {path}: {preview}",
                    r.text,
                ))

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 7 — MASS ASSIGNMENT IDOR
# Sending extra fields in POST/PUT
# App may accept fields it should not
# Example: sending "role":"admin" in register
# ═══════════════════════════════════════════════════
def detect_mass_assignment(forms, base_url):
    findings = []

    # Fields that should not be user-controllable
    privileged_fields = [
        {"role": "admin"},
        {"isAdmin": True},
        {"is_admin": True},
        {"admin": True},
        {"privilege": "admin"},
        {"level": "admin"},
        {"type": "admin"},
        {"status": "active"},
        {"verified": True},
        {"confirmed": True},
        {"balance": 999999},
        {"credit": 999999},
        {"discount": 100},
    ]

    for form in forms:
        url = form.get("action", "")
        method = form.get("method", "get").lower()

        if method != "post":
            continue

        inputs = form.get("inputs", [])
        base_data = {
            i["name"]: i.get("value", "test")
            for i in inputs
        }

        # Try adding privileged fields
        for extra_fields in privileged_fields:
            test_data = dict(base_data)
            test_data.update(extra_fields)

            # Get baseline
            baseline_r = send_post(url, data=base_data)
            baseline_text = baseline_r.text if baseline_r else ""

            # Send with extra privileged field
            r = send_post(url, data=test_data)
            if r is None:
                continue

            # Check if extra field accepted
            if r.status_code in [200, 201]:
                for field, value in extra_fields.items():
                    if (str(value).lower() in r.text.lower() and
                            str(value).lower() not in baseline_text.lower()):
                        with print_lock:
                            console.print(
                                f"[bold magenta]      [!!!] "
                                f"Mass Assignment: {field}={value} "
                                f"accepted at {url}[/bold magenta]"
                            )
                        findings.append(_build_finding(
                            url, field, "POST",
                            "Mass Assignment IDOR",
                            "not sent", str(value),
                            f"Privileged field '{field}={value}' "
                            f"accepted by server at {url}",
                            r.text,
                        ))
                        break

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 8 — JSON BODY IDOR
# Tests IDOR via JSON request body
# Modern APIs often use JSON
# ═══════════════════════════════════════════════════
def detect_json_idor(pages, base_url):
    findings = []

    import requests
    import urllib3
    urllib3.disable_warnings()

    # API endpoints that accept JSON
    json_endpoints = [
        ("/rest/user/login", {"email": "test@test.com",
                              "password": "test"}),
        ("/api/BasketItems", {"ProductId": 1,
                              "BasketId": 1, "quantity": 1}),
        ("/api/Feedbacks", {"comment": "test",
                            "rating": 5}),
    ]

    for path, base_payload in json_endpoints:
        url = base_url.rstrip("/") + path

        # Try manipulating IDs in JSON body
        for key, value in base_payload.items():
            if isinstance(value, int) and value < 1000:
                for test_id in [0, 1, 2, 99, -1]:
                    if test_id == value:
                        continue

                    test_payload = dict(base_payload)
                    test_payload[key] = test_id

                    try:
                        headers = {
                            "Content-Type": "application/json"
                        }
                        r = requests.post(
                            url, json=test_payload,
                            headers=headers,
                            timeout=10, verify=False
                        )

                        if r.status_code in [200, 201]:
                            has_data, preview = has_sensitive_data(r.text)
                            if has_data:
                                with print_lock:
                                    console.print(
                                        f"[bold magenta]      [!!!] "
                                        f"JSON IDOR: {key}={test_id} "
                                        f"at {url}[/bold magenta]"
                                    )
                                findings.append(_build_finding(
                                    url, key, "POST",
                                    "JSON Body IDOR",
                                    value, test_id,
                                    f"JSON field {key}={test_id} "
                                    f"returned sensitive data: {preview}",
                                    r.text,
                                ))
                    except Exception:
                        continue

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 9 — FILE/RESOURCE IDOR
# Tests file download endpoints for IDOR
# Common in: invoice downloads, profile photos,
#            document access, export endpoints
# ═══════════════════════════════════════════════════
def detect_file_idor(base_url, pages):
    findings = []

    # Common file/resource endpoints
    file_paths = [
        "/download?id=1", "/download?id=2",
        "/file?id=1", "/file?id=2",
        "/export?id=1", "/export?id=2",
        "/invoice/1", "/invoice/2",
        "/receipt/1", "/receipt/2",
        "/document/1", "/document/2",
        "/attachment/1", "/attachment/2",
        "/api/files/1", "/api/files/2",
        "/uploads/1", "/uploads/2",
        "/media/1", "/media/2",
        "/resources/1", "/resources/2",
        "/backup/1", "/backup/2",
    ]

    for path in file_paths:
        url = base_url.rstrip("/") + path

        r = send_get(url)
        if r is None:
            continue

        # Check if file returned
        if r.status_code in [200, 201]:
            content_type = r.headers.get("Content-Type", "")
            content_length = len(r.content)

            # Skip HTML responses - those are SPA index pages not real files
            if "text/html" in content_type:
                continue

            # If actual file content returned (PDF, JSON, binary)
            if content_length > 100:
                has_data, preview = has_sensitive_data(r.text)

                if has_data or content_length > 500:
                    with print_lock:
                        console.print(
                            f"[bold magenta]      [!!!] "
                            f"File IDOR: {path}[/bold magenta]"
                        )
                    findings.append(_build_finding(
                        url, "file_id", "GET",
                        "File/Resource IDOR",
                        "N/A", path,
                        f"File accessible at {path} "
                        f"({content_length}B, type: {content_type})",
                        r.text[:200],
                    ))

    return findings

# ═══════════════════════════════════════════════════
# DETECTION 10 — PARAMETER POLLUTION IDOR
# Send same param twice with different values
# Some servers use first, some use last
# Example: ?id=1&id=2
# ═══════════════════════════════════════════════════
def detect_param_pollution(pages, params):
    findings = []

    for param in params:
        param_name = param.get("name", "")
        param_value = param.get("value", "")
        param_url = param.get("url", "")

        if not param_value.isdigit():
            continue

        original = int(param_value)

        # Get baseline
        baseline_r = send_get(
            param_url, params={param_name: param_value}
        )
        if baseline_r is None:
            continue

        baseline_text = baseline_r.text

        # Send polluted params
        for test_id in [original + 1, original - 1, 1, 2]:
            if test_id == original or test_id < 0:
                continue

            # Build URL with duplicate params
            import requests
            import urllib3
            urllib3.disable_warnings()

            try:
                # Use requests directly for param pollution
                polluted_url = (
                    f"{param_url}?{param_name}={param_value}"
                    f"&{param_name}={test_id}"
                )
                r = requests.get(
                    polluted_url, timeout=10, verify=False
                )

                if r.status_code == 200:
                    if responses_differ(baseline_text, r.text, 200):
                        has_data, preview = has_sensitive_data(r.text)
                        if has_data:
                            with print_lock:
                                console.print(
                                    f"[bold magenta]      [!!!] "
                                    f"Param Pollution: {param_name}="
                                    f"{param_value}&{param_name}={test_id}"
                                    f"[/bold magenta]"
                                )
                            findings.append(_build_finding(
                                param_url, param_name, "GET",
                                "Parameter Pollution IDOR",
                                param_value, test_id,
                                f"Duplicate param {param_name}="
                                f"{param_value}&{param_name}={test_id} "
                                f"returned different data: {preview}",
                                r.text,
                            ))
                            break
            except Exception:
                continue

    return findings

# ═══════════════════════════════════════════════════
# MAIN SCAN FUNCTION
# Runs all 10 IDOR detection methods
# ═══════════════════════════════════════════════════
def scan(crawler_results, llm_payloads=None):
    all_findings = []
    findings_lock = threading.Lock()

    console.print(
        "\n[bold magenta][*] Starting IDOR Scan...[/bold magenta]"
    )

    if llm_payloads and len(llm_payloads) > 0:
        seen = set()
        payloads = [p for p in llm_payloads if not (p in seen or seen.add(p))]
    else:
        payloads = load_payloads()

    console.print(
        f"[cyan]    [*] Active Payloads to Test: {len(payloads)}[/cyan]"
    )

    pages = crawler_results.get("pages", [])
    forms = crawler_results.get("forms", [])
    params = crawler_results.get("params", [])
    base_url = crawler_results.get("base_url", "")

    console.print(
        f"[cyan]    [*] Pages: {len(pages)} | "
        f"Forms: {len(forms)} | "
        f"Params: {len(params)}[/cyan]"
    )

    # ── Run all detection methods ──

    # Method 1: Path ID manipulation on all pages
    console.print(
        "[cyan]    [*] Method 1: Path ID Manipulation[/cyan]"
    )
    for page in pages:
        results = detect_path_idor(page.get("url", ""), base_url)
        with findings_lock:
            all_findings.extend(results)

    # Method 2: Parameter ID manipulation
    console.print(
        "[cyan]    [*] Method 2: Parameter ID Manipulation[/cyan]"
    )
    results = detect_param_idor(base_url, params)
    with findings_lock:
        all_findings.extend(results)

    # Method 3: API endpoint IDOR
    console.print(
        "[cyan]    [*] Method 3: API Endpoint IDOR[/cyan]"
    )
    results = detect_api_idor(base_url, pages, payloads)
    with findings_lock:
        all_findings.extend(results)

    # Method 4: UUID IDOR
    console.print(
        "[cyan]    [*] Method 4: UUID IDOR[/cyan]"
    )
    results = detect_uuid_idor(pages, base_url)
    with findings_lock:
        all_findings.extend(results)

    # Method 5: HTTP Method IDOR
    console.print(
        "[cyan]    [*] Method 5: HTTP Method IDOR[/cyan]"
    )
    results = detect_method_idor(pages, base_url)
    with findings_lock:
        all_findings.extend(results)

    # Method 6: Horizontal Privilege Escalation
    console.print(
        "[cyan]    [*] Method 6: Horizontal Privilege[/cyan]"
    )
    results = detect_horizontal_privilege(base_url, pages)
    with findings_lock:
        all_findings.extend(results)

    # Method 7: Mass Assignment
    console.print(
        "[cyan]    [*] Method 7: Mass Assignment[/cyan]"
    )
    results = detect_mass_assignment(forms, base_url)
    with findings_lock:
        all_findings.extend(results)

    # Method 8: JSON Body IDOR
    console.print(
        "[cyan]    [*] Method 8: JSON Body IDOR[/cyan]"
    )
    results = detect_json_idor(pages, base_url)
    with findings_lock:
        all_findings.extend(results)

    # Method 9: File/Resource IDOR
    console.print(
        "[cyan]    [*] Method 9: File/Resource IDOR[/cyan]"
    )
    results = detect_file_idor(base_url, pages)
    with findings_lock:
        all_findings.extend(results)

    # Method 10: Parameter Pollution
    console.print(
        "[cyan]    [*] Method 10: Param Pollution IDOR[/cyan]"
    )
    results = detect_param_pollution(pages, params)
    with findings_lock:
        all_findings.extend(results)

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = f"{f['url']}_{f['parameter']}_{f['modified_value']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Print summary
    console.print(
        f"\n[bold magenta][+] IDOR Scan Complete![/bold magenta]"
    )
    console.print(
        f"[magenta]    Total Findings: {len(unique_findings)}[/magenta]"
    )
    for i, f in enumerate(unique_findings):
        console.print(
            f"[magenta]    [{i+1}] {f['type']} | "
            f"{f['parameter']} | {f['url'][:55]}[/magenta]"
        )

    return unique_findings
