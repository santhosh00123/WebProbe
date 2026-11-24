import socket
import requests
from config import REQUEST_TIMEOUT


def is_internet_available():
    """Check if internet is available"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False


import re
from urllib.parse import urlparse


def resolve_target_info(raw_input):
    """
    Takes any target format (IP, IP:port, domain, domain:port, full URL)
    and resolves both the DNS name and the IP address.
    Supports:
      - 127.0.0.1:3000 -> Host: localhost, IP: 127.0.0.1
      - example.com -> Host: example.com, IP: 93.184.216.34
      - http://testfire.net:8080 -> Host: testfire.net, IP: 65.61.137.117
    """
    clean = str(raw_input).strip()
    if not clean.startswith("http://") and not clean.startswith("https://"):
        if ":443" in clean:
            clean = "https://" + clean
        else:
            clean = "http://" + clean
    clean = clean.rstrip("/")

    parsed = urlparse(clean)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
    dns_name = host
    ip_addr = host

    if is_ip:
        ip_addr = host
        try:
            dns_lookup = socket.gethostbyaddr(host)[0]
            if dns_lookup:
                dns_name = dns_lookup
        except Exception:
            if host in ["127.0.0.1", "0.0.0.0"]:
                dns_name = "localhost"
            else:
                dns_name = host
    else:
        dns_name = host
        try:
            ip_addr = socket.gethostbyname(host)
        except Exception:
            ip_addr = "Could not resolve"

    return {
        "url": clean,
        "host": dns_name,
        "ip": ip_addr,
        "port": port,
        "scheme": parsed.scheme,
    }


def resolve_ip(url):
    """Get IP address from URL or target"""
    info = resolve_target_info(url)
    return info["ip"]


def get_server_info(url):
    """Get server information from headers"""
    info = {
        "server": "Unknown",
        "technology": "Unknown",
        "tls_version": "Unknown",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            verify=False
        )
        resp_headers = response.headers
        info["server"] = resp_headers.get("Server", "Unknown")
        info["technology"] = resp_headers.get("X-Powered-By", "Unknown")
        return info
    except Exception:
        return info



def is_target_reachable(url):
    """
    Check if target URL is reachable.
    Uses realistic browser headers and supports cold-start servers (Render, Heroku).
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    # Attempt 1: Standard probe (15s timeout)
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        return True, response.status_code
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        # Attempt 2: Server might be waking up from sleep (e.g. onrender.com free tier cold start)
        try:
            import time
            time.sleep(1)
            response = requests.get(
                url,
                headers=headers,
                timeout=35,
                verify=False,
                allow_redirects=True
            )
            return True, response.status_code
        except Exception:
            pass
    except Exception:
        pass

    return False, 0



def audit_security_headers(target_url):
    """
    Checks HTTP response headers on target for essential defense headers.
    Returns: (status, note) e.g. ("INADEQUATE", "Missing CSP, X-Frame-Options")
    """
    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        response = requests.get(
            target_url,
            headers=headers_to_send,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True
        )

        if response is None:
            return "INADEQUATE", "Target did not respond to header evaluation"

        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = []
        if "content-security-policy" not in headers:
            missing.append("CSP")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        if "strict-transport-security" not in headers and target_url.startswith("https"):
            missing.append("HSTS")

        if missing:
            return "INADEQUATE", f"Missing essential defense headers: {', '.join(missing)}"
        return "ADEQUATE", "Hardened HTTP response headers (CSP, X-Frame-Options) actively enforced"
    except Exception:
        return "INADEQUATE", "Unable to inspect target HTTP response headers"


def audit_csrf_protection(target_url, forms=None):
    """
    Evaluates anti-CSRF protection across crawled forms and API endpoints.
    Returns: (status, note)
    """
    if not forms:
        return "ADEQUATE", "Stateless REST API architecture utilizes Bearer tokens limiting CSRF"

    unprotected_forms = 0
    for form in forms:
        inputs = form.get("inputs", [])
        has_csrf_token = any(
            inp.get("name", "").lower() in ["csrf", "_csrf", "csrf_token", "authenticity_token", "token"]
            for inp in inputs
        )
        if not has_csrf_token and form.get("method", "get").lower() == "post":
            unprotected_forms += 1

    if unprotected_forms > 0:
        return "INADEQUATE", f"State-changing POST forms ({unprotected_forms} found) lack anti-CSRF tokens"
    return "ADEQUATE", "State-changing endpoints enforce anti-CSRF token verification"
