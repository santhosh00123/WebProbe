# crawler/endpoint_finder.py
# Universal endpoint, link, script, and hidden-page finder for modern web apps & APIs.

import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from utils.http_engine import send_get


GENERIC_DISCOVERY_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/api", "/api/v1", "/api/v2",
    "/docs", "/swagger", "/openapi.json",
    "/login", "/register", "/signup",
    "/search", "/admin", "/dashboard",
    "/profile", "/account", "/settings",
    "/health", "/status", "/info"
]

STATIC_EXTENSIONS = {
    # Images & icons
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".avif",
    # Styles & Fonts
    ".css", ".scss", ".less", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Audio / Video / Media
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv", ".m4a", ".ogg",
    # Documents & Archives
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
    # Binaries & Maps
    ".exe", ".bin", ".dmg", ".iso", ".apk", ".map"
}


def get_domain(url):
    """Returns netloc for backwards compatibility (e.g. 'example.com' or 'target.local:8080')"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def get_hostname(url):
    """Returns hostname in lowercase without port (e.g. 'example.com')"""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def get_base_url(url):
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return url


def get_path(url):
    try:
        parsed = urlparse(url)
        return parsed.path
    except Exception:
        return ""


def is_static_asset(url):
    """Checks if URL points to a static media, stylesheet, font, or binary asset"""
    try:
        path = urlparse(url).path.lower()
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        return False
    except Exception:
        return False


def is_same_domain(candidate_url, base_url, allowed_hosts=None):
    """
    Checks if candidate_url belongs to the same target domain / host.
    Handles:
    - Same hostname
    - Apex vs www (example.com matches www.example.com)
    - Custom port matching (if non-standard port specified on base)
    - Optional allowed_hosts list/set
    """
    try:
        parsed_cand = urlparse(candidate_url)
        parsed_base = urlparse(base_url)

        cand_host = (parsed_cand.hostname or "").lower()
        base_host = (parsed_base.hostname or "").lower()

        if not cand_host or not base_host:
            return False

        # Non-standard custom port matching (e.g. :3000, :8080)
        base_custom_port = parsed_base.port
        cand_custom_port = parsed_cand.port
        if base_custom_port and base_custom_port not in (80, 443):
            if cand_custom_port != base_custom_port:
                return False

        # Explicit allowed hosts check
        if allowed_hosts and cand_host in allowed_hosts:
            return True

        # Direct host match
        if cand_host == base_host:
            return True

        # Apex vs www. match
        strip_cand = cand_host.removeprefix("www.")
        strip_base = base_host.removeprefix("www.")
        if strip_cand == strip_base:
            return True

        return False
    except Exception:
        return False


def normalize_url(url):
    """
    Normalizes a URL for deduplication and clean crawling:
    - Strips fragment (#...)
    - Lowercases scheme and netloc
    - Strips default ports (:80 on http, :443 on https)
    - Normalizes trailing slash on non-root paths (/page/ -> /page)
    - Preserves and sorts query parameters
    """
    try:
        parsed = urlparse(url.strip())
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()

        # Remove default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        query = ""
        if parsed.query:
            query_items = parse_qsl(parsed.query, keep_blank_values=True)
            if query_items:
                query = urlencode(sorted(query_items))

        if query:
            return f"{scheme}://{netloc}{path}?{query}"
        return f"{scheme}://{netloc}{path}"
    except Exception:
        return url.split("#")[0].rstrip("/")


def find_links(url, html_content, base_url=None, allowed_hosts=None):
    """
    Finds all valid same-domain links on a page across HTML tags, navigation attributes,
    and inline JavaScript navigation statements. Filters out static non-HTML assets.
    """
    links = []
    scope_base = base_url or url
    extracted_candidates = set()

    try:
        soup = BeautifulSoup(html_content, "lxml")

        # 1. <a> and <area> links
        for el in soup.find_all(["a", "area"], href=True):
            href = el["href"].strip()
            if href:
                extracted_candidates.add(href)

        # 2. Form actions
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action:
                extracted_candidates.add(action)

        # 3. Frames and iframes
        for frame in soup.find_all(["iframe", "frame"], src=True):
            src = frame["src"].strip()
            if src:
                extracted_candidates.add(src)

        # 4. Canonical and alternate links
        for link_tag in soup.find_all("link", href=True):
            rel = [r.lower() for r in link_tag.get("rel", [])] if isinstance(link_tag.get("rel"), list) else [str(link_tag.get("rel", "")).lower()]
            if any(r in rel for r in ["canonical", "alternate"]):
                extracted_candidates.add(link_tag["href"].strip())

        # 5. HTML5 data navigation attributes
        for el in soup.find_all(attrs={"data-href": True}):
            extracted_candidates.add(el["data-href"].strip())
        for el in soup.find_all(attrs={"data-url": True}):
            extracted_candidates.add(el["data-url"].strip())

    except Exception:
        pass

    # 6. JavaScript location assignments in HTML text
    try:
        js_nav_patterns = [
            r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\'\s<>]+)["\']',
            r'location\.(?:assign|replace)\s*\(\s*["\']([^"\'\s<>]+)["\']\)',
            r'routerLink=["\'](/[^"\'\s<>]+)["\']',
        ]
        for pat in js_nav_patterns:
            for match in re.finditer(pat, html_content):
                extracted_candidates.add(match.group(1).strip())
    except Exception:
        pass

    # Filter and normalize candidate URLs
    for raw in extracted_candidates:
        if not raw:
            continue
        if raw.startswith(("javascript:", "mailto:", "tel:", "data:", "callto:", "#")):
            continue
        if '"' in raw or "'" in raw or len(raw) > 500:
            continue

        full_url = urljoin(url, raw).split("#")[0].strip()
        if not full_url or not full_url.startswith(("http://", "https://")):
            continue

        # Skip static assets (images, css, fonts, media, archives)
        if is_static_asset(full_url):
            continue

        # Only follow same domain
        if is_same_domain(full_url, scope_base, allowed_hosts):
            normalized = normalize_url(full_url)
            links.append(normalized)

    return list(dict.fromkeys(links))


def find_script_sources(url, html_content, base_url=None):
    """Extracts internal and same-domain <script src="..."> URLs from HTML"""
    scripts = []
    scope_base = base_url or url

    try:
        soup = BeautifulSoup(html_content, "lxml")
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            if not src:
                continue
            full_url = urljoin(url, src).split("?")[0]
            if is_same_domain(full_url, scope_base):
                scripts.append(full_url)
    except Exception:
        pass

    return list(set(scripts))


def find_api_endpoints_in_text(text, base_url):
    """
    Extracts API endpoints, routes, and fetch calls from JS or HTML content.
    Handles quotes, template literals (`/api/...`), and string variables.
    """
    endpoints = set()

    # 1. Template literals with variables (e.g. `${API_BASE}/api/cases/${caseId}`)
    for match in re.finditer(r'`(?:\$\{[^}]+\})?(/[^`\s]+)`', text):
        clean_ep = re.sub(r'\$\{[^}]+\}', '1', match.group(1))
        endpoints.add(clean_ep)

    # 2. Quoted strings with common API route prefixes
    for match in re.finditer(r'["\']((?:/api|/rest|/v1|/v2|/auth|/cases|/data|/query|/admin|/search|/login|/users|/orders|/products|/graph|/simulate)[^"\'\s<>{}$]*)["\']', text):
        endpoints.add(match.group(1))

    # 3. Explicit fetch/axios calls
    for match in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*[`"\']([^`"\'\s)]+)[`"\']', text):
        raw_url = match.group(1)
        if raw_url.startswith("/"):
            endpoints.add(raw_url)
        elif raw_url.startswith("http") and is_same_domain(raw_url, base_url):
            endpoints.add(urlparse(raw_url).path)

    full_endpoints = []
    for ep in endpoints:
        ep_clean = ep.strip()
        if ep_clean.startswith("/"):
            full_endpoints.append(base_url.rstrip("/") + ep_clean)
        elif ep_clean.startswith("http"):
            full_endpoints.append(ep_clean)

    return list(set(full_endpoints))


def find_api_endpoints(url, html_content, base_url=None):
    """
    Discovers all API endpoints in HTML and in external same-domain JavaScript bundles.
    """
    scope_base = base_url or get_base_url(url)
    endpoints = set()

    # 1. Search in HTML body & inline scripts
    endpoints.update(find_api_endpoints_in_text(html_content, scope_base))

    # 2. Search in external same-domain JS files (limit to first 5 JS bundles for speed)
    script_urls = find_script_sources(url, html_content, scope_base)[:5]
    for script_url in script_urls:
        try:
            resp = send_get(script_url, timeout=10)
            if resp and resp.status_code == 200:
                endpoints.update(find_api_endpoints_in_text(resp.text, scope_base))
        except Exception:
            pass

    return list(endpoints)


def extract_js_forms_and_params(js_content, base_url):
    """
    Synthesizes form definitions from JavaScript JSON.stringify() or POST fetch calls.
    Returns: list of form dicts e.g. [{"action": ..., "method": "post", "inputs": [...]}]
    """
    synthetic_forms = []
    idx = 0

    while True:
        pos = js_content.find("fetch(", idx)
        if pos == -1:
            break
        idx = pos + 6
        chunk = js_content[pos:pos + 800]

        if "POST" in chunk or "PUT" in chunk or "PATCH" in chunk:
            method = "post"
            if "PUT" in chunk:
                method = "put"
            elif "PATCH" in chunk:
                method = "patch"

            ep_match = re.search(r'fetch\s*\(\s*[`"\'](?:\$\{[^}]+\})?(/[^`"\'\s,)]+)', chunk)
            if ep_match:
                raw_ep = ep_match.group(1).strip()
                full_action = base_url.rstrip("/") + ("/" + raw_ep.lstrip("/"))

                body_match = re.search(r'JSON\.stringify\(\s*\{([^}]+)\}', chunk)
                if body_match:
                    keys = re.findall(r'([a-zA-Z0-9_]+)\s*:', body_match.group(1))
                    if keys:
                        inputs = [{"name": k, "type": "text", "value": "test"} for k in keys]
                        synthetic_forms.append({
                            "action": full_action,
                            "method": method,
                            "inputs": inputs,
                            "source_url": base_url,
                            "content_type": "json"
                        })

    return synthetic_forms


def parse_robots_txt(base_url):
    """
    Crawls /robots.txt to discover hidden admin, internal, and disallow paths.
    """
    hidden_paths = []
    try:
        robots_url = base_url.rstrip("/") + "/robots.txt"
        resp = send_get(robots_url, timeout=8)
        if resp and resp.status_code == 200 and "User-agent" in resp.text:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/" and "*" not in path:
                            full = base_url.rstrip("/") + ("/" + path.lstrip("/"))
                            if not is_static_asset(full):
                                hidden_paths.append(normalize_url(full))
    except Exception:
        pass
    return list(dict.fromkeys(hidden_paths))


def parse_sitemap_xml(base_url):
    """
    Crawls /sitemap.xml to discover all author-indexed URLs.
    Supports standard sitemaps as well as sitemap index files.
    """
    sitemap_links = []
    try:
        sitemap_url = base_url.rstrip("/") + "/sitemap.xml"
        resp = send_get(sitemap_url, timeout=8)
        if resp and resp.status_code == 200 and "<loc>" in resp.text:
            urls = re.findall(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', resp.text)
            
            # Check if this is a sitemap index containing child sitemaps
            child_sitemaps = [u.strip() for u in urls if "sitemap" in u.lower() and u.lower().endswith(".xml") and is_same_domain(u, base_url)][:3]
            for child_url in child_sitemaps:
                try:
                    c_resp = send_get(child_url, timeout=8)
                    if c_resp and c_resp.status_code == 200:
                        c_urls = re.findall(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', c_resp.text)
                        urls.extend(c_urls)
                except Exception:
                    pass

            for u in urls:
                u_clean = u.strip()
                if is_same_domain(u_clean, base_url) and not is_static_asset(u_clean):
                    sitemap_links.append(normalize_url(u_clean))
    except Exception:
        pass
    return list(dict.fromkeys(sitemap_links))


def find_interesting_paths(base_url):
    """Returns generic discovery endpoints"""
    paths = []
    for path in GENERIC_DISCOVERY_PATHS:
        full_url = base_url.rstrip("/") + path
        paths.append(full_url)
    return paths
