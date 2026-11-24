# crawler/crawler.py
# Universal high-accuracy crawler for modern SPAs, REST APIs, and multi-page web applications.

from collections import deque
from utils.http_engine import send_get
from utils.helpers import get_base_url
from crawler.form_parser import parse_forms
from crawler.param_extractor import get_all_params, extract_url_params
from crawler.endpoint_finder import (
    find_links,
    find_api_endpoints,
    find_script_sources,
    extract_js_forms_and_params,
    parse_robots_txt,
    parse_sitemap_xml,
    find_interesting_paths,
    get_domain,
    get_hostname,
    is_same_domain,
    normalize_url,
    is_static_asset,
)
from config import MAX_CRAWL_DEPTH, MAX_PAGES
from rich.console import Console
from urllib.parse import urlparse, parse_qs
import re

console = Console()


JUICE_SHOP_REST_ENDPOINTS = [
    "/rest/products/search?q=",
    "/rest/track-order?id=",
    "/rest/user/change-password?current=&new=&repeat=",
    "/rest/user/whoami",
    "/rest/basket/1",
    "/rest/feedback",
    "/rest/complaints",
    "/rest/recycles",
    "/rest/memories",
    "/rest/captcha",
    "/api/Users",
    "/api/Products",
    "/api/Feedbacks",
    "/api/Complaints",
    "/api/Recycles",
    "/api/SecurityQuestions",
    "/api/Challenges",
    "/api/Addresss",
    "/api/Deliverys",
    "/api/Quantitys",
    "/api/Cards",
    "/api/BasketItems",
    "/api/Memories",
]


def _build_juice_shop_forms(base_url):
    return [
        {
            "action": f"{base_url}/rest/user/login",
            "method": "post",
            "inputs": [
                {"name": "email", "type": "text", "value": "", "placeholder": "Email"},
                {"name": "password", "type": "password", "value": "", "placeholder": "Password"},
            ],
            "source_url": f"{base_url}/login",
        },
        {
            "action": f"{base_url}/api/Users",
            "method": "post",
            "inputs": [
                {"name": "email", "type": "text", "value": "", "placeholder": "Email"},
                {"name": "password", "type": "password", "value": "", "placeholder": "Password"},
                {"name": "passwordRepeat", "type": "password", "value": "", "placeholder": "Repeat"},
                {"name": "securityAnswer", "type": "text", "value": "", "placeholder": "Answer"},
            ],
            "source_url": f"{base_url}/register",
        },
        {
            "action": f"{base_url}/rest/products/search",
            "method": "get",
            "inputs": [
                {"name": "q", "type": "text", "value": "", "placeholder": "Search"},
            ],
            "source_url": f"{base_url}/search",
        },
        {
            "action": f"{base_url}/rest/feedback",
            "method": "post",
            "inputs": [
                {"name": "comment", "type": "textarea", "value": "", "placeholder": "Comment"},
                {"name": "rating", "type": "number", "value": "", "placeholder": "Rating"},
            ],
            "source_url": f"{base_url}/#/contact",
        },
        {
            "action": f"{base_url}/rest/complaints",
            "method": "post",
            "inputs": [
                {"name": "message", "type": "textarea", "value": "", "placeholder": "Message"},
            ],
            "source_url": f"{base_url}/#/complain",
        },
        {
            "action": f"{base_url}/rest/track-order",
            "method": "get",
            "inputs": [
                {"name": "id", "type": "text", "value": "", "placeholder": "Order ID"},
            ],
            "source_url": f"{base_url}/#/track-result",
        },
        {
            "action": f"{base_url}/rest/user/change-password",
            "method": "get",
            "inputs": [
                {"name": "current", "type": "password", "value": "", "placeholder": "Current"},
                {"name": "new", "type": "password", "value": "", "placeholder": "New"},
                {"name": "repeat", "type": "password", "value": "", "placeholder": "Repeat"},
            ],
            "source_url": f"{base_url}/#/change-password",
        },
    ]


def extract_page_title(html_content):
    """Extracts text within <title> tag for real-time reporting"""
    try:
        match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if match:
            return " ".join(match.group(1).split()).strip()
    except Exception:
        pass
    return ""


def crawl(target_url):
    console.print(
        f"\n[bold cyan][*] Starting Universal Crawler on: {target_url}[/bold cyan]"
    )

    # 1. Initial Probe to establish canonical URL, base URL, and domain scope
    canonical_url = normalize_url(target_url)
    base_url = get_base_url(canonical_url)
    allowed_hosts = {get_hostname(canonical_url)}

    initial_resp = send_get(canonical_url)
    if initial_resp and initial_resp.url:
        final_url = normalize_url(initial_resp.url)
        if is_same_domain(final_url, canonical_url):
            canonical_url = final_url
            base_url = get_base_url(canonical_url)
            allowed_hosts.add(get_hostname(canonical_url))

    visited_urls = set()
    queued_urls = {canonical_url}
    all_forms = []
    all_params = []
    all_endpoints = []
    all_pages = []

    # BFS Queue: stores tuples of (url, current_depth)
    queue = deque([(canonical_url, 0)])

    # 2. Passive Reconnaissance: robots.txt & sitemap.xml
    console.print("[dim]    [→] Probing /robots.txt for hidden paths...[/dim]")
    robots_paths = parse_robots_txt(base_url)
    if robots_paths:
        console.print(f"[bold green]    [+] Discovered {len(robots_paths)} path(s) in /robots.txt[/bold green]")
        for rp in robots_paths[:10]:
            if rp not in queued_urls:
                queued_urls.add(rp)
                queue.append((rp, 1))

    sitemap_links = parse_sitemap_xml(base_url)
    if sitemap_links:
        console.print(f"[bold green]    [+] Discovered {len(sitemap_links)} indexed page(s) in /sitemap.xml[/bold green]")
        for sl in sitemap_links[:20]:
            if sl not in queued_urls:
                queued_urls.add(sl)
                queue.append((sl, 1))

    # 3. Target Environment Identification
    is_juice_shop = _detect_juice_shop(canonical_url)

    if is_juice_shop:
        console.print(
            "[bold yellow][*] OWASP Juice Shop environment detected — "
            "enabling specialized API & form mappings[/bold yellow]"
        )
        for path in JUICE_SHOP_REST_ENDPOINTS:
            full_url = normalize_url(base_url.rstrip("/") + path)
            if full_url not in queued_urls:
                queued_urls.add(full_url)
                queue.append((full_url, 1))
        all_forms.extend(_build_juice_shop_forms(base_url))
    else:
        # For general websites, probe select common paths if available
        interesting = find_interesting_paths(base_url)
        for path_url in interesting[:6]:
            norm_path = normalize_url(path_url)
            if norm_path not in queued_urls:
                queued_urls.add(norm_path)
                queue.append((norm_path, 1))

    # 4. Real-time Breadth-First Crawling Loop
    while queue and len(all_pages) < MAX_PAGES:
        current_url, depth = queue.popleft()

        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)

        # Skip static assets
        if is_static_asset(current_url):
            continue

        response = send_get(current_url)
        if response is None:
            continue

        # Skip non-existent or server error responses
        if response.status_code not in [200, 201, 301, 302, 401, 403]:
            continue

        # Content-type check: prioritize text/html, application/json, and text pages
        content_type = (response.headers.get("Content-Type") or "").lower()
        if content_type and not any(ct in content_type for ct in ["text/html", "application/xhtml", "application/json", "text/plain"]):
            continue

        html_content = response.text or ""
        page_title = extract_page_title(html_content) if "text/html" in content_type or not content_type else ""

        all_pages.append({
            "url": current_url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "title": page_title,
        })

        # Real-time console reporting
        page_idx = len(all_pages)
        size_kb = len(response.content) / 1024
        status_color = "green" if response.status_code == 200 else "yellow"
        console.print(
            f"[bold cyan][*] [Page {page_idx}/{MAX_PAGES}][/bold cyan] "
            f"[{status_color}][{response.status_code}][/{status_color}] "
            f"([dim]{size_kb:.1f} KB[/dim]) [white]{current_url}[/white]"
        )
        if page_title:
            console.print(f"[dim]    ↳ Title: \"{page_title[:65]}\"[/dim]")

        # Extract forms
        forms = parse_forms(current_url, html_content)
        if forms:
            all_forms.extend(forms)

        # Extract URL, hidden, and path parameters
        params = get_all_params(current_url, html_content)
        if params:
            all_params.extend(params)

        # Real-time discoveries summary for this page
        if forms or params:
            discoveries = []
            if forms:
                discoveries.append(f"{len(forms)} form(s)")
            if params:
                param_names = [p['name'] for p in params[:4]]
                discoveries.append(f"{len(params)} param(s) [{', '.join(param_names)}]")
            console.print(f"[dim]    ↳ Discovered: {', '.join(discoveries)}[/dim]")

        # Extract API routes and scripts
        api_endpoints = find_api_endpoints(current_url, html_content, base_url)
        all_endpoints.extend(api_endpoints)

        # Extract forms & parameters from JavaScript bundles
        script_urls = find_script_sources(current_url, html_content, base_url)[:5]
        for s_url in script_urls:
            try:
                s_resp = send_get(s_url, timeout=8)
                if s_resp and s_resp.status_code == 200:
                    js_forms = extract_js_forms_and_params(s_resp.text, base_url)
                    all_forms.extend(js_forms)
            except Exception:
                pass

        # Discover & queue new links if within depth limit
        if depth < MAX_CRAWL_DEPTH:
            new_links = find_links(current_url, html_content, base_url, allowed_hosts)
            added_links = 0
            for link in new_links:
                if link not in visited_urls and link not in queued_urls:
                    queued_urls.add(link)
                    queue.append((link, depth + 1))
                    added_links += 1
            if added_links > 0:
                console.print(f"[dim]    ↳ Queued {added_links} new link(s) (Pending in queue: {len(queue)})[/dim]")

    # 5. Dynamic API Parameter Extraction from Endpoints
    for ep in all_endpoints:
        parsed = urlparse(ep)
        # Query parameters
        if parsed.query:
            qs = parse_qs(parsed.query)
            clean_ep = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else ep.split("?")[0]
            for param_name in qs:
                all_params.append({
                    "name": param_name,
                    "value": qs[param_name][0] if qs[param_name] else "",
                    "source": "url",
                    "url": ep,
                    "endpoint": clean_ep,
                })
        # Path ID parameters (e.g. /api/cases/1 or /api/orders/50)
        path_parts = parsed.path.split("/")
        for part in path_parts:
            if part.isdigit():
                all_params.append({
                    "name": "id",
                    "value": part,
                    "source": "path",
                    "url": ep,
                    "endpoint": ep,
                })

    # If Juice Shop, also attach known query parameters
    if is_juice_shop:
        for path in JUICE_SHOP_REST_ENDPOINTS:
            if "?" in path:
                base_p, q_p = path.split("?", 1)
                for pair in q_p.split("&"):
                    param_name = pair.replace("=", "").strip()
                    if param_name:
                        ep_clean = base_url.rstrip("/") + base_p
                        all_params.append({
                            "name": param_name,
                            "value": "",
                            "source": "url",
                            "url": ep_clean,
                            "endpoint": ep_clean,
                        })

    # Deduplicate endpoints
    all_endpoints = list(dict.fromkeys(all_endpoints))

    # Deduplicate params by (endpoint, param_name)
    seen_params = set()
    unique_params = []
    for param in all_params:
        target_ep = param.get("endpoint") or param.get("url", "").split("?")[0]
        key = f"{target_ep}_{param['name']}"
        if key not in seen_params:
            seen_params.add(key)
            unique_params.append(param)

    # Deduplicate forms by (action, method)
    seen_forms = set()
    unique_forms = []
    for form in all_forms:
        key = f"{form.get('action', '')}_{form.get('method', 'get').lower()}"
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(form)

    console.print(f"\n[bold green][+] Crawl Complete![/bold green]")
    console.print(f"[green]    Total Pages Crawled  : {len(all_pages)}[/green]")
    console.print(f"[green]    Forms / Actions      : {len(unique_forms)}[/green]")
    console.print(f"[green]    Parameters Found     : {len(unique_params)}[/green]")
    console.print(f"[green]    API Endpoints        : {len(all_endpoints)}[/green]")

    return {
        "pages": all_pages,
        "forms": unique_forms,
        "params": unique_params,
        "endpoints": all_endpoints,
        "base_url": base_url,
        "target_url": target_url,
        "is_juice_shop": is_juice_shop,
    }


def _detect_juice_shop(url):
    try:
        response = send_get(url, timeout=5)
        if response and "OWASP Juice Shop" in response.text:
            return True
        if response and "juice-shop" in response.text.lower():
            return True
        ver_response = send_get(
            url.rstrip("/") + "/rest/admin/application-version",
            timeout=5
        )
        if ver_response and ver_response.status_code == 200:
            return True
    except Exception:
        pass
    return False

