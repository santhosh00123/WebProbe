from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup


def extract_url_params(url):
    """
    Extract parameters from URL
    Example: /search?q=test&page=1
    Returns: [{"name": "q", "value": "test", "source": "url", "url": url, "endpoint": ...}, ...]
    """
    params = []
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        clean_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url.split("?")[0]

        for name, values in query_params.items():
            params.append({
                "name": name,
                "value": values[0] if values else "",
                "source": "url",
                "url": url,
                "endpoint": clean_endpoint,
            })
    except Exception:
        pass

    return params


def extract_hidden_params(html_content, url):
    """
    Extract hidden input parameters from HTML
    These are often interesting for security testing
    """
    params = []
    try:
        soup = BeautifulSoup(html_content, "lxml")
        hidden_inputs = soup.find_all(
            "input",
            attrs={"type": "hidden"}
        )

        for inp in hidden_inputs:
            name = inp.attrs.get("name", "")
            value = inp.attrs.get("value", "")
            if name:
                params.append({
                    "name": name,
                    "value": value,
                    "source": "hidden",
                    "url": url,
                })
    except Exception:
        pass

    return params


def extract_api_params(url):
    """
    Extract ID parameters from API-style URLs
    Example: /api/users/1 → id=1
    Example: /orders/100  → id=100
    """
    params = []
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")

        for part in path_parts:
            # Check if part is a number (likely an ID)
            if part.isdigit():
                params.append({
                    "name": "id",
                    "value": part,
                    "source": "path",
                    "url": url,
                })
    except Exception:
        pass

    return params


def get_all_params(url, html_content):
    """
    Get all parameters from URL and HTML
    Combines url params + hidden params + api params
    """
    all_params = []

    # URL parameters
    url_params = extract_url_params(url)
    all_params.extend(url_params)

    # Hidden parameters
    hidden_params = extract_hidden_params(html_content, url)
    all_params.extend(hidden_params)

    # API path parameters
    api_params = extract_api_params(url)
    all_params.extend(api_params)

    # Remove duplicates by name
    seen = set()
    unique_params = []
    for param in all_params:
        if param["name"] not in seen:
            seen.add(param["name"])
            unique_params.append(param)

    return unique_params
