import requests
import time
import urllib3
from config import REQUEST_TIMEOUT, REQUEST_DELAY

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


def _merge_headers(custom_headers=None):
    merged = dict(DEFAULT_HEADERS)
    if custom_headers:
        merged.update(custom_headers)
    return merged


def send_get(url, params=None, headers=None, timeout=None):
    """Send GET request with realistic browser headers"""
    try:
        time.sleep(REQUEST_DELAY)
        merged_headers = _merge_headers(headers)
        response = requests.get(
            url,
            params=params,
            headers=merged_headers,
            timeout=timeout or REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        return response
    except Exception:
        return None


def send_post(url, data=None, json=None, headers=None, timeout=None):
    """Send POST request with realistic browser headers"""
    try:
        time.sleep(REQUEST_DELAY)
        merged_headers = _merge_headers(headers)
        response = requests.post(
            url,
            data=data,
            json=json,
            headers=merged_headers,
            timeout=timeout or REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        return response
    except Exception:
        return None



def get_response_info(response):
    """Extract useful info from response"""
    if response is None:
        return None
    return {
        "status_code": response.status_code,
        "content_length": len(response.content),
        "headers": dict(response.headers),
        "body": response.text,
        "url": response.url,
    }
