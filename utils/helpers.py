from datetime import datetime
from urllib.parse import urlparse


def get_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_date():
    """Get current date"""
    return datetime.now().strftime("%Y-%m-%d")


def get_filename_timestamp():
    """Get timestamp for filename"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def clean_url(url):
    """Clean and validate URL"""
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url


def get_base_url(url):
    """Get base URL from full URL"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_hostname(url):
    """Get hostname from URL"""
    parsed = urlparse(url)
    return parsed.netloc


def print_banner():
    """Print WebProbe banner"""
    banner = """
    ██╗    ██╗███████╗██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
    ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
    ██║ █╗ ██║█████╗  ██████╔╝██████╔╝██████╔╝██║   ██║██████╔╝█████╗
    ██║███╗██║██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
    ╚███╔███╔╝███████╗██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗
     ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝

                    Scan. Detect. Report. Secure.
                         WebProbe v1.0
    """
    print(banner)
