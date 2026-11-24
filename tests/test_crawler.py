#!/usr/bin/env python3
"""
WebProbe Universal Crawler Unit & Integration Tests
Tests:
- Domain scope matching (apex, www, ports, external filtering)
- Static asset detection and filtering
- URL normalization & deduplication
- Link extraction across HTML5, forms, iframes, and JavaScript navigation
- Title extraction
- Form parsing & parameter extraction
- Full Breadth-First Search (BFS) crawl simulation
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crawler.endpoint_finder import (
    is_same_domain,
    is_static_asset,
    normalize_url,
    find_links,
    get_domain,
    get_hostname,
    parse_robots_txt,
    parse_sitemap_xml,
)
from crawler.form_parser import parse_forms
from crawler.param_extractor import extract_url_params, get_all_params
from crawler.crawler import crawl, extract_page_title


class TestUniversalCrawler(unittest.TestCase):

    def test_01_domain_matching(self):
        """Test domain scope matching including apex/www and ports"""
        base = "https://example.com"
        
        # Same domain
        self.assertTrue(is_same_domain("https://example.com/about", base))
        # Apex vs WWW
        self.assertTrue(is_same_domain("https://www.example.com/products", base))
        self.assertTrue(is_same_domain("http://example.com/contact", "https://www.example.com"))
        
        # External domain
        self.assertFalse(is_same_domain("https://google.com", base))
        self.assertFalse(is_same_domain("https://twitter.com/profile", base))
        self.assertFalse(is_same_domain("https://cdn.example-cdn.com/asset.js", base))
        
        # Port matching
        local_base = "http://localhost:3000"
        self.assertTrue(is_same_domain("http://localhost:3000/app", local_base))
        self.assertFalse(is_same_domain("http://localhost:8080/app", local_base))
        
        # Allowed hosts list
        self.assertTrue(is_same_domain("https://api.example.com/v1", base, allowed_hosts={"api.example.com"}))
        self.assertFalse(is_same_domain("https://api.example.com/v1", base))

    def test_02_static_asset_filtering(self):
        """Test static asset filtering to preserve crawl budget"""
        self.assertTrue(is_static_asset("https://example.com/logo.png"))
        self.assertTrue(is_static_asset("https://example.com/styles/main.css"))
        self.assertTrue(is_static_asset("https://example.com/fonts/inter.woff2"))
        self.assertTrue(is_static_asset("https://example.com/docs/manual.pdf"))
        self.assertTrue(is_static_asset("https://example.com/downloads/archive.zip"))
        self.assertTrue(is_static_asset("https://example.com/video.mp4"))
        
        # Valid web pages should NOT be considered static assets
        self.assertFalse(is_static_asset("https://example.com/about"))
        self.assertFalse(is_static_asset("https://example.com/products/item?id=123"))
        self.assertFalse(is_static_asset("https://example.com/index.php"))
        self.assertFalse(is_static_asset("https://example.com/contact.html"))

    def test_03_url_normalization(self):
        """Test URL normalization for deduplication"""
        # Fragment removal
        self.assertEqual(
            normalize_url("https://example.com/page#section"),
            "https://example.com/page"
        )
        # Trailing slash normalization
        self.assertEqual(
            normalize_url("https://example.com/page/"),
            "https://example.com/page"
        )
        # Root URL preserved
        self.assertEqual(
            normalize_url("https://example.com/"),
            "https://example.com/"
        )
        # Default port removal
        self.assertEqual(
            normalize_url("http://example.com:80/about"),
            "http://example.com/about"
        )
        self.assertEqual(
            normalize_url("https://example.com:443/about"),
            "https://example.com/about"
        )
        # Query parameter sorting
        self.assertEqual(
            normalize_url("https://example.com/search?b=2&a=1"),
            "https://example.com/search?a=1&b=2"
        )

    def test_04_find_links_comprehensive(self):
        """Test link discovery across anchors, forms, iframes, data-attributes, and JS navigation"""
        html = """
        <html>
        <head>
            <title>Test Page</title>
            <link rel="canonical" href="https://example.com/canonical-page">
        </head>
        <body>
            <a href="/about-us">About</a>
            <a href="https://www.example.com/team">Team (www)</a>
            <a href="https://external.com/out">External</a>
            <a href="/image.jpg">Photo</a>
            <area href="/area-link">
            <form action="/submit-form" method="post">
                <input name="test" value="1">
            </form>
            <iframe src="/embedded-frame"></iframe>
            <div data-href="/data-navigation">Click</div>
            <script>
                window.location.href = "/dashboard";
                location.assign('/reports');
            </script>
        </body>
        </html>
        """
        links = find_links("https://example.com/home", html, base_url="https://example.com")
        
        # Verify internal paths are extracted
        self.assertIn("https://example.com/about-us", links)
        self.assertIn("https://www.example.com/team", links)
        self.assertIn("https://example.com/canonical-page", links)
        self.assertIn("https://example.com/area-link", links)
        self.assertIn("https://example.com/submit-form", links)
        self.assertIn("https://example.com/embedded-frame", links)
        self.assertIn("https://example.com/data-navigation", links)
        self.assertIn("https://example.com/dashboard", links)
        self.assertIn("https://example.com/reports", links)
        
        # Verify external and static links are excluded
        self.assertNotIn("https://external.com/out", links)
        self.assertNotIn("https://example.com/image.jpg", links)

    def test_05_title_extraction(self):
        """Test HTML page title extraction"""
        html = "<html><head><title>  Welcome to Acme Startup &amp; Co.  </title></head><body></body></html>"
        self.assertEqual(extract_page_title(html), "Welcome to Acme Startup &amp; Co.")

    def test_06_form_parser_id_fallback(self):
        """Test form parsing with HTML5 id fallback and buttons"""
        html = """
        <form action="/login.php#top" method="POST">
            <input type="text" id="username_id" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit" name="btn_login" value="1">Log In</button>
        </form>
        """
        forms = parse_forms("https://example.com/login", html)
        self.assertEqual(len(forms), 1)
        form = forms[0]
        self.assertEqual(form["action"], "https://example.com/login.php")
        self.assertEqual(form["method"], "post")
        input_names = [i["name"] for i in form["inputs"]]
        self.assertIn("username_id", input_names)
        self.assertIn("password", input_names)
        self.assertIn("btn_login", input_names)

    def test_07_param_extractor_endpoint_info(self):
        """Test parameter extraction with clean endpoint url"""
        url = "https://example.com/items.php?category=books&sort=asc"
        params = extract_url_params(url)
        self.assertEqual(len(params), 2)
        p_map = {p["name"]: p for p in params}
        self.assertIn("category", p_map)
        self.assertEqual(p_map["category"]["value"], "books")
        self.assertEqual(p_map["category"]["endpoint"], "https://example.com/items.php")

    @patch("crawler.crawler.send_get")
    def test_08_crawl_bfs_multi_page_simulation(self, mock_send_get):
        """Simulate a multi-page crawl of a generic website"""
        # Define simulated responses
        def side_effect(url, **kwargs):
            norm = normalize_url(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.url = norm
            resp.content = b"<html>...</html>"
            
            if norm == "https://startup.io/" or norm == "https://startup.io":
                resp.headers = {"Content-Type": "text/html"}
                resp.text = """
                <html>
                <head><title>Startup Home</title></head>
                <body>
                    <a href="/features">Features</a>
                    <a href="/pricing">Pricing</a>
                    <a href="/contact">Contact</a>
                </body>
                </html>
                """
                return resp
            elif "/features" in norm:
                resp.headers = {"Content-Type": "text/html"}
                resp.text = """
                <html>
                <head><title>Features</title></head>
                <body>
                    <a href="/features?category=ai">AI Features</a>
                </body>
                </html>
                """
                return resp
            elif "/pricing" in norm:
                resp.headers = {"Content-Type": "text/html"}
                resp.text = """
                <html>
                <head><title>Pricing</title></head>
                <body>
                    <form action="/subscribe" method="post">
                        <input name="tier" value="pro">
                        <input name="billing" value="annual">
                    </form>
                </body>
                </html>
                """
                return resp
            elif "/contact" in norm:
                resp.headers = {"Content-Type": "text/html"}
                resp.text = """
                <html>
                <head><title>Contact Us</title></head>
                <body>
                    <form action="/send-message" method="post">
                        <input name="email" value="">
                        <textarea name="message"></textarea>
                    </form>
                </body>
                </html>
                """
                return resp
            elif "/subscribe" in norm or "/send-message" in norm or "category=ai" in norm:
                resp.headers = {"Content-Type": "text/html"}
                resp.text = "<html><head><title>Success</title></head><body>OK</body></html>"
                return resp
            else:
                # 404 for robots.txt or sitemap.xml
                resp.status_code = 404
                resp.text = "Not Found"
                return resp

        mock_send_get.side_effect = side_effect

        results = crawl("https://startup.io")

        self.assertFalse(results["is_juice_shop"])
        self.assertGreaterEqual(len(results["pages"]), 4)
        
        # Verify page titles are recorded
        titles = [p.get("title") for p in results["pages"]]
        self.assertIn("Startup Home", titles)
        self.assertIn("Features", titles)
        self.assertIn("Pricing", titles)
        self.assertIn("Contact Us", titles)

        # Verify forms are discovered
        form_actions = [f["action"] for f in results["forms"]]
        self.assertTrue(any("/subscribe" in act for act in form_actions))
        self.assertTrue(any("/send-message" in act for act in form_actions))

        # Verify query parameters are discovered
        param_names = [p["name"] for p in results["params"]]
        self.assertIn("category", param_names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
