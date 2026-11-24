#!/usr/bin/env python3
"""
Integration test running a real local HTTP server to verify end-to-end
real-time crawling over localhost sockets.
"""

import unittest
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crawler.crawler import crawl


class DummyWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logs during test

    def do_GET(self):
        path = self.path
        if path in ["/", "/index.html"]:
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>Acme Corp Home</title></head>
            <body>
                <h1>Welcome to Acme</h1>
                <a href="/catalog">View Catalog</a>
                <a href="/contact.html">Contact Us</a>
                <a href="/login">User Login</a>
                <a href="/static/logo.png">Logo</a>
                <a href="https://external-domain.com">External</a>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif "/catalog" in path and "item=" not in path:
            html = """
            <html>
            <head><title>Product Catalog</title></head>
            <body>
                <a href="/catalog?item=laptop&sort=desc">Laptop</a>
                <a href="/catalog?item=keyboard">Keyboard</a>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif "item=" in path:
            html = "<html><head><title>Item Detail</title></head><body>Details</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif path == "/contact.html":
            html = """
            <html>
            <head><title>Contact Form</title></head>
            <body>
                <form action="/submit-feedback" method="POST">
                    <input type="text" name="user_email" placeholder="Your Email">
                    <textarea name="user_feedback"></textarea>
                    <button type="submit" name="send_btn">Send</button>
                </form>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif path == "/login":
            html = """
            <html>
            <head><title>Sign In</title></head>
            <body>
                <form action="/login" method="POST">
                    <input type="text" id="login_user">
                    <input type="password" id="login_pass">
                </form>
            </body>
            </html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class TestLocalLiveCrawl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Bind to ephemeral port
        cls.server = HTTPServer(("127.0.0.1", 0), DummyWebHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_live_localhost_crawl(self):
        target_url = f"http://127.0.0.1:{self.port}"
        results = crawl(target_url)

        self.assertFalse(results["is_juice_shop"])
        crawled_urls = [p["url"] for p in results["pages"]]
        
        # Verify discovered pages
        self.assertTrue(any(f":{self.port}/catalog" in u for u in crawled_urls))
        self.assertTrue(any(f":{self.port}/contact.html" in u for u in crawled_urls))
        self.assertTrue(any(f":{self.port}/login" in u for u in crawled_urls))

        # Verify logo.png was NOT crawled as a page
        self.assertFalse(any("logo.png" in u for u in crawled_urls))

        # Verify forms extracted
        self.assertGreaterEqual(len(results["forms"]), 2)
        form_inputs = []
        for f in results["forms"]:
            for inp in f["inputs"]:
                form_inputs.append(inp["name"])
        self.assertIn("user_email", form_inputs)
        self.assertIn("login_user", form_inputs)

        # Verify URL query parameters extracted
        param_names = [p["name"] for p in results["params"]]
        self.assertIn("item", param_names)


if __name__ == "__main__":
    unittest.main()
