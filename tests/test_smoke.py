#!/usr/bin/env python3
"""
WebProbe Smoke & Diagnostic Test Suite
Tests all internal components without requiring external internet or target servers:
- Config & Environment
- Utility & Helper functions
- Crawler: Form parsing, Endpoint discovery, Parameter extraction
- Scanners: SQL error signatures, XSS context detection, IDOR sensitive patterns
- LLM Engine: JSON parser, Payload validator
- Risk Engine: Finding enrichment, Risk assessment
- Dependency & System Check: fpdf2, requests, rich, bs4
"""

import unittest
import sys
import os

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.helpers import clean_url, get_base_url, get_hostname, get_timestamp
from crawler.form_parser import parse_forms
from crawler.param_extractor import extract_url_params, extract_hidden_params, extract_api_params
from crawler.endpoint_finder import get_domain
from scanner.sqli import has_sql_error, load_payloads as load_sqli_payloads
from scanner.xss import detect_context, is_reflected_properly, load_payloads as load_xss_payloads, XSS_MARKER
from scanner.idor import has_sensitive_data, load_payloads as load_idor_payloads
from llm.llm_engine import parse_llm_response, validate_payloads
from risk.risk_engine import enrich_finding, get_overall_risk
import config


class TestWebProbeSmoke(unittest.TestCase):

    def test_01_config_and_constants(self):
        """Verify configuration constants are properly defined"""
        self.assertIn("1", config.SCAN_OPTIONS)
        self.assertIn("7", config.SCAN_OPTIONS)
        self.assertEqual(config.SCAN_OPTIONS["7"], ["sqli", "xss", "idor"])
        self.assertGreater(config.REQUEST_TIMEOUT, 0)
        self.assertIn("sqli", config.CVSS_SCORES)
        self.assertEqual(config.CVSS_SCORES["sqli"], 9.8)

    def test_02_url_helpers(self):
        """Verify URL normalization and parsing utilities"""
        self.assertEqual(clean_url("example.com"), "http://example.com")
        self.assertEqual(clean_url("https://example.com"), "https://example.com")
        self.assertEqual(get_base_url("http://example.com:3000/rest/users?id=1"), "http://example.com:3000")
        self.assertEqual(get_hostname("http://example.com:3000/test"), "example.com:3000")
        self.assertEqual(get_domain("http://target.local:8080/path"), "target.local:8080")
        self.assertTrue(len(get_timestamp()) > 10)

    def test_03_crawler_form_parser(self):
        """Verify HTML form parsing with inputs, textareas, and select elements"""
        sample_html = """
        <html>
            <body>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Username" value="">
                    <input type="password" name="password" placeholder="Password" value="">
                    <input type="submit" value="Submit">
                </form>
                <form action="/feedback" method="post">
                    <textarea name="comment"></textarea>
                    <select name="rating">
                        <option value="1">1</option>
                    </select>
                </form>
            </body>
        </html>
        """
        forms = parse_forms("http://test.local", sample_html)
        self.assertEqual(len(forms), 2)
        
        login_form = forms[0]
        self.assertEqual(login_form["action"], "http://test.local/login")
        self.assertEqual(login_form["method"], "post")
        input_names = [i["name"] for i in login_form["inputs"]]
        self.assertIn("username", input_names)
        self.assertIn("password", input_names)

        feedback_form = forms[1]
        fb_names = [i["name"] for i in feedback_form["inputs"]]
        self.assertIn("comment", fb_names)
        self.assertIn("rating", fb_names)

    def test_04_crawler_param_extractor(self):
        """Verify extraction of URL, hidden, and REST API path parameters"""
        # URL params
        url_params = extract_url_params("http://example.com/search?q=test&page=2")
        self.assertEqual(len(url_params), 2)
        names = {p["name"]: p["value"] for p in url_params}
        self.assertEqual(names.get("q"), "test")
        self.assertEqual(names.get("page"), "2")

        # Hidden inputs
        html = '<input type="hidden" name="csrf_token" value="abc123xyz">'
        hidden = extract_hidden_params(html, "http://example.com")
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0]["name"], "csrf_token")
        self.assertEqual(hidden[0]["value"], "abc123xyz")

        # API numeric path params
        api_params = extract_api_params("http://example.com/api/users/42/details")
        self.assertEqual(len(api_params), 1)
        self.assertEqual(api_params[0]["name"], "id")
        self.assertEqual(api_params[0]["value"], "42")

    def test_05_sqli_error_signatures_and_payloads(self):
        """Verify SQL error detection signatures and payload file integrity"""
        # Test error patterns
        has_err, err_msg = has_sql_error("Fatal error: You have an error in your SQL syntax near '' at line 1")
        self.assertTrue(has_err)
        self.assertIn("syntax", err_msg)

        has_sqlite_err, err_msg = has_sql_error("sqlite3.OperationalError: no such table")
        self.assertTrue(has_sqlite_err)

        has_no_err, _ = has_sql_error("Search results: 0 products found.")
        self.assertFalse(has_no_err)

        # Test payloads loading
        payloads = load_sqli_payloads()
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any("' OR '1'='1" in p for p in payloads))

    def test_06_xss_context_and_payloads(self):
        """Verify XSS context detection and marker checking"""
        # Context detection
        html_tag_ctx = f'<input value="{XSS_MARKER}">'
        self.assertIn(detect_context(html_tag_ctx), ["html_attr", "html_tag", "html_body"])

        script_ctx = f'<script>var search = "{XSS_MARKER}";</script>'
        self.assertEqual(detect_context(script_ctx), "script_var")

        # Reflection verification
        reflected, reflect_type = is_reflected_properly(
            f"<div>{XSS_MARKER}</div>",
            XSS_MARKER,
            "<div>baseline</div>"
        )
        self.assertTrue(reflected)
        self.assertEqual(reflect_type, "marker_confirmed")

        # Payloads loading
        payloads = load_xss_payloads()
        self.assertGreater(len(payloads), 0)

    def test_07_idor_sensitive_patterns_and_payloads(self):
        """Verify sensitive data regex patterns for IDOR detection"""
        # Positive detections
        has_data, match = has_sensitive_data('{"status": "ok", "email": "admin@target.local", "role": "admin"}')
        self.assertTrue(has_data)
        self.assertIn("email", match)

        has_card, match = has_sensitive_data('{"credit_card": "4111222233334444"}')
        self.assertTrue(has_card)

        # Negative detection (public non-sensitive content)
        has_none, _ = has_sensitive_data('{"product": "Apple Juice", "price": 2.99}')
        self.assertFalse(has_none)

        # Payload loading
        payloads = load_idor_payloads()
        self.assertGreater(len(payloads), 0)

    def test_08_llm_response_parsing_and_validation(self):
        """Verify LLM response parser (JSON array handling) and validation scoring"""
        # Pure JSON
        json_resp = '["\' OR 1=1--", "\' UNION SELECT 1--", "admin\'--", "1\' AND 1=1--", "1; SELECT pg_sleep(3)--"]'
        parsed = parse_llm_response(json_resp)
        self.assertEqual(len(parsed), 5)
        self.assertEqual(parsed[0], "' OR 1=1--")

        # Markdown wrapped JSON
        md_resp = "Here are the payloads:\n```json\n[\"<script>alert(1)</script>\", \"<img src=x onerror=alert(1)>\"]\n```"
        parsed_md = parse_llm_response(md_resp)
        self.assertEqual(len(parsed_md), 2)
        self.assertEqual(parsed_md[0], "<script>alert(1)</script>")

        # Validation score
        valid, msg, score = validate_payloads(parsed, "sqli")
        self.assertTrue(valid)
        self.assertGreaterEqual(score, 50)

    def test_09_risk_engine_enrichment(self):
        """Verify finding enrichment, CVSS defaults, and overall risk calculation"""
        finding = {
            "vulnerability": "SQL Injection",
            "type": "SQL Injection — Error Based",
            "url": "http://localhost:3000/rest/products/search?q=",
            "parameter": "q",
            "payload": "admin'--",
            "risk_level": "CRITICAL",
        }
        enriched = enrich_finding(finding)
        self.assertIn("why_vulnerable", enriched)
        self.assertIn("impact_list", enriched)
        self.assertIn("remediation", enriched)
        self.assertEqual(enriched["remediation"]["title"], "SQL Injection Remediation")

        # Overall risk calculation
        findings = [
            {"risk_level": "CRITICAL"},
            {"risk_level": "HIGH"},
        ]
        self.assertEqual(get_overall_risk(findings), "CRITICAL")

        low_findings = [{"risk_level": "LOW"}]
        self.assertEqual(get_overall_risk(low_findings), "LOW")

    def test_10_pdf_generator_dependency_check(self):
        """Check availability of fpdf2 required for PDF generation"""
        try:
            import fpdf
            fpdf_available = True
        except ImportError:
            fpdf_available = False

        if not fpdf_available:
            print("\n  [DIAGNOSTIC NOTE] 'fpdf2' is currently NOT installed in this environment.")
            print("  Run 'pip install fpdf2==2.7.6' to enable PDF reporting.")
        else:
            self.assertTrue(fpdf_available)


if __name__ == "__main__":
    unittest.main(verbosity=2)
