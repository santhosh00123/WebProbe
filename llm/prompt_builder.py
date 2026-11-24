# llm/prompt_builder.py
# Advanced prompt building for each vulnerability type
# Imported by llm_engine.py

def build_sqli_prompt(url, param, technology="", attempt=1):
    return (
        f"SQL injection payloads for {url} param {param}. "
        f"Attempt {attempt}. Technology: {technology or 'unknown'}. "
        f"Return JSON array of 25 payloads covering error-based, "
        f"boolean-blind, time-based, UNION, login bypass, WAF bypass."
    )

def build_xss_prompt(url, param, context="html_body", attempt=1):
    return (
        f"XSS payloads for {url} param {param} in {context} context. "
        f"Attempt {attempt}. Return JSON array of 25 payloads covering "
        f"reflected, stored, DOM, filter bypass, event handlers."
    )

def build_idor_prompt(url, param, param_type="numeric", attempt=1):
    return (
        f"IDOR test values for {url} param {param} type {param_type}. "
        f"Attempt {attempt}. Return JSON array of 20 values."
    )
