import os
import re
import json
import socket
import time
import requests
import urllib3
from rich.console import Console

urllib3.disable_warnings()
console = Console()

def _get_env():
    from dotenv import load_dotenv
    load_dotenv()
    return {
        "groq": os.getenv("GROQ_API_KEY", ""),
        "deepseek": os.getenv("DEEPSEEK_API_KEY", ""),
    }

def is_internet_available():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def _is_valid_key(key):
    return bool(
        key and
        len(key) > 15 and
        key not in ["", "your_groq_key_here", "your_deepseek_key_here", "your_key_here"]
    )

def has_api_key():
    keys = _get_env()
    return _is_valid_key(keys["groq"]) or _is_valid_key(keys["deepseek"])

def get_active_provider():
    keys = _get_env()
    if _is_valid_key(keys["groq"]):
        return "groq"
    if _is_valid_key(keys["deepseek"]):
        return "deepseek"
    return None

def call_groq(prompt, max_tokens=1500):
    keys = _get_env()
    api_key = keys["groq"]
    if not _is_valid_key(api_key):
        return None
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        }
        payload = {
            "model": "qwen/qwen3.8-27b",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a world-class offensive security researcher "
                        "with 15 years of experience in penetration testing and bug bounty. "
                        "Generate highly targeted advanced security testing payloads. "
                        "CRITICAL RULE: Return ONLY a valid JSON array of strings. "
                        "No markdown, no explanation, no code blocks. "
                        "Start with [ and end with ]."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.8,
            "top_p": 0.95,
        }
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30,
            verify=False,
        )
        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        elif response.status_code == 429:
            console.print("[yellow]    [!] Groq rate limited — waiting 5s[/yellow]")
            time.sleep(10)
            return None
        else:
            console.print("[yellow]    [!] Groq error: " + str(response.status_code) + "[/yellow]")
            return None
    except requests.exceptions.Timeout:
        console.print("[yellow]    [!] Groq timeout[/yellow]")
        return None
    except Exception as e:
        console.print("[yellow]    [!] Groq exception: " + str(e)[:80] + "[/yellow]")
        return None

def call_deepseek(prompt, max_tokens=1500):
    keys = _get_env()
    api_key = keys["deepseek"]
    if not _is_valid_key(api_key):
        return None
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        }
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert offensive security researcher. "
                        "Generate advanced security testing payloads. "
                        "Return ONLY a JSON array of strings. No explanation."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.7,
        }
        response = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30,
            verify=False,
        )
        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        else:
            console.print("[yellow]    [!] DeepSeek error: " + str(response.status_code) + "[/yellow]")
            return None
    except Exception as e:
        console.print("[yellow]    [!] DeepSeek exception: " + str(e)[:80] + "[/yellow]")
        return None

def call_llm(prompt, max_tokens=1500):
    provider = get_active_provider()
    if provider == "groq":
        result = call_groq(prompt, max_tokens)
        if result:
            return result, "groq"
        result = call_deepseek(prompt, max_tokens)
        if result:
            return result, "deepseek"
        return None, None
    elif provider == "deepseek":
        result = call_deepseek(prompt, max_tokens)
        if result:
            return result, "deepseek"
        return None, None
    return None, None

def parse_llm_response(response_text):
    if not response_text:
        return []
    text = re.sub(r'```json\s*', '', response_text)
    text = re.sub(r'```\s*', '', text)
    text = text.strip()
    try:
        payloads = json.loads(text)
        if isinstance(payloads, list):
            return [str(p) for p in payloads if p and str(p).strip()]
    except Exception:
        pass
    try:
        match = re.search(r'\[[\s\S]*?\]', text)
        if match:
            payloads = json.loads(match.group(0))
            if isinstance(payloads, list):
                return [str(p) for p in payloads if p and str(p).strip()]
    except Exception:
        pass
    try:
        quoted = re.findall(r'"([^"]+)"', text)
        if len(quoted) >= 3:
            return quoted[:30]
    except Exception:
        pass
    lines = []
    for line in text.split("\n"):
        line = line.strip().strip('"').strip("'").strip(",").strip("-").strip()
        if len(line) > 2 and not line.startswith("{") and not line.startswith("["):
            lines.append(line)
    return lines[:25]

def validate_payloads(payloads, vuln_type):
    if not payloads:
        return False, "Empty list", 0
    if len(payloads) < 5:
        return False, "Only " + str(len(payloads)) + " payloads — need at least 5", 0
    score = 0
    total = len(payloads)
    if vuln_type == "sqli":
        sqli_patterns = [
            "'", '"', "--", "#", "/*",
            "or", "and", "union", "select",
            "sleep", "waitfor", "benchmark",
            "information_schema", "char(", "concat(",
        ]
        matching = sum(
            1 for p in payloads
            if any(pat in p.lower() for pat in sqli_patterns)
        )
        score = (matching / total) * 100
        if score < 50:
            return False, "Only " + str(int(score)) + "% SQLi patterns", score
    elif vuln_type == "xss":
        xss_patterns = [
            "<", ">", "script", "alert", "onerror",
            "onload", "javascript", "img", "svg",
            "iframe", "onfocus", "onclick", "prompt",
            "confirm", "eval", "document",
        ]
        matching = sum(
            1 for p in payloads
            if any(pat in p.lower() for pat in xss_patterns)
        )
        score = (matching / total) * 100
        if score < 50:
            return False, "Only " + str(int(score)) + "% XSS patterns", score
    elif vuln_type == "idor":
        score = 80
        if len(payloads) < 10:
            return False, "Too few IDOR values", 50
    return True, "Quality score: " + str(int(score)) + "%", score

def build_sqli_prompt(url, param, context="", failed=None, attempt=1):
    failed_str = ""
    if failed and len(failed) > 0:
        failed_str = "REJECTED payloads (do NOT repeat): " + json.dumps(failed[:8]) + "\n"
    advanced_note = ""
    if attempt == 2:
        advanced_note = "Focus on WAF bypass, encoding, obfuscation techniques.\n"
    elif attempt == 3:
        advanced_note = "Use advanced time-based with heavy obfuscation and stacked queries.\n"
    return (
        "You are an expert SQL injection pentester doing authorized testing.\n"
        "Target URL: " + url + "\n"
        "Vulnerable Parameter: " + param + "\n"
        "Context: " + (context or "web application") + "\n"
        "Attempt: " + str(attempt) + " of 3\n"
        + failed_str + advanced_note +
        "Generate exactly 35 advanced SQL injection payloads covering:\n"
        "1. Error-based (MySQL, PostgreSQL, SQLite, MSSQL, Oracle)\n"
        "2. Boolean-based blind (true/false condition differences)\n"
        "3. Time-based blind (SLEEP, WAITFOR DELAY, pg_sleep)\n"
        "4. UNION-based (1 to 8 column variants)\n"
        "5. Login and authentication bypass (' OR 1=1--, admin'--)\n"
        "6. WAF bypass (comment obfuscation, URL encoding, case variation)\n"
        "7. Stacked queries (semicolon separated)\n"
        "8. JSON body and REST endpoint injection\n"
        "Return ONLY a valid JSON array of 35 strings.\n"
        "NO explanation. NO markdown. JUST the JSON array."
    )

def build_xss_prompt(url, param, context="html_body", failed=None, attempt=1):
    failed_str = ""
    if failed and len(failed) > 0:
        failed_str = "REJECTED payloads (do NOT repeat): " + json.dumps(failed[:8]) + "\n"
    advanced_note = ""
    if attempt == 2:
        advanced_note = "Focus on CSP bypass, filter evasion, encoding tricks.\n"
    elif attempt == 3:
        advanced_note = "Use polyglot XSS, mutation patterns, framework-specific payloads.\n"
    return (
        "You are an expert XSS pentester doing authorized testing.\n"
        "Target URL: " + url + "\n"
        "Vulnerable Parameter: " + param + "\n"
        "Injection Context: " + context + "\n"
        "Attempt: " + str(attempt) + " of 1\n"
        + failed_str + advanced_note +
        "Generate exactly 35 advanced XSS payloads covering:\n"
        "1. Reflected XSS script tags and image error vectors\n"
        "2. Event handler XSS (onerror, onload, onfocus, onclick, onmouseover)\n"
        "3. Stored XSS payloads (HTML forms, comments, messages)\n"
        "4. Filter bypass (HTML entity, URL encoding, case variation, null byte)\n"
        "5. Tag attribute injection breakouts (quote escapes, autofocus)\n"
        "6. JavaScript protocol handlers (javascript:alert(1))\n"
        "7. SVG, iframe, math, object, embed based XSS\n"
        "8. Client-side template injection (Angular, Vue, React)\n"
        "9. Cookie extraction vectors\n"
        "Return ONLY a valid JSON array of 35 strings.\n"
        "NO explanation. NO markdown. JUST the JSON array."
    )

def build_idor_prompt(url, param, param_type="numeric", failed=None, attempt=1):
    failed_str = ""
    if failed and len(failed) > 0:
        failed_str = "Already tested (avoid): " + json.dumps(failed[:8]) + "\n"
    return (
        "You are an expert IDOR pentester doing authorized testing.\n"
        "Target URL: " + url + "\n"
        "Parameter: " + param + "\n"
        "Parameter Type: " + param_type + "\n"
        "Attempt: " + str(attempt) + " of 1\n"
        + failed_str +
        "Generate 30 IDOR test values covering:\n"
        "1. Sequential integers (0,1,2,3,4,5,10,100,1000)\n"
        "2. Boundary values (-1, 0, 999999)\n"
        "3. Privileged string IDs (admin, root, test, guest, system, administrator, manager, superuser)\n"
        "4. Type confusion (1.0, 01, 001)\n"
        "5. Encoded values (%31, %32)\n"
        "6. Negative and special boundary values\n"
        "Return ONLY a valid JSON array of 30 strings.\n"
        "NO explanation. NO markdown. JUST the JSON array."
    )

def generate_payloads(vuln_type, target_url, param_name, context="", local_payloads=None):
    local = local_payloads or []
    if not is_internet_available():
        console.print("[yellow]    [!] Offline — using local payloads (" + str(len(local)) + ")[/yellow]")
        return local
    provider = get_active_provider()
    if not provider:
        console.print("[yellow]    [!] No API key — using local payloads (" + str(len(local)) + ")[/yellow]")
        return local
    console.print("[bold cyan]    [*] LLM Engine: " + provider.upper() + " | Type: " + vuln_type.upper() + " | Param: " + param_name + "[/bold cyan]")
    failed_payloads = []
    best_payloads = []
    best_score = 0
    MAX_ATTEMPTS = 1
    for attempt in range(1, MAX_ATTEMPTS + 1):
        console.print("[cyan]    [*] Generating AI payloads via " + provider.upper() + "...[/cyan]")
        if vuln_type == "sqli":
            prompt = build_sqli_prompt(target_url, param_name, context, None, attempt)
        elif vuln_type == "xss":
            prompt = build_xss_prompt(target_url, param_name, context, None, attempt)
        elif vuln_type == "idor":
            prompt = build_idor_prompt(target_url, param_name, "numeric", None, attempt)
        else:
            prompt = "Generate 30 security test payloads for " + vuln_type + " on " + target_url + " param " + param_name + ". Return ONLY JSON array."
        response_text, used_provider = call_llm(prompt)
        if response_text is None:
            console.print("[yellow]    [!] LLM returned no response — using local fallback (" + str(len(local)) + ")[/yellow]")
            break
        payloads = parse_llm_response(response_text)
        if not payloads:
            console.print("[yellow]    [!] Could not parse LLM response — using local fallback (" + str(len(local)) + ")[/yellow]")
            break
        valid, reason, score = validate_payloads(payloads, vuln_type)
        status_icon = "+" if valid else "!"
        status_color = "green" if valid else "yellow"
        console.print("[" + status_color + "]    [" + status_icon + "] " + str(len(payloads)) + " payloads | " + reason + " | Provider: " + str(used_provider) + "[/" + status_color + "]")
        if valid:
            best_payloads = payloads
            console.print("[green]    [+] Quality payloads accepted (" + str(len(payloads)) + " payloads)[/green]")
            break
        else:
            console.print("[yellow]    [!] Low quality (" + reason + ") — falling back to local payloads (" + str(len(local)) + ")[/yellow]")
            break
    if best_payloads:
        local_unique = [p for p in local if p not in best_payloads]
        combined = best_payloads + local_unique
        console.print("[bold green]    [+] Generated: " + str(len(best_payloads)) + " AI + " + str(len(local_unique)) + " unique local = " + str(len(combined)) + " total test vectors[/bold green]")
        return combined
    console.print("[cyan]    [*] Active local payloads: " + str(len(local)) + "[/cyan]")
    return local

def test_connection():
    console.print("\n[bold cyan][*] Testing LLM Engine...[/bold cyan]")
    internet = is_internet_available()
    provider = get_active_provider()
    console.print("  Internet : " + ("OK" if internet else "NO"))
    console.print("  Provider : " + (provider.upper() if provider else "None"))
    console.print("  API Key  : " + ("Found" if has_api_key() else "Missing"))
    if not internet:
        console.print("[red][-] No internet — LLM unavailable[/red]")
        return False
    if not provider:
        console.print("[red][-] No API key — LLM unavailable[/red]")
        return False
    test_prompt = 'Return exactly this JSON array: ["test_sqli_1", "test_xss_2", "test_idor_3"]'
    response, used = call_llm(test_prompt, max_tokens=100)
    if response:
        payloads = parse_llm_response(response)
        console.print("[bold green][+] LLM Engine WORKING! Provider: " + str(used).upper() + "[/bold green]")
        console.print("[green]    Parsed: " + str(payloads[:3]) + "[/green]")
        return True
    else:
        console.print("[red][-] LLM Engine FAILED — will use local payloads[/red]")
        return False


# Rate limit helper
def wait_for_rate_limit():
    import time
    time.sleep(8)
