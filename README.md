# WebProbe v1.0 — Automated Web Security Assessment & Reporting Framework

WebProbe is an automated web penetration testing and vulnerability auditing framework designed to detect high-impact web vulnerabilities, evaluate exploitability, perform risk analysis, and generate executive-grade PDF security assessment dossiers.

---

## Key Features

- **Multi-Vector Crawling**:
  - HTML DOM & form extraction with input typing.
  - Parameter mining across query strings and body fields.
  - Single-Page Application (SPA) script route extraction (`/api/`, `/rest/`, `/v1/`, etc.).
  - Dedicated heuristics for lab environments (e.g. OWASP Juice Shop).

- **High-Fidelity Vulnerability Detection**:
  - **SQL Injection (SQLi)**: Union-based, Error-based, Boolean blind, Time-based blind, and Authentication bypass.
  - **Cross-Site Scripting (XSS)**: Reflected XSS, Filter bypass vectors, Header injections (`User-Agent`, `Referer`), DOM dangerous sink detection, and Stored XSS with automated math CAPTCHA resolution.
  - **Insecure Direct Object Reference (IDOR)**: Path-based ID manipulation, API tampering, sensitive data leak confirmation, and privilege boundary verification.

- **Hybrid LLM + Deterministic Engine**:
  - Contextual payload generation using DeepSeek AI (`deepseek-chat`).
  - Graceful, automatic offline fallback to curated local payload dictionaries (`payloads/sqli.txt`, `payloads/xss.txt`, `payloads/idor.txt`).

- **Risk Engine & Threat Prioritization**:
  - Maps vulnerabilities to **CWE** and **OWASP Top 10 (2021)** categories.
  - CVSS v3.1 base scoring with business impact categorization.
  - Overall application risk rating based on findings distribution.

- **Executive PDF Reporting**:
  - Strict pagination layout with **zero empty gaps or orphan rows**.
  - Dynamic Table of Contents with calculated page numbering and dot leaders.
  - 2-page detailed technical dossiers per vulnerability (Proof-of-Concept, dynamic step-by-step reproduction, data flow analysis, technical impact, vulnerable vs. remediated code, and references).
  - Cross-finding attack chain scenarios and prioritized remediation roadmaps.

---

## Architecture Overview

```
webprobe/
├── config.py                 # Central configurations, timeouts, and thresholds
├── main.py                   # Main CLI entry point with interactive scan selector
├── crawler/
│   ├── crawler.py            # Primary BFS crawler orchestrator
│   ├── endpoint_finder.py    # Route & script link regex miner
│   ├── form_parser.py        # HTML form & input extraction
│   └── param_extractor.py    # Query parameter extractor
├── scanner/
│   ├── sqli.py               # SQL Injection scanner
│   ├── xss.py                # XSS scanner (Reflected, Stored, DOM, Header)
│   └── idor.py               # IDOR scanner
├── llm/
│   ├── llm_engine.py         # DeepSeek API client & fallback logic
│   └── prompt_builder.py     # Prompt engineering for payload generation
├── risk/
│   └── risk_engine.py        # CVSS scoring, risk ratings & matrix builder
├── report/
│   └── pdf_generator.py      # Publication-grade PDF assessment generator
├── utils/
│   ├── helpers.py            # Formatting, timestamps, and banner utilities
│   ├── http_engine.py        # HTTP request wrapper with rate limiting
│   └── network.py            # Host resolution & connectivity checks
├── payloads/                 # Offline fallback payload databases
│   ├── sqli.txt
│   ├── xss.txt
│   └── idor.txt
└── tests/
    └── test_smoke.py         # Automated smoke and integration test suite
```

---

## Installation

### Prerequisites
- Python 3.10+
- Linux / macOS / Windows

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SanthoshNagularapu/WebProbe.git
   cd WebProbe
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: On Debian/Ubuntu/Kali systems, if PEP 668 is active, use a virtual environment or `pip install --break-system-packages -r requirements.txt`)*

3. **Configure Environment (Optional)**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Provide your `LLM_API_KEY` if you wish to enable DeepSeek AI payload expansion. If left blank, WebProbe operates entirely offline with curated local payloads.

---

## Running Scans

### Quick Start (Interactive)
```bash
python3 main.py
```
Enter your target URL (e.g., `http://localhost:3000`) and choose your scan type from the interactive menu:
1. SQL Injection only
2. XSS only
3. IDOR only
4. SQLi + XSS
5. SQLi + IDOR
6. XSS + IDOR
7. ALL (SQLi + XSS + IDOR)

### Non-Interactive CLI
```bash
# lab setuped
python3 main.py http://localhost:3000

# Random website
python3 main.py http://example.com
```

### Running Tests
Execute the automated smoke tests to verify all scanner, risk, crawler, and config components:
```bash
# Fully non-interactive — no prompts at all
python3 main.py http://localhost:3000 --scan all

# Specific scan type without menu
python3 main.py http://example.com --scan sqli+xss

# Force offline/manual payloads only (skip LLM)
python3 main.py http://localhost:3000 --scan all --no-llm

# Custom output directory for report
python3 main.py http://example.com --scan all --output /tmp/my_reports

# Show help
python3 main.py --help

# Show version
python3 main.py --version

# Run only one test file
python3 -m unittest tests.test_sqli

# Run tests with verbose output
python3 -m unittest discover tests -v
```

---

## Generated Reports

Generated PDF reports are saved to:
```
outputs/reports/webprobe_report_YYYYMMDD_HHMMSS.pdf
```
Each report includes:
1. Cover Page & Document Control
2. Dynamic Table of Contents
3. Executive Summary & Overall Risk Rating
4. Target Architecture & Scope Information
5. Vulnerabilities Breakdown Table
6. 2-Page Technical Dossiers per Finding
7. Cross-Finding Attack Chain Scenarios
8. Prioritized Remediation Roadmap & Conclusion

---

## Legal & Ethical Disclaimer

WebProbe is designed and intended strictly for educational purposes, security research, and authorized penetration testing on systems where prior written consent has been granted. Running vulnerability scans against targets without authorization is illegal. The author assumes no liability for unauthorized usage.

## License

MIT. See [LICENSE](LICENSE).
