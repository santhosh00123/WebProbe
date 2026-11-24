# risk/risk_engine.py
# Risk Engine — enriches findings with why, impact, remediation
# Cleans all unicode characters from finding data

REMEDIATION = {
    "sqli": {
        "title": "SQL Injection Remediation",
        "steps": [
            "Use parameterized queries and prepared statements exclusively",
            "Implement input validation and whitelist allowed characters",
            "Apply principle of least privilege to database accounts",
            "Use ORM frameworks (SQLAlchemy, Hibernate, Sequelize)",
            "Deploy Web Application Firewall (WAF) as defense in depth",
            "Enable database query logging and anomaly detection",
            "Regularly audit and test all database-connected inputs",
        ],
        "code_fix": (
            "VULNERABLE:\n"
            "  query = 'SELECT * FROM users WHERE email=' + user_input\n\n"
            "FIXED:\n"
            "  cursor.execute('SELECT * FROM users WHERE email = %s', (user_input,))"
        ),
        "references": [
            "OWASP Top 10: A03:2021 - Injection",
            "CWE-89: Improper Neutralization of SQL Commands",
            "NIST SP 800-53: SI-10 Information Input Validation",
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting Remediation",
        "steps": [
            "Implement output encoding for all user-controlled data",
            "Apply Content Security Policy (CSP) headers",
            "Use HTTPOnly and Secure flags on session cookies",
            "Validate and sanitize all inputs server-side",
            "Use DOMPurify library for client-side sanitization",
            "Add X-XSS-Protection and X-Content-Type-Options headers",
            "Avoid using innerHTML and document.write with user data",
        ],
        "code_fix": (
            "VULNERABLE:\n"
            "  element.innerHTML = userInput\n\n"
            "FIXED:\n"
            "  element.textContent = userInput\n"
            "  // OR: element.innerHTML = DOMPurify.sanitize(userInput)"
        ),
        "references": [
            "OWASP Top 10: A03:2021 - Injection",
            "CWE-79: Cross-site Scripting",
            "OWASP XSS Prevention Cheat Sheet",
        ],
    },
    "idor": {
        "title": "IDOR and Broken Access Control Remediation",
        "steps": [
            "Implement server-side authorization checks on every request",
            "Use indirect object references (random tokens instead of IDs)",
            "Validate that authenticated user owns the requested resource",
            "Implement Role-Based Access Control (RBAC)",
            "Log all access control failures and alert on anomalies",
            "Use UUIDs instead of sequential integer IDs",
            "Apply principle of least privilege throughout application",
        ],
        "code_fix": (
            "VULNERABLE:\n"
            "  GET /api/users/1234  (any user can access any ID)\n\n"
            "FIXED:\n"
            "  if resource.owner_id != current_user.id:\n"
            "      return 403 Forbidden"
        ),
        "references": [
            "OWASP Top 10: A01:2021 - Broken Access Control",
            "CWE-639: Authorization Bypass Through User-Controlled Key",
            "OWASP Access Control Cheat Sheet",
        ],
    },
}

WHY_VULNERABLE = {
    "sqli": (
        "The application directly concatenates user-supplied input into "
        "SQL queries without sanitization or parameterization. This allows "
        "an attacker to manipulate query logic, bypass authentication, "
        "extract sensitive data, or execute operating system commands."
    ),
    "xss": (
        "The application reflects or stores user-supplied input in HTML "
        "responses without proper output encoding. This allows attackers "
        "to inject malicious JavaScript that executes in victims browsers, "
        "enabling session hijacking, credential theft, and malicious redirects."
    ),
    "idor": (
        "The application exposes direct references to internal objects "
        "without verifying the authenticated user has permission to access "
        "the requested resource. Attackers can enumerate and access data "
        "belonging to other users by manipulating these references."
    ),
}

IMPACT = {
    "sqli": [
        "Complete authentication bypass without valid credentials",
        "Full database read access including all user data",
        "Ability to modify or delete database records",
        "Potential for Remote Code Execution via database features",
        "Exposure of sensitive PII, passwords, and business data",
    ],
    "xss": [
        "Session cookie theft leading to account takeover",
        "Credential harvesting via fake login forms",
        "Malicious redirection to phishing sites",
        "Keylogging and capture of sensitive user input",
        "Web page defacement affecting all users",
    ],
    "idor": [
        "Unauthorized access to other users private data",
        "Horizontal privilege escalation between accounts",
        "Exposure of sensitive personal and financial records",
        "Ability to modify or delete other users data",
        "Potential for full account takeover",
    ],
}


# CVSS v3.1 Scoring & Real-World Effect Definitions
CVSS_DATA = {
    "sqli": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "cwe_title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp": "A03:2021 — Injection",
        "metrics": [
            ("Attack Vector (AV)", "Network (N)", "Remotely accessible via public HTTP/S endpoints without network isolation.", "Any remote attacker can reach and exploit the injection sink over the internet."),
            ("Attack Complexity (AC)", "Low (L)", "No specialized conditions or race conditions needed; deterministic syntax execution.", "Exploitation is 100% repeatable with standard automated injection tools."),
            ("Privileges Required (PR)", "None (N)", "Unauthenticated attacker can target the endpoint without valid credentials.", "Zero barrier to entry; anonymous actors can compromise backend resources."),
            ("User Interaction (UI)", "None (N)", "0-click vulnerability requiring no victim involvement or interaction.", "Direct attacker-to-server interaction enables automated mass exploitation."),
            ("Scope (S)", "Unchanged (U)", "Impact is contained within the application database and host storage environment.", "Direct compromise of the backend database engine and stored data stores."),
            ("Confidentiality (C)", "High (H)", "Complete disclosure of database contents, tables, records, and credentials.", "Total exfiltration of user passwords, PII, payment info, and proprietary assets."),
            ("Integrity (I)", "High (H)", "Complete unauthorized ability to modify, insert, or delete database tables and records.", "Attacker can forge admin accounts, alter transactions, or corrupt records."),
            ("Availability (A)", "High (H)", "Potential database service degradation, resource exhaustion, or storage corruption.", "Malicious queries can lock SQLite/Postgres tables or crash query processes.")
        ],
        "effects": {
            "technical": "Unsanitized user input alters the SQL query logic executed by the database engine. Attackers can bypass authentication, execute arbitrary database functions, extract all stored tables, and tamper with application data.",
            "business": "Catastrophic data breach of sensitive customer data and credentials, leading to reputational damage, mandatory regulatory breach notifications under GDPR/PCI-DSS, legal liabilities, and regulatory penalties.",
            "compliance": "Violates GDPR Article 32 (Security of Processing), PCI-DSS Requirement 6.5.1 (Injection flaws), and ISO/IEC 27001 Control A.14.2.5.",
            "sla": "Immediate Mitigation Required: Within 24 Hours."
        }
    },
    "xss_stored": {
        "score": 8.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "cwe_title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp": "A03:2021 — Injection",
        "metrics": [
            ("Attack Vector (AV)", "Network (N)", "Exploitable over HTTP/S via persistent data storage sinks.", "Remote injection into shared application records viewable by other users."),
            ("Attack Complexity (AC)", "Low (L)", "Payload persists in storage and executes reliably on target render.", "Deterministic payload execution across every user visiting the affected page."),
            ("Privileges Required (PR)", "None (N)", "Public submission sinks allow injection without authentication.", "Zero authentication needed to store malicious vectors in shared resources."),
            ("User Interaction (UI)", "Required (R)", "Victim user must navigate to the compromised page containing stored payload.", "Execution occurs seamlessly when legitimate users browse the application."),
            ("Scope (S)", "Changed (C)", "Exploits victim browser execution context beyond backend server boundary.", "Attack escapes server sandbox into the trusted client browser environment."),
            ("Confidentiality (C)", "High (H)", "Steals session cookies, JWT authentication tokens, and sensitive DOM data.", "Enables persistent account takeover of visiting users and administrators."),
            ("Integrity (I)", "High (H)", "Enables arbitrary DOM modification, form action rewriting, and client-side actions.", "Attacker can deface the application, rewrite links, or inject fake login modals."),
            ("Availability (A)", "None (N)", "Does not directly terminate server application availability.", "Backend application remains operational while client sessions are compromised.")
        ],
        "effects": {
            "technical": "Malicious JavaScript is persistently stored in application state and executed automatically in the browser context of every user viewing the affected resource. Enables persistent session hijacking and malicious actions on behalf of victims.",
            "business": "Account takeover of authenticated users and administrators, loss of client trust, compromised customer sessions, and compliance violations.",
            "compliance": "Violates GDPR Article 32, PCI-DSS Requirement 6.5.7 (Cross-Site Scripting), and OWASP ASVS V5.3.",
            "sla": "Urgent Mitigation Required: Within 7 Days."
        }
    },
    "xss": {
        "score": 7.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "cwe_title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp": "A03:2021 — Injection",
        "metrics": [
            ("Attack Vector (AV)", "Network (N)", "Remotely deliverable via crafted URL parameters or search queries.", "Can be distributed globally via phishing links or malicious web redirects."),
            ("Attack Complexity (AC)", "Low (L)", "Direct reflection of unencoded input into the DOM or response body.", "Reliable execution whenever victim follows the attacker-crafted link."),
            ("Privileges Required (PR)", "None (N)", "No authenticated session required to craft or deliver the malicious URL.", "Anyone can generate and send the exploit link to target victims."),
            ("User Interaction (UI)", "Required (R)", "Requires victim to click an attacker-supplied link or visit a malicious page.", "Relies on social engineering, email phishing, or link redirection to trigger."),
            ("Scope (S)", "Changed (C)", "Cross-site script execution breaches browser security domain.", "JavaScript runs in the context of the vulnerable web origin."),
            ("Confidentiality (C)", "Low (L)", "Enables theft of accessible cookies and page content visible to the script.", "Access to DOM data, form values, and non-HttpOnly session tokens."),
            ("Integrity (I)", "Low (L)", "Allows unauthorized modification of the currently rendered webpage DOM.", "Attacker can alter page layout, display deceptive text, or capture keystrokes."),
            ("Availability (A)", "None (N)", "Does not impact backend service availability.", "Application backend remains fully functional.")
        ],
        "effects": {
            "technical": "User input supplied via request parameters is reflected directly in the HTTP response without output encoding, executing script in the victim browser upon following a malicious link.",
            "business": "Phishing enablement, credential harvesting via spoofed login modals, unauthorized client-side API requests, and brand tarnishment.",
            "compliance": "Violates PCI-DSS Requirement 6.5.7 and OWASP ASVS V5.3.",
            "sla": "Urgent Mitigation Required: Within 7 Days."
        }
    },
    "idor": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "cwe": "CWE-639",
        "cwe_title": "Authorization Bypass Through User-Controlled Key",
        "owasp": "A01:2021 — Broken Access Control",
        "metrics": [
            ("Attack Vector (AV)", "Network (N)", "Accessible over network via direct REST API endpoint parameter manipulation.", "Exploitable by sending requests directly to publicly routable API routes."),
            ("Attack Complexity (AC)", "Low (L)", "Easily automated via simple sequential or enumerated object identifiers.", "Attacker can cycle through numeric IDs (1, 2, 3...) to dump all records."),
            ("Privileges Required (PR)", "None (N)", "Endpoints fail to verify requester identity or permit unauthenticated requests.", "No specialized role needed; anonymous or low-privileged users can exploit."),
            ("User Interaction (UI)", "None (N)", "Direct automated API enumeration without victim involvement.", "0-click vulnerability exploitable instantly via automated enumeration scripts."),
            ("Scope (S)", "Unchanged (U)", "Impact is centered on application data records.", "Breach of database objects managed by the affected application API."),
            ("Confidentiality (C)", "High (H)", "Enables horizontal and vertical extraction of other users confidential records.", "Complete leakage of customer profiles, orders, messages, or payment tokens."),
            ("Integrity (I)", "Low (L)", "Potential unauthorized modification or state tampering across user accounts.", "Attacker may be able to alter other users preferences, baskets, or records."),
            ("Availability (A)", "None (N)", "Does not directly terminate service availability.", "System services remain online while privacy guarantees are broken.")
        ],
        "effects": {
            "technical": "Missing server-side ownership authorization checks allow arbitrary object references (e.g. numeric IDs, UUIDs, or keys) to be manipulated, exposing records belonging to other tenants or users.",
            "business": "Mass personal data exposure (PII breach), severe GDPR/privacy regulation fines, competitive intelligence leaks, and unauthorized record tampering.",
            "compliance": "Violates GDPR Article 25 (Data Protection by Design), PCI-DSS Requirement 6.5.8 (Access control), and HIPAA Security Rule 45 CFR § 164.312(a)(1).",
            "sla": "Urgent Mitigation Required: Within 7 Days."
        }
    }
}


def _clean_str(text):
    """Remove all non-latin1 characters from string"""
    if not text:
        return ""
    replacements = {
        "\u2014": "-", "\u2013": "-", "\u2018": "'",
        "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2022": "*", "\u2026": "...", "\u2192": "->",
        "\u2713": "[OK]", "\u2717": "[X]", "\u00e9": "e",
    }
    for char, replacement in replacements.items():
        text = str(text).replace(char, replacement)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def get_vuln_key(finding):
    vuln_type = str(finding.get("vulnerability", "")).lower()
    finding_type = str(finding.get("type", "")).lower()
    if "sql" in vuln_type or "sql" in finding_type:
        return "sqli"
    elif "stored" in finding_type or "stored" in vuln_type:
        return "xss_stored"
    elif "xss" in vuln_type or "cross" in finding_type or "xss" in finding_type:
        return "xss"
    elif "idor" in vuln_type or "idor" in finding_type or "access" in finding_type:
        return "idor"
    return "sqli"


def enrich_finding(finding):
    key = get_vuln_key(finding)
    cvss_meta = CVSS_DATA.get(key, CVSS_DATA["sqli"])

    # Clean all string fields to remove unicode
    for field in ["type", "vulnerability", "url", "parameter",
                  "payload", "evidence", "method", "injection_point",
                  "sqli_type", "xss_type", "idor_type", "timestamp"]:
        if field in finding:
            finding[field] = _clean_str(str(finding[field]))

    finding["why_vulnerable"] = WHY_VULNERABLE.get(key if key != "xss_stored" else "xss", "")
    finding["impact_list"] = IMPACT.get(key if key != "xss_stored" else "xss", [])
    finding["remediation"] = REMEDIATION.get(key if key != "xss_stored" else "xss", {})

    finding["risk_level"] = finding.get("risk_level") or cvss_meta["severity"]
    finding["cvss_score"] = finding.get("cvss_score") or cvss_meta["score"]
    finding["cvss_vector"] = cvss_meta["vector"]
    finding["cvss_metrics"] = cvss_meta["metrics"]
    finding["cvss_effects"] = cvss_meta["effects"]
    finding["cwe"] = finding.get("cwe") or cvss_meta["cwe"]
    finding["cwe_title"] = cvss_meta["cwe_title"]
    finding["owasp"] = finding.get("owasp") or cvss_meta["owasp"]

    return finding


def enrich_all(findings):
    return [enrich_finding(f) for f in findings]


def get_overall_risk(findings):
    if any(f.get("risk_level") == "CRITICAL" for f in findings):
        return "CRITICAL"
    elif any(f.get("risk_level") == "HIGH" for f in findings):
        return "HIGH"
    elif any(f.get("risk_level") == "MEDIUM" for f in findings):
        return "MEDIUM"
    return "LOW"

