# main.py
# WebProbe v1.0 — Main Entry Point
# Connects all pieces together
# Shows scan menu, runs selected scans

import sys
import os
import re
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.helpers import print_banner, get_timestamp, clean_url
from utils.network import is_internet_available, is_target_reachable, resolve_ip, get_server_info, resolve_target_info
from crawler.crawler import crawl
from scanner.sqli import scan as sqli_scan
from scanner.xss import scan as xss_scan
from scanner.idor import scan as idor_scan
from llm.llm_engine import generate_payloads, test_connection, has_api_key
from config import SCAN_OPTIONS, TOOL_NAME, TOOL_VERSION

console = Console()

# ═══════════════════════════════════════════════════
# SHOW SCAN MENU
# Asks user which vulnerabilities to scan
# ═══════════════════════════════════════════════════
# ═══════════════════════════════════════════════════
# SHOW SCAN MENU
# Flexible input parser supporting single digits,
# comma/space separated numbers (1,2 / 1,3 / 2,3 / 1,2,3), and 'all'
# ═══════════════════════════════════════════════════
def show_scan_menu():
    console.print("\n[bold cyan]╔══════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║                  SELECT SCAN MODULES                 ║[/bold cyan]")
    console.print("[bold cyan]╠══════════════════════════════════════════════════════╣[/bold cyan]")
    console.print("[bold cyan]║  1 → SQL Injection (SQLi)                            ║[/bold cyan]")
    console.print("[bold cyan]║  2 → Cross-Site Scripting (XSS)                      ║[/bold cyan]")
    console.print("[bold cyan]║  3 → Broken Access Control (IDOR)                    ║[/bold cyan]")
    console.print("[bold cyan]║  4 → SQLi + XSS        (or enter: 1,2)               ║[/bold cyan]")
    console.print("[bold cyan]║  5 → SQLi + IDOR       (or enter: 1,3)               ║[/bold cyan]")
    console.print("[bold cyan]║  6 → XSS + IDOR        (or enter: 2,3)               ║[/bold cyan]")
    console.print("[bold cyan]║  7 → ALL VULNERABILITIES (or enter: 1,2,3 or 'all')  ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════════════════════╝[/bold cyan]")

    while True:
        raw_choice = console.input(
            "\n[bold yellow]Enter choice (e.g. 1, 2, 3, 1,2, 1,3, 2,3, or 1,2,3): [/bold yellow]"
        ).strip().lower()

        if raw_choice in SCAN_OPTIONS:
            selected = SCAN_OPTIONS[raw_choice]
            console.print(f"[bold green][+] Selected Modules: {', '.join(selected).upper()}[/bold green]")
            return selected

        if raw_choice in ["all", "a", "*"]:
            selected = ["sqli", "xss", "idor"]
            console.print(f"[bold green][+] Selected Modules: {', '.join(selected).upper()}[/bold green]")
            return selected

        tokens = [t.strip() for t in re.split(r'[,+\s]+', raw_choice) if t.strip()]
        selected = []
        for t in tokens:
            if t == "1" and "sqli" not in selected:
                selected.append("sqli")
            elif t == "2" and "xss" not in selected:
                selected.append("xss")
            elif t == "3" and "idor" not in selected:
                selected.append("idor")

        if selected:
            console.print(f"[bold green][+] Selected Modules: {', '.join(selected).upper()}[/bold green]")
            return selected

        console.print("[red][!] Invalid selection. Enter 1, 2, 3, combinations like 1,2 or 1,2,3, or 7.[/red]")

# ═══════════════════════════════════════════════════
# SHOW STATUS PANEL
# Shows target URL, hostname/DNS, IP, reachability,
# internet connection, and API key status
# ═══════════════════════════════════════════════════
def show_status(target_url):
    internet = is_internet_available()
    api_key = has_api_key()
    reachable, status_code = is_target_reachable(target_url)
    info = resolve_target_info(target_url)

    console.print("\n[bold cyan]═══ SCAN ENVIRONMENT & TARGET STATUS ═══[/bold cyan]")
    console.print(f"  Target URL    : [bold white]{info['url']}[/bold white]")
    console.print(f"  Target Host   : [bold cyan]{info['host']}[/bold cyan] (Port: {info['port']})")
    console.print(f"  Resolved IP   : [dim]{info['ip']}[/dim]")
    console.print(f"  Reachable     : {'[green]✅ Yes (HTTP ' + str(status_code) + ')[/green]' if reachable else '[red]❌ Unreachable[/red]'}")
    console.print(f"  Internet Conn : {'[green]✅ Active (Online)[/green]' if internet else '[yellow]⚠️ Offline[/yellow]'}")
    console.print(f"  API Key       : {'[green]✅ Detected[/green]' if api_key else '[yellow]⚠️ Not Set (Using curated local wordlists)[/yellow]'}")
    console.print(f"  Payload Mode  : {'[green]✅ Hybrid AI (1-shot) + Local Dictionaries[/green]' if (internet and api_key) else '[yellow]⚠️ Deterministic Local Payload Engine[/yellow]'}")
    console.print(f"  Start Time    : [dim]{get_timestamp()}[/dim]")

    return reachable

# ═══════════════════════════════════════════════════
# PRINT ALL FINDINGS SUMMARY & DETAILED RISK ANALYSIS
# ═══════════════════════════════════════════════════
def print_summary(all_findings):
    console.print(
        "\n[bold white]╔══════════════════════════════════════════════════════════════════╗[/bold white]"
    )
    console.print(
        "[bold white]║           WEBPROBE ENTERPRISE RISK & AUDIT BREAKDOWN             ║[/bold white]"
    )
    console.print(
        "[bold white]╚══════════════════════════════════════════════════════════════════╝[/bold white]"
    )

    from risk.risk_engine import get_overall_risk
    overall_risk = get_overall_risk(all_findings)
    risk_badge_color = {
        "CRITICAL": "bold red on black",
        "HIGH": "bold yellow on black",
        "MEDIUM": "bold blue on black"
    }.get(overall_risk, "bold green on black")

    total = len(all_findings)
    critical = sum(1 for f in all_findings if f.get("risk_level") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("risk_level") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("risk_level") == "MEDIUM")
    low = sum(1 for f in all_findings if f.get("risk_level") == "LOW")

    console.print(f"\n  Overall Application Risk : [{risk_badge_color}]  {overall_risk}  [/{risk_badge_color}]")
    console.print(f"  Total Verified Findings  : [bold]{total}[/bold]")
    console.print(f"  Critical (CVSS 9.0-10.0) : [red]{critical}[/red]")
    console.print(f"  High     (CVSS 7.0-8.9)  : [yellow]{high}[/yellow]")
    console.print(f"  Medium   (CVSS 4.0-6.9)  : [blue]{medium}[/blue]")
    console.print(f"  Low      (CVSS 1.0-3.9)  : [green]{low}[/green]")

    if all_findings:
        table = Table(
            title="\nVerified Vulnerabilities Breakdown",
            box=box.ROUNDED,
            show_lines=True,
            header_style="bold cyan",
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Severity", width=10, justify="center")
        table.add_column("CVSS", width=6, justify="center")
        table.add_column("Vulnerability Type", width=28)
        table.add_column("CWE", width=10, justify="center")
        table.add_column("Parameter", width=12)
        table.add_column("Target Endpoint", overflow="fold", min_width=38)

        for i, f in enumerate(all_findings, 1):
            risk = f.get("risk_level", "INFO")
            risk_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "green",
            }.get(risk, "white")

            url_clean = f.get("url", "")

            table.add_row(
                str(i),
                f"[{risk_color}]{risk}[/{risk_color}]",
                str(f.get("cvss_score", "N/A")),
                f.get("type", "Unknown"),
                f.get("cwe", "N/A"),
                f.get("parameter", "N/A"),
                url_clean,
            )
        console.print(table)

    return all_findings

# ═══════════════════════════════════════════════════
# ═══════════════════════════════════════════════════
# HELP MANUAL (-h / --help)
# Simple, clear, non-heavy instructions for new users
# ═══════════════════════════════════════════════════
def show_help():
    print_banner()
    console.print("[bold cyan]WebProbe v1.0 — Enterprise Web Vulnerability Scanner & Penetration Testing Tool[/bold cyan]")
    console.print("[dim]Automated dynamic assessment framework for SQLi, XSS, and IDOR vulnerabilities.[/dim]\n")

    console.print("[bold yellow]USAGE:[/bold yellow]")
    console.print("  [white]webprobe[/white] / [white]python3 main.py[/white]                      [dim]Interactive mode (prompts for target & modules)[/dim]")
    console.print("  [white]webprobe <TARGET>[/white]                             [dim]Scan target with interactive module menu[/dim]")
    console.print("  [white]webprobe <TARGET> -s <MODULES>[/white]                 [dim]Run scan directly without prompts[/dim]")
    console.print("  [white]webprobe -h, --help[/white]                           [dim]Display this help manual[/dim]")
    console.print("  [white]webprobe -v, --version[/white]                        [dim]Show version information[/dim]\n")

    console.print("[bold yellow]TARGET INPUT FORMATS:[/bold yellow]")
    console.print("  [green]• Full URL     :[/green] [white]http://localhost:3000[/white] or [white]https://target.com[/white]")
    console.print("  [green]• Host + Port  :[/green] [white]localhost:3000[/white] or [white]testfire.net:8080[/white]")
    console.print("  [green]• IP Address   :[/green] [white]127.0.0.1:3000[/white] or [white]192.168.1.100[/white]")
    console.print("  [green]• Domain Only  :[/green] [white]example.com[/white] (auto-resolves DNS and port 80/443)\n")

    console.print("[bold yellow]SCAN MODULES (-s, --scan):[/bold yellow]")
    console.print("  [cyan]1[/cyan]       : SQL Injection (SQLi)")
    console.print("  [cyan]2[/cyan]       : Cross-Site Scripting (XSS)")
    console.print("  [cyan]3[/cyan]       : Broken Access Control (IDOR)")
    console.print("  [cyan]1,2[/cyan]     : SQLi + XSS")
    console.print("  [cyan]1,3[/cyan]     : SQLi + IDOR")
    console.print("  [cyan]2,3[/cyan]     : XSS + IDOR")
    console.print("  [cyan]1,2,3[/cyan]   : Comprehensive Audit (All Modules - SQLi + XSS + IDOR)")
    console.print("  [cyan]all[/cyan]     : Alias for 1,2,3\n")

    console.print("[bold yellow]QUICK EXAMPLES:[/bold yellow]")
    console.print("  [dim]# Run against local test lab with interactive selector:[/dim]")
    console.print("  [bold white]webprobe http://localhost:3000[/bold white]  [dim]or[/dim]  [bold white]python3 main.py http://localhost:3000[/bold white]\n")
    console.print("  [dim]# Run full audit directly on domain:[/dim]")
    console.print("  [bold white]webprobe example.com -s 1,2,3[/bold white]\n")
    console.print("  [dim]# Test only SQL injection and XSS:[/dim]")
    console.print("  [bold white]webprobe 127.0.0.1:3000 -s 1,2[/bold white]\n")


# ═══════════════════════════════════════════════════
# MAIN FUNCTION
# ═══════════════════════════════════════════════════
def main():
    # Check for help or version flags
    args = sys.argv[1:]
    if any(arg in ["-h", "--help", "help", "-?"] for arg in args):
        show_help()
        sys.exit(0)

    if any(arg in ["-v", "--version", "version"] for arg in args):
        console.print(f"[bold cyan]{TOOL_NAME} {TOOL_VERSION}[/bold cyan]")
        sys.exit(0)

    print_banner()

    target = None
    direct_scan = None

    # Parse arguments
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ["-s", "--scan"] and i + 1 < len(args):
            direct_scan = args[i + 1]
            i += 2
        elif not arg.startswith("-") and target is None:
            target = arg
            i += 1
        else:
            i += 1

    if not target:
        target = console.input(
            "[bold yellow]Enter target (URL, domain, IP, or host:port): [/bold yellow]"
        ).strip()

    # Clean and normalize target (supports domain, domain:port, IP, IP:port, or full URL)
    target_info = resolve_target_info(target)
    target = target_info["url"]

    # Show status
    reachable = show_status(target)
    if not reachable:
        console.print(
            f"[red][!] Target {target} is not reachable. Check URL.[/red]"
        )
        sys.exit(1)

    # Show scan menu or use direct argument
    if direct_scan:
        scan_types = []
        raw = direct_scan.lower()
        if raw in ["all", "a", "7", "1,2,3"]:
            scan_types = ["sqli", "xss", "idor"]
        else:
            for t in re.split(r'[,+\s]+', raw):
                if t == "1" and "sqli" not in scan_types: scan_types.append("sqli")
                elif t == "2" and "xss" not in scan_types: scan_types.append("xss")
                elif t == "3" and "idor" not in scan_types: scan_types.append("idor")
        if not scan_types:
            scan_types = ["sqli", "xss", "idor"]
        console.print(f"[bold green][+] Direct Scan Selected: {', '.join(scan_types).upper()}[/bold green]")
    else:
        scan_types = show_scan_menu()

    # Crawl target
    console.print(
        "\n[bold cyan][*] Starting crawl...[/bold cyan]"
    )
    crawler_results = crawl(target)

    # Run selected scans
    all_findings = []

    if "sqli" in scan_types:
        console.print("\n[bold red][*] Running SQLi scan...[/bold red]")
        from scanner.sqli import load_payloads as sqli_local
        local = sqli_local()
        llm_payloads = generate_payloads(
            "sqli", target, "input",
            "web application", local
        )
        findings = sqli_scan(crawler_results, llm_payloads)
        all_findings.extend(findings)

    if "xss" in scan_types:
        console.print("\n[bold yellow][*] Running XSS scan...[/bold yellow]")
        from scanner.xss import load_payloads as xss_local
        local = xss_local()
        llm_payloads = generate_payloads(
            "xss", target, "input",
            "web application", local
        )
        findings = xss_scan(crawler_results, llm_payloads)
        all_findings.extend(findings)

    if "idor" in scan_types:
        console.print(
            "\n[bold magenta][*] Running IDOR scan...[/bold magenta]"
        )
        from scanner.idor import load_payloads as idor_local
        local = idor_local()
        idor_llm = generate_payloads("idor", target, "id", "API numeric ID", local)
        findings = idor_scan(crawler_results, idor_llm)
        all_findings.extend(findings)

    # Risk Engine Enrichment
    from risk.risk_engine import enrich_all, get_overall_risk
    enriched_findings = enrich_all(all_findings)
    overall_risk = get_overall_risk(enriched_findings)

    # Print summary
    print_summary(enriched_findings)

    # Generate PDF Report
    console.print("\n[bold cyan][*] Generating Executive PDF Report...[/bold cyan]")
    try:
        from report.pdf_generator import generate_report
        scan_info = {
            "start_time": get_timestamp(),
            "scan_types": ", ".join(scan_types).upper(),
        }
        report_path = generate_report(target, crawler_results, enriched_findings, scan_info)
        if report_path:
            console.print(f"[bold green][+] Executive PDF Report created: {report_path}[/bold green]")
    except ImportError as e:
        console.print(f"[yellow][!] PDF report skipped (fpdf2 missing: {e}). Install: pip install fpdf2==2.7.6[/yellow]")
    except Exception as e:
        console.print(f"[red][!] Report generation error: {e}[/red]")

    return enriched_findings, crawler_results

if __name__ == "__main__":
    main()
