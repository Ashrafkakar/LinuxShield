"""Interactive terminal interface for LinuxShield."""
import argparse
import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

from .scanner import run_scan
from .reports import write_html, write_json

HISTORY_DIR = Path.home() / ".linuxshield"
LATEST_REPORT = HISTORY_DIR / "latest_scan.json"

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
CYAN, GREEN, YELLOW, RED, BLUE, BOLD = "96", "92", "93", "91", "94", "1"


def color(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def banner():
    os.system("clear" if os.name == "posix" else "cls")

    print(color("96", r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗███████╗██╗  ██╗     ║
    ║   ██║     ██║████╗  ██║██║   ██║╚██╗██╔╝██╔════╝██║  ██║     ║
    ║   ██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ ███████╗███████║     ║
    ║   ██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ ╚════██║██╔══██║     ║
    ║   ███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗███████║██║  ██║     ║
    ║   ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
"""))

    print(color("92", "                  LINUX SECURITY AUDITOR"))
    print(color("96", "                     Created by Kakar"))
    print(color("94", "             ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(color("92", "                  DETECT • ANALYZE • SECURE"))
    print()

def save_latest(report):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    write_json(report, str(LATEST_REPORT))


def show_findings(report):
    print()
    print(color(BOLD, f"LinuxShield | Security score: {report['score']}/100"))
    print(f"Host: {report['host']}")
    print("-" * 68)

    for finding in report["findings"]:
        severity = str(finding["severity"]).upper()
        shade = RED if severity in ("HIGH", "CRITICAL", "ERROR") else YELLOW
        print(color(shade, f"[{severity}] {finding['title']}"))
        print(f"  {finding['details']}")
        print(color(GREEN, f"  Recommendation: {finding['recommendation']}"))
        print()


def run_new_scan():
    print(color(CYAN, "\n[*] Running security scan...\n"))
    report = run_scan()
    save_latest(report)
    show_findings(report)
    print(color(GREEN, f"[*] Latest scan saved to: {LATEST_REPORT}"))


def view_latest():
    if not LATEST_REPORT.exists():
        print(color(YELLOW, "\nNo saved scan found yet. Choose option 1 first."))
        return

    try:
        report = json.loads(LATEST_REPORT.read_text(encoding="utf-8"))
        print(color(CYAN, f"\n[*] Showing saved scan: {LATEST_REPORT}"))
        show_findings(report)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(color(RED, f"Could not read saved scan: {exc}"))


def create_report(fmt):
    if LATEST_REPORT.exists():
        try:
            report = json.loads(LATEST_REPORT.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            print(color(YELLOW, "Saved scan is unreadable. Running a fresh scan."))
            report = run_scan()
            save_latest(report)
    else:
        print(color(YELLOW, "No saved scan yet. Running a fresh scan first."))
        report = run_scan()
        save_latest(report)

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    filename = HISTORY_DIR / f"linuxshield_report.{fmt}"
    writer = write_html if fmt == "html" else write_json
    writer(report, str(filename))
    print(color(GREEN, f"\n[+] {fmt.upper()} report saved: {filename}"))


def system_info():
    print(color(CYAN, "\nSystem Information"))
    print(f"Operating system: {platform.system()}")
    print(f"Platform:         {platform.platform()}")
    print(f"Machine:          {platform.machine()}")
    print(f"Python:           {platform.python_version()}")
    print(f"Hostname:         {platform.node()}")
    print(f"Saved scan:       {'Yes' if LATEST_REPORT.exists() else 'No'}")


def menu():
    while True:
        banner()
        print(color(GREEN, "  [1] Run security scan"))
        print(color(GREEN, "  [2] View latest saved scan findings"))
        print(color(GREEN, "  [3] Generate HTML report"))
        print(color(GREEN, "  [4] Generate JSON report"))
        print(color(GREEN, "  [5] System information"))
        print(color(RED,   "  [0] Exit"))
        print()

        try:
            choice = input(color(YELLOW, "LinuxShield > ")).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye, jani!")
            break

        if choice == "1":
            try:
                run_new_scan()
            except Exception as exc:
                print(color(RED, f"Scan failed: {exc}"))
        elif choice == "2":
            view_latest()
        elif choice == "3":
            create_report("html")
        elif choice == "4":
            create_report("json")
        elif choice == "5":
            system_info()
        elif choice == "0":
            print(color(GREEN, "LinuxShield closed. Stay secure!"))
            break
        else:
            print(color(RED, "Invalid option. Choose 0–5."))

        if choice != "0":
            input(color(BLUE, "\nPress Enter to return to the menu..."))


def main():
    parser = argparse.ArgumentParser(description="LinuxShield security auditor")
    parser.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE")
    parser.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    args = parser.parse_args()

    if args.json or args.html:
        report = run_scan()
        save_latest(report)
        if args.json:
            write_json(report, args.json)
            print(f"JSON report saved to {args.json}")
        if args.html:
            write_html(report, args.html)
            print(f"HTML report saved to {args.html}")
        return

    menu()


if __name__ == "__main__":
    main()

