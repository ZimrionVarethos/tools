#!/usr/bin/env python3
"""
AD1 Browser History Forensics Analyzer (ad1/history.py)
Can be executed directly: python ad1/history.py <evidence.ad1>
"""
import sys
import os
import argparse

# Ensure parent directory (tools root) is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ad1.cli import cmd_history


def main(args_list=None):
    parser = argparse.ArgumentParser(
        prog="ad1 history",
        description=" Extract, parse, and analyze browser history (Chrome, Edge, Firefox, Brave, Opera, Safari) from AccessData AD1 logical images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ad1/history.py evidence.ad1
  python ad1/history.py evidence.ad1 --browser chrome --limit 50
  python ad1/history.py evidence.ad1 --query "google.com" --html report.html
  python ad1/history.py evidence.ad1 --search-only --csv search_history.csv
  python ad1/history.py evidence.ad1 --export-all
        """
    )

    parser.add_argument("input", help="Path to input AD1 image file (e.g. evidence.ad1)")
    parser.add_argument("-b", "--browser", choices=["all", "chrome", "edge", "firefox", "brave", "opera", "safari"], default="all", help="Filter by browser (default: all)")
    parser.add_argument("-q", "--query", help="Filter by keyword, domain, or search term")
    parser.add_argument("--search-only", action="store_true", help="Filter search engine queries only")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Row display limit in terminal (default: 100)")
    parser.add_argument("--creds-dir", default="./extracted_credentials", help="Destination folder for extracted DPAPI bundles (default: ./extracted_credentials)")
    parser.add_argument("--no-creds-extract", action="store_true", help="Disable automatic credential & DPAPI bundle extraction on login URL detection")
    parser.add_argument("-p", "--password", help="User Windows plaintext password to directly decrypt Chromium credentials")
    parser.add_argument("--ntlm", help="User Windows NTLM hash (hex string) to directly decrypt Chromium credentials")
    parser.add_argument("-w", "--wordlist", help="Password dictionary wordlist (e.g. rockyou.txt) to bruteforce MasterKey and decrypt credentials")
    parser.add_argument("--auto-sam", action="store_true", help="Extract NTLM hashes from SAM & SYSTEM hives to automatically decrypt credentials")
    
    # Export options
    export_group = parser.add_argument_group("Export Formats")
    export_group.add_argument("--csv", help="Export to CSV file")
    export_group.add_argument("--json", help="Export to JSON file")
    export_group.add_argument("--md", "--markdown", dest="md", help="Export to Markdown (.md) report")
    export_group.add_argument("--html", help="Export to interactive HTML report")
    export_group.add_argument("--export-all", action="store_true", help="Generate MD, JSON, CSV, and HTML reports automatically")

    args = parser.parse_args(args_list)

    if args.export_all:
        base_name = os.path.splitext(os.path.basename(args.input))[0]
        if not args.md:
            args.md = f"{base_name}_history.md"
        if not args.json:
            args.json = f"{base_name}_history.json"
        if not args.csv:
            args.csv = f"{base_name}_history.csv"
        if not args.html:
            args.html = f"{base_name}_history.html"

    cmd_history(args)


if __name__ == "__main__":
    main()
