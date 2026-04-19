#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           403 BYPASS  —  by 0xZ33                            ║
║        github.com/Zeeshanafridai/bypass-403                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bypass.scanner import scan, save_report
from bypass.core import R, G, Y, C, DIM, BOLD, RST


def main():
    parser = argparse.ArgumentParser(
        prog="403-bypass",
        description="403/401 Bypass Automation Tool"
    )

    # Target
    target_grp = parser.add_mutually_exclusive_group(required=True)
    target_grp.add_argument("-u", "--url",  help="Single target URL")
    target_grp.add_argument("-l", "--list", help="File with URLs (one per line)")

    # Request options
    parser.add_argument("-c", "--cookies",  help="Cookies string")
    parser.add_argument("-H", "--header",   action="append",
                        help="Extra header (Name: Value)")

    # Technique selection
    parser.add_argument("--techniques",     nargs="+",
                        choices=["path", "headers", "verbs", "protocol"],
                        default=["path", "headers", "verbs", "protocol"],
                        help="Bypass techniques (default: all)")

    parser.add_argument("--delay",          type=float, default=0.0,
                        help="Delay between requests in seconds")

    # Output
    parser.add_argument("--report",         action="store_true")
    parser.add_argument("--report-prefix",  default="bypass_report")
    parser.add_argument("-o", "--output",   help="Save raw JSON")
    parser.add_argument("--only-bypassed",  action="store_true",
                        help="Print only successful bypass URLs")
    parser.add_argument("-q", "--quiet",    action="store_true")

    args = parser.parse_args()

    # Parse extra headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    # Load URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list) as f:
            urls = [l.strip() for l in f if l.strip()]

    all_results = []
    for url in urls:
        results = scan(
            url        = url,
            cookies    = args.cookies,
            extra_headers = headers or None,
            techniques = args.techniques,
            verbose    = not args.quiet,
            delay      = args.delay,
        )
        all_results.append(results)

        if args.only_bypassed:
            for b in results.get("bypassed", []):
                print(b.get("url", ""))

        if args.report:
            paths = save_report(results, args.report_prefix)
            if not args.quiet:
                print(f"\n{C}[*] Reports:{RST}")
                print(f"    JSON     : {paths['json']}")
                print(f"    Markdown : {paths['markdown']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results if len(all_results) > 1 else all_results[0],
                      f, indent=2, default=str)
        if not args.quiet:
            print(f"\n{G}[+] Results: {args.output}{RST}")


if __name__ == "__main__":
    main()
