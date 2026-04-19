"""
403 Bypass Scanner — Main Orchestrator + Report Generator
"""

import json
import time
import datetime
import urllib.parse
from .core import http_request, is_bypass, colored_status, R, G, Y, C, DIM, BOLD, RST
from .techniques import path_bypass, header_bypass, verb_bypass, protocol_bypass


BANNER = f"""
{R}
  ██╗  ██╗ ██████╗ ██████╗     ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
  ██║  ██║██╔═══██╗╚════██╗    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ███████║██║   ██║ █████╔╝    ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
  ╚════██║██║   ██║ ╚═══██╗    ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
       ██║╚██████╔╝██████╔╝    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
       ╚═╝ ╚═════╝ ╚═════╝     ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
{RST}{DIM}  403/401 Bypass Automation — Path, Headers, Verbs, Protocol — Chains All Techniques{RST}
"""


def get_baseline(url: str, cookies: str = None,
                  headers: dict = None) -> dict:
    """Get baseline response (the 403/401 we're trying to bypass)."""
    resp = http_request(url, headers=headers, cookies=cookies)
    return resp


def scan(url: str, cookies: str = None,
          extra_headers: dict = None,
          techniques: list = None,
          verbose: bool = True,
          delay: float = 0.0) -> dict:
    """
    Full 403/401 bypass scan against a URL.

    Args:
        url:           Target URL returning 403/401
        cookies:       Session cookies
        extra_headers: Additional request headers
        techniques:    List of technique names (default: all)
                       Options: path, headers, verbs, protocol
        verbose:       Print progress
        delay:         Delay between requests (seconds)

    Returns:
        Full results dict
    """
    results = {
        "url":           url,
        "start_time":    datetime.datetime.utcnow().isoformat(),
        "baseline_status": None,
        "findings":      [],
        "bypassed":      [],
        "total_tested":  0,
        "summary":       {},
    }

    if verbose:
        print(BANNER)
        print(f"  {C}Target{RST}      : {url}")
        print(f"  {C}Cookies{RST}     : {'Yes' if cookies else 'No'}")
        print()

    # Get baseline
    if verbose:
        print(f"{Y}[STEP 1] Establishing Baseline{RST}")

    baseline = get_baseline(url, cookies=cookies, headers=extra_headers)
    results["baseline_status"] = baseline["status"]

    if verbose:
        print(f"  Baseline: {colored_status(baseline['status'])} | "
              f"Length: {baseline['body_length']} | "
              f"Time: {baseline['elapsed']}s")
        if baseline["server"]:
            print(f"  Server : {baseline['server']}")
        print()

    # Check if it's actually returning 403/401
    if baseline["status"] not in (403, 401, 404, 405):
        if verbose:
            print(f"  {Y}[!] URL returns {baseline['status']} — "
                  f"not a typical 403/401. Proceeding anyway.{RST}\n")

    # Parse path from URL
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path or "/"

    active = techniques or ["path", "headers", "verbs", "protocol"]
    all_findings = []

    # ── Path bypass ──────────────────────────────────────────────────────────
    if "path" in active:
        if verbose:
            print(f"{Y}[STEP 2] Path Manipulation Bypasses{RST}")
        found = path_bypass.run(url, path, baseline,
                                 cookies=cookies,
                                 extra_headers=extra_headers,
                                 verbose=verbose)
        all_findings.extend(found)
        if delay:
            time.sleep(delay)

    # ── Header bypass ────────────────────────────────────────────────────────
    if "headers" in active:
        if verbose:
            print(f"{Y}[STEP 3] Header Injection Bypasses{RST}")
        found = header_bypass.run(url, path, baseline,
                                   cookies=cookies,
                                   extra_headers=extra_headers,
                                   verbose=verbose)
        all_findings.extend(found)
        if delay:
            time.sleep(delay)

    # ── Verb bypass ──────────────────────────────────────────────────────────
    if "verbs" in active:
        if verbose:
            print(f"{Y}[STEP 4] HTTP Verb Tampering Bypasses{RST}")
        found = verb_bypass.run(url, baseline,
                                 cookies=cookies,
                                 extra_headers=extra_headers,
                                 verbose=verbose)
        all_findings.extend(found)
        if delay:
            time.sleep(delay)

    # ── Protocol bypass ──────────────────────────────────────────────────────
    if "protocol" in active:
        if verbose:
            print(f"{Y}[STEP 5] Protocol & Port Bypasses{RST}")
        found = protocol_bypass.run(url, baseline,
                                     cookies=cookies,
                                     extra_headers=extra_headers,
                                     verbose=verbose)
        all_findings.extend(found)

    results["findings"]     = all_findings
    results["bypassed"]     = [f for f in all_findings if f.get("bypass")]
    results["total_tested"] = len(all_findings)

    # Summary
    by_technique = {}
    for f in results["bypassed"]:
        t = f.get("technique", "unknown")
        by_technique[t] = by_technique.get(t, 0) + 1

    results["summary"] = {
        "total_tested":   results["total_tested"],
        "bypassed_count": len(results["bypassed"]),
        "by_technique":   by_technique,
        "baseline_status":baseline["status"],
    }

    if verbose:
        _print_summary(results)

    return results


def _print_summary(results: dict):
    bypassed = results["bypassed"]
    summary  = results["summary"]

    print(f"\n{R}{BOLD}{'═'*65}{RST}")
    print(f"{R}{BOLD}  403 BYPASS SCAN COMPLETE{RST}")
    print(f"{R}{BOLD}{'═'*65}{RST}\n")
    print(f"  URL tested       : {results['url']}")
    print(f"  Baseline status  : {colored_status(summary['baseline_status'])}")
    print(f"  Total techniques : {summary['total_tested']}")
    print(f"  Bypasses found   : {G}{BOLD}{summary['bypassed_count']}{RST}")

    if bypassed:
        print(f"\n  {G}{BOLD}SUCCESSFUL BYPASSES:{RST}\n")
        # Group by confidence
        for conf in ("high", "medium", "low"):
            group = [f for f in bypassed if f.get("confidence") == conf]
            if group:
                col   = G if conf == "high" else Y
                print(f"  {col}{conf.upper()} CONFIDENCE ({len(group)}){RST}")
                for f in group:
                    tech = f.get("technique", "")
                    var  = f.get("variant", "")
                    st   = f.get("status", "?")
                    ln   = f.get("body_length", 0)
                    url  = f.get("url", "")
                    hdrs = ""
                    if f.get("header"):
                        hdrs = f" | Header: {f['header']}: {f.get('value','')[:30]}"
                    print(f"    {G}→{RST} [{tech}] {var}")
                    print(f"       Status: {colored_status(st)} | "
                          f"Length: {ln}{hdrs}")
                    if len(url) < 80:
                        print(f"       URL: {url}")
                    print()
    else:
        print(f"\n  {DIM}No bypasses found.{RST}")
        print(f"  {DIM}Tips:{RST}")
        print(f"  {DIM}  • Try with a valid session cookie: --cookies{RST}")
        print(f"  {DIM}  • Try other paths on the same host{RST}")
        print(f"  {DIM}  • Check if rate limiting is blocking you{RST}\n")


def save_report(results: dict, prefix: str = "bypass_report") -> dict:
    """Save JSON + Markdown report."""
    now   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jpath = f"{prefix}_{now}.json"
    mpath = f"{prefix}_{now}.md"

    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    bypassed = results.get("bypassed", [])
    lines    = []
    lines.append("# 403 Bypass Report\n")
    lines.append(f"**Target:** `{results.get('url','')}`  ")
    lines.append(f"**Date:** {results.get('start_time','')}  ")
    lines.append(f"**Bypasses:** {len(bypassed)}  \n")
    lines.append("---\n")

    for b in bypassed:
        lines.append(f"## [{b.get('confidence','?').upper()}] {b.get('variant','')}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Technique** | {b.get('technique','')} |")
        lines.append(f"| **Status** | {b.get('status','')} |")
        lines.append(f"| **Body Length** | {b.get('body_length','')} |")
        lines.append(f"| **URL** | `{b.get('url','')}` |")
        if b.get("header"):
            lines.append(f"| **Header** | `{b['header']}: {b.get('value','')}` |")
        lines.append(f"| **Reason** | {b.get('reason','')} |\n")
        if b.get("body_snippet"):
            lines.append(f"**Response snippet:**\n```\n{b['body_snippet'][:300]}\n```\n")
        lines.append("---\n")

    lines.append("## Remediation\n")
    lines.append("- Enforce access controls at the application layer, not just the WAF/proxy")
    lines.append("- Normalize URLs server-side before access control checks")
    lines.append("- Do not trust X-Forwarded-For or similar headers for authorization")
    lines.append("- Apply access control checks consistently regardless of HTTP method")
    lines.append("- Test ACL rules against all bypass techniques in your CI/CD pipeline\n")

    with open(mpath, "w") as f:
        f.write("\n".join(lines))

    return {"json": jpath, "markdown": mpath}
