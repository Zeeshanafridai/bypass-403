"""
Core HTTP engine for 403 bypass testing.
Tracks every request/response pair for diff analysis.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import hashlib
from typing import Optional

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
DIM  = "\033[90m"
BOLD = "\033[1m"
RST  = "\033[0m"

STATUS_COLORS = {
    200: G + BOLD,
    201: G + BOLD,
    204: G,
    301: Y,
    302: Y,
    307: Y,
    308: Y,
    400: DIM,
    401: Y,
    403: R,
    404: DIM,
    405: Y,
    429: Y,
    500: R,
    502: Y,
    503: Y,
}

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def http_request(url: str, method: str = "GET",
                  headers: dict = None, data: bytes = None,
                  cookies: str = None, timeout: int = 12,
                  follow_redirects: bool = False) -> dict:
    """
    Make HTTP request. Returns rich result dict.
    Does NOT follow redirects by default — we want to see 30x responses.
    """
    req_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept":     "*/*",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            url, data=data, headers=req_headers, method=method.upper()
        )
        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX)
            )
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                NoRedirect()
            )
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            body    = resp.read(512 * 1024).decode("utf-8", errors="replace")
            rhdrs   = {k.lower(): v for k, v in dict(resp.headers).items()}
            return _build(resp.status, rhdrs, body, elapsed, url, method, req_headers)

    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        rhdrs   = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return _build(e.code, rhdrs, body, elapsed, url, method, req_headers)

    except Exception as e:
        elapsed = time.perf_counter() - start
        return _build(0, {}, "", elapsed, url, method, req_headers, error=str(e))


def _build(status, headers, body, elapsed, url, method, sent_headers, error=None):
    return {
        "status":       status,
        "headers":      headers,
        "body":         body,
        "body_length":  len(body),
        "body_hash":    hashlib.md5(body.encode()).hexdigest(),
        "elapsed":      round(elapsed, 3),
        "url":          url,
        "method":       method,
        "sent_headers": sent_headers,
        "location":     headers.get("location", ""),
        "content_type": headers.get("content-type", ""),
        "server":       headers.get("server", ""),
        "error":        error,
    }


def colored_status(status: int) -> str:
    col = STATUS_COLORS.get(status, DIM)
    return f"{col}{status}{RST}"


def is_bypass(original_status: int, bypass_status: int,
               original_length: int, bypass_length: int) -> tuple:
    """
    Determine if a bypass attempt was successful.
    Returns (is_bypass: bool, confidence: str, reason: str)
    """
    # Clear bypass: was 403/401, now 200/201/204
    if original_status in (403, 401) and bypass_status in (200, 201, 204):
        return True, "high", f"Status changed {original_status}→{bypass_status}"

    # Redirect bypass: was 403, now redirecting elsewhere
    if original_status in (403, 401) and bypass_status in (301, 302, 307, 308):
        return True, "medium", f"Redirect on {bypass_status} — follow to confirm"

    # Different 4xx — may indicate different code path
    if original_status == 403 and bypass_status == 401:
        return True, "low", "Auth required (not forbidden) — different behaviour"

    # Same status but very different body size (content exposed)
    if bypass_status == original_status and abs(bypass_length - original_length) > 500:
        return True, "low", f"Same status but body diff {bypass_length - original_length:+d} bytes"

    # 500 error — may expose info / hit backend
    if bypass_status == 500 and original_status == 403:
        return True, "medium", "500 error on bypass — backend reached, inspect response"

    return False, "none", ""
