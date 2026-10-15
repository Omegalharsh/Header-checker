# HeaderChecker 🔒

A fast, multi-threaded command-line tool that audits the **HTTP security headers** of web applications. It flags missing headers, weak configurations, information leaks, insecure cookies and permissive CORS, then grades each target and tells you how to fix every issue.

Built in Python as part of my web application security practice, and designed to speed up the reconnaissance phase of a web application penetration test or vulnerability assessment.

> ⚠️ **Legal notice:** Use this tool only on systems you own or have explicit written permission to test. The author is not responsible for misuse.

---

## Features

| Category | What it checks |
|---|---|
| **Missing headers** | Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options (or CSP `frame-ancestors`), Referrer-Policy, Permissions-Policy |
| **Weak values** | CSP with `unsafe-inline` / `unsafe-eval` / wildcards, short HSTS `max-age`, missing `includeSubDomains`, invalid X-Frame-Options, weak Referrer-Policy |
| **Information disclosure** | `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` revealing technology and versions |
| **Cookie security** | Missing `Secure`, `HttpOnly` and `SameSite` flags, plus `SameSite=None` without `Secure` |
| **CORS** | Wildcard `Access-Control-Allow-Origin`, rated High when combined with credentials |

Other highlights:

- **Severity ratings** (High / Medium / Low / Info) and an overall **grade** (A to F) per target
- **Remediation advice** for every finding
- **Bulk scanning** from a file, with multi-threading
- **JSON and CSV reports** for documentation and further analysis
- Colored terminal output, configurable timeout, redirect and TLS options
- Only reads response headers, never downloads the page body (lightweight on the target)

---

## Installation

```bash
git clone https://github.com/<your-username>/HeaderChecker.git
cd HeaderChecker
pip install requests
```

Requires **Python 3.8+**.

---

## Usage

```bash
# Scan a single site
python header_checker.py https://example.com

# Scan many sites from a file with 10 threads
python header_checker.py -f urls.txt -t 10

# Save reports
python header_checker.py https://example.com --json report.json --csv report.csv

# Skip TLS verification and don't follow redirects
python header_checker.py https://example.com --insecure --no-redirect
```

### Options

| Option | Description |
|---|---|
| `url` | Single URL to scan |
| `-f, --file` | File containing one URL per line (`#` for comments) |
| `-t, --threads` | Number of concurrent threads (default: 5) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--insecure` | Skip TLS certificate verification |
| `--no-redirect` | Do not follow redirects |
| `--no-color` | Disable colored output |
| `--json FILE` | Save results as JSON |
| `--csv FILE` | Save results as CSV |

---

## Sample Output

Tested against a local server deliberately configured with weak headers:

```
========================================================================
Target : http://127.0.0.1:8099
Final  : http://127.0.0.1:8099/  [HTTP 200]
Grade  : F (16/100)
------------------------------------------------------------------------
[HIGH  ] Missing Header: Strict-Transport-Security
         Issue : Strict-Transport-Security is not set.
         Fix   : Add HSTS, e.g. 'max-age=31536000; includeSubDomains'.
[MEDIUM] Weak Value: Content-Security-Policy
         Issue : CSP allows 'unsafe-inline'.
         Fix   : Remove 'unsafe-inline'; use nonces or hashes.
[MEDIUM] Cookie: Set-Cookie (sid)
         Issue : Missing HttpOnly flag.
         Fix   : Add HttpOnly so JavaScript cannot read the cookie.
[LOW   ] Information Disclosure: X-Powered-By
         Issue : Reveals technology/version: 'PHP/5.6'.
         Fix   : Remove or genericize the X-Powered-By header.
...
```

---

## How It Works

```
CLI args → list of URLs → thread pool → scan(url)
                                          ├─ requests.get() (headers only)
                                          ├─ check_required / check_weak_values
                                          ├─ check_leaks / check_cookies / check_cors
                                          └─ grade()
        → terminal output → optional JSON / CSV report
```

### Scoring

Each target starts at 100 points. High findings subtract 20, Medium 10 and Low 4 (Info is not scored).

| Score | Grade |
|---|---|
| 90 to 100 | A |
| 75 to 89 | B |
| 60 to 74 | C |
| 40 to 59 | D |
| below 40 | F |

---

## Extending the Tool

Adding a new check takes two steps:

1. Write a function that takes `headers` and `findings`:
   ```python
   def check_cache_control(headers, findings):
       if "no-store" not in headers.get("Cache-Control", "").lower():
           findings.append(finding("Low", "Missing Header", "Cache-Control",
                                   "No 'no-store' directive.", "Add Cache-Control: no-store on sensitive pages."))
   ```
2. Call it inside `scan()`.

---

## Roadmap

- [ ] HTML report output
- [ ] HTTP to HTTPS redirect check
- [ ] `Cache-Control` check for sensitive pages
- [ ] Subdomain list input from recon tools (Subfinder / Amass)
- [ ] Burp Suite extension version

---

## Limitations

- Checks headers from a single `GET` request. Headers may differ across pages, authenticated areas or API endpoints.
- Findings are indicators, not proof of exploitability. Always validate manually before reporting.
- Does not replace a full penetration test or a dedicated scanner.

---

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MDN: HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/Security)

---

## Author

**Your Name**
[LinkedIn](https://linkedin.com/in/your-profile) · [GitHub](https://github.com/your-username)

## License

Released under the MIT License. Add a `LICENSE` file to the repo.
