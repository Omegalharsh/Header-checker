#!/usr/bin/env python3
"""
header_checker.py - HTTP Security Header Analyzer

Checks one or many URLs for:
  * Missing security headers
  * Weak header values (e.g. CSP with unsafe-inline, short HSTS max-age)
  * Information-leaking headers (Server, X-Powered-By ...)
  * Insecure cookie flags (Secure, HttpOnly, SameSite)
  * Permissive CORS configuration

Usage:
  python header_checker.py https://example.com
  python header_checker.py -f urls.txt -t 10 --json report.json --csv report.csv

Install:  pip install requests

LEGAL: Only scan systems you own or have written permission to test.
"""

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENT = "HeaderChecker/1.0 (security-assessment)"

# header -> (severity if missing, recommendation)
REQUIRED_HEADERS = {
    "Content-Security-Policy": ("High", "Define a CSP to restrict script/style sources and mitigate XSS."),
    "Strict-Transport-Security": ("High", "Add HSTS, e.g. 'max-age=31536000; includeSubDomains'."),
    "X-Content-Type-Options": ("Medium", "Set to 'nosniff' to prevent MIME sniffing."),
    "X-Frame-Options": ("Medium", "Set to 'DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors) to stop clickjacking."),
    "Referrer-Policy": ("Low", "Set e.g. 'strict-origin-when-cross-origin' to limit referrer leakage."),
    "Permissions-Policy": ("Low", "Restrict browser features (camera, geolocation, microphone)."),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}


def finding(severity, category, header, issue, recommendation):
    return {
        "severity": severity,
        "category": category,
        "header": header,
        "issue": issue,
        "recommendation": recommendation,
    }


def normalize_url(url):
    url = url.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def check_required(headers, findings):
    for name, (sev, rec) in REQUIRED_HEADERS.items():
        if name not in headers:
            # CSP frame-ancestors can replace X-Frame-Options
            if name == "X-Frame-Options" and "frame-ancestors" in headers.get("Content-Security-Policy", "").lower():
                continue
            findings.append(finding(sev, "Missing Header", name, f"{name} is not set.", rec))


def check_weak_values(headers, url, findings):
    csp = headers.get("Content-Security-Policy", "")
    if csp:
        low = csp.lower()
        if "unsafe-inline" in low:
            findings.append(finding("Medium", "Weak Value", "Content-Security-Policy",
                                    "CSP allows 'unsafe-inline'.", "Remove 'unsafe-inline'; use nonces or hashes."))
        if "unsafe-eval" in low:
            findings.append(finding("Medium", "Weak Value", "Content-Security-Policy",
                                    "CSP allows 'unsafe-eval'.", "Remove 'unsafe-eval'."))
        if " * " in f" {low} " or "script-src *" in low or "default-src *" in low:
            findings.append(finding("Medium", "Weak Value", "Content-Security-Policy",
                                    "CSP uses a wildcard source.", "Restrict to explicit trusted origins."))

    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        low = hsts.lower()
        max_age = 0
        for part in low.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if max_age < 15552000:  # 180 days
            findings.append(finding("Medium", "Weak Value", "Strict-Transport-Security",
                                    f"HSTS max-age is short ({max_age}s).", "Use at least 31536000 (1 year)."))
        if "includesubdomains" not in low:
            findings.append(finding("Low", "Weak Value", "Strict-Transport-Security",
                                    "HSTS lacks includeSubDomains.", "Add includeSubDomains if all subdomains support HTTPS."))
    elif urlparse(url).scheme == "http":
        findings.append(finding("Info", "Transport", "Strict-Transport-Security",
                                "Site served over plain HTTP; HSTS is ignored over HTTP.", "Redirect to HTTPS and set HSTS there."))

    xfo = headers.get("X-Frame-Options", "")
    if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(finding("Medium", "Weak Value", "X-Frame-Options",
                                f"Unexpected value '{xfo}'.", "Use 'DENY' or 'SAMEORIGIN'."))

    xcto = headers.get("X-Content-Type-Options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        findings.append(finding("Medium", "Weak Value", "X-Content-Type-Options",
                                f"Unexpected value '{xcto}'.", "Set to 'nosniff'."))

    ref = headers.get("Referrer-Policy", "")
    if ref and ref.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(finding("Low", "Weak Value", "Referrer-Policy",
                                f"Weak policy '{ref}'.", "Use 'strict-origin-when-cross-origin' or stricter."))


def check_leaks(headers, findings):
    for name in LEAKY_HEADERS:
        if name in headers:
            findings.append(finding("Low", "Information Disclosure", name,
                                    f"Reveals technology/version: '{headers[name]}'.",
                                    f"Remove or genericize the {name} header."))


def check_cookies(resp, findings):
    # requests merges Set-Cookie; read the raw headers for accuracy
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw_cookies = []
    is_https = urlparse(resp.url).scheme == "https"

    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        if is_https and "secure" not in low:
            findings.append(finding("Medium", "Cookie", f"Set-Cookie ({name})",
                                    "Missing Secure flag.", "Add the Secure flag."))
        if "httponly" not in low:
            findings.append(finding("Medium", "Cookie", f"Set-Cookie ({name})",
                                    "Missing HttpOnly flag.", "Add HttpOnly so JavaScript cannot read the cookie."))
        if "samesite" not in low:
            findings.append(finding("Low", "Cookie", f"Set-Cookie ({name})",
                                    "Missing SameSite attribute.", "Add SameSite=Lax or Strict to reduce CSRF risk."))
        elif "samesite=none" in low and "secure" not in low:
            findings.append(finding("Medium", "Cookie", f"Set-Cookie ({name})",
                                    "SameSite=None without Secure.", "SameSite=None requires Secure."))


def check_cors(headers, findings):
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        sev = "High" if acac == "true" else "Low"
        findings.append(finding(sev, "CORS", "Access-Control-Allow-Origin",
                                "Wildcard origin allowed" + (" with credentials." if acac == "true" else "."),
                                "Allow only specific trusted origins."))


def scan(url, timeout=10, verify=True, follow=True):
    """Scan a single URL and return a result dict."""
    url = normalize_url(url)
    result = {"url": url, "final_url": None, "status": None, "error": None, "findings": [], "grade": None}
    try:
        resp = requests.get(
            url, timeout=timeout, verify=verify, allow_redirects=follow,
            headers={"User-Agent": USER_AGENT}, stream=True,
        )
        resp.close()
    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {e.__class__.__name__} (use --insecure to skip verification)"
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"{e.__class__.__name__}: {e}"
        return result

    headers = resp.headers  # case-insensitive dict
    findings = result["findings"]
    result["final_url"] = resp.url
    result["status"] = resp.status_code

    check_required(headers, findings)
    check_weak_values(headers, resp.url, findings)
    check_leaks(headers, findings)
    check_cookies(resp, findings)
    check_cors(headers, findings)

    findings.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])
    result["grade"] = grade(findings)
    return result


def grade(findings):
    penalty = {"High": 20, "Medium": 10, "Low": 4, "Info": 0}
    score = max(0, 100 - sum(penalty[f["severity"]] for f in findings))
    letter = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return f"{letter} ({score}/100)"


# ---------- Output ----------

COLORS = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[94m", "Info": "\033[90m"}
RESET = "\033[0m"


def print_result(res, use_color=True):
    print("=" * 72)
    print(f"Target : {res['url']}")
    if res["error"]:
        print(f"ERROR  : {res['error']}")
        return
    print(f"Final  : {res['final_url']}  [HTTP {res['status']}]")
    print(f"Grade  : {res['grade']}")
    print("-" * 72)
    if not res["findings"]:
        print("No issues found.")
        return
    for f in res["findings"]:
        tag = f"[{f['severity'].upper():6}]"
        if use_color:
            tag = f"{COLORS[f['severity']]}{tag}{RESET}"
        print(f"{tag} {f['category']}: {f['header']}")
        print(f"         Issue : {f['issue']}")
        print(f"         Fix   : {f['recommendation']}")


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nJSON report saved to {path}")


def write_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "status", "grade", "severity", "category", "header", "issue", "recommendation", "error"])
        for r in results:
            if r["error"]:
                w.writerow([r["url"], "", "", "", "", "", "", "", r["error"]])
            for f in r["findings"]:
                w.writerow([r["url"], r["status"], r["grade"], f["severity"], f["category"],
                            f["header"], f["issue"], f["recommendation"], ""])
    print(f"CSV report saved to {path}")


# ---------- CLI ----------

def main():
    p = argparse.ArgumentParser(description="HTTP security header analyzer (use only on authorized targets).")
    p.add_argument("url", nargs="?", help="Single URL to scan")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("-t", "--threads", type=int, default=5, help="Concurrent threads (default 5)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default 10)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    p.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--json", metavar="FILE", help="Save results as JSON")
    p.add_argument("--csv", metavar="FILE", help="Save results as CSV")
    args = p.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"Cannot read {args.file}: {e}")
    if not targets:
        p.error("provide a URL or --file")

    targets = list(dict.fromkeys(targets))  # de-duplicate, keep order
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = {
            pool.submit(scan, t, args.timeout, not args.insecure, not args.no_redirect): t
            for t in targets
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    order = {normalize_url(t): i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r["url"], 0))

    for r in results:
        print_result(r, use_color=not args.no_color and sys.stdout.isatty())

    if args.json:
        write_json(results, args.json)
    if args.csv:
        write_csv(results, args.csv)


if __name__ == "__main__":
    main()