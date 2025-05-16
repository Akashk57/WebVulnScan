import requests
from bs4 import BeautifulSoup
import argparse

def check_sql_injection(url):
    payload = "' OR '1'='1"
    try:
        res = requests.get(url + payload, timeout=5)
        if "sql" in res.text.lower() or "syntax" in res.text.lower():
            return True
    except Exception:
        pass
    return False

def check_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        res = requests.get(url, params={'q': xss_payload})
        if xss_payload in res.text:
            return True
    except Exception:
        pass
    return False

def check_headers(url):
    try:
        res = requests.get(url)
        headers = res.headers
        issues = []
        if 'Content-Security-Policy' not in headers:
            issues.append("Missing Content-Security-Policy")
        if 'X-Frame-Options' not in headers:
            issues.append("Missing X-Frame-Options")
        return issues
    except:
        return []

def scan_url(url):
    print(f"\n[+] Scanning {url}")
    if check_sql_injection(url):
        print("[!] Possible SQL Injection detected.")
    if check_xss(url):
        print("[!] Reflected XSS vulnerability detected.")
    header_issues = check_headers(url)
    for issue in header_issues:
        print(f"[!] Header issue: {issue}")
    print("[*] Scan complete.\n")

def main():
    parser = argparse.ArgumentParser(description="WebVulnScan - Basic Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL or file with list of URLs")
    args = parser.parse_args()

    if args.url.endswith(".txt"):
        with open(args.url, "r") as f:
            urls = [line.strip() for line in f.readlines()]
            for url in urls:
                scan_url(url)
    else:
        scan_url(args.url)

if __name__ == "__main__":
    main()
