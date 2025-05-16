WebVulnScan

WebVulnScan is a simple command-line tool for Kali Linux that scans web application URLs to detect common security vulnerabilities. It is written in Python and designed for quick, lightweight testing of websites.

Features
->Detects basic SQL Injection vulnerabilities
->Checks for reflected Cross-Site Scripting (XSS)
->Identifies missing security headers (e.g., Content-Security-Policy, X-Frame-Options)
->Scans a single URL or multiple URLs from a text file
->Simple and readable CLI output

Requirements
Python 3
requests, beautifulsoup4, argparse (install via pip3 install -r requirements.txt)

Usage
To scan a single URL:
python3 webvulnscan.py https://example.com

To scan multiple URLs from a file:
python3 webvulnscan.py urls.txt

Disclaimer
This tool is for educational and authorized use only. Do not scan websites without explicit permission. Unauthorized scanning is illegal and unethical.
