# 🔍 ShadowScan Fusion

> Advanced web vulnerability scanner with **50+ detectors**, **async architecture**, **plugin system**, optimized for **Termux and Linux**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version 31.2](https://img.shields.io/badge/Version-31.2.0-brightgreen.svg)]()

---

## 📋 Features

- **50+ Vulnerability Detectors**: XSS, SQLi, SSTI, LFI, CMDI, SSRF, and more
- **Async & High-Performance**: Optimized concurrency with token bucket rate limiting
- **Plugin System**: Extend with custom detectors
- **Termux Optimized**: Special handling for mobile penetration testing
- **Smart Crawling**: Recursive endpoint discovery with depth control
- **Multiple Report Formats**: HTML, JSON, JSONL logging
- **Security Compliance**: OWASP Top 10, CWE, PCI-DSS mapping
- **Knowledge Base**: Learning from previous scans
- **WAF Detection**: Identifies security systems (Cloudflare, AWS WAF, etc.)
- **Technology Fingerprinting**: Detects frameworks and libraries

---

## 🚀 Installation

### Requirements
- **Python 3.8+**
- **pip** (Python package manager)
- **Linux/Termux environment**

### Step 1: Clone Repository
```bash
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation
```bash
python shadowscan.py --version
```

---

## 💻 Quick Start

### Basic Scan
```bash
python shadowscan.py https://example.com
```

### Fast Mode (Termux - Low Resources)
```bash
python shadowscan.py https://example.com -m fast --threads 2
```

### Deep Scan with Custom Options
```bash
python shadowscan.py https://example.com \
  -m deep \
  --threads 6 \
  --max-pages 500 \
  --max-depth 3 \
  -o my_scan
```

### With Authentication
```bash
python shadowscan.py https://example.com \
  --login-url https://example.com/login \
  -u username \
  -p password
```

### Using Proxy
```bash
python shadowscan.py https://example.com \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl
```

---

## 📚 Usage Guide

### Command Line Arguments

```
Positional:
  target                Target URL to scan

Scan Modes:
  -m, --mode {fast|standard|deep|full}
                        Scan depth (default: standard)
  --max-pages INT       Maximum pages to crawl (default: 100)
  --max-depth INT       Maximum crawl depth (default: 2)
  --no-crawl            Disable crawling, scan target only

Performance:
  -t, --threads INT     Number of threads (default: auto)
  --timeout INT         Request timeout in seconds (default: 12/15)
  --delay FLOAT         Delay between requests (default: 0.05)
  --rate-limit INT      Requests per second (default: 100)

Authentication:
  --login-url URL       Login page URL
  -u, --username USER   Username for login
  -p, --password PASS   Password for login
  --auth-token TOKEN    Bearer/API token
  --auth-type {bearer|basic|digest}

Network:
  --proxy URL           HTTP/HTTPS proxy URL
  --cookies STR         Cookies (format: name=value;name2=value2)
  --custom-headers JSON Custom headers as JSON
  --no-verify-ssl       Disable SSL verification
  --no-follow-redirects Don't follow redirects

Scope & Filtering:
  --scope-domains DOMAIN [DOMAIN ...]
                        Domains to include in scope
  --exclude-paths PATH [PATH ...]
                        URL patterns to exclude
  --include-paths PATH [PATH ...]
                        URL patterns to include

Output:
  -o, --output NAME     Report name (default: scan_TIMESTAMP)
  --format {html|json|both}
                        Report format (default: both)
  --silent              Suppress console output
  -v, --verbose         Verbose debug output

Configuration:
  -c, --config FILE     Load config from YAML/JSON file
  --version             Show version
```

### Configuration File

Create `config.yaml`:
```yaml
mode: deep
threads: 8
max_pages: 500
max_depth: 3
rate_limit: 50
safe_mode: true
exclude_paths:
  - /logout
  - /admin
  - /*.pdf
```

Run with config:
```bash
python shadowscan.py https://example.com -c config.yaml
```

---

## 🎯 Detector Categories

### Injection Attacks
- **XSS** (Cross-Site Scripting) - Reflected, Stored, DOM-based
- **SQLi** (SQL Injection) - Error, Boolean, Time-based
- **NoSQL Injection** - MongoDB, CouchDB techniques
- **SSTI** (Server-Side Template Injection) - Jinja2, Freemarker, etc.
- **Command Injection** - OS command execution
- **LDAP Injection** - LDAP filter attacks
- **XPath Injection** - XML path attacks

### Path/File Traversal
- **LFI** (Local File Inclusion)
- **Path Traversal** - ../../../ attacks
- **File Inclusion** - PHP wrappers, filter chains

### Server-Side Vulnerabilities
- **SSRF** (Server-Side Request Forgery)
- **XXE** (XML External Entity) - XXE injection
- **Deserialization** - Unsafe object deserialization
- **Mass Assignment** - Over-posting vulnerabilities

### Access Control
- **IDOR** (Insecure Direct Object Reference)
- **CORS Misconfiguration** - Wildcard origins, credentials
- **Clickjacking** - X-Frame-Options bypass
- **Open Redirect** - Arbitrary redirects

### Authentication & Session
- **JWT Issues** - Weak signatures, missing validation
- **Session Fixation** - Session ID reuse
- **Cookie Security** - Missing Secure, HttpOnly flags
- **Password Reset Flaws** - Token prediction

### Information Disclosure
- **Sensitive Files** - .env, .git, config files
- **Secrets Detection** - API keys, tokens in responses
- **Technology Fingerprinting** - Framework detection
- **WAF Detection** - Security system identification
- **Security Headers** - Missing HSTS, CSP, X-Frame-Options

### Other Vulnerabilities
- **Prototype Pollution** - JavaScript object pollution
- **HTTP Smuggling** - Request smuggling attacks
- **CRLF Injection** - Response header injection
- **Host Header Injection** - Web cache poisoning
- **Cache Deception** - Cache-based attacks
- **Race Conditions** - Timing-based vulnerabilities

---

## 📊 Reports

Reports are saved to `reports/` directory:

### HTML Report
Beautiful dark-themed HTML report with:
- Risk score and grade (A-F)
- Severity breakdown (Critical, High, Medium, Low)
- Detailed findings with evidence and remediation
- Endpoint list with parameters
- OWASP Top 10 and CWE mappings

```bash
# Generate HTML report
python shadowscan.py https://example.com -o my_scan --format html
# Open: reports/my_scan.html
```

### JSON Report
Structured JSON format for automation and parsing:
```bash
python shadowscan.py https://example.com --format json
```

### JSONL Logs
Stream of events for real-time monitoring:
```bash
tail -f logs/scan_*.jsonl
```

---

## 🌍 Termux-Specific Setup

### Install Python on Termux
```bash
pkg update && pkg upgrade
pkg install python python-pip
pkg install git
```

### Clone & Setup
```bash
cd ~
git clone https://github.com/amirfarssoo-max/ShadowScan.git
cd ShadowScan
pip install -r requirements.txt
```

### Run on Termux
```bash
# Fast scan to conserve resources
python shadowscan.py https://example.com -m fast -t 2

# With verbosity
python shadowscan.py https://example.com -v
```

**Note**: Termux automatically enables `termux-wake-lock` to prevent sleep during scanning.

---

## 🔌 Plugin System

Create custom detectors in `detectors/` directory:

```python
# detectors/my_detector.py
from shadowscan import BaseDetector, Severity, Finding

class MyCustomDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="My Custom Detector",
            description="Detects custom vulnerability",
            category="custom",
            severity=Severity.HIGH
        )
    
    async def detect(self, client, endpoint, options):
        findings = []
        # Your detection logic here
        for param in endpoint.parameters:
            resp = await self.test_payload(client, endpoint.url, param, "test_payload")
            if resp and "vulnerable_indicator" in resp.text:
                self.add_finding(
                    title="Custom Vulnerability Found",
                    description="Details about the vulnerability",
                    url=endpoint.url,
                    parameter=param,
                    confidence=0.9,
                    verified=True
                )
        return self.findings
```

Place `my_detector.py` in `detectors/` and it will auto-load!

---

## 📈 Performance Tips

### For Termux/Low-Resource Devices
```bash
python shadowscan.py https://example.com \
  -m fast \
  --threads 2 \
  --rate-limit 50 \
  --delay 0.1 \
  --max-pages 50 \
  --max-depth 1
```

### For High-Performance Servers
```bash
python shadowscan.py https://example.com \
  -m full \
  --threads 16 \
  --rate-limit 500 \
  --delay 0.01 \
  --max-pages 1000 \
  --max-depth 5
```

### Crawl Mode Settings
- **fast**: Quick endpoint discovery
- **normal**: Balanced discovery
- **thorough**: Complete enumeration

---

## ⚠️ Disclaimer

**ShadowScan is for authorized security testing only.**

- Only scan systems you own or have explicit written permission to test
- Unauthorized scanning is illegal and unethical
- The author is not responsible for misuse or damage caused by this tool
- Use responsibly and follow all applicable laws

---

## 🐛 Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'httpx'`
```bash
pip install httpx
```

### Issue: SSL/TLS certificate errors
```bash
# Disable verification (not recommended for production)
python shadowscan.py https://example.com --no-verify-ssl
```

### Issue: Timeout errors
```bash
# Increase timeout
python shadowscan.py https://example.com --timeout 30
```

### Issue: Too many requests blocked
```bash
# Lower rate limit
python shadowscan.py https://example.com --rate-limit 30 --delay 0.2
```

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- **GitHub**: [amirfarssoo-max/ShadowScan](https://github.com/amirfarssoo-max/ShadowScan)
- **Issues**: [Report bugs](https://github.com/amirfarssoo-max/ShadowScan/issues)
- **Discussions**: [Ask questions](https://github.com/amirfarssoo-max/ShadowScan/discussions)

---

## ⭐ Show Your Support

If ShadowScan helped you, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs and suggesting features
- 📢 Sharing with your security community
- 🤝 Contributing improvements

---

## 📧 Contact

**Author**: amirfarssoo-max

---

**Last Updated**: 2026-07-15  
**Version**: 31.2.0-FUSION-FIXED
