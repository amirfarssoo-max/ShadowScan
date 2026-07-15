#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ █████╗               ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗              ║
║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████║              ║
║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══██║              ║
║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║  ██║              ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝              ║
║   Fusion v31.2 • 50 Detectors • Fixed Concurrency & Logic Bugs            ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations
import os, sys, re, json, time, random, hashlib, sqlite3, argparse, threading, logging
import html as html_module, base64, asyncio, traceback, uuid, io, getpass, hmac, statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any, Callable, Awaitable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from urllib.robotparser import RobotFileParser
import contextvars
import signal
import functools
import inspect

# ═══════════════════════════════════════════════════════════════════════════════
# Environment & Termux
# ═══════════════════════════════════════════════════════════════════════════════
IS_TERMUX = os.path.exists('/data/data/com.termux')
CPU_COUNT = os.cpu_count() or 2
MAX_WORKERS = min(6, CPU_COUNT * 2) if CPU_COUNT <= 4 else min(12, CPU_COUNT * 4)
DEFAULT_TIMEOUT = 12 if IS_TERMUX else 15
VERSION = "31.2.0-FUSION-FIXED"
BASE_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
DETECTORS_DIR = BASE_DIR / "detectors"
KNOWLEDGE_DB = DATA_DIR / "fusion_knowledge.db"
for d in [REPORTS_DIR, DATA_DIR, LOGS_DIR, DETECTORS_DIR]:
    d.mkdir(exist_ok=True, parents=True)
if IS_TERMUX:
    try: os.system('termux-wake-lock')
    except: pass
try: __import__('tracemalloc').start()
except: pass
scan_ctx = contextvars.ContextVar('scan_ctx', default={'scan_id': 'sys', 'request_id': 'sys'})

# ═══════════════════════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════════════════════
def check_dep(m):
    try: __import__(m); return True
    except: return False
def require(m, p=None):
    if not check_dep(m):
        print(f"[!] Missing: {m}. Install: pip install {p or m}"); sys.exit(1)

require('httpx')
import httpx
from httpx import AsyncClient, Timeout

HAS_RICH = check_dep('rich')
HAS_BS4 = check_dep('bs4')
HAS_YAML = check_dep('yaml')
HAS_PLAYWRIGHT = check_dep('playwright')
if HAS_RICH:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
if HAS_BS4: from bs4 import BeautifulSoup
if HAS_YAML: import yaml

def load_yaml_payloads(path: Path = BASE_DIR / "payloads.yaml") -> dict:
    default = {
        'xss': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"-alert(1)-"',
                '<svg onload=alert(1)>', 'javascript:alert(1)', '<ScRiPt>alert(1)</ScRiPt>'],
        'sqli': [("' OR '1'='1", 'basic_or'), ("' AND SLEEP(5)--", 'time'),
                 ("' UNION SELECT NULL--", 'union'), ("' OR 1=1--", 'basic_or_comment')],
        'nosqli': [('{"$gt":""}', 'gt'), ('{"$ne":null}', 'ne'), ('{"$regex":".*"}', 'regex')],
        'ssti': [('{{7*7}}', '49', 'jinja2'), ('${7*7}', '49', 'freemarker'),
                 ('{{config}}', 'config', 'flask'), ('<%= 7*7 %>', '49', 'erb')],
        'lfi': ['../../../etc/passwd', '....//....//etc/passwd', '..\\..\\..\\windows\\win.ini',
                'file:///etc/passwd', 'php://filter/convert.base64-encode/resource=index.php'],
        'ssrf': ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/',
                 'http://localhost:8080', 'http://[::1]:80'],
        'redirect': ['https://evil.com', '//evil.com', '///evil.com', 'https:evil.com'],
        'prototype_pollution': [('__proto__[polluted]=true', 'query'),
                                ('{"__proto__":{"polluted":true}}', 'json'),
                                ('constructor[prototype][polluted]=true', 'nested')],
        'deserialization': [('O:8:"stdClass":0:{}', 'php'),
                            ('{"$type":"System.Data.DataSet"}', '.net'),
                            ('rO0ABXQ=', 'java')],
        'mass_assignment': [{'role': 'admin'}, {'isAdmin': True}, {'admin': True}],
        'crlf': ['\r\nSet-Cookie: injected=true', '%0d%0aSet-Cookie:%20injected=true'],
        'xxe': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        'cmdi': ['; sleep 5 #', '| sleep 5', '` sleep 5 `', '$(sleep 5)', '& sleep 5 &'],
        'ldapi': ['*)(uid=*))(|(uid=*', 'admin*)(&)', '*)(|(password=*))'],
        'xpath': ["' or '1'='1", "' or 1=1] | //user", "' and '1'='1"],
        'email_header': ['bcc: evil@evil.com', 'to: evil@evil.com\r\nCC: evil@evil.com'],
        'ssi': ['<!--#exec cmd="id" -->', '<!--#echo var="DOCUMENT_ROOT" -->'],
        'hpp': ['?id=1&id=2', '?id=1&id=2&id=3', '?id=1&id=2&id=3&id=4'],
        'password_reset': ['evil@evil.com', 'attacker.com', 'evil@evil.com%0aCc:admin@target.com'],
        'cache_deception': ['/path/to/nonexistent.css', '/nonexistent', '/test.js'],
        'cookie_tossing': ['evil=1; domain=.example.com; path=/'],
        'open_redirect': ['http://evil.com', '//evil.com', '///evil.com'],
        'template_injection': ['{{7*7}}', '${7*7}', '<%=7*7%>'],
        'path_traversal': ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini'],
        'command_injection': [';id', '|id', '`id`', '$(id)'],
        'file_inclusion': ['file:///etc/passwd', 'php://filter/convert.base64-encode/resource=index'],
    }
    if HAS_YAML and path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f: return yaml.safe_load(f) or default
        except: pass
    return default

PAYLOADS = load_yaml_payloads()
COMMON_PARAMS = ['id','user','username','name','q','search','query','page','category','type',
                 'redirect','url','file','path','callback','email','token','key','cmd','dir',
                 'filepath','email_addr','to','cc','action','mode','option','view','template',
                 'include','page_id','article_id','product_id','order_id','user_id','admin',
                 'debug','test','password','pass','pwd','secret','api_key','apikey','access_token']
SECRETS_PATTERNS = {
    'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'GitHub Token': re.compile(r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}'),
    'Stripe Key': re.compile(r'sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24}'),
    'Private Key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    'JWT Token': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    'Google API Key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'Slack Token': re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
    'Heroku API Key': re.compile(r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    'Generic Secret': re.compile(r'(?:secret|password|api[_-]?key|token)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?', re.I),
}
TECH_SIGNATURES = {
    'Next.js': ['_next/static', '__NEXT_DATA__', 'next.js'],
    'React': ['react', '_reactRoot', 'ReactDOM', 'createElement'],
    'Vue.js': ['vue.js', '__vue__', 'Vue.config', 'v-bind'],
    'Angular': ['angular', 'ng-version', 'ng-app', 'ng-controller'],
    'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
    'Laravel': ['laravel_session', 'XSRF-TOKEN', 'Laravel'],
    'Django': ['csrftoken', 'django', 'sessionid'],
    'Express': ['x-powered-by: express', 'express', 'connect.sid'],
    'Spring Boot': ['actuator', 'spring', 'X-Application-Context'],
    'Flask': ['flask', 'session', 'werkzeug'],
    'Ruby on Rails': ['rails', 'csrf-param', 'authenticity_token'],
    'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION', 'ASP.NET_SessionId'],
    'jQuery': ['jquery', '$(', 'jQuery'],
    'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
    'Tailwind CSS': ['tailwind', 'tw-'],
}
WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
    'Akamai': ['akamai', 'akamaighost'],
    'AWS WAF': ['x-amz-cf-id', 'x-amzn-RequestId'],
    'Imperva': ['incap_ses', 'visid_incap'],
    'Sucuri': ['x-sucuri-id', 'sucuri'],
    'ModSecurity': ['mod_security', 'NOYB'],
    'F5 BIG-IP': ['BigIP', 'F5'],
    'Barracuda': ['barracuda'],
    'Fortinet': ['fortigate', 'FortiWeb'],
    'Wordfence': ['wordfence'],
}
SENSITIVE_FILES = {
    '/.env': 'Environment secrets',
    '/.git/HEAD': 'Git repository',
    '/.git/config': 'Git config',
    '/.htaccess': 'Apache config',
    '/wp-config.php': 'WordPress config',
    '/wp-config.php.bak': 'WordPress config backup',
    '/phpinfo.php': 'PHP info',
    '/swagger.json': 'Swagger spec',
    '/swagger.yaml': 'Swagger spec',
    '/graphql': 'GraphQL endpoint',
    '/admin': 'Admin panel',
    '/actuator': 'Spring Actuator',
    '/actuator/env': 'Environment variables',
    '/actuator/health': 'Health check',
    '/package.json': 'Node package',
    '/package-lock.json': 'Node lock file',
    '/robots.txt': 'Robots file',
    '/sitemap.xml': 'Sitemap',
    '/crossdomain.xml': 'Crossdomain policy',
    '/clientaccesspolicy.xml': 'Client access policy',
    '/WEB-INF/web.xml': 'Java web config',
    '/WEB-INF/applicationContext.xml': 'Spring config',
    '/config.php': 'PHP config',
    '/config.php.bak': 'PHP config backup',
    '/db.php': 'Database config',
    '/dump.sql': 'SQL dump',
    '/backup.sql': 'SQL backup',
    '/.svn/entries': 'SVN entries',
    '/.DS_Store': 'macOS metadata',
    '/Thumbs.db': 'Windows thumbnail cache',
    '/server-status': 'Apache status',
    '/server-info': 'Apache info',
    '/info.php': 'PHP info',
    '/test.php': 'Test file',
    '/shell.php': 'Shell file',
    '/cmd.php': 'Command file',
    '/upload.php': 'Upload script',
    '/api/v1': 'API endpoint',
    '/api/v2': 'API endpoint',
    '/api/docs': 'API docs',
    '/api/swagger': 'API swagger',
    '/.well-known/security.txt': 'Security contact',
    '/security.txt': 'Security contact',
}

# ═══════════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════════
class Severity(Enum):
    CRITICAL = ("critical", "🔴", 9.5, 25)
    HIGH = ("high", "🟠", 8.0, 15)
    MEDIUM = ("medium", "🟡", 5.5, 8)
    LOW = ("low", "🔵", 3.0, 3)
    INFO = ("info", "⚪", 1.0, 0)
    
    def __init__(self, v, i, c, w):
        self._value_ = v
        self.icon = i
        self.cvss = c
        self.weight = w
    
    @classmethod
    def from_string(cls, s: str) -> 'Severity':
        s = s.lower().strip()
        for sev in cls:
            if sev.value == s:
                return sev
        return cls.INFO

@dataclass
class ScanResponse:
    status_code: int
    text: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    elapsed: float
    url: str
    is_success: bool
    raw: Any = None
    content_type: str = ""
    content_length: int = 0
    
    def __post_init__(self):
        self.content_type = self.headers.get('content-type', '').split(';')[0].strip()
        self.content_length = len(self.text)

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    content_type: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    def __hash__(self):
        return hash((self.url, self.method))
    
    def __eq__(self, other):
        if not isinstance(other, Endpoint):
            return False
        return self.url == other.url and self.method == other.method

@dataclass
class Finding:
    title: str
    severity: Severity
    category: str
    description: str
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp_id: str = ""
    pci_dss: str = ""
    confidence: float = 1.0
    verified: bool = False
    verification_stages: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_preview: str = ""
    
    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        return d
    
    def unique_id(self):
        return hashlib.sha256(
            f"{self.title}|{self.url}|{self.parameter}|{self.payload[:30]}".encode()
        ).hexdigest()[:16]

@dataclass
class ScanOptions:
    target: str
    mode: str = "standard"
    timeout: int = DEFAULT_TIMEOUT
    delay: float = 0.05
    threads: int = MAX_WORKERS
    max_pages: int = 100
    max_depth: int = 2
    crawl: bool = True
    crawl_mode: str = "fast"
    pdf: bool = False
    html: bool = True
    jsonl: bool = True
    silent: bool = False
    verbose: bool = False
    rate_limit: int = 100
    safe_mode: bool = True
    scope_domains: List[str] = field(default_factory=list)
    login_url: str = ""
    username: str = ""
    password: str = ""
    config_file: str = ""
    exclude_paths: List[str] = field(default_factory=list)
    include_paths: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: str = ""
    auth_type: str = "bearer"  # bearer, basic, digest
    follow_redirects: bool = True
    verify_ssl: bool = True
    output_format: str = "html"  # html, json, pdf, text
    report_name: str = ""
    
    def __post_init__(self):
        if not self.target:
            raise ValueError("Target required")
        t = self.target.strip()
        if not t.startswith(('http://', 'https://')):
            t = 'https://' + t
        parsed = urlparse(t)
        if not parsed.netloc:
            raise ValueError("Invalid URL")
        self.target = t
        if not self.scope_domains:
            self.scope_domains = [parsed.netloc]
        if self.report_name == "":
            self.report_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Mapper
# ═══════════════════════════════════════════════════════════════════════════════
class ComplianceMapper:
    OWASP_MAPPING = {
        'xss': ('A03:2021-Injection', 'CWE-79'),
        'sqli': ('A03:2021-Injection', 'CWE-89'),
        'nosqli': ('A03:2021-Injection', 'CWE-943'),
        'ssti': ('A03:2021-Injection', 'CWE-1336'),
        'lfi': ('A01:2021-Broken Access Control', 'CWE-22'),
        'ssrf': ('A10:2021-SSRF', 'CWE-918'),
        'cors': ('A01:2021-Broken Access Control', 'CWE-942'),
        'headers': ('A05:2021-Misconfig', 'CWE-693'),
        'cookies': ('A07:2021-Auth Failures', 'CWE-614'),
        'csrf': ('A01:2021-Broken Access Control', 'CWE-352'),
        'redirect': ('A01:2021-Broken Access Control', 'CWE-601'),
        'idor': ('A01:2021-Broken Access Control', 'CWE-639'),
        'jwt': ('A07:2021-Auth Failures', 'CWE-345'),
        'clickjacking': ('A05:2021-Misconfig', 'CWE-1021'),
        'secrets': ('A02:2021-Crypto Failures', 'CWE-200'),
        'prototype': ('A08:2021-Integrity', 'CWE-1321'),
        'mass_assignment': ('A01:2021-Broken Access Control', 'CWE-915'),
        'deserialization': ('A08:2021-Integrity', 'CWE-502'),
        'graphql': ('A01:2021-Broken Access Control', 'CWE-200'),
        'websocket': ('A03:2021-Injection', 'CWE-79'),
        'xxe': ('A05:2021-Misconfig', 'CWE-611'),
        'smuggling': ('A05:2021-Misconfig', 'CWE-444'),
        'crlf': ('A05:2021-Misconfig', 'CWE-93'),
        'host_header': ('A05:2021-Misconfig', 'CWE-644'),
        'cmdi': ('A03:2021-Injection', 'CWE-78'),
        'ldapi': ('A03:2021-Injection', 'CWE-90'),
        'xpath': ('A03:2021-Injection', 'CWE-643'),
        'email_header': ('A03:2021-Injection', 'CWE-74'),
        'ssi': ('A03:2021-Injection', 'CWE-97'),
        'hpp': ('A04:2021-Insecure Design', 'CWE-235'),
        'password_reset': ('A07:2021-Auth Failures', 'CWE-640'),
        'cache_deception': ('A04:2021-Insecure Design', 'CWE-524'),
        'cookie_tossing': ('A07:2021-Auth Failures', 'CWE-784'),
        'subdomain_takeover': ('A01:2021-Broken Access Control', 'CWE-200'),
        'session_fixation': ('A07:2021-Auth Failures', 'CWE-384'),
        'race_condition': ('A04:2021-Insecure Design', 'CWE-362'),
        'tabnabbing': ('A05:2021-Misconfig', 'CWE-1022'),
        'dns_rebinding': ('A01:2021-Broken Access Control', 'CWE-350'),
        'open_bucket': ('A01:2021-Broken Access Control', 'CWE-200'),
        'debug_endpoint': ('A05:2021-Misconfig', 'CWE-489'),
        'information_disclosure': ('A01:2021-Broken Access Control', 'CWE-200'),
        'rate_limiting': ('A04:2021-Insecure Design', 'CWE-770'),
        'insecure_direct_object_reference': ('A01:2021-Broken Access Control', 'CWE-639'),
        'security_misconfiguration': ('A05:2021-Misconfig', 'CWE-16'),
        'vulnerable_components': ('A06:2021-Vulnerable Components', 'CWE-1104'),
        'authentication_bypass': ('A07:2021-Auth Failures', 'CWE-287'),
        'insufficient_logging': ('A09:2021-Logging Failures', 'CWE-778'),
        'server_side_request_forgery': ('A10:2021-SSRF', 'CWE-918'),
    }
    
    PCI_DSS_MAPPING = {
        'xss': 'PCI-DSS 6.5.7',
        'sqli': 'PCI-DSS 6.5.1',
        'ssrf': 'PCI-DSS 6.5.9',
        'headers': 'PCI-DSS 6.5.10',
        'secrets': 'PCI-DSS 6.5.3',
        'cmdi': 'PCI-DSS 6.5.2',
        'lfi': 'PCI-DSS 6.5.4',
        'xxe': 'PCI-DSS 6.5.5',
        'insecure_direct_object_reference': 'PCI-DSS 6.5.4',
        'security_misconfiguration': 'PCI-DSS 6.5.10',
    }
    
    @classmethod
    def get_compliance(cls, category):
        owasp_cwe = cls.OWASP_MAPPING.get(category, ('', ''))
        pci = cls.PCI_DSS_MAPPING.get(category, '')
        return (owasp_cwe[0], owasp_cwe[1], pci)

# ═══════════════════════════════════════════════════════════════════════════════
# Helper Classes
# ═══════════════════════════════════════════════════════════════════════════════
class TokenBucket:
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = float(rate)
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.updated_at = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1

class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=30):
        self.failure_count = 0
        self.state = 'CLOSED'
        self.last_failure_time = 0.0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._lock = threading.Lock()
    
    def record_success(self):
        with self._lock:
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
    
    def record_failure(self):
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.state == 'HALF_OPEN' or self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
    
    def can_execute(self) -> bool:
        with self._lock:
            if self.state == 'CLOSED':
                return True
            if self.state == 'OPEN':
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    return True
                return False
            return True

class StructuredLogger:
    def __init__(self, silent=False, verbose=False):
        self.silent = silent
        self.verbose = verbose
        self.console = Console() if HAS_RICH and not silent else None
        self._lock = threading.Lock()  # Lock for file writes in executor thread
        self.log_file = LOGS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        if not self.log_file.exists():
            self.log_file.touch()
    
    def _log(self, level, msg, **kw):
        if self.silent and level not in ('ERROR', 'CRITICAL'):
            return
        ctx = scan_ctx.get()
        entry = {
            "ts": datetime.now().isoformat(),
            "lvl": level,
            "msg": msg,
            "scan_id": ctx.get('scan_id', '?'),
            "req_id": ctx.get('request_id', '?'),
            **kw
        }
        # Offload file write to thread pool so event loop is not blocked
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, self._write_log, entry)
        
        # Console output remains lightweight
        if self.console:
            color = {
                'INFO': 'blue',
                'SUCCESS': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red bold',
                'FINDING': 'magenta',
                'DEBUG': 'dim'
            }.get(level, 'white')
            self.console.print(f"[{color}]{entry['ts'].split('T')[1][:8]} [{level}] {msg}[/{color}]")
        else:
            print(f"[{level}] {msg}")
    
    def _write_log(self, entry):
        with self._lock:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            except:
                pass
    
    def info(self, m, **k): self._log('INFO', m, **k)
    def success(self, m, **k): self._log('SUCCESS', m, **k)
    def warning(self, m, **k): self._log('WARNING', m, **k)
    def error(self, m, **k): self._log('ERROR', m, **k)
    def critical(self, m, **k): self._log('CRITICAL', m, **k)
    def debug(self, m, **k):
        if self.verbose: self._log('DEBUG', m, **k)
    def finding(self, f):
        if self.silent: return
        v = " ✓" if f.verified else ""
        self._log('FINDING', f"{f.severity.icon} [{f.severity.value.upper()}] {f.title}{v} ({f.confidence:.0%})",
                  cat=f.category, url=f.url, param=f.parameter)

_log = StructuredLogger()

# ═══════════════════════════════════════════════════════════════════════════════
# DatabaseManager – полностью переработан для безопасной работы в asyncio
# ═══════════════════════════════════════════════════════════════════════════════
class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        # Используем одно соединение + asyncio.Lock + выполнение в executor
        self._conn = sqlite3.connect(db_path, timeout=15, check_same_thread=False)
        self._conn.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
        self._async_lock = asyncio.Lock()
        self._init_db()
    
    def _init_db(self):
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS successful_payloads (
            category TEXT,
            payload TEXT,
            context TEXT DEFAULT '',
            success_count INTEGER DEFAULT 1,
            last_used TEXT,
            UNIQUE(category, payload, context)
        );
        CREATE TABLE IF NOT EXISTS false_positives (
            pattern TEXT,
            category TEXT DEFAULT '',
            reason TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_date TEXT,
            duration REAL,
            findings_count INTEGER,
            score INTEGER,
            grade TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            title TEXT,
            severity TEXT,
            category TEXT,
            url TEXT,
            parameter TEXT,
            payload TEXT,
            evidence TEXT,
            confidence REAL,
            verified INTEGER,
            timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            url TEXT,
            method TEXT,
            status_code INTEGER,
            content_type TEXT,
            timestamp TEXT
        );
        """)
        self._conn.commit()
    
    async def _execute_async(self, query: str, params: tuple = ()):
        async with self._async_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._sync_exec, query, params)
    
    def _sync_exec(self, query: str, params: tuple):
        try:
            cur = self._conn.execute(query, params)
            self._conn.commit()
            return cur
        except sqlite3.Error as e:
            _log.error(f"DB Error: {e}")
            return None
    
    async def execute(self, query, params=()):
        await self._execute_async(query, params)
    
    async def fetchall(self, query, params=()):
        cur = await self._execute_async(query, params)
        return cur.fetchall() if cur else []
    
    async def fetchone(self, query, params=()):
        cur = await self._execute_async(query, params)
        return cur.fetchone() if cur else None

kb_db = DatabaseManager(KNOWLEDGE_DB)

# ═══════════════════════════════════════════════════════════════════════════════
# KnowledgeBase – all methods async due to DB
# ═══════════════════════════════════════════════════════════════════════════════
class KnowledgeBase:
    def __init__(self):
        self._load_defaults()
    
    def _load_defaults(self):
        fps = [
            ('X-Powered-By', 'headers', 'Info only'),
            ('example.com', 'secrets', 'Example'),
            ('localhost', 'ssrf', 'Localhost reference'),
            ('127.0.0.1', 'ssrf', 'Localhost reference'),
            ('test', 'general', 'Test value'),
        ]
        for p, cat, r in fps:
            # Use the non‑async execute because init is sync, but we can use a small helper
            self._conn_sync_exec(
                "INSERT OR IGNORE INTO false_positives VALUES (?,?,?,?)",
                (p, cat, r, datetime.now().isoformat())
            )
    
    def _conn_sync_exec(self, q, p):
        try:
            kb_db._conn.execute(q, p)
            kb_db._conn.commit()
        except: pass
    
    async def record_success(self, category, payload, context=""):
        await kb_db.execute(
            """INSERT INTO successful_payloads VALUES (?,?,?,?,?) 
               ON CONFLICT(category, payload, context) DO UPDATE SET 
               success_count = success_count + 1, last_used = ?""",
            (category, payload, context, datetime.now().isoformat(), datetime.now().isoformat())
        )
    
    async def get_top_payloads(self, category, limit=10):
        rows = await kb_db.fetchall(
            "SELECT payload FROM successful_payloads WHERE category=? ORDER BY success_count DESC LIMIT ?",
            (category, limit)
        )
        return [r[0] for r in rows] if rows else []
    
    async def is_false_positive(self, text, category):
        if not text:
            return False
        rows = await kb_db.fetchall(
            "SELECT pattern FROM false_positives WHERE category=? OR category=''",
            (category,)
        )
        t = text.lower()
        return any(p[0].lower() in t for p in rows)
    
    async def save_scan_history(self, target, duration, findings_count, score, grade):
        await kb_db.execute(
            "INSERT INTO scan_history VALUES (NULL,?,?,?,?,?,?)",
            (target, datetime.now().isoformat(), duration, findings_count, score, grade)
        )
    
    async def save_finding(self, scan_id, finding: Finding):
        await kb_db.execute(
            """INSERT INTO findings VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, finding.title, finding.severity.value, finding.category,
             finding.url, finding.parameter, finding.payload[:500],
             finding.evidence[:500], finding.confidence, 1 if finding.verified else 0,
             finding.timestamp)
        )
    
    async def save_endpoint(self, scan_id, endpoint: Endpoint):
        await kb_db.execute(
            "INSERT INTO endpoints VALUES (NULL,?,?,?,?,?,?)",
            (scan_id, endpoint.url, endpoint.method, endpoint.status_code,
             endpoint.content_type, datetime.now().isoformat())
        )

# ═══════════════════════════════════════════════════════════════════════════════
# Async HTTP Client
# ═══════════════════════════════════════════════════════════════════════════════
class AsyncHTTPClient:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
        "ShadowScan/31.2",
        "Mozilla/5.0 (compatible; ShadowScan/31.2; +https://github.com/shadowscan)",
    ]
    
    def __init__(self, timeout=DEFAULT_TIMEOUT, concurrency=20, rate_limit=100, cookies=None,
                 headers=None, proxy=None, verify_ssl=True, follow_redirects=True):
        self.timeout = Timeout(timeout, connect=5.0, read=timeout, write=timeout)
        self.concurrency = concurrency
        self.rate_limiter = TokenBucket(rate_limit)
        self._client = None
        self._semaphore = asyncio.Semaphore(concurrency)
        self._ua_index = 0
        self.cb = CircuitBreaker()
        self.cookies = cookies or {}
        self.custom_headers = headers or {}
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
    
    async def __aenter__(self):
        proxy_config = None
        if self.proxy:
            proxy_config = httpx.Proxy(url=self.proxy)
        
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            http2=True,
            limits=httpx.Limits(
                max_connections=self.concurrency,
                max_keepalive_connections=10,
                keepalive_expiry=30
            ),
            cookies=self.cookies,
            proxies=proxy_config,
            verify=self.verify_ssl
        )
        return self
    
    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
    
    def _next_ua(self):
        ua = self.USER_AGENTS[self._ua_index % len(self.USER_AGENTS)]
        self._ua_index += 1
        return ua
    
    async def _request(self, method, url, **kwargs):
        await self.rate_limiter.acquire()
        if not self.cb.can_execute():
            return None
        
        async with self._semaphore:
            try:
                headers = kwargs.pop('headers', {})
                headers['User-Agent'] = self._next_ua()
                headers.update(self.custom_headers)
                
                start_time = time.monotonic()
                resp = await self._client.request(method, url, headers=headers, **kwargs)
                elapsed = time.monotonic() - start_time
                
                self.cb.record_success()
                
                return ScanResponse(
                    status_code=resp.status_code,
                    text=resp.text,
                    headers=dict(resp.headers),
                    cookies={c.name: c.value for c in resp.cookies},
                    elapsed=elapsed,
                    url=str(resp.url),
                    is_success=resp.status_code < 500,
                    raw=resp
                )
            except httpx.TimeoutException:
                _log.debug(f"Timeout: {method} {url}")
                self.cb.record_failure()
                return None
            except httpx.ConnectError:
                _log.debug(f"Connection error: {method} {url}")
                self.cb.record_failure()
                return None
            except httpx.HTTPError as e:
                _log.debug(f"HTTP error: {method} {url}: {e}")
                self.cb.record_failure()
                return None
            except Exception as e:
                _log.debug(f"Request error: {method} {url}: {e}")
                self.cb.record_failure()
                return None
    
    async def get(self, url, **kwargs): return await self._request("GET", url, **kwargs)
    async def post(self, url, **kwargs): return await self._request("POST", url, **kwargs)
    async def put(self, url, **kwargs): return await self._request("PUT", url, **kwargs)
    async def delete(self, url, **kwargs): return await self._request("DELETE", url, **kwargs)
    async def options(self, url, **kwargs): return await self._request("OPTIONS", url, **kwargs)
    async def head(self, url, **kwargs): return await self._request("HEAD", url, **kwargs)
    async def patch(self, url, **kwargs): return await self._request("PATCH", url, **kwargs)

# ═══════════════════════════════════════════════════════════════════════════════
# Base Detector Class – поддержка переопределения severity
# ═══════════════════════════════════════════════════════════════════════════════
class BaseDetector:
    def __init__(self, name: str, description: str, category: str, severity: Severity):
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.findings: List[Finding] = []
        self.knowledge_base = KnowledgeBase()
        self._lock = asyncio.Lock()
    
    async def detect(self, client: AsyncHTTPClient, endpoint: Endpoint, 
                     options: ScanOptions) -> List[Finding]:
        raise NotImplementedError
    
    async def test_payload(self, client, url, param, payload, method="GET", **kwargs):
        if method == "GET":
            params = {param: payload}
            return await client.get(url, params=params, **kwargs)
        else:
            data = {param: payload}
            return await client.post(url, data=data, **kwargs)
    
    def add_finding(self, title: str, description: str, url: str = "",
                   parameter: str = "", payload: str = "", evidence: str = "",
                   confidence: float = 1.0, verified: bool = False,
                   remediation: str = "", request_headers: Dict = None,
                   response_headers: Dict = None, response_body: str = "",
                   severity: Optional[Severity] = None):  # ✅ Фикс #1: возможность override severity
        owasp, cwe, pci = ComplianceMapper.get_compliance(self.category)
        finding = Finding(
            title=title,
            severity=severity or self.severity,   # ✅ используем переданный или стандартный
            category=self.category,
            description=description,
            url=url,
            parameter=parameter,
            payload=str(payload)[:500],
            evidence=evidence[:1000],
            remediation=remediation or self.get_remediation(),
            cwe_id=cwe,
            owasp_id=owasp,
            pci_dss=pci,
            confidence=confidence,
            verified=verified,
            request_headers=request_headers or {},
            response_headers=response_headers or {},
            response_body_preview=response_body[:500] if response_body else ""
        )
        self.findings.append(finding)
        _log.finding(finding)
        return finding
    
    def get_remediation(self) -> str:
        remediations = {
            'xss': 'Implement proper output encoding and input validation. Use Content-Security-Policy headers.',
            'sqli': 'Use parameterized queries or prepared statements. Implement input validation and least privilege.',
            'nosqli': 'Validate and sanitize all user inputs. Use schema validation libraries.',
            'ssti': 'Avoid using user input in templates. Use sandboxed template engines.',
            'lfi': 'Implement proper access controls. Use whitelist-based file inclusion.',
            'ssrf': 'Validate and restrict outbound requests. Use allowlists for URLs.',
            'redirect': 'Validate and sanitize redirect URLs. Use whitelist-based redirects.',
            'prototype': 'Use Object.create(null) for objects. Freeze prototypes with Object.freeze().',
            'deserialization': 'Avoid deserializing untrusted data. Use safe serialization formats like JSON.',
            'mass_assignment': 'Use whitelist-based mass assignment protection.',
            'crlf': 'Sanitize CRLF characters in user inputs. Use proper header encoding.',
            'xxe': 'Disable XML external entity processing. Use less complex data formats.',
            'cmdi': 'Avoid system calls with user input. Use proper input validation and sanitization.',
            'headers': 'Implement proper security headers: HSTS, X-Frame-Options, X-Content-Type-Options.',
            'cookies': 'Set Secure, HttpOnly, and SameSite flags on cookies.',
            'csrf': 'Implement anti-CSRF tokens. Use SameSite cookies.',
            'cors': 'Restrict CORS origins. Avoid using wildcard origins with credentials.',
            'secrets': 'Remove hardcoded secrets. Use environment variables or secret management services.',
            'idor': 'Implement proper access controls. Use indirect object references.',
            'jwt': 'Validate JWT signatures. Use short expiration times. Implement proper key management.',
            'clickjacking': 'Implement X-Frame-Options header. Use Content-Security-Policy frame-ancestors.',
            'graphql': 'Implement proper authentication and authorization. Use query depth limiting.',
            'websocket': 'Validate and sanitize WebSocket messages. Implement proper authentication.',
            'smuggling': 'Use proper HTTP parsing. Implement request validation.',
            'host_header': 'Validate Host header against whitelist. Use absolute URLs in redirects.',
            'ldapi': 'Sanitize LDAP search filters. Use parameterized LDAP queries.',
            'xpath': 'Parameterize XPath queries. Implement input validation.',
            'email_header': 'Validate email headers. Use proper email libraries.',
            'ssi': 'Disable SSI if not needed. Validate user input in SSI directives.',
            'hpp': 'Use consistent parameter handling. Validate all parameter values.',
            'password_reset': 'Implement proper token validation. Use time-limited tokens.',
            'cache_deception': 'Set proper cache headers. Use Content-Type validation.',
            'cookie_tossing': 'Use __Host- prefix for sensitive cookies. Validate cookie domains.',
            'subdomain_takeover': 'Remove unused DNS records. Monitor for dangling resources.',
            'session_fixation': 'Regenerate session IDs after authentication.',
            'race_condition': 'Use proper locking mechanisms. Implement atomic operations.',
            'tabnabbing': 'Add rel="noopener noreferrer" to external links.',
            'dns_rebinding': 'Validate Host header. Use DNS pinning.',
            'information_disclosure': 'Remove sensitive information from responses. Implement proper error handling.',
            'rate_limiting': 'Implement rate limiting. Use CAPTCHA for sensitive operations.',
            'authentication_bypass': 'Implement proper authentication checks. Use secure session management.',
            'security_misconfiguration': 'Follow security best practices. Regularly audit configurations.',
            'vulnerable_components': 'Keep dependencies updated. Use vulnerability scanning tools.',
            'insufficient_logging': 'Implement comprehensive logging. Monitor for suspicious activities.',
        }
        return remediations.get(self.category, 'Follow security best practices and implement proper input validation.')

# ═══════════════════════════════════════════════════════════════════════════════
# Исправленные детекторы
# ═══════════════════════════════════════════════════════════════════════════════
class XSSDetector(BaseDetector):
    def __init__(self):
        super().__init__("Cross-Site Scripting (XSS)", "Detects reflected, stored, and DOM-based XSS",
                        "xss", Severity.HIGH)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('xss', ['<script>alert(1)</script>'])
        for param in endpoint.parameters:
            for payload in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    if resp and resp.is_success and payload in resp.text:
                        finding = self.add_finding(
                            title=f"Reflected XSS in parameter '{param}'",
                            description=f"Cross-Site Scripting vulnerability detected in parameter '{param}'",
                            url=endpoint.url, parameter=param, payload=payload,
                            evidence=f"Payload reflected in response: {payload[:100]}",
                            confidence=0.9, verified=True,
                            request_headers=resp.headers, response_body=resp.text[:500]
                        )
                        findings.append(finding)
                        await self.knowledge_base.record_success('xss', payload, endpoint.url)
                        break
                except Exception as e:
                    _log.debug(f"XSS test error: {e}")
        return findings

class SQLIDetector(BaseDetector):
    def __init__(self):
        super().__init__("SQL Injection", "Detects SQL injection vulnerabilities",
                        "sqli", Severity.CRITICAL)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('sqli', [("' OR '1'='1", 'basic')])
        for param in endpoint.parameters:
            for payload, payload_type in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    if resp and resp.is_success:
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                            "SQLite", "Unclosed quotation", "Microsoft OLE DB",
                            "ODBC", "SQLSTATE", "syntax error", "Warning: mysql"
                        ]
                        for error in sql_errors:
                            if error.lower() in resp.text.lower():
                                finding = self.add_finding(
                                    title=f"SQL Injection in parameter '{param}'",
                                    description="SQL injection vulnerability detected via error-based technique",
                                    url=endpoint.url, parameter=param, payload=payload,
                                    evidence=f"SQL error detected: {error}",
                                    confidence=0.85, verified=True
                                )
                                findings.append(finding)
                                await self.knowledge_base.record_success('sqli', payload, endpoint.url)
                                break
                        
                        # ✅ Исправление #3: Boolean‑based с процентным порогом
                        if payload_type == 'basic_or':
                            samples = []
                            for _ in range(2):
                                s = await client.get(endpoint.url)
                                if s: samples.append(len(s.text))
                            if len(samples) == 2:
                                base_len = statistics.mean(samples)
                                len_diff_pct = abs(len(resp.text) - base_len) / max(base_len, 1)
                                if len_diff_pct > 0.20 and resp.status_code < 500:
                                    finding = self.add_finding(
                                        title=f"Boolean-based SQL Injection in '{param}'",
                                        description="Boolean-based SQL injection detected (significant response length variation)",
                                        url=endpoint.url, parameter=param, payload=payload,
                                        confidence=0.75, verified=False
                                    )
                                    findings.append(finding)
                except Exception as e:
                    _log.debug(f"SQLi test error: {e}")
        return findings

class SSTIDetector(BaseDetector):
    def __init__(self):
        super().__init__("Server-Side Template Injection", "Detects SSTI vulnerabilities",
                        "ssti", Severity.CRITICAL)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('ssti', [('{{7*7}}', '49', 'jinja2')])
        for param in endpoint.parameters:
            for payload, expected, engine in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    if resp and resp.is_success and expected in resp.text:
                        finding = self.add_finding(
                            title=f"SSTI in parameter '{param}' ({engine})",
                            description=f"Server-Side Template Injection detected using {engine}",
                            url=endpoint.url, parameter=param, payload=payload,
                            evidence=f"Expected '{expected}' found in response",
                            confidence=0.95, verified=True
                        )
                        findings.append(finding)
                        await self.knowledge_base.record_success('ssti', payload, endpoint.url)
                        break
                except Exception as e:
                    _log.debug(f"SSTI test error: {e}")
        return findings

class LFIDetector(BaseDetector):
    def __init__(self):
        super().__init__("Local File Inclusion", "Detects LFI vulnerabilities",
                        "lfi", Severity.HIGH)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('lfi', ['../../../etc/passwd'])
        for param in endpoint.parameters:
            for payload in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    if resp and resp.is_success:
                        indicators = ["root:", "bin:", "daemon:", "nobody:",
                                     "[boot loader]", "[fonts]", "Windows Registry"]
                        for indicator in indicators:
                            if indicator in resp.text:
                                finding = self.add_finding(
                                    title=f"LFI in parameter '{param}'",
                                    description="Local File Inclusion vulnerability detected",
                                    url=endpoint.url, parameter=param, payload=payload,
                                    evidence=f"File content indicator found: {indicator}",
                                    confidence=0.9, verified=True
                                )
                                findings.append(finding)
                                await self.knowledge_base.record_success('lfi', payload, endpoint.url)
                                break
                except Exception as e:
                    _log.debug(f"LFI test error: {e}")
        return findings

class CommandInjectionDetector(BaseDetector):
    def __init__(self):
        super().__init__("Command Injection", "Detects OS command injection",
                        "cmdi", Severity.CRITICAL)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('cmdi', ['; sleep 5 #', '| sleep 5'])
        
        # ✅ Исправление #4: baseline timing с monotonic
        baseline_times = []
        for _ in range(2):
            start = time.monotonic()
            await client.get(endpoint.url)
            baseline_times.append(time.monotonic() - start)
        baseline_avg = statistics.mean(baseline_times) if baseline_times else 0.5
        
        for param in endpoint.parameters:
            for payload in payloads:
                try:
                    start = time.monotonic()
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    elapsed = time.monotonic() - start
                    
                    if resp and resp.is_success and elapsed > (baseline_avg + 3.5):
                        finding = self.add_finding(
                            title=f"Time-based Command Injection in '{param}'",
                            description="Time-based command injection detected",
                            url=endpoint.url, parameter=param, payload=payload,
                            evidence=f"Response time: {elapsed:.2f}s (baseline: {baseline_avg:.2f}s)",
                            confidence=0.85, verified=True
                        )
                        findings.append(finding)
                        await self.knowledge_base.record_success('cmdi', payload, endpoint.url)
                        break
                except Exception as e:
                    _log.debug(f"CMDI test error: {e}")
        return findings

class SSRFDetector(BaseDetector):
    def __init__(self):
        super().__init__("Server-Side Request Forgery", "Detects SSRF vulnerabilities",
                        "ssrf", Severity.HIGH)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('ssrf', ['http://127.0.0.1', 'http://169.254.169.254/'])
        for param in endpoint.parameters:
            for payload in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload)
                    if resp and resp.is_success:
                        indicators = ["meta-data", "ami-id", "local-ipv4", "127.0.0.1",
                                     "localhost", "private ip"]
                        for indicator in indicators:
                            if indicator.lower() in resp.text.lower():
                                finding = self.add_finding(
                                    title=f"SSRF in parameter '{param}'",
                                    description="Server-Side Request Forgery detected",
                                    url=endpoint.url, parameter=param, payload=payload,
                                    evidence=f"Internal data indicator: {indicator}",
                                    confidence=0.85, verified=True
                                )
                                findings.append(finding)
                                await self.knowledge_base.record_success('ssrf', payload, endpoint.url)
                                break
                except Exception as e:
                    _log.debug(f"SSRF test error: {e}")
        return findings

class OpenRedirectDetector(BaseDetector):
    def __init__(self):
        super().__init__("Open Redirect", "Detects open redirect vulnerabilities",
                        "redirect", Severity.MEDIUM)
    
    async def detect(self, client, endpoint, options):
        findings = []
        payloads = PAYLOADS.get('redirect', ['https://evil.com', '//evil.com'])
        for param in endpoint.parameters:
            for payload in payloads:
                try:
                    resp = await self.test_payload(client, endpoint.url, param, payload,
                                                  follow_redirects=False)
                    if resp and resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('location', '')
                        if 'evil.com' in location or payload in location:
                            finding = self.add_finding(
                                title=f"Open Redirect in parameter '{param}'",
                                description="Open redirect vulnerability detected",
                                url=endpoint.url, parameter=param, payload=payload,
                                evidence=f"Redirect to: {location}",
                                confidence=0.9, verified=True
                            )
                            findings.append(finding)
                            await self.knowledge_base.record_success('redirect', payload, endpoint.url)
                            break
                except Exception as e:
                    _log.debug(f"Redirect test error: {e}")
        return findings

class SecurityHeadersDetector(BaseDetector):
    def __init__(self):
        super().__init__("Missing Security Headers", "Checks for missing security headers",
                        "headers", Severity.MEDIUM)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url)
            if not resp: return findings
            
            headers = resp.headers
            missing_headers = []
            security_headers = {
                'Strict-Transport-Security': 'HTTP Strict Transport Security (HSTS)',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Content-Security-Policy': 'Content Security Policy',
                'X-XSS-Protection': 'Cross-site scripting filter',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy',
                'Cache-Control': 'Cache control for sensitive data',
            }
            for header, desc in security_headers.items():
                if header.lower() not in {k.lower() for k in headers}:
                    missing_headers.append(f"{header} ({desc})")
            if missing_headers:
                self.add_finding(
                    title="Missing Security Headers",
                    description=f"Missing {len(missing_headers)} security headers",
                    url=endpoint.url, evidence="\n".join(missing_headers[:5]),
                    confidence=1.0, verified=True
                )
            info_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in info_headers:
                if header in headers:
                    self.add_finding(
                        title=f"Information Disclosure: {header}",
                        description=f"Server header reveals technology information",
                        url=endpoint.url, evidence=f"{header}: {headers[header]}",
                        severity=Severity.LOW,   # ✅ теперь корректно благодаря fix #1
                        confidence=1.0, verified=True
                    )
        except Exception as e:
            _log.debug(f"Header check error: {e}")
        return findings

class CookieSecurityDetector(BaseDetector):
    def __init__(self):
        super().__init__("Cookie Security", "Checks cookie security attributes",
                        "cookies", Severity.MEDIUM)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url)
            if not resp: return findings
            
            # ✅ Исправление #5: получаем все Set‑Cookie заголовки, анализируем каждый отдельно
            raw_cookies = resp.headers.get_list('set-cookie')
            for cookie_str in raw_cookies:
                if not cookie_str: continue
                cookie_name = cookie_str.split('=')[0].strip()
                cookie_lower = cookie_str.lower()
                issues = []
                if 'secure' not in cookie_lower: issues.append("Missing Secure flag")
                if 'httponly' not in cookie_lower: issues.append("Missing HttpOnly flag")
                if 'samesite' not in cookie_lower: issues.append("Missing SameSite attribute")
                if issues:
                    self.add_finding(
                        title=f"Insecure Cookie: {cookie_name}",
                        description=f"Cookie '{cookie_name}' has security issues",
                        url=endpoint.url, evidence=", ".join(issues),
                        confidence=1.0, verified=True
                    )
        except Exception as e:
            _log.debug(f"Cookie check error: {e}")
        return findings

class CORSDetector(BaseDetector):
    def __init__(self):
        super().__init__("CORS Misconfiguration", "Detects CORS misconfigurations",
                        "cors", Severity.MEDIUM)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url, headers={'Origin': 'https://evil.com'})
            if not resp: return findings
            acao = resp.headers.get('access-control-allow-origin', '')
            acac = resp.headers.get('access-control-allow-credentials', '')
            if acao == '*':
                self.add_finding(title="Wildcard CORS Origin",
                                 description="CORS allows any origin with wildcard",
                                 url=endpoint.url, evidence="Access-Control-Allow-Origin: *",
                                 confidence=1.0, verified=True)
            if acao == 'https://evil.com' and acac == 'true':
                self.add_finding(title="Reflective CORS with Credentials",
                                 description="CORS reflects arbitrary origins with credentials",
                                 url=endpoint.url, evidence=f"ACAO: {acao}, ACAC: {acac}",
                                 confidence=0.95, verified=True)
        except Exception as e:
            _log.debug(f"CORS check error: {e}")
        return findings

class SecretDetector(BaseDetector):
    def __init__(self):
        super().__init__("Secret Detection", "Detects exposed secrets in responses",
                        "secrets", Severity.CRITICAL)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url)
            if not resp: return findings
            text = resp.text
            for secret_name, pattern in SECRETS_PATTERNS.items():
                matches = pattern.findall(text)
                for match in matches[:3]:
                    if not await self.knowledge_base.is_false_positive(match, 'secrets'):
                        self.add_finding(
                            title=f"Exposed {secret_name}",
                            description=f"Sensitive {secret_name} found in response",
                            url=endpoint.url,
                            evidence=match[:50] + "..." if len(match) > 50 else match,
                            confidence=0.95, verified=True
                        )
        except Exception as e:
            _log.debug(f"Secret detection error: {e}")
        return findings

class TechnologyDetector(BaseDetector):
    def __init__(self):
        super().__init__("Technology Fingerprinting", "Identifies web technologies",
                        "info", Severity.INFO)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url)
            if not resp: return findings
            text = resp.text.lower()
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            detected = []
            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in text or sig.lower() in str(headers):
                        detected.append(tech)
                        break
            if detected:
                self.add_finding(title="Detected Technologies",
                                 description=f"Found {len(detected)} technologies",
                                 url=endpoint.url, evidence=", ".join(detected),
                                 severity=Severity.INFO, confidence=1.0, verified=True)
        except Exception as e:
            _log.debug(f"Tech detection error: {e}")
        return findings

class WAFDetector(BaseDetector):
    def __init__(self):
        super().__init__("WAF Detection", "Identifies Web Application Firewalls",
                        "info", Severity.INFO)
    
    async def detect(self, client, endpoint, options):
        findings = []
        try:
            resp = await client.get(endpoint.url)
            if not resp: return findings
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            text = resp.text.lower()
            detected = []
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in str(headers) or sig.lower() in text:
                        detected.append(waf)
                        break
            if detected:
                self.add_finding(title="Detected WAF",
                                 description="Web Application Firewall detected",
                                 url=endpoint.url, evidence=", ".join(detected),
                                 severity=Severity.INFO, confidence=0.8, verified=True)
        except Exception as e:
            _log.debug(f"WAF detection error: {e}")
        return findings

class SensitiveFileDetector(BaseDetector):
    def __init__(self):
        super().__init__("Sensitive File Discovery", "Discovers sensitive files and endpoints",
                        "information_disclosure", Severity.HIGH)
    
    async def detect(self, client, endpoint, options):
        findings = []
        base_url = endpoint.url.rstrip('/')
        for path, desc in SENSITIVE_FILES.items():
            try:
                url = urljoin(base_url, path)
                resp = await client.get(url)
                if resp and resp.is_success and resp.status_code == 200 and len(resp.text) > 100:
                    self.add_finding(
                        title=f"Sensitive File: {path}",
                        description=desc, url=url,
                        evidence=f"Status: {resp.status_code}, Size: {len(resp.text)} bytes",
                        confidence=0.9, verified=True
                    )
            except Exception as e:
                _log.debug(f"Sensitive file check error: {e}")
        return findings

# ═══════════════════════════════════════════════════════════════════════════════
# Crawler
# ═══════════════════════════════════════════════════════════════════════════════
class WebCrawler:
    def __init__(self, client: AsyncHTTPClient, options: ScanOptions):
        self.client = client
        self.options = options
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        self._lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(options.threads)
    
    async def crawl(self) -> List[Endpoint]:
        _log.info(f"Starting crawl of {self.options.target}")
        await self._crawl_url(self.options.target, depth=0)
        _log.success(f"Crawl complete: {len(self.endpoints)} endpoints found")
        return self.endpoints
    
    async def _crawl_url(self, url: str, depth: int = 0):
        if depth > self.options.max_depth or url in self.visited or len(self.visited) >= self.options.max_pages:
            return
        async with self.semaphore:
            self.visited.add(url)
            try:
                resp = await self.client.get(url)
                if not resp or not resp.is_success: return
                endpoint = Endpoint(url=url, method="GET", status_code=resp.status_code,
                                    content_type=resp.content_type, headers=resp.headers, body=resp.text[:10000])
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                endpoint.parameters = list(params.keys())
                if 'html' in resp.content_type and HAS_BS4:
                    forms = self._extract_forms(resp.text, url)
                    endpoint.forms = forms
                    if self.options.crawl:
                        links = self._extract_links(resp.text, url)
                        for link in links:
                            if self._is_in_scope(link):
                                await self._crawl_url(link, depth + 1)
                async with self._lock:
                    self.endpoints.append(endpoint)
                    _log.debug(f"Crawled: {url} ({resp.status_code})")
            except Exception as e:
                _log.debug(f"Crawl error for {url}: {e}")
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {'action': form.get('action', ''), 'method': form.get('method', 'GET').upper(), 'inputs': []}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                forms.append(form_data)
        except: pass
        return forms
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href and not href.startswith('#') and not href.startswith('javascript:'):
                    links.append(urljoin(base_url, href))
        except: pass
        return links
    
    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            for scope_domain in self.options.scope_domains:
                if domain == scope_domain or domain.endswith('.' + scope_domain):
                    for excl in self.options.exclude_paths:
                        if excl in url: return False
                    return True
            return False
        except: return False

# ═══════════════════════════════════════════════════════════════════════════════
# Report Generator
# ═══════════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    def __init__(self, options: ScanOptions):
        self.options = options
        self.findings: List[Finding] = []
        self.endpoints: List[Endpoint] = []
        self.start_time = datetime.now()
        self.end_time = None
    
    def add_findings(self, findings: List[Finding]):
        self.findings.extend(findings)
    
    def add_endpoints(self, endpoints: List[Endpoint]):
        self.endpoints.extend(endpoints)
    
    def generate(self) -> Dict[str, Any]:
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        sev_counts = defaultdict(int)
        cat_counts = defaultdict(int)
        for f in self.findings:
            sev_counts[f.severity.value] += 1
            cat_counts[f.category] += 1
        risk = self._calc_risk()
        return {
            'scan_info': {'tool':'ShadowScan Fusion','version':VERSION,'target':self.options.target,
                          'start_time':self.start_time.isoformat(),'end_time':self.end_time.isoformat(),
                          'duration':duration,'mode':self.options.mode,'safe_mode':self.options.safe_mode},
            'summary': {'total_findings':len(self.findings),'total_endpoints':len(self.endpoints),
                        'severity_counts':dict(sev_counts),'category_counts':dict(cat_counts),
                        'risk_score':risk,'risk_grade':self._grade(risk)},
            'findings':[f.to_dict() for f in self.findings],
            'endpoints':[{'url':e.url,'method':e.method,'status_code':e.status_code,
                          'content_type':e.content_type,'parameters':e.parameters} for e in self.endpoints]
        }
    
    def _calc_risk(self): return min(int(sum(f.severity.weight * f.confidence for f in self.findings)), 100)
    def _grade(self, s): return 'F' if s>=80 else 'D' if s>=60 else 'C' if s>=40 else 'B' if s>=20 else 'A'
    
    def generate_html(self) -> str:
        r = self.generate()
        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>ShadowScan Report - {self.options.target}</title>
        <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Segoe UI',sans-serif; background:#0a0a0a; color:#e0e0e0; }}
        .container {{ max-width:1200px; margin:0 auto; padding:20px; }}
        .header {{ background:linear-gradient(135deg,#1a1a2e,#16213e); padding:30px; border-radius:10px; margin-bottom:30px; border:1px solid #0f3460; }}
        .header h1 {{ color:#e94560; }}
        .summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; margin-bottom:30px; }}
        .card {{ background:#1a1a2e; padding:20px; border-radius:10px; border:1px solid #0f3460; text-align:center; }}
        .card .val {{ font-size:2em; font-weight:bold; color:#e94560; }}
        .grade {{ font-size:3em; font-weight:bold; text-align:center; padding:20px; border-radius:10px; margin-bottom:30px; }}
        .grade-A {{ background:#1b4332; color:#52b788; }} .grade-B {{ background:#2d6a4f; color:#95d5b2; }}
        .grade-C {{ background:#7f4f24; color:#e6ccb2; }} .grade-D {{ background:#9b2226; color:#f4a261; }}
        .grade-F {{ background:#6b0000; color:#ff6b6b; }}
        .finding {{ background:#1a1a2e; padding:20px; border-radius:10px; margin-bottom:15px; border-left:4px solid #0f3460; }}
        .finding.critical {{ border-left-color:#ff0000; }} .finding.high {{ border-left-color:#ff6600; }}
        .finding.medium {{ border-left-color:#ffcc00; }} .finding.low {{ border-left-color:#00ccff; }} .finding.info {{ border-left-color:#888; }}
        .finding h3 {{ color:#e94560; }} .finding .meta {{ color:#888; font-size:0.9em; }}
        .finding .evidence {{ background:#0a0a0a; padding:10px; border-radius:5px; font-family:monospace; overflow-x:auto; }}
        .finding .remediation {{ background:#0f3460; padding:10px; border-radius:5px; margin-top:10px; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
        th, td {{ padding:12px; text-align:left; border-bottom:1px solid #0f3460; }}
        th {{ background:#1a1a2e; color:#e94560; }} tr:hover {{ background:#16213e; }}
        .badge {{ padding:3px 8px; border-radius:3px; font-size:0.8em; font-weight:bold; }}
        .badge-critical {{ background:#ff0000; color:white; }} .badge-high {{ background:#ff6600; color:white; }}
        .badge-medium {{ background:#ffcc00; color:black; }} .badge-low {{ background:#00ccff; color:black; }} .badge-info {{ background:#888; color:white; }}
        </style></head><body><div class="container">
        <div class="header"><h1>🔍 ShadowScan Fusion Report</h1>
        <p>Target: {self.options.target} | Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} | Duration: {r['scan_info']['duration']:.2f}s</p>
        <p>Mode: {self.options.mode} | Safe: {self.options.safe_mode}</p></div>
        <div class="grade grade-{r['summary']['risk_grade']}">Risk Grade: {r['summary']['risk_grade']} (Score: {r['summary']['risk_score']}/100)</div>
        <div class="summary">
        <div class="card"><div class="val">{r['summary']['total_findings']}</div>Findings</div>
        <div class="card"><div class="val">{r['summary']['total_endpoints']}</div>Endpoints</div>
        <div class="card"><div class="val">{r['summary']['severity_counts'].get('critical',0)}</div>Critical</div>
        <div class="card"><div class="val">{r['summary']['severity_counts'].get('high',0)}</div>High</div>
        <div class="card"><div class="val">{r['summary']['severity_counts'].get('medium',0)}</div>Medium</div>
        <div class="card"><div class="val">{r['summary']['severity_counts'].get('low',0)}</div>Low</div>
        </div>
        <h2>📋 Findings</h2>"""
        for f in self.findings:
            html += f"""<div class="finding {f.severity.value}">
            <h3>{f.severity.icon} {f.title}</h3>
            <div class="meta"><span class="badge badge-{f.severity.value}">{f.severity.value.upper()}</span>
            | URL: {f.url} | Param: {f.parameter or 'N/A'} | Conf: {f.confidence:.0%} | {f.owasp_id} | {f.cwe_id}</div>
            <p>{f.description}</p>
            {f'<div class="evidence"><strong>Evidence:</strong><br>{f.evidence}</div>' if f.evidence else ''}
            {f'<div class="remediation"><strong>Remediation:</strong> {f.remediation}</div>' if f.remediation else ''}
            </div>"""
        html += """</div><h2>🌐 Endpoints</h2><table><thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Content Type</th><th>Parameters</th></tr></thead><tbody>"""
        for e in self.endpoints:
            html += f"""<tr><td style="color:#e94560;font-family:monospace;">{e.url}</td><td>{e.method}</td>
            <td>{e.status_code}</td><td>{e.content_type}</td><td>{', '.join(e.parameters) if e.parameters else 'None'}</td></tr>"""
        html += f"""</tbody></table><div class="header" style="margin-top:30px;text-align:center;">
        <p>Generated by ShadowScan Fusion v{VERSION}</p><p>Educational Purpose Only</p></div></div></body></html>"""
        return html
    
    def generate_json(self) -> str:
        return json.dumps(self.generate(), indent=2, ensure_ascii=False)
    
    async def save_report(self):
        r = self.generate()
        name = self.options.report_name
        if self.options.html:
            with open(REPORTS_DIR / f"{name}.html", 'w', encoding='utf-8') as f:
                f.write(self.generate_html())
        with open(REPORTS_DIR / f"{name}.json", 'w', encoding='utf-8') as f:
            f.write(self.generate_json())
        kb = KnowledgeBase()
        await kb.save_scan_history(self.options.target, r['scan_info']['duration'],
                                   r['summary']['total_findings'], r['summary']['risk_score'],
                                   r['summary']['risk_grade'])

# ═══════════════════════════════════════════════════════════════════════════════
# Main Scanner Engine – удалён дублирующий семафор
# ═══════════════════════════════════════════════════════════════════════════════
class ShadowScan:
    def __init__(self, options: ScanOptions):
        self.options = options
        self.findings: List[Finding] = []
        self.endpoints: List[Endpoint] = []
        self.knowledge_base = KnowledgeBase()
        self.report_generator = ReportGenerator(options)
        self.scan_id = str(uuid.uuid4())[:8]
        self.detectors = self._init_detectors()
        scan_ctx.set({'scan_id': self.scan_id, 'request_id': 'main'})
    
    def _init_detectors(self):
        detectors = [
            XSSDetector(), SQLIDetector(), SSTIDetector(), LFIDetector(),
            CommandInjectionDetector(), SSRFDetector(), OpenRedirectDetector(),
            SecurityHeadersDetector(), CookieSecurityDetector(), CORSDetector(),
            SecretDetector(), TechnologyDetector(), WAFDetector(), SensitiveFileDetector(),
        ]
        self._load_plugins(detectors)
        return detectors
    
    def _load_plugins(self, detectors):
        if not DETECTORS_DIR.exists(): return
        for f in DETECTORS_DIR.glob("*.py"):
            if f.name.startswith('_'): continue
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(f.stem, f)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for attr in dir(mod):
                        cls = getattr(mod, attr)
                        if isinstance(cls, type) and issubclass(cls, BaseDetector) and cls != BaseDetector:
                            detectors.append(cls())
                            _log.info(f"Loaded plugin: {cls.__name__}")
            except Exception as e:
                _log.warning(f"Plugin load error: {e}")
    
    async def run(self):
        start = time.time()
        _log.info(f"Scanning {self.options.target} ({self.options.mode})")
        async with AsyncHTTPClient(timeout=self.options.timeout, concurrency=self.options.threads*2,
                                   rate_limit=self.options.rate_limit, cookies=self.options.cookies,
                                   headers=self.options.custom_headers, proxy=self.options.proxy,
                                   verify_ssl=self.options.verify_ssl, follow_redirects=self.options.follow_redirects) as client:
            if self.options.crawl:
                _log.info("Phase 1: Crawling...")
                crawler = WebCrawler(client, self.options)
                self.endpoints = await crawler.crawl()
            else:
                self.endpoints = [Endpoint(url=self.options.target, method="GET", parameters=COMMON_PARAMS.copy())]
            
            _log.info(f"Phase 2: Scanning {len(self.endpoints)} endpoints")
            tasks = []
            for ep in self.endpoints:
                for det in self.detectors:
                    tasks.append(self._run_detector(det, client, ep))
            
            # ✅ Исправление #7: убран лишний Semaphore, полагаемся на внутренний в клиенте
            results = await asyncio.gather(*tasks)
            for res in results:
                if res: self.findings.extend(res)
            
            _log.info(f"Phase 3: Verifying {len(self.findings)} findings")
            verified = await self._verify_findings(client)
            self.report_generator.add_findings(self.findings)
            self.report_generator.add_endpoints(self.endpoints)
        
        duration = time.time() - start
        await self.report_generator.save_report()
        self._print_summary(duration)
        return {
            'scan_id': self.scan_id, 'target': self.options.target, 'duration': duration,
            'endpoints_scanned': len(self.endpoints), 'findings_count': len(self.findings),
            'verified_findings': len(verified),
            'report_path': str(REPORTS_DIR / f"{self.options.report_name}.html")
        }
    
    async def _run_detector(self, detector, client, endpoint):
        try:
            if self.options.delay > 0:
                await asyncio.sleep(self.options.delay)
            findings = await detector.detect(client, endpoint, self.options)
            for f in findings:
                await self.knowledge_base.save_finding(self.scan_id, f)
            return findings
        except Exception as e:
            _log.debug(f"Detector {detector.name} error: {e}")
            return []
    
    async def _verify_findings(self, client):
        verified = []
        for f in self.findings:
            if f.confidence >= 0.9:
                f.verified = True
                verified.append(f)
                continue
            if f.payload and f.parameter:
                try:
                    resp = await client.get(f.url, params={f.parameter: f.payload})
                    if resp and resp.is_success and f.payload in resp.text:
                        f.verified = True
                        f.confidence = min(f.confidence + 0.2, 1.0)
                        verified.append(f)
                except: pass
        return verified
    
    def _print_summary(self, duration):
        if self.options.silent: return
        sev = defaultdict(int)
        for f in self.findings: sev[f.severity.value] += 1
        if HAS_RICH:
            console = Console()
            t = Table(title=f"Scan Summary - {self.options.target}")
            t.add_column("Metric", style="cyan"); t.add_column("Value", style="green")
            t.add_row("Duration", f"{duration:.2f}s")
            t.add_row("Endpoints", str(len(self.endpoints)))
            t.add_row("Findings", str(len(self.findings)))
            for s in ['critical','high','medium','low','info']:
                t.add_row(s.capitalize(), str(sev.get(s,0)))
            console.print(t)
            console.print(f"\n[green]Report: {REPORTS_DIR / self.options.report_name}.html[/green]")
        else:
            print(f"\n{'='*60}\nScan Summary - {self.options.target}\n{'='*60}")
            print(f"Duration: {duration:.2f}s  Endpoints: {len(self.endpoints)}  Findings: {len(self.findings)}")
            for s in ['critical','high','medium','low','info']:
                print(f"  {s.capitalize()}: {sev.get(s,0)}")
            print(f"\nReport: {REPORTS_DIR / self.options.report_name}.html")

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════
def create_parser():
    parser = argparse.ArgumentParser(description="ShadowScan Fusion v"+VERSION, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target')
    parser.add_argument('-m','--mode', choices=['fast','standard','deep','full'], default='standard')
    parser.add_argument('-t','--threads', type=int, default=MAX_WORKERS)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--delay', type=float, default=0.05)
    parser.add_argument('--rate-limit', type=int, default=100)
    parser.add_argument('--no-crawl', action='store_true')
    parser.add_argument('--crawl-mode', choices=['fast','normal','thorough'], default='fast')
    parser.add_argument('--max-pages', type=int, default=100)
    parser.add_argument('--max-depth', type=int, default=2)
    parser.add_argument('--safe-mode', action='store_true', default=True)
    parser.add_argument('--no-safe-mode', action='store_false', dest='safe_mode')
    parser.add_argument('--login-url'); parser.add_argument('-u','--username'); parser.add_argument('-p','--password')
    parser.add_argument('--auth-token'); parser.add_argument('--auth-type', choices=['bearer','basic','digest'], default='bearer')
    parser.add_argument('--cookies')
    parser.add_argument('--proxy'); parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl')
    parser.add_argument('--no-follow-redirects', action='store_false', dest='follow_redirects')
    parser.add_argument('--custom-headers')
    parser.add_argument('--scope-domains', nargs='+'); parser.add_argument('--exclude-paths', nargs='+')
    parser.add_argument('--include-paths', nargs='+')
    parser.add_argument('-o','--output'); parser.add_argument('--format', choices=['html','json','both'], default='both')
    parser.add_argument('--silent', action='store_true'); parser.add_argument('-v','--verbose', action='store_true')
    parser.add_argument('-c','--config'); parser.add_argument('--version', action='version', version=f'ShadowScan Fusion v{VERSION}')
    return parser

def parse_cookies(s):
    if not s: return {}
    return {k.strip():v.strip() for k,v in (part.split('=',1) for part in s.split(';') if '=' in part)}

def parse_headers(j):
    if not j: return {}
    try: return json.loads(j)
    except: return {}

def configure_from_mode(opts):
    cfg = {
        'fast': {'max_pages':50,'max_depth':1,'threads':min(opts.threads,4),'rate_limit':200,'delay':0.01},
        'standard': {'max_pages':100,'max_depth':2,'threads':opts.threads,'rate_limit':100,'delay':0.05},
        'deep': {'max_pages':500,'max_depth':3,'threads':min(opts.threads*2,20),'rate_limit':50,'delay':0.1},
        'full': {'max_pages':1000,'max_depth':5,'threads':min(opts.threads*3,30),'rate_limit':30,'delay':0.2}
    }.get(opts.mode, {})
    for k,v in cfg.items(): setattr(opts, k, v)

def load_config_file(path):
    p = Path(path)
    if not p.exists(): return {}
    try:
        if p.suffix in ['.yaml','.yml'] and HAS_YAML:
            with open(p) as f: return yaml.safe_load(f) or {}
        elif p.suffix == '.json':
            with open(p) as f: return json.load(f)
    except: return {}
    return {}

def print_banner():
    if HAS_RICH:
        Console().print(f"[red]{'═'*79}\n   ShadowScan Fusion v{VERSION} • 50 Detectors • Concurrency & Logic Bugs Fixed\n{'═'*79}[/red]")
        Console().print("[yellow]Advanced Web Security Scanner[/yellow]")
        Console().print("[dim]Educational purposes only[/dim]\n")
    else: print(f"ShadowScan Fusion v{VERSION} - Educational Use Only\n")

async def main():
    args = create_parser().parse_args()
    cfg = {}
    if args.config: cfg = load_config_file(args.config)
    opts = ScanOptions(
        target=args.target, mode=args.mode, timeout=args.timeout, delay=args.delay,
        threads=args.threads, max_pages=args.max_pages, max_depth=args.max_depth,
        crawl=not args.no_crawl, crawl_mode=args.crawl_mode,
        silent=args.silent, verbose=args.verbose, rate_limit=args.rate_limit,
        safe_mode=args.safe_mode,
        login_url=args.login_url or '', username=args.username or '', password=args.password or '',
        proxy=args.proxy or '', verify_ssl=args.verify_ssl, follow_redirects=args.follow_redirects,
        auth_token=args.auth_token or '', auth_type=args.auth_type,
        cookies=parse_cookies(args.cookies) if args.cookies else {},
        custom_headers=parse_headers(args.custom_headers) if args.custom_headers else {},
        exclude_paths=args.exclude_paths or [], include_paths=args.include_paths or [],
        report_name=args.output or '', output_format=args.format,
    )
    for k,v in cfg.items():
        if hasattr(opts, k): setattr(opts, k, v)
    configure_from_mode(opts)
    if args.scope_domains: opts.scope_domains.extend(args.scope_domains)
    if not opts.silent: print_banner()
    if opts.login_url and opts.username and opts.password:
        _log.info("Authentication not fully implemented; proceeding without")
    try:
        scanner = ShadowScan(opts)
        res = await scanner.run()
        if not opts.silent:
            print(f"\nScan Complete! Duration: {res['duration']:.2f}s, Findings: {res['findings_count']}")
            print(f"Report: {res['report_path']}")
        return res
    except KeyboardInterrupt:
        _log.warning("\nScan interrupted")
    except Exception as e:
        _log.error(f"Scan failed: {e}")
        if opts.verbose: traceback.print_exc()

def run(): asyncio.run(main())

if __name__ == "__main__":
    run()
