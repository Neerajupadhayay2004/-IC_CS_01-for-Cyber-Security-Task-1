"""Security headers checker"""

import requests
from typing import Dict, List
from .config import SECURITY_HEADERS

class SecurityHeaderChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Educational Purpose)'
        })
    
    def check_headers(self, url: str) -> Dict:
        """Check security headers for a URL"""
        print(f"[v0] Checking security headers for {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            results = {
                'url': url,
                'missing_headers': [],
                'present_headers': [],
                'warnings': []
            }
            
            # Check each security header
            for header_name, header_info in SECURITY_HEADERS.items():
                if header_name in headers:
                    results['present_headers'].append({
                        'name': header_name,
                        'value': headers[header_name],
                        'description': header_info['description'],
                        'severity': header_info['severity']
                    })
                else:
                    results['missing_headers'].append({
                        'name': header_name,
                        'description': header_info['description'],
                        'severity': header_info['severity']
                    })
            
            # Additional checks
            if 'X-Powered-By' in headers:
                results['warnings'].append({
                    'type': 'Information Disclosure',
                    'header': 'X-Powered-By',
                    'value': headers['X-Powered-By'],
                    'description': 'Server technology exposed',
                    'severity': 'low'
                })
            
            if 'Server' in headers:
                results['warnings'].append({
                    'type': 'Information Disclosure',
                    'header': 'Server',
                    'value': headers['Server'],
                    'description': 'Server information exposed',
                    'severity': 'low'
                })
            
            return results
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'missing_headers': [],
                'present_headers': [],
                'warnings': []
            }
