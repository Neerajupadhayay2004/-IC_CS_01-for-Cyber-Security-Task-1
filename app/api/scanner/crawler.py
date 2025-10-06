"""Web crawler to discover pages and links"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from typing import Set, List, Dict
import re

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[Dict] = []
        self.forms: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Educational Purpose)'
        })
        
    def is_valid_url(self, url: str) -> bool:
        """Check if URL belongs to the same domain"""
        parsed_base = urlparse(self.base_url)
        parsed_url = urlparse(url)
        return parsed_base.netloc == parsed_url.netloc
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and trailing slashes"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized.rstrip('/')
    
    def extract_forms(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Extract all forms from a page"""
        forms = []
        for form in soup.find_all('form'):
            form_details = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Extract all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                if input_name:
                    form_details['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', '')
                    })
            
            forms.append(form_details)
        return forms
    
    def crawl_page(self, url: str, depth: int = 0) -> None:
        """Crawl a single page and extract links and forms"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        if url in self.visited_urls:
            return
        
        try:
            print(f"[v0] Crawling: {url} (depth: {depth})")
            response = self.session.get(url, timeout=10, allow_redirects=True)
            self.visited_urls.add(url)
            
            # Store page info
            self.discovered_urls.append({
                'url': url,
                'status_code': response.status_code,
                'depth': depth,
                'content_type': response.headers.get('Content-Type', '')
            })
            
            # Only parse HTML content
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract forms
            page_forms = self.extract_forms(soup, url)
            for form in page_forms:
                form['page_url'] = url
                self.forms.append(form)
            
            # Extract and follow links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                normalized_url = self.normalize_url(full_url)
                
                if self.is_valid_url(normalized_url) and normalized_url not in self.visited_urls:
                    time.sleep(1)  # Polite crawling
                    self.crawl_page(normalized_url, depth + 1)
            
        except Exception as e:
            print(f"[v0] Error crawling {url}: {str(e)}")
    
    def start_crawl(self) -> Dict:
        """Start the crawling process"""
        print(f"[v0] Starting crawl of {self.base_url}")
        self.crawl_page(self.base_url)
        
        return {
            'base_url': self.base_url,
            'total_pages': len(self.visited_urls),
            'total_forms': len(self.forms),
            'pages': self.discovered_urls,
            'forms': self.forms
        }
