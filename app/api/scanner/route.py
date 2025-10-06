"""Flask API route for the security scanner"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from .crawler import WebCrawler
from .vulnerability_scanner import VulnerabilityScanner
from .header_checker import SecurityHeaderChecker
from .database import db, ScanHistory
import json
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'scanner.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/api/scan', methods=['POST'])
def scan_website():
    """Main endpoint to scan a website"""
    try:
        data = request.get_json()
        target_url = data.get('url')
        
        if not target_url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        scan_results = {
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'status': 'completed'
        }
        
        # Step 1: Crawl the website
        print(f"[v0] Starting crawl for {target_url}")
        crawler = WebCrawler(target_url, max_depth=2, max_pages=20)
        crawl_results = crawler.start_crawl()
        scan_results['crawl_results'] = crawl_results
        
        # Step 2: Check security headers
        print(f"[v0] Checking security headers")
        header_checker = SecurityHeaderChecker()
        header_results = header_checker.check_headers(target_url)
        scan_results['header_results'] = header_results
        
        # Step 3: Scan for vulnerabilities
        print(f"[v0] Scanning for vulnerabilities")
        vuln_scanner = VulnerabilityScanner()
        all_vulnerabilities = []
        
        # Scan each discovered page
        for page in crawl_results['pages'][:5]:  # Limit to first 5 pages
            page_url = page['url']
            vuln_results = vuln_scanner.scan_url(page_url, crawl_results['forms'])
            all_vulnerabilities.append(vuln_results)
        
        scan_results['vulnerability_results'] = all_vulnerabilities
        
        # Generate summary
        total_sql_vulns = sum(len(v['sql_injection']) for v in all_vulnerabilities)
        total_xss_vulns = sum(len(v['xss']) for v in all_vulnerabilities)
        
        scan_results['summary'] = {
            'total_pages_scanned': len(crawl_results['pages']),
            'total_forms_found': len(crawl_results['forms']),
            'sql_injection_vulnerabilities': total_sql_vulns,
            'xss_vulnerabilities': total_xss_vulns,
            'missing_security_headers': len(header_results['missing_headers']),
            'security_warnings': len(header_results['warnings'])
        }
        
        saved_scan = ScanHistory.save_scan(scan_results)
        scan_results['scan_id'] = saved_scan.id
        
        return jsonify(scan_results), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'failed'
        }), 500

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    """Get all scan history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        scans = ScanHistory.get_all_scans(limit=limit)
        
        return jsonify({
            'total': len(scans),
            'scans': [scan.to_dict() for scan in scans]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_scan_detail(scan_id):
    """Get details of a specific scan"""
    try:
        scan = ScanHistory.get_scan_by_id(scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan from history"""
    try:
        success = ScanHistory.delete_scan(scan_id)
        
        if not success:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify({'message': 'Scan deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
