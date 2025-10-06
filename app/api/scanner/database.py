"""Database models and operations for storing scan results"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class ScanHistory(db.Model):
    """Model for storing scan history"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='completed')
    
    # Summary statistics
    total_pages_scanned = db.Column(db.Integer, default=0)
    total_forms_found = db.Column(db.Integer, default=0)
    sql_injection_count = db.Column(db.Integer, default=0)
    xss_count = db.Column(db.Integer, default=0)
    missing_headers_count = db.Column(db.Integer, default=0)
    security_warnings_count = db.Column(db.Integer, default=0)
    
    # Full results stored as JSON
    crawl_results = db.Column(db.Text)
    header_results = db.Column(db.Text)
    vulnerability_results = db.Column(db.Text)
    
    def __repr__(self):
        return f'<ScanHistory {self.id}: {self.target_url}>'
    
    def to_dict(self):
        """Convert scan history to dictionary"""
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_time': self.scan_time.isoformat(),
            'status': self.status,
            'summary': {
                'total_pages_scanned': self.total_pages_scanned,
                'total_forms_found': self.total_forms_found,
                'sql_injection_vulnerabilities': self.sql_injection_count,
                'xss_vulnerabilities': self.xss_count,
                'missing_security_headers': self.missing_headers_count,
                'security_warnings': self.security_warnings_count
            },
            'crawl_results': json.loads(self.crawl_results) if self.crawl_results else {},
            'header_results': json.loads(self.header_results) if self.header_results else {},
            'vulnerability_results': json.loads(self.vulnerability_results) if self.vulnerability_results else []
        }
    
    @staticmethod
    def save_scan(scan_data):
        """Save a scan result to the database"""
        scan = ScanHistory(
            target_url=scan_data['target_url'],
            status=scan_data['status'],
            total_pages_scanned=scan_data['summary']['total_pages_scanned'],
            total_forms_found=scan_data['summary']['total_forms_found'],
            sql_injection_count=scan_data['summary']['sql_injection_vulnerabilities'],
            xss_count=scan_data['summary']['xss_vulnerabilities'],
            missing_headers_count=scan_data['summary']['missing_security_headers'],
            security_warnings_count=scan_data['summary']['security_warnings'],
            crawl_results=json.dumps(scan_data['crawl_results']),
            header_results=json.dumps(scan_data['header_results']),
            vulnerability_results=json.dumps(scan_data['vulnerability_results'])
        )
        
        db.session.add(scan)
        db.session.commit()
        
        return scan
    
    @staticmethod
    def get_all_scans(limit=50):
        """Get all scan history, most recent first"""
        return ScanHistory.query.order_by(ScanHistory.scan_time.desc()).limit(limit).all()
    
    @staticmethod
    def get_scan_by_id(scan_id):
        """Get a specific scan by ID"""
        return ScanHistory.query.get(scan_id)
    
    @staticmethod
    def delete_scan(scan_id):
        """Delete a scan from history"""
        scan = ScanHistory.query.get(scan_id)
        if scan:
            db.session.delete(scan)
            db.session.commit()
            return True
        return False
