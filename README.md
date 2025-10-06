# 🔒 Web Application Security Scanner

A comprehensive, automated security scanner that identifies vulnerabilities in web applications. Built for security professionals, penetration testers, and developers who want to proactively identify and fix security issues.
<img width="1920" height="1080" alt="Screenshot_2025-10-06_23-57-36" src="https://github.com/user-attachments/assets/db846001-27ed-4f57-bfc0-d9547ad5f940" />
<img width="1920" height="1080" alt="Screenshot_2025-10-06_23-58-32" src="https://github.com/user-attachments/assets/805a855a-d746-4aed-a2da-bd9be2a68780" />
<img width="1920" height="1080" alt="Screenshot_2025-10-06_23-58-05" src="https://github.com/user-attachments/assets/eaf57bda-a566-4ca7-aa17-14576c8fabda" />

**Live Demo:** [https://ics01.netlify.app/](https://ics01.netlify.app/)

---

## 🎯 Overview

This security scanner performs automated penetration testing on web applications to identify common vulnerabilities and security misconfigurations. It combines intelligent web crawling with targeted vulnerability detection to provide comprehensive security assessments.

### Key Capabilities

- **Automated Web Crawling** - Discovers all accessible pages, endpoints, and forms
- **SQL Injection Detection** - Tests for SQL injection vulnerabilities using diverse payload techniques
- **Cross-Site Scripting (XSS) Detection** - Identifies reflected and stored XSS vulnerabilities
- **Security Headers Analysis** - Validates critical HTTP security headers
- **Persistent Scan History** - SQLite database stores all scan results for tracking and comparison
- **Modern Dashboard** - Real-time scanning with intuitive result visualization

---

## ✨ Features

### 🕷️ Intelligent Web Crawler
- Recursive page discovery with configurable depth limits
- Domain-aware crawling (respects same-origin policy)
- Form detection with input field analysis
- JavaScript rendering support via Selenium (optional)
- Respectful crawling with rate limiting

### 🛡️ Vulnerability Detection

**SQL Injection Testing**
- Classic SQL injection patterns (`' OR '1'='1`, `' OR 1=1--`)
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Error-based SQL injection detection
- Database-specific payload testing

**Cross-Site Scripting (XSS)**
- Reflected XSS detection
- DOM-based XSS analysis
- Multiple encoding bypass techniques
- Context-aware payload generation

**Security Headers Validation**
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### 📊 Reporting & Analytics
- Comprehensive vulnerability reports with severity ratings
- Scan history with timestamp tracking
- Export functionality for compliance documentation
- Side-by-side scan comparison
- Visual security posture dashboard

---

## 🏗️ Architecture

### Backend (Python)
```
Flask API Server
├── Web Crawler (BeautifulSoup4)
├── Vulnerability Scanner
│   ├── SQL Injection Tester
│   └── XSS Detector
├── Security Headers Analyzer
└── SQLite Database
```

**Technologies:**
- **Flask** - RESTful API framework
- **Requests** - HTTP client library
- **BeautifulSoup4** - HTML/XML parsing
- **Selenium** - JavaScript-enabled browser automation
- **SQLite3** - Lightweight embedded database

### Frontend (Next.js)
```
Next.js Application
├── App Router (Next.js 15)
├── TypeScript Components
├── Tailwind CSS Styling
└── shadcn/ui Components
```

**Technologies:**
- **Next.js 15** - React framework with server components
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first CSS framework
- **shadcn/ui** - Accessible component library

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Node.js 18 or higher
- npm or yarn package manager

### Installation

**1. Clone the Repository**
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

**2. Backend Setup**
```bash
# Install Python dependencies
python scripts/install_dependencies.py

# Or manually install from requirements.txt
pip install -r scripts/requirements.txt

# Initialize the database
python scripts/init_database.py
```

**3. Frontend Setup**
```bash
# Install Node dependencies
npm install

# Or with yarn
yarn install
```

**4. Start the Application**

Terminal 1 - Backend:
```bash
python scripts/run_flask_server.py
# API runs on http://localhost:5000
```

Terminal 2 - Frontend:
```bash
npm run dev
# UI runs on http://localhost:3000
```

**5. Access the Dashboard**

Open your browser and navigate to:
```
http://localhost:3000
```

---

## 📖 Usage Guide

### Running Your First Scan

1. **Enter Target URL**
   - Navigate to the dashboard at `http://localhost:3000`
   - Input the target website URL (e.g., `https://example.com`)

2. **Initiate Scan**
   - Click the "Start Scan" button
   - Monitor real-time progress in the dashboard

3. **Review Results**
   - **Vulnerabilities Tab** - SQL Injection and XSS findings with severity levels
   - **Security Headers Tab** - Missing and present security headers
   - **Crawl Results Tab** - Discovered pages, forms, and endpoints
   - **Scan History Tab** - Previous scans with comparison tools

### Understanding Results

**Vulnerability Severity Levels:**
- 🔴 **Critical** - Immediate action required (e.g., SQL Injection)
- 🟠 **High** - Should be fixed promptly (e.g., Reflected XSS)
- 🟡 **Medium** - Important security improvement (e.g., Missing CSP)
- 🟢 **Low** - Best practice recommendation (e.g., Missing security headers)

---

## ⚙️ Configuration

### Scanner Settings

Edit `app/api/scanner/config.py`:

```python
# Crawler Configuration
MAX_CRAWL_DEPTH = 3
MAX_PAGES = 50
REQUEST_TIMEOUT = 10
CRAWL_DELAY = 1  # seconds between requests

# Vulnerability Testing
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    # Add custom payloads
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    # Add custom payloads
]

# Security Headers
REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    # Add custom headers
]
```

### Database Configuration

The scanner uses SQLite by default. To use MySQL:

```python
# In app/api/scanner/database.py
DATABASE_CONFIG = {
    'type': 'mysql',
    'host': 'localhost',
    'port': 3306,
    'database': 'security_scanner',
    'user': 'your_username',
    'password': 'your_password'
}
```

---

## 🔌 API Reference

### Endpoints

#### `POST /api/scan`
Initiate a security scan for a target URL.

**Request:**
```json
{
  "url": "https://example.com",
  "options": {
    "max_depth": 3,
    "max_pages": 50,
    "enable_js": false
  }
}
```

**Response:**
```json
{
  "scan_id": 12345,
  "target_url": "https://example.com",
  "scan_time": "2025-10-07T14:30:00Z",
  "status": "completed",
  "summary": {
    "total_pages": 25,
    "vulnerabilities_found": 3,
    "critical": 1,
    "high": 2,
    "medium": 0
  },
  "crawl_results": {
    "pages_discovered": 25,
    "forms_found": 8
  },
  "vulnerability_results": [...],
  "header_results": {...}
}
```

#### `GET /api/history`
Retrieve scan history.

**Query Parameters:**
- `limit` (optional) - Maximum results to return (default: 50)
- `offset` (optional) - Pagination offset (default: 0)

**Response:**
```json
{
  "total": 156,
  "scans": [
    {
      "scan_id": 12345,
      "target_url": "https://example.com",
      "scan_time": "2025-10-07T14:30:00Z",
      "vulnerabilities_count": 3
    }
  ]
}
```

#### `GET /api/history/:id`
Get detailed results for a specific scan.

#### `DELETE /api/history/:id`
Delete a scan from history.

#### `GET /api/health`
API health check endpoint.

---

## 🔐 Security & Ethics

### ⚠️ Important Disclaimers

**Legal Warning:**
- This tool is for **authorized security testing only**
- Unauthorized scanning may violate computer fraud laws
- Always obtain written permission before testing any system
- Review local laws and regulations regarding security testing

**Responsible Use:**
- Only scan websites you own or have explicit permission to test
- Respect rate limits and server resources
- Do not use for malicious purposes
- Report discovered vulnerabilities responsibly

**Limitations:**
- This scanner does not guarantee complete security coverage
- False positives and negatives may occur
- Manual verification of findings is recommended
- Use in conjunction with other security tools

---

## 🛠️ Development

### Project Structure

```
security-scanner/
├── app/
│   ├── api/
│   │   └── scanner/
│   │       ├── config.py
│   │       ├── crawler.py
│   │       ├── scanner.py
│   │       └── database.py
│   ├── components/
│   │   └── ui/
│   ├── page.tsx
│   └── layout.tsx
├── scripts/
│   ├── install_dependencies.py
│   ├── init_database.py
│   ├── run_flask_server.py
│   └── requirements.txt
├── public/
├── package.json
├── tsconfig.json
└── README.md
```

### Running Tests

```bash
# Python tests
python -m pytest tests/

# Frontend tests
npm run test
```

### Building for Production

```bash
# Build Next.js frontend
npm run build
npm run start

# Run Flask with production server (gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## 🗺️ Roadmap

### Planned Features

- [ ] **Authentication System** - User accounts and role-based access
- [ ] **Additional Vulnerability Checks**
  - [ ] CSRF detection
  - [ ] SSRF vulnerabilities
  - [ ] Open redirect detection
  - [ ] Sensitive data exposure
- [ ] **Advanced Reporting**
  - [ ] PDF export with charts
  - [ ] Executive summary generation
  - [ ] Compliance mapping (OWASP Top 10)
- [ ] **Automation**
  - [ ] Scheduled scans
  - [ ] Email notifications
  - [ ] Webhook integrations
- [ ] **Enhanced Features**
  - [ ] Custom payload libraries
  - [ ] Machine learning-based detection
  - [ ] Multi-threaded scanning
  - [ ] Browser extension

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Write clean, documented code
- Add tests for new features
- Update documentation as needed
- Follow existing code style
- Ensure all tests pass before submitting

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

Permission is granted to use, copy, modify, and distribute this software for educational and authorized security testing purposes. The software is provided "as is" without warranty.

---

## 👥 Authors

**Your Name** - Initial work - [GitHub](https://github.com/Neerajupadhayay2004)

See also the list of [contributors](https://github.com/Neerajupadhayay2004/security-scanner/contributors) who participated in this project.

---

## 🙏 Acknowledgments

- OWASP Foundation for vulnerability testing methodologies
- The security research community
- shadcn for the excellent UI component library
- All contributors and testers

---

## 📞 Support

- **Documentation:** [Wiki](https://github.com/Neerajupadhayay2004/security-scanner/wiki)
- **Issues:** [GitHub Issues](https://github.com/Neerajupadhayay2004/security-scanner/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Neerajupadhayay2004/security-scanner/discussions)

---

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/Neerajupadhayay2004/security-scanner)
![GitHub forks](https://img.shields.io/github/forks/Neerajupadhayay2004/security-scanner)
![GitHub issues](https://img.shields.io/github/issues/Neerajupadhayay2004/security-scanner)

---

<div align="center">

**⚠️ Use Responsibly | Educational Purposes Only ⚠️**

Made with ❤️ for the security community

[Report Bug](https://github.com/Neerajupadhayay2004/security-scanner/issues) · [Request Feature](https://github.com/Neerajupadhayay2004/security-scanner/issues) · [Documentation](https://github.com/Neerajupadhayay2004/security-scanner/wiki)

</div>
