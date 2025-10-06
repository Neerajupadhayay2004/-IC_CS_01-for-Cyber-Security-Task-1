# Web Application Security Scanner

A comprehensive security scanner that automatically detects vulnerabilities in web applications including SQL Injection, XSS, and security header issues.

## Features

- **Web Crawler**: Automatically discovers pages and forms on target websites
- **SQL Injection Detection**: Tests forms with various SQL injection payloads
- **XSS Detection**: Tests for Cross-Site Scripting vulnerabilities
- **Security Headers Check**: Validates presence of important security headers (CSP, HSTS, etc.)
- **Modern UI**: Clean, responsive dashboard built with Next.js and shadcn/ui
- **Real-time Scanning**: Live progress updates during security scans
- **Scan History**: SQLite database stores all scan results for future reference
- **Export & Review**: View, compare, and delete previous scans

## Tech Stack

### Backend (Python)
- **Flask**: Web framework for API endpoints
- **Requests**: HTTP library for web requests
- **BeautifulSoup4**: HTML parsing and web scraping
- **Selenium**: Browser automation (optional, for JavaScript-heavy sites)

### Frontend (Next.js)
- **Next.js 15**: React framework with App Router
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Utility-first styling
- **shadcn/ui**: High-quality UI components

## Installation & Setup

### Step 1: Install Python Dependencies

\`\`\`bash
# Install Python packages
python scripts/install_dependencies.py
\`\`\`

Or manually:
\`\`\`bash
pip install -r scripts/requirements.txt
\`\`\`

### Step 2: Initialize Database

\`\`\`bash
# Create the SQLite database and tables
python scripts/init_database.py
\`\`\`

### Step 3: Start the Flask API Server

\`\`\`bash
python scripts/run_flask_server.py
\`\`\`

The API will be available at `http://localhost:5000`

### Step 4: Start the Next.js Frontend

\`\`\`bash
npm install
npm run dev
\`\`\`

The web interface will be available at `http://localhost:3000`

## Usage

1. Open your browser and navigate to `http://localhost:3000`
2. Enter a target URL (e.g., `https://example.com`)
3. Click "Scan" to start the security analysis
4. View results in three tabs:
   - **Vulnerabilities**: SQL Injection and XSS findings
   - **Security Headers**: Missing and present security headers
   - **Crawl Results**: Discovered pages and forms
   - **Scan History**: View past scan results and compare

## How It Works

### 1. Web Crawler
- Starts from the base URL and discovers all linked pages
- Respects domain boundaries (only crawls same domain)
- Extracts all forms with their inputs and methods
- Configurable depth and page limits

### 2. Vulnerability Scanner
- **SQL Injection**: Tests form inputs with common SQL injection payloads
- **XSS**: Tests for reflected XSS by injecting JavaScript payloads
- Analyzes responses for error messages and reflected content

### 3. Security Headers Checker
- Validates presence of critical security headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - And more...

## Configuration

Edit `app/api/scanner/config.py` to customize:

- SQL injection payloads
- XSS payloads
- Crawler settings (depth, max pages, timeout)
- Security headers to check

## Important Notes

⚠️ **Educational Purpose Only**: This tool is for educational purposes and authorized security testing only. Always obtain permission before scanning any website you don't own.

⚠️ **Rate Limiting**: The scanner includes delays between requests to be respectful to target servers.

⚠️ **Legal Disclaimer**: Unauthorized security testing may be illegal. Use responsibly.

## API Endpoints

### POST /api/scan
Initiates a security scan for a target URL.

**Request:**
\`\`\`json
{
  "url": "https://example.com"
}
\`\`\`

**Response:**
\`\`\`json
{
  "scan_id": 1,
  "target_url": "https://example.com",
  "scan_time": "2025-01-06T10:30:00",
  "status": "completed",
  "summary": {...},
  "crawl_results": {...},
  "header_results": {...},
  "vulnerability_results": [...]
}
\`\`\`

### GET /api/history
Get all scan history (most recent first).

**Query Parameters:**
- `limit` (optional): Maximum number of scans to return (default: 50)

**Response:**
\`\`\`json
{
  "total": 10,
  "scans": [...]
}
\`\`\`

### GET /api/history/:id
Get details of a specific scan by ID.

### DELETE /api/history/:id
Delete a scan from history.

### GET /api/health
Health check endpoint.

## Next Steps

- Implement user authentication
- Add more vulnerability checks (CSRF, SSRF, etc.)
- Export reports as PDF
- Schedule automated scans
- Add email notifications

## License

MIT License - Educational purposes only
