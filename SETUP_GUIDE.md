# 🚀 Security Scanner - Complete Setup Guide

## Prerequisites

- **Python 3.8+** (tested with Python 3.13)
- **Node.js 18+** and npm
- **VS Code** (recommended)

---

## 📦 Step 1: Install Python Dependencies

Open your terminal in the project directory and run:

\`\`\`bash
# Create virtual environment (if not already created)
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r scripts/requirements.txt
\`\`\`

**Note:** We removed `lxml` for Python 3.13 compatibility. BeautifulSoup now uses Python's built-in `html.parser`.

---

## 📦 Step 2: Install Node.js Dependencies

\`\`\`bash
npm install --legacy-peer-deps
\`\`\`

**Note:** We use `--legacy-peer-deps` to handle React version conflicts with some packages.

---

## 🗄️ Step 3: Initialize Database

\`\`\`bash
python scripts/init_database.py
\`\`\`

This creates the SQLite database for storing scan results.

---

## 🚀 Step 4: Start the Servers

You need **TWO terminals** running simultaneously:

### Terminal 1: Flask Backend (Port 5000)

\`\`\`bash
# Make sure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Start Flask server
python scripts/run_flask_server.py
\`\`\`

You should see:
\`\`\`
 * Running on http://127.0.0.1:5000
\`\`\`

### Terminal 2: Next.js Frontend (Port 3000)

\`\`\`bash
npm run dev
\`\`\`

You should see:
\`\`\`
▲ Next.js 15.5.4
- Local: http://localhost:3000
\`\`\`

---

## 🌐 Step 5: Open the App

Open your browser and go to:
\`\`\`
http://localhost:3000
\`\`\`

---

## 🎯 How to Use

1. **Enter a URL** to scan (e.g., `http://testphp.vulnweb.com`)
2. **Click "Start Scan"** and wait for results
3. **View Results** in three tabs:
   - **Vulnerabilities**: SQL Injection & XSS findings
   - **Security Headers**: Missing or weak headers
   - **Crawl Results**: Discovered pages and forms

4. **Scan History**: View, reload, or delete previous scans

---

## 🛠️ VS Code Setup

### Recommended Extensions

1. **Python** (ms-python.python)
2. **Pylance** (ms-python.vscode-pylance)
3. **ESLint** (dbaeumer.vscode-eslint)
4. **Tailwind CSS IntelliSense** (bradlc.vscode-tailwindcss)

### Running in VS Code

1. **Open Integrated Terminal**: `` Ctrl+` `` (backtick)
2. **Split Terminal**: Click the split icon or `Ctrl+Shift+5`
3. **Run Flask in Terminal 1**:
   \`\`\`bash
   source venv/bin/activate
   python scripts/run_flask_server.py
   \`\`\`
4. **Run Next.js in Terminal 2**:
   \`\`\`bash
   npm run dev
   \`\`\`

### VS Code Tasks (Optional)

Press `Ctrl+Shift+P` → Type "Tasks: Run Task" → Select:
- **Start Flask Server**
- **Start Next.js Dev Server**

---

## 🐛 Troubleshooting

### Python Issues

**Problem:** `ModuleNotFoundError: No module named 'flask'`
\`\`\`bash
# Make sure virtual environment is activated
source venv/bin/activate
pip install -r scripts/requirements.txt
\`\`\`

**Problem:** `lxml` installation fails
\`\`\`bash
# Already fixed! We removed lxml from requirements.txt
# BeautifulSoup now uses html.parser
\`\`\`

### Node.js Issues

**Problem:** `ERESOLVE unable to resolve dependency tree`
\`\`\`bash
# Use legacy peer deps flag
npm install --legacy-peer-deps
\`\`\`

**Problem:** Port 3000 already in use
\`\`\`bash
# Kill the process or use a different port
npm run dev -- -p 3001
\`\`\`

### Flask Issues

**Problem:** Port 5000 already in use
\`\`\`bash
# Kill the process using port 5000
# Linux/Mac:
lsof -ti:5000 | xargs kill -9
# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F
\`\`\`

**Problem:** CORS errors
\`\`\`bash
# Make sure Flask server is running on port 5000
# Check that flask-cors is installed
pip install flask-cors
\`\`\`

---

## 📁 Project Structure

\`\`\`
security-scanner/
├── app/
│   ├── api/
│   │   └── scanner/
│   │       ├── config.py          # Scanner configuration
│   │       ├── crawler.py         # Web crawler
│   │       ├── vulnerability_scanner.py  # SQL/XSS scanner
│   │       ├── header_checker.py  # Security headers checker
│   │       ├── database.py        # Database models
│   │       └── route.py           # Flask API routes
│   ├── page.tsx                   # Main dashboard
│   ├── layout.tsx                 # Root layout
│   └── globals.css                # Global styles
├── components/
│   └── scan-history.tsx           # Scan history component
├── scripts/
│   ├── requirements.txt           # Python dependencies
│   ├── install_dependencies.py    # Dependency installer
│   ├── init_database.py           # Database initializer
│   └── run_flask_server.py        # Flask server launcher
├── security_scanner.db            # SQLite database (created after init)
└── package.json                   # Node.js dependencies
\`\`\`

---

## 🔒 Security Notes

⚠️ **Educational Purpose Only**

- This tool is for **educational and authorized testing only**
- Never scan websites without permission
- Unauthorized scanning may be illegal
- Use responsibly and ethically

---

## 📚 Features

✅ **Web Crawler** - Discovers pages and forms automatically  
✅ **SQL Injection Scanner** - Tests 17 different SQL injection payloads  
✅ **XSS Scanner** - Tests 15 different XSS attack vectors  
✅ **Security Headers** - Checks 7 critical security headers  
✅ **Scan History** - Stores and retrieves previous scan results  
✅ **Dark Theme UI** - Professional cybersecurity-themed interface  

---

## 🎓 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## 💡 Tips

- Start with test sites like `http://testphp.vulnweb.com`
- Adjust scan depth in `config.py` for faster/deeper scans
- Check the browser console for detailed logs
- Use the scan history to compare results over time

---

**Happy Scanning! 🔍🛡️**
