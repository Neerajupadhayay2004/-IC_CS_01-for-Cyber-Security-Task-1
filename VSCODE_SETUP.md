# VS Code Setup Guide for SecureWeb Scanner

## Prerequisites

Before you begin, make sure you have the following installed:

1. **Python 3.8+** - [Download Python](https://www.python.org/downloads/)
2. **Node.js 18+** - [Download Node.js](https://nodejs.org/)
3. **VS Code** - [Download VS Code](https://code.visualstudio.com/)

## Step 1: Install VS Code Extensions

Open VS Code and install these recommended extensions:

1. **Python** (by Microsoft) - Python language support
2. **Pylance** (by Microsoft) - Python IntelliSense
3. **ES7+ React/Redux/React-Native snippets** - React code snippets
4. **Tailwind CSS IntelliSense** - Tailwind CSS autocomplete
5. **Prettier** - Code formatter
6. **ESLint** - JavaScript linter

## Step 2: Clone/Open Project in VS Code

1. Open VS Code
2. Click `File` → `Open Folder`
3. Navigate to your project directory and open it

## Step 3: Setup Python Environment

### Option A: Using VS Code Terminal

1. Open VS Code terminal: `View` → `Terminal` or press `` Ctrl+` ``
2. Create a virtual environment:
   \`\`\`bash
   python -m venv venv
   \`\`\`

3. Activate the virtual environment:
   - **Windows:**
     \`\`\`bash
     venv\Scripts\activate
     \`\`\`
   - **Mac/Linux:**
     \`\`\`bash
     source venv/bin/activate
     \`\`\`

4. Install Python dependencies:
   \`\`\`bash
   pip install -r scripts/requirements.txt
   \`\`\`

### Option B: Using Python Script

Run the installation script:
\`\`\`bash
python scripts/install_dependencies.py
\`\`\`

## Step 4: Setup Next.js Frontend

1. In VS Code terminal, install Node.js dependencies:
   \`\`\`bash
   npm install
   \`\`\`

## Step 5: Initialize Database

Run the database initialization script:
\`\`\`bash
python scripts/init_database.py
\`\`\`

This creates the SQLite database at `app/api/scanner/scans.db`

## Step 6: Configure VS Code Settings

Create `.vscode/settings.json` in your project root:

\`\`\`json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "[python]": {
    "editor.defaultFormatter": "ms-python.python"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescriptreact]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  }
}
\`\`\`

## Step 7: Running the Application

### Method 1: Using VS Code Tasks (Recommended)

1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type "Tasks: Run Task"
3. Select "Start Flask Server" or "Start Next.js Dev"

### Method 2: Using Terminals

**Terminal 1 - Flask Backend:**
\`\`\`bash
# Activate virtual environment first
python scripts/run_flask_server.py
\`\`\`

**Terminal 2 - Next.js Frontend:**
\`\`\`bash
npm run dev
\`\`\`

## Step 8: Access the Application

1. **Frontend:** Open browser to `http://localhost:3000`
2. **Backend API:** Running on `http://localhost:5000`

## VS Code Keyboard Shortcuts

- **Open Terminal:** `` Ctrl+` ``
- **Split Terminal:** `Ctrl+Shift+5`
- **New Terminal:** `Ctrl+Shift+` `
- **Toggle Sidebar:** `Ctrl+B`
- **Command Palette:** `Ctrl+Shift+P`
- **Quick Open File:** `Ctrl+P`
- **Find in Files:** `Ctrl+Shift+F`

## Debugging in VS Code

### Debug Python (Flask)

Create `.vscode/launch.json`:

\`\`\`json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: Flask",
      "type": "python",
      "request": "launch",
      "module": "flask",
      "env": {
        "FLASK_APP": "app/api/scanner/route.py",
        "FLASK_ENV": "development"
      },
      "args": ["run", "--port=5000"],
      "jinja": true,
      "justMyCode": true
    }
  ]
}
\`\`\`

### Debug Next.js

Next.js debugging is built-in. Just run:
\`\`\`bash
npm run dev
\`\`\`

Then use Chrome DevTools or VS Code's JavaScript debugger.

## Common Issues & Solutions

### Issue: Python not found
**Solution:** Make sure Python is in your PATH. Restart VS Code after installing Python.

### Issue: Module not found errors
**Solution:** Activate virtual environment and reinstall dependencies:
\`\`\`bash
pip install -r scripts/requirements.txt
\`\`\`

### Issue: Port already in use
**Solution:** Kill the process using the port:
- **Windows:** `netstat -ano | findstr :5000` then `taskkill /PID <PID> /F`
- **Mac/Linux:** `lsof -ti:5000 | xargs kill -9`

### Issue: CORS errors
**Solution:** Make sure Flask server is running on port 5000 and Next.js on port 3000.

## Project Structure

\`\`\`
security-scanner/
├── app/
│   ├── api/
│   │   └── scanner/
│   │       ├── config.py          # Scanner configuration
│   │       ├── crawler.py         # Web crawler
│   │       ├── vulnerability_scanner.py  # SQL/XSS scanner
│   │       ├── header_checker.py  # Security headers checker
│   │       ├── database.py        # Database operations
│   │       ├── route.py          # Flask API routes
│   │       └── scans.db          # SQLite database
│   ├── page.tsx                  # Main dashboard
│   ├── layout.tsx                # Root layout
│   └── globals.css               # Global styles
├── components/
│   ├── ui/                       # shadcn/ui components
│   └── scan-history.tsx          # Scan history component
├── scripts/
│   ├── requirements.txt          # Python dependencies
│   ├── install_dependencies.py   # Dependency installer
│   ├── run_flask_server.py      # Flask server runner
│   └── init_database.py         # Database initializer
└── package.json                  # Node.js dependencies
\`\`\`

## Next Steps

1. Start scanning websites for vulnerabilities
2. Review scan history and reports
3. Export results for documentation
4. Customize scanner payloads in `vulnerability_scanner.py`
5. Add more security checks as needed

## Support

For issues or questions:
- Check the console logs in VS Code terminal
- Review Flask server logs for backend errors
- Check browser console for frontend errors
- Ensure all dependencies are installed correctly

Happy scanning! 🔒
