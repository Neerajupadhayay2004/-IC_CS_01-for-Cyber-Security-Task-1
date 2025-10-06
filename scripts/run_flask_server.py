"""Script to run the Flask API server"""

import sys
import os

# Add the parent directory to the path so we can import from app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.api.scanner.route import app

if __name__ == '__main__':
    print("Starting Security Scanner API Server...")
    print("API will be available at: http://localhost:5000")
    print("Health check: http://localhost:5000/api/health")
    print("Scan endpoint: POST http://localhost:5000/api/scan")
    app.run(debug=True, host='0.0.0.0', port=5000)
