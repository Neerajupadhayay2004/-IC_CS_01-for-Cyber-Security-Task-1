"""Initialize the database and create tables"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.api.scanner.route import app, db

def init_database():
    """Initialize the database"""
    with app.app_context():
        print("[v0] Creating database tables...")
        db.create_all()
        print("[v0] Database initialized successfully!")
        print(f"[v0] Database location: {app.config['SQLALCHEMY_DATABASE_URI']}")

if __name__ == '__main__':
    init_database()
