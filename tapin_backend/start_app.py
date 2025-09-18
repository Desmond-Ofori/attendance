#!/usr/bin/env python3
"""
Startup script for consolidated TapIn Attendance Application
This script starts the unified Flask application with both frontend and backend
"""
import os
import sys
from pathlib import Path

def main():
    """Main startup function"""
    print("=" * 60)
    print("TapIn Attendance Application - Consolidated Edition")
    print("=" * 60)

    # Ensure we're in the right directory
    if not Path("app.py").exists():
        print("Please run this script from the tapin_backend directory")
        sys.exit(1)

    # Import and run the app
    from app import app, socketio
    from models import db

    print("Starting TapIn Attendance Application...")
    print("Application running at: http://localhost:8000")
    print("Frontend: http://localhost:8000/")
    print("API Health Check: http://localhost:8000/api/health")
    print("API Documentation available in README.md")
    print("-" * 50)

    with app.app_context():
        if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
            db.create_all()
            print("Database (SQLite) initialized successfully")
        else:
            # Run migrations for production
            from flask_migrate import upgrade
            try:
                upgrade()
                print("Production database migrations applied successfully")
            except Exception as e:
                print(f"Warning: Migration failed - {e}")
                # Still start the app, but log the error

    # Run with Socket.IO
    debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
    socketio.run(app, host='0.0.0.0', port=8000, debug=debug_mode)

if __name__ == '__main__':
    main()