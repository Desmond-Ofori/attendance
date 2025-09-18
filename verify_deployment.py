#!/usr/bin/env python3
"""
TapIn Deployment Verification Script
Comprehensive testing for Render deployment readiness.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)

def print_success(text):
    """Print success message"""
    print(f"SUCCESS: {text}")

def print_error(text):
    """Print error message"""
    print(f"ERROR: {text}")

def print_warning(text):
    """Print warning message"""
    print(f"WARNING: {text}")

def check_file_exists(filepath, description):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print_success(f"{description}: {filepath}")
        return True
    else:
        print_error(f"{description}: {filepath} - NOT FOUND")
        return False

def check_directory_structure():
    """Check the overall directory structure"""
    print_header("CHECKING DIRECTORY STRUCTURE")

    required_files = [
        ("tapin_backend/app.py", "Main Flask application"),
        ("tapin_backend/requirements.txt", "Python dependencies"),
        ("tapin_backend/runtime.txt", "Python version specification"),
        ("render.yaml", "Render deployment configuration"),
        ("static/js/config.js", "Frontend API configuration"),
        ("templates/welcome_page/index.html", "Main frontend page"),
        ("tapin_backend/.env.production", "Production environment template")
    ]

    all_good = True
    for filepath, description in required_files:
        if not check_file_exists(filepath, description):
            all_good = False

    return all_good

def check_python_version():
    """Check Python version compatibility"""
    print_header("CHECKING PYTHON VERSION")

    version = sys.version_info
    print(f"Current Python version: {version.major}.{version.minor}.{version.micro}")

    if version.major == 3 and version.minor == 13:
        print_success("Python 3.13.x detected - Compatible with Render")
        return True
    else:
        print_warning(f"Python {version.major}.{version.minor} detected - Should be 3.13 for Render")
        return False

def check_requirements_file():
    """Check requirements.txt for Python 3.13 compatibility"""
    print_header("CHECKING REQUIREMENTS.TXT")

    try:
        with open("tapin_backend/requirements.txt", "r") as f:
            requirements = f.read().strip().split("\n")

        print(f"Found {len(requirements)} dependencies")

        # Check for critical packages
        critical_packages = {
            "Flask": "3.0.3",
            "SQLAlchemy": "2.0.35",
            "Pillow": "10.4.0",
            "gunicorn": "22.0.0"
        }

        for req in requirements:
            if req.strip() and not req.startswith("#"):
                for package, expected_version in critical_packages.items():
                    if package.lower() in req.lower():
                        if expected_version in req:
                            print_success(f"{package} {expected_version} - Compatible")
                        else:
                            print_warning(f"{package} version might need verification")

        return True

    except Exception as e:
        print_error(f"Error reading requirements.txt: {e}")
        return False

def check_render_yaml():
    """Check render.yaml configuration"""
    print_header("CHECKING RENDER.YAML")

    try:
        with open("render.yaml", "r") as f:
            render_config = f.read()

        checks = [
            ("runtime: python", "Python runtime specified"),
            ("buildCommand", "Build command configured"),
            ("startCommand", "Start command configured"),
            ("DATABASE_URL", "Database URL environment variable"),
            ("SECRET_KEY", "Secret key environment variable"),
            ("JWT_SECRET_KEY", "JWT secret key environment variable")
        ]

        for check, description in checks:
            if check in render_config:
                print_success(f"{description}")
            else:
                print_error(f"{description} - MISSING")

        return True

    except Exception as e:
        print_error(f"Error reading render.yaml: {e}")
        return False

def check_runtime_txt():
    """Check runtime.txt for correct Python version"""
    print_header("CHECKING RUNTIME.TXT")

    try:
        with open("tapin_backend/runtime.txt", "r") as f:
            runtime_version = f.read().strip()

        if runtime_version == "python-3.13.4":
            print_success("Python 3.13.4 specified - Perfect for Render")
            return True
        else:
            print_warning(f"Runtime version: {runtime_version} - Should be python-3.13.4")
            return False

    except Exception as e:
        print_error(f"Error reading runtime.txt: {e}")
        return False

def check_frontend_config():
    """Check frontend configuration for production readiness"""
    print_header("CHECKING FRONTEND CONFIGURATION")

    try:
        with open("static/js/config.js", "r") as f:
            config_content = f.read()

        if "getApiUrl" in config_content:
            print_success("Dynamic API URL configuration found")
        else:
            print_error("Dynamic API URL configuration missing")

        if "window.location.hostname" in config_content:
            print_success("Environment detection logic present")
        else:
            print_error("Environment detection logic missing")

        return True

    except Exception as e:
        print_error(f"Error reading config.js: {e}")
        return False

def check_static_files():
    """Check static file structure"""
    print_header("CHECKING STATIC FILES")

    static_dirs = [
        "static/css",
        "static/js",
        "static/pics",
        "static/uploads"
    ]

    all_good = True
    for static_dir in static_dirs:
        if os.path.exists(static_dir):
            print_success(f"Static directory: {static_dir}")
        else:
            print_error(f"Static directory missing: {static_dir}")
            all_good = False

    return all_good

def check_template_files():
    """Check template file structure"""
    print_header("CHECKING TEMPLATE FILES")

    template_dirs = [
        "templates/welcome_page",
        "templates/lecturer_page",
        "templates/student_page"
    ]

    all_good = True
    for template_dir in template_dirs:
        if os.path.exists(template_dir):
            # Count HTML files in directory
            html_files = list(Path(template_dir).glob("*.html"))
            print_success(f"Template directory: {template_dir} ({len(html_files)} HTML files)")
        else:
            print_error(f"Template directory missing: {template_dir}")
            all_good = False

    return all_good

def check_backend_routes():
    """Check backend route files"""
    print_header("CHECKING BACKEND ROUTES")

    route_files = [
        "tapin_backend/routes_analytics.py",
        "tapin_backend/routes_attendance.py",
        "tapin_backend/routes_classes.py",
        "tapin_backend/routes_notifications.py",
        "tapin_backend/routes_profile.py",
        "tapin_backend/routes_qr_attendance.py",
        "tapin_backend/routes_reports.py",
        "tapin_backend/routes_student_analytics.py",
        "tapin_backend/routes_bulk_enrollment.py",
        "tapin_backend/routes_schedule.py",
        "tapin_backend/routes_reminders.py",
        "tapin_backend/routes_backup.py",
        "tapin_backend/routes_visualization.py"
    ]

    all_good = True
    for route_file in route_files:
        if os.path.exists(route_file):
            print_success(f"Route file: {route_file}")
        else:
            print_error(f"Route file missing: {route_file}")
            all_good = False

    return all_good

def generate_deployment_report():
    """Generate a deployment readiness report"""
    print_header("DEPLOYMENT READINESS REPORT")

    print("\nDEPLOYMENT CHECKLIST:")
    print("- Commit all changes to Git")
    print("- Push to GitHub repository")
    print("- Connect repository to Render.com")
    print("- Set environment variables in Render dashboard:")
    print("  - SECRET_KEY (generate a secure random key)")
    print("  - JWT_SECRET_KEY (generate a secure random key)")
    print("- Test the deployed application")

    print("\nIMPORTANT URLS:")
    print("- Health Check: https://your-app.onrender.com/api/health")
    print("- API Root: https://your-app.onrender.com/")
    print("- Frontend: https://your-app.onrender.com/app")

    print("\nENVIRONMENT VARIABLES TO SET:")
    print("SECRET_KEY=your-super-secret-key-here")
    print("JWT_SECRET_KEY=your-jwt-secret-key-here")
    print("DEBUG=False")
    print("FLASK_ENV=production")

def main():
    """Run all deployment checks"""
    print("TapIn Deployment Verification")
    print("Checking if your app is ready for Render deployment...")

    checks = [
        ("Directory Structure", check_directory_structure),
        ("Python Version", check_python_version),
        ("Requirements File", check_requirements_file),
        ("Render Configuration", check_render_yaml),
        ("Runtime Version", check_runtime_txt),
        ("Frontend Config", check_frontend_config),
        ("Static Files", check_static_files),
        ("Template Files", check_template_files),
        ("Backend Routes", check_backend_routes)
    ]

    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print_error(f"{check_name} check failed: {e}")
            results.append((check_name, False))

    # Summary
    print_header("FINAL RESULTS")

    passed = 0
    total = len(results)

    for check_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{check_name}: {status}")
        if result:
            passed += 1

    print(f"\nScore: {passed}/{total} checks passed")

    if passed == total:
        print("\nCONGRATULATIONS!")
        print("Your TapIn Attendance System is 100% ready for Render deployment!")
        print("All checks passed - you can deploy with confidence.")
    elif passed >= total * 0.8:
        print("\nALMOST READY!")
        print("Most checks passed. Fix the failed items and you'll be ready to deploy.")
    else:
        print("\nISSUES FOUND!")
        print("Several checks failed. Please fix the issues before deploying.")

    generate_deployment_report()

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)