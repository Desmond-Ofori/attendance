#!/usr/bin/env python3
"""
Comprehensive Deployment Verification for TapIn Attendance System
Checks all components to ensure successful Render deployment
"""

import os
import json
import sys
from pathlib import Path

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)

def print_success(text):
    """Print success message"""
    print(f"[OK] {text}")

def print_error(text):
    """Print error message"""
    print(f"[ERROR] {text}")

def print_warning(text):
    """Print warning message"""
    print(f"[WARNING] {text}")

def check_file_structure():
    """Check if all required files exist"""
    print_header("FILE STRUCTURE VERIFICATION")

    required_files = [
        "tapin_backend/app.py",
        "tapin_backend/start_app.py",
        "tapin_backend/requirements.txt",
        "tapin_backend/models.py",
        "static/js/auth.js",
        "static/js/config.js",
        "static/css/lecturer_page_css/lecturer_style.css",
        "static/pics/attendance_app_icon.png",
        "templates/lecturer_page/lecturer_home.html",
        "templates/welcome_page/index.html",
        "render.yaml"
    ]

    all_good = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print_success(f"Found: {file_path}")
        else:
            print_error(f"Missing: {file_path}")
            all_good = False

    return all_good

def check_static_files():
    """Check static file references in HTML"""
    print_header("STATIC FILE REFERENCES")

    html_files = [
        "templates/lecturer_page/lecturer_home.html",
        "templates/welcome_page/index.html"
    ]

    issues = []
    for html_file in html_files:
        if os.path.exists(html_file):
            with open(html_file, 'r', encoding='utf-8') as f:
                content = f.read()

                # Check for problematic relative links
                if 'href="lecturer_' in content and 'url_for' not in content:
                    issues.append(f"{html_file}: Contains relative links that need Flask url_for")

                # Check for correct static file paths
                if '/static/' in content:
                    print_success(f"{html_file}: Static file paths are correct")
                else:
                    print_warning(f"{html_file}: No static file references found")

    if issues:
        for issue in issues:
            print_error(issue)
        return False

    return True

def check_flask_routes():
    """Check Flask route configuration"""
    print_header("FLASK ROUTE CONFIGURATION")

    app_file = "tapin_backend/app.py"
    if not os.path.exists(app_file):
        print_error("Backend app.py not found")
        return False

    with open(app_file, 'r', encoding='utf-8') as f:
        content = f.read()

    routes_to_check = [
        "@app.route('/')",
        "@app.route('/lecturer/dashboard')",
        "@app.route('/student/dashboard')",
        "@app.post('/login')",
        "@app.post('/register')",
        "@app.get('/api/health')"
    ]

    all_good = True
    for route in routes_to_check:
        if route in content:
            print_success(f"Found route: {route}")
        else:
            print_error(f"Missing route: {route}")
            all_good = False

    return all_good

def check_render_config():
    """Check Render deployment configuration"""
    print_header("RENDER DEPLOYMENT CONFIGURATION")

    render_file = "render.yaml"
    if not os.path.exists(render_file):
        print_error("render.yaml not found")
        return False

    with open(render_file, 'r', encoding='utf-8') as f:
        config = f.read()

    checks = [
        ("Single service", "tapin-attendance-app" in config),
        ("Python runtime", "runtime: python" in config),
        ("Correct build command", "tapin_backend" in config),
        ("Correct start command", "start_app.py" in config),
        ("Environment variables", "SECRET_KEY" in config),
        ("PORT configuration", "PORT" in config)
    ]

    all_good = True
    for check_name, condition in checks:
        if condition:
            print_success(f"{check_name}: Configured correctly")
        else:
            print_error(f"{check_name}: Configuration issue")
            all_good = False

    return all_good

def check_dependencies():
    """Check Python dependencies"""
    print_header("PYTHON DEPENDENCIES")

    req_file = "tapin_backend/requirements.txt"
    if not os.path.exists(req_file):
        print_error("requirements.txt not found")
        return False

    with open(req_file, 'r', encoding='utf-8') as f:
        content = f.read()

    required_deps = [
        "Flask",
        "SQLAlchemy",
        "Flask-SQLAlchemy",
        "Flask-Cors",
        "python-dotenv",
        "gunicorn"
    ]

    all_good = True
    for dep in required_deps:
        if dep in content:
            print_success(f"Found dependency: {dep}")
        else:
            print_error(f"Missing dependency: {dep}")
            all_good = False

    return all_good

def check_javascript_integration():
    """Check JavaScript integration"""
    print_header("JAVASCRIPT INTEGRATION")

    js_files = [
        "static/js/auth.js",
        "static/js/config.js"
    ]

    html_file = "templates/lecturer_page/lecturer_home.html"

    if not os.path.exists(html_file):
        print_error("HTML file not found for JS check")
        return False

    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    js_issues = []
    for js_file in js_files:
        if os.path.exists(js_file):
            js_path = f"/static/js/{os.path.basename(js_file)}"
            if js_path in html_content:
                print_success(f"JS file properly included: {js_file}")
            else:
                js_issues.append(f"JS file not included in HTML: {js_file}")
        else:
            js_issues.append(f"JS file missing: {js_file}")

    if js_issues:
        for issue in js_issues:
            print_error(issue)
        return False

    return True

def check_api_endpoints():
    """Check API endpoint configuration"""
    print_header("API ENDPOINTS CONFIGURATION")

    app_file = "tapin_backend/app.py"
    if not os.path.exists(app_file):
        print_error("Backend app.py not found")
        return False

    with open(app_file, 'r', encoding='utf-8') as f:
        content = f.read()

    api_endpoints = [
        "app.register_blueprint(auth_bp",
        "app.register_blueprint(classes_bp",
        "app.register_blueprint(attendance_bp",
        "app.register_blueprint(analytics_bp"
    ]

    all_good = True
    for endpoint in api_endpoints:
        if endpoint in content:
            print_success(f"API endpoint registered: {endpoint.split('(')[1].split(',')[0]}")
        else:
            print_error(f"Missing API endpoint: {endpoint}")
            all_good = False

    return all_good

def generate_deployment_report():
    """Generate final deployment report"""
    print_header("DEPLOYMENT READINESS REPORT")

    print("""
DEPLOYMENT STATUS SUMMARY:

[OK] FILE STRUCTURE: All required files present
[OK] STATIC FILES: Properly configured and referenced
[OK] FLASK ROUTES: All routes properly defined
[OK] RENDER CONFIG: Single service deployment ready
[OK] DEPENDENCIES: All required packages included
[OK] JAVASCRIPT: Properly integrated with HTML
[OK] API ENDPOINTS: All blueprints registered

READY FOR DEPLOYMENT ON RENDER!

FINAL CHECKLIST:
1. Push code to GitHub repository
2. Connect repository to Render
3. Use render.yaml configuration
4. Set environment variables in Render dashboard
5. Deploy and test immediately

ENVIRONMENT VARIABLES TO SET:
- SECRET_KEY (auto-generated by Render)
- JWT_SECRET_KEY (auto-generated by Render)
- DATABASE_URL (auto-generated by Render)
- FLASK_ENV=production
- DEBUG=False
- PORT=8000

POST-DEPLOYMENT TESTING:
1. Visit: https://your-app.onrender.com/
2. Test registration: /account
3. Test login: /lecturer_login or /student_login
4. Test dashboard: /lecturer/dashboard or /student/dashboard
5. Test API: /api/health

Everything is configured correctly for successful deployment!
""")

def main():
    """Run all deployment checks"""
    print("TapIn Attendance System - Deployment Verification")
    print("Checking all components for successful Render deployment...")

    checks = [
        ("File Structure", check_file_structure),
        ("Static Files", check_static_files),
        ("Flask Routes", check_flask_routes),
        ("Render Config", check_render_config),
        ("Dependencies", check_dependencies),
        ("JavaScript Integration", check_javascript_integration),
        ("API Endpoints", check_api_endpoints)
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
    print_header("VERIFICATION SUMMARY")

    passed = 0
    total = len(results)

    for check_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{check_name}: {status}")
        if result:
            passed += 1

    print(f"\nScore: {passed}/{total} checks passed")

    if passed == total:
        print("\nALL CHECKS PASSED - READY FOR DEPLOYMENT!")
        generate_deployment_report()
        return True
    else:
        print(f"\n{total - passed} checks failed - please review issues above")
        return False

if __name__ == "__main__":
    success = main()
    print(f"\n{'='*70}")
    if success:
        print("DEPLOYMENT VERIFICATION COMPLETE - READY TO DEPLOY!")
    else:
        print("ISSUES FOUND - PLEASE FIX BEFORE DEPLOYMENT!")
    print(f"{'='*70}")