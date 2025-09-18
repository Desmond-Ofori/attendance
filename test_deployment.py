#!/usr/bin/env python3
"""
TapIn Deployment Test Script
Tests compatibility with Python 3.13.4 and verifies all imports work correctly.
"""

import sys
import os

def test_python_version():
    """Test Python version compatibility"""
    print(f"Python Version: {sys.version}")
    version = sys.version_info

    if version.major == 3 and version.minor == 13:
        print("SUCCESS: Python 3.13.x detected - Compatible!")
        return True
    else:
        print(f"WARNING: Python {version.major}.{version.minor} detected - May have compatibility issues")
        return False

def test_imports():
    """Test all required imports"""
    print("\nTesting imports...")

    imports = [
        'flask',
        'flask_cors',
        'flask_socketio',
        'sqlalchemy',
        'flask_sqlalchemy',
        'passlib',
        'jwt',
        'dotenv',
        'gunicorn',
        'eventlet',
        'qrcode',
        'PIL',
        'flask_jwt_extended',
        'werkzeug'
    ]

    failed_imports = []

    for package in imports:
        try:
            if package == 'PIL':
                import PIL
                print(f"SUCCESS: PIL (Pillow) {PIL.__version__}")
            elif package == 'jwt':
                import jwt
                print(f"SUCCESS: PyJWT {jwt.__version__}")
            elif package == 'dotenv':
                import dotenv
                print(f"SUCCESS: python-dotenv {dotenv.__version__}")
            else:
                module = __import__(package)
                version = getattr(module, '__version__', 'Unknown')
                print(f"SUCCESS: {package} {version}")
        except ImportError as e:
            print(f"ERROR: {package} - Import failed: {e}")
            failed_imports.append(package)

    return len(failed_imports) == 0

def test_app_import():
    """Test importing the main app"""
    print("\nTesting app import...")

    try:
        # Add tapin_backend to path
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'tapin_backend'))

        from app import app
        print("SUCCESS: Main app imported successfully")

        # Test basic app functionality
        with app.app_context():
            print("SUCCESS: App context works")

        return True
    except Exception as e:
        print(f"ERROR: App import failed: {e}")
        return False

def test_database_connection():
    """Test database connection"""
    print("\nTesting database connection...")

    try:
        from tapin_backend.app import db

        with db.engine.connect() as connection:
            result = connection.execute(db.text("SELECT 1"))
            print("SUCCESS: Database connection successful")
            return True
    except Exception as e:
        print(f"ERROR: Database connection failed: {e}")
        return False

def main():
    """Run all tests"""
    print("TEST: TapIn Deployment Compatibility Test")
    print("=" * 50)

    tests = [
        ("Python Version", test_python_version),
        ("Package Imports", test_imports),
        ("App Import", test_app_import),
        ("Database Connection", test_database_connection)
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\nTESTING: {test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"ERROR: {test_name} test crashed: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 50)
    print("TEST RESULTS SUMMARY")
    print("=" * 50)

    all_passed = True
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{test_name}: {status}")
        if not result:
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("SUCCESS: ALL TESTS PASSED! Your app is ready for deployment on Python 3.13.4")
        print("\nNEXT STEPS:")
        print("1. Commit your changes: git add . && git commit -m 'Ready for deployment'")
        print("2. Push to your repository: git push origin main")
        print("3. Deploy on Render.com using the render.yaml configuration")
        return 0
    else:
        print("WARNING: SOME TESTS FAILED! Please fix the issues before deployment.")
        return 1

if __name__ == "__main__":
    exit(main())