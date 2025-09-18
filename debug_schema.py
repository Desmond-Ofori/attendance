import sys
from sqlalchemy import inspect
from tapin_backend.app import app
from tapin_backend.models import db

with app.app_context():
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('users')]
    print('Users table columns:', columns)
    # Check if all required columns are present
    required = {'id', 'fullname', 'email', 'student_id', 'phone', 'role', 'is_verified', 'password_hash', 'last_login_at', 'created_at', 'avatar_url'}
    missing = required - set(columns)
    if missing:
        print('Missing columns:', missing)
    else:
        print('Schema matches model')