from tapin_backend.app import app
from tapin_backend.models import db, User
from tapin_backend.utils import hash_password
from flask import url_for

with app.app_context():
    db.create_all()
    
    # Lecturer
    lecturer = User(
        fullname='Test Lecturer',
        email='lecturer@test.com',
        role='lecturer',
        password_hash=hash_password('TestPass123!'),
        is_verified=False
    )
    db.session.add(lecturer)
    
    # Student
    student = User(
        fullname='Test Student',
        email='student@test.com',
        student_id='STU001',
        role='student',
        password_hash=hash_password('TestPass123!'),
        is_verified=False
    )
    db.session.add(student)
    
    db.session.commit()
    print("Test users created: lecturer@test.com and student@test.com (password: TestPass123!)")