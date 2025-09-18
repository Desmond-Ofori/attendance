import os
from tapin_backend.app import app
from tapin_backend.models import db, User
from tapin_backend.utils import hash_password

with app.app_context():
    db.create_all()
    # Run migrate_db to ensure all columns are added
    from tapin_backend.models import migrate_db
    migrate_db(app)
    if User.query.count() == 0:
        lecturer = User(
            fullname='Test Lecturer',
            email='lecturer@test.com',
            role='lecturer',
            password_hash=hash_password('TestPass123!'),
            is_verified=True
        )
        db.session.add(lecturer)
        
        student = User(
            fullname='Test Student',
            email='student@test.com',
            student_id='STU001',
            role='student',
            password_hash=hash_password('TestPass123!'),
            is_verified=True
        )
        db.session.add(student)
        
        db.session.commit()
        print("Test users seeded: lecturer@test.com and student@test.com (password: TestPass123!)")
    print("Database initialized successfully.")