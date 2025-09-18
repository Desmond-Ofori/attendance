from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import reflection

engine = create_engine('sqlite:///instance/tapin.db')
inspector = reflection.Inspector.from_engine(engine)

# Fix users.is_verified
if 'is_verified' not in [col['name'] for col in inspector.get_columns('users')]:
    with engine.connect() as conn:
        conn.execute(text('ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE'))
        conn.commit()
    print('Added is_verified column to users.')
else:
    print('is_verified column already exists in users.')

# Fix classes.class_name
if 'class_name' not in [col['name'] for col in inspector.get_columns('classes')]:
    with engine.connect() as conn:
        conn.execute(text('ALTER TABLE classes ADD COLUMN class_name TEXT'))
        conn.commit()
    print('Added class_name column to classes.')

# Update existing class_name from course_name
with engine.connect() as conn:
    conn.execute(text("UPDATE classes SET class_name = COALESCE(course_name, '') WHERE class_name IS NULL OR class_name = ''"))
    conn.commit()
print('Updated class_name from course_name where needed.')

# Fix attendance_sessions.lecturer_id
if 'lecturer_id' not in [col['name'] for col in inspector.get_columns('attendance_sessions')]:
    with engine.connect() as conn:
        conn.execute(text('ALTER TABLE attendance_sessions ADD COLUMN lecturer_id INTEGER'))
        conn.commit()
    print('Added lecturer_id column to attendance_sessions.')

# Populate lecturer_id from classes.lecturer_id (SQLite syntax: correlated subquery)
with engine.connect() as conn:
    conn.execute(text("""
        UPDATE attendance_sessions
        SET lecturer_id = (
            SELECT classes.lecturer_id
            FROM classes
            WHERE classes.id = attendance_sessions.class_id
        )
        WHERE lecturer_id IS NULL
    """))
    conn.commit()
print('Populated lecturer_id from classes.lecturer_id.')

# Add foreign key constraint (SQLite supports it, but if exists, ignore)
try:
    with engine.connect() as conn:
        conn.execute(text("""
            ALTER TABLE attendance_sessions ADD CONSTRAINT fk_attendance_sessions_lecturer_id
            FOREIGN KEY (lecturer_id) REFERENCES users(id)
        """))
        conn.commit()
    print('Added foreign key for lecturer_id.')
except Exception as e:
    print(f'Foreign key already exists or error: {e}')

print('Database schema fixes completed.')