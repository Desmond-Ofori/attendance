import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'instance', 'tapin.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Add fullname if not exists
c.execute("PRAGMA table_info(users)")
columns = [row[1] for row in c.fetchall()]
if 'fullname' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN fullname VARCHAR(120) NOT NULL DEFAULT 'Unknown'")

# Handle legacy 'name' column: set default if exists and no default
c.execute("PRAGMA table_info(users)")
info = [row for row in c.fetchall() if row[1] == 'name']
if info and info[0][5] is None:  # no default
    # Update existing rows to use fullname as name
    c.execute("UPDATE users SET name = COALESCE(fullname, 'Unknown') WHERE name IS NULL OR name = ''")
    # Since ALTER to add default not possible for existing columns, ensure no nulls
    print("Handled legacy 'name' column.")

# Add student_id if not exists
if 'student_id' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN student_id VARCHAR(50)")

# Add phone if not exists
if 'phone' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN phone VARCHAR(30)")

# Add avatar_url if not exists
if 'avatar_url' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(255)")

# Add role if not exists
if 'role' not in columns:
    c.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'student'")

conn.commit()
conn.close()
print("Migration completed.")