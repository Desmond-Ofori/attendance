import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'instance', 'tapin.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("PRAGMA table_info(classes)")
columns = c.fetchall()
print("Classes table columns:")
for col in columns:
    print(col)

conn.close()