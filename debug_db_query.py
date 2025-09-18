import psycopg2
import sys

try:
    # Connection params from DATABASE_URL
    conn = psycopg2.connect(
        host="dpg-d359u7r3fgac73b9kkp0-a",
        database="tapin_db_eo22",
        user="tapin_db_eo22_user",
        password="RPKM4lNr946D9jpkOwnQ8UUA8dadW00u"
    )
    cur = conn.cursor()
    
    email = "ey49590568@gmail.com"
    
    # Query 1: Inspect the specific row
    cur.execute(f"SELECT id, email, role, pg_typeof(role) FROM users WHERE email='{email}';")
    row1 = cur.fetchone()
    print("Row for email:")
    print(row1)
    
    # Query 2: The exact failing query
    cur.execute(f"SELECT id, email, role FROM users WHERE email='{email}' AND role='lecturer' LIMIT 1;")
    row2 = cur.fetchone()
    print("\nResult of exact query:")
    print(row2)
    
    # Query 3: Check all roles for this email (if multiple somehow)
    cur.execute(f"SELECT role FROM users WHERE email='{email}';")
    roles = cur.fetchall()
    print("\nAll roles for email:")
    print(roles)
    
    cur.close()
    conn.close()
    print("\nQueries executed successfully.")
    
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)