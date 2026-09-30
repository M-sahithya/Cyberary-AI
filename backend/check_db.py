import sqlite3

conn = sqlite3.connect('data/cyberary.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]
print("Tables:", tables)
for t in tables:
    cursor.execute(f"PRAGMA table_info({t})")
    cols = [f"{col[1]} ({col[2]})" for col in cursor.fetchall()]
    print(f"\n{t}:")
    print(", ".join(cols))
conn.close()