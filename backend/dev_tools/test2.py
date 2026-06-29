import sqlite3
db = sqlite3.connect('hexaguard.db')
db.row_factory = sqlite3.Row
logs = db.execute("SELECT username, details, status, created_at FROM audit_logs WHERE action='login_failed' ORDER BY created_at DESC LIMIT 5").fetchall()
print([dict(l) for l in logs])

