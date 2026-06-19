import sqlite3
import bcrypt

db = sqlite3.connect('securax.db')
db.row_factory = sqlite3.Row
row = db.execute("SELECT * FROM users WHERE username='admin'").fetchone()
if not row:
    print("User not found")
else:
    print("Locked until:", row["locked_until"])
    print("Failed attempts:", row["failed_attempts"])
    print("Is active:", row["is_active"])
    hash_in_db = row["password_hash"]
    print("Hash:", hash_in_db)
    ok = bcrypt.checkpw(b"Admin@2024!", hash_in_db.encode())
    print("Password match:", ok)
    
    # unlock user
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username='admin'")
    db.commit()
    print("User unlocked.")

