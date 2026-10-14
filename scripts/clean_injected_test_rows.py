#!/usr/bin/env python3
"""scripts/clean_injected_test_rows.py
Removes the 2 test-injected rows ('audit_1d43a988', 'audit_884dd66f') from phd_dedup_audit
in securax.db, restoring the table to its genuine count of 12 rows.
"""
import sqlite3
import shutil
import hashlib

def get_db_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def clean_db():
    db_path = "securax.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    cur.execute("SELECT id, run_timestamp, audit_summary FROM phd_dedup_audit WHERE id IN ('audit_1d43a988', 'audit_884dd66f')")
    rows_to_delete = cur.fetchall()
    print("[*] Rows identified for deletion (injected by test_gate1_7_discovery_dedup.py):")
    for r in rows_to_delete:
        print(f"    - ID: {r[0]} | Timestamp: {r[1]} | Summary: {r[2]}")
        
    cur.execute("DELETE FROM phd_dedup_audit WHERE id IN ('audit_1d43a988', 'audit_884dd66f')")
    deleted = cur.rowcount
    conn.commit()
    print(f"[+] Successfully deleted {deleted} test-injected rows from {db_path}.")
    
    cur.execute("SELECT count(*) FROM phd_dedup_audit")
    remaining = cur.fetchone()[0]
    print(f"[+] phd_dedup_audit row count restored to genuine count: {remaining} rows (expected: 12).")
    conn.close()
    
    # Sync to backend/securax.db
    shutil.copy2("securax.db", "backend/securax.db")
    print(f"[+] Synced clean database to backend/securax.db.")
    print(f"[+] New SHA256 (securax.db): {get_db_sha256('securax.db')}")
    print(f"[+] New SHA256 (backend/securax.db): {get_db_sha256('backend/securax.db')}")

if __name__ == "__main__":
    clean_db()
