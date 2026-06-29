#!/usr/bin/env python3
"""
HexaGuard — SQLite → MySQL migration script.

Usage (on PythonAnywhere Bash console):
    cd /home/abdallahbenaicha/finalpfe-master/backend
    pip install pymysql   # if not already installed
    MYSQL_HOST=abdallahbenaicha.mysql.pythonanywhere-services.com \
    MYSQL_USER=abdallahbenaicha \
    MYSQL_PASS=your_mysql_password \
    MYSQL_DB=abdallahbenaicha$hexaguard \
    DB_PATH=/home/abdallahbenaicha/finalpfe-master/backend/hexaguard.db \
    python scripts/migrate_to_mysql.py
"""

import json
import os
import sqlite3
import sys

try:
    import pymysql
    import pymysql.cursors
except ImportError:
    sys.exit("ERROR: pymysql not installed. Run: pip install pymysql")

# ── Config from env ───────────────────────────────────────────────────────────
SQLITE_PATH = os.environ.get("DB_PATH", "hexaguard.db")
MYSQL_HOST  = os.environ["MYSQL_HOST"]
MYSQL_USER  = os.environ["MYSQL_USER"]
MYSQL_PASS  = os.environ["MYSQL_PASS"]
MYSQL_DB    = os.environ["MYSQL_DB"]
MYSQL_PORT  = int(os.environ.get("MYSQL_PORT", "3306"))

print(f"Source SQLite : {SQLITE_PATH}")
print(f"Target MySQL  : {MYSQL_USER}@{MYSQL_HOST}/{MYSQL_DB}")
print()


def sqlite_rows(conn, table):
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]


def bulk_insert(my_cur, table, rows):
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ", ".join(["%s"] * len(cols))
    sql = f"INSERT IGNORE INTO `{table}` ({', '.join(f'`{c}`' for c in cols)}) VALUES ({placeholders})"
    data = [tuple(r[c] for c in cols) for r in rows]
    my_cur.executemany(sql, data)
    return len(rows)


def main():
    # Open SQLite
    if not os.path.exists(SQLITE_PATH):
        sys.exit(f"ERROR: SQLite file not found: {SQLITE_PATH}")
    sqlite_conn = sqlite3.connect(SQLITE_PATH)

    # Open MySQL
    mysql_conn = pymysql.connect(
        host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASS,
        database=MYSQL_DB, port=MYSQL_PORT,
        cursorclass=pymysql.cursors.DictCursor,
        charset="utf8mb4", autocommit=False,
    )

    cur = mysql_conn.cursor()

    TABLES = ["users", "scan_reports", "scan_vulnerabilities", "audit_logs"]

    total = 0
    for table in TABLES:
        try:
            rows = sqlite_rows(sqlite_conn, table)
        except Exception as exc:
            print(f"  SKIP {table}: {exc}")
            continue

        n = bulk_insert(cur, table, rows)
        total += n
        print(f"  {table:30s}  {n:>6} rows migrated")

    mysql_conn.commit()
    sqlite_conn.close()
    mysql_conn.close()

    print(f"\nDone — {total} total rows migrated.")
    print("\nNext steps:")
    print("  1. Add to .env on PythonAnywhere:")
    print("       MYSQL_HOST=abdallahbenaicha.mysql.pythonanywhere-services.com")
    print("       MYSQL_USER=abdallahbenaicha")
    print("       MYSQL_PASS=<your password>")
    print("       MYSQL_DB=abdallahbenaicha$hexaguard")
    print("  2. Reload the web app in the PythonAnywhere Web tab.")


if __name__ == "__main__":
    main()
