import sqlite3

def run():
    con = sqlite3.connect("backend/securax.db")
    cur = con.cursor()
    cur.execute("""
        UPDATE phd_discovery_cache 
        SET verification_status = 'legacy_unverified',
            record_type = 'vacancy_lead'
        WHERE verification_status = 'verified_vacancy' 
          AND confidence >= 0.85;
    """)
    con.commit()
    print(f"UPDATED ROWS: {cur.rowcount}")

if __name__ == "__main__":
    run()
