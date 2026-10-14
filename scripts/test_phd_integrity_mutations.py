#!/usr/bin/env python3
"""scripts/test_phd_integrity_mutations.py

Mutation tests for scripts/check_phd_integrity.py.
Proves that the integrity script reliably fails (Exit Code 1) when:
  1) A row has verified_vacancy with null deadline.
  2) A row has deadline_status='active' with null deadline.
  3) A row has a non-doctoral title ("Lecturer") without being rejected.
  4) A duplicate EURAXESS record is planted.
"""

import os
import sys
import sqlite3
import tempfile
import subprocess

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "check_phd_integrity.py")

def create_base_db(db_path: str):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE phd_discovery_cache (
            id TEXT PRIMARY KEY,
            source_id TEXT,
            program TEXT,
            institution TEXT,
            deadline_parsed TEXT,
            deadline_status TEXT,
            confidence REAL,
            verification_status TEXT,
            record_type TEXT,
            raw_json TEXT
        )
    """)
    # Insert 1 clean valid record
    c.execute("""
        INSERT INTO phd_discovery_cache
        (id, source_id, program, institution, deadline_parsed, deadline_status, confidence, verification_status, record_type, raw_json)
        VALUES ('valid_1', 'jobs_ac_uk', 'PhD Studentship in Cybersecurity', 'University of Oxford', '2026-12-01', 'active', NULL, 'verified_vacancy', 'verified_vacancy', '{}')
    """)
    conn.commit()
    conn.close()

def run_integrity(db_path: str):
    res = subprocess.run([sys.executable, SCRIPT_PATH, db_path], capture_output=True, text=True)
    return res.returncode, res.stdout, res.stderr

def test_mutations():
    print("=" * 70)
    print("STARTING PHD INTEGRITY SCRIPT MUTATION TESTS")
    print("=" * 70)

    # 1. Baseline Test
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    try:
        create_base_db(db_path)
        code, out, _ = run_integrity(db_path)
        print(f"[1] Baseline Clean DB: Exit Code = {code}")
        assert code == 0, f"Baseline should pass (0), got {code}"
        assert "[PASS]" in out, "Baseline output should indicate PASS"
        print("    --> PASS: Baseline passes cleanly.")

        # 2. Mutation 1: verified_vacancy with deadline null
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO phd_discovery_cache
            (id, source_id, program, institution, deadline_parsed, deadline_status, confidence, verification_status, record_type, raw_json)
            VALUES ('mut_1', 'academictransfer', 'PhD in Cryptography', 'TU Delft', NULL, 'unknown', NULL, 'verified_vacancy', 'verified_vacancy', '{}')
        """)
        conn.commit()
        conn.close()
        code, out, _ = run_integrity(db_path)
        print(f"[2] Mutation 1 (verified_vacancy with null deadline): Exit Code = {code}")
        assert code == 1, f"Mutation 1 must fail with exit code 1, got {code}"
        assert "(a) verified_vacancy without real deadline" in out
        print("    --> PASS: Detected Category (a) violation.")

        # Clean mutation 1
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM phd_discovery_cache WHERE id='mut_1'")
        conn.commit()
        conn.close()

        # 3. Mutation 2: deadline_status='active' with deadline null
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO phd_discovery_cache
            (id, source_id, program, institution, deadline_parsed, deadline_status, confidence, verification_status, record_type, raw_json)
            VALUES ('mut_2', 'jobs_ac_uk', 'PhD in AI Security', 'Imperial College', NULL, 'active', NULL, 'unverified_lead', 'vacancy_lead', '{}')
        """)
        conn.commit()
        conn.close()
        code, out, _ = run_integrity(db_path)
        print(f"[3] Mutation 2 (deadline_status='active' with null deadline): Exit Code = {code}")
        assert code == 1, f"Mutation 2 must fail with exit code 1, got {code}"
        assert "(b) deadline_status='active' with null deadline" in out
        print("    --> PASS: Detected Category (b) violation.")

        # Clean mutation 2
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM phd_discovery_cache WHERE id='mut_2'")
        conn.commit()
        conn.close()

        # 4. Mutation 3: Non-doctoral title ("Lecturer")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO phd_discovery_cache
            (id, source_id, program, institution, deadline_parsed, deadline_status, confidence, verification_status, record_type, raw_json)
            VALUES ('mut_3', 'jobs_ac_uk', 'Lecturer in Cybersecurity & Networking', 'University of Leeds', '2026-11-15', 'active', NULL, 'unverified_lead', 'vacancy_lead', '{}')
        """)
        conn.commit()
        conn.close()
        code, out, _ = run_integrity(db_path)
        print(f"[4] Mutation 3 (Title with 'Lecturer'): Exit Code = {code}")
        assert code == 1, f"Mutation 3 must fail with exit code 1, got {code}"
        assert "(f) Non-doctoral academic roles without doctoral keyword in title" in out
        print("    --> PASS: Detected Category (f) violation.")

        # Clean mutation 3
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM phd_discovery_cache WHERE id='mut_3'")
        conn.commit()
        conn.close()

        # 5. Mutation 4: Duplicate EURAXESS external ID
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO phd_discovery_cache
            (id, source_id, program, institution, deadline_parsed, deadline_status, confidence, verification_status, record_type, raw_json)
            VALUES ('eurx_99999_a', 'euraxess', 'PhD in Software Security', 'Inria', '2026-11-15', 'active', NULL, 'unverified_lead', 'vacancy_lead', '{}'),
                   ('eurx_99999_b', 'euraxess', 'PhD in Software Security', 'Inria', '2026-11-15', 'active', NULL, 'unverified_lead', 'vacancy_lead', '{}')
        """)
        conn.commit()
        conn.close()
        code, out, _ = run_integrity(db_path)
        print(f"[5] Mutation 4 (Duplicate EURAXESS ID): Exit Code = {code}")
        assert code == 1, f"Mutation 4 must fail with exit code 1, got {code}"
        assert "(e) Duplicate EURAXESS records" in out
        print("    --> PASS: Detected Category (e) violation.")

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

    print("=" * 70)
    print("[ALL MUTATION TESTS PASSED] The integrity checker strictly fails (Exit Code 1) for every violation.")
    print("=" * 70)

if __name__ == "__main__":
    test_mutations()
