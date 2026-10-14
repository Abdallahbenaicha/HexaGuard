#!/usr/bin/env python3
"""scripts/fix_phd_db_integrity.py

Remediation script for PhD discovery cache:
1. Takes a fresh backup first into backend/backups/.
2. Re-tags rejected non-doctoral records as 'rejected_non_doctoral' (does NOT delete them).
3. Normalizes null deadlines to deadline_status='unknown'.
4. Removes generic fallback institution strings ('Netherlands Research Univ', 'European Research Institu') to NULL.
5. Clears hardcoded confidence to NULL for adapter sources.
6. Downgrades verified_vacancy to unverified_lead if deadline or institution is missing.
7. Deduplicates EURAXESS duplicate records in DB.
"""

import sys
import os
import shutil
import sqlite3
import re
from datetime import datetime

NON_DOC_TERMS = [
    "lecturer", "senior lecturer", "assistant professor", "associate professor",
    "professor", "chair", "faculty position", "postdoctoral", "postdoc",
    "post-doctoral", "teaching assistant", "research fellow", "teaching fellow",
    "technician", "bioimage analyst", "researcher holding a master degree",
    "higher tecnician", "research assistant (0.2 fte)"
]
STRICT_DOC_TERMS = ["phd", "doctoral", "doctorate", "studentship", "doctorat", "dphil"]

def backup_db(db_path: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(os.path.dirname(os.path.abspath(db_path)), "backups")
    if not os.path.exists(backup_dir):
        backup_dir = os.path.join("backend", "backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"securax_backup_before_fix_{timestamp}.db")
    shutil.copy2(db_path, backup_path)
    print(f"[+] Backup successfully created: {backup_path} ({os.path.getsize(backup_path)} bytes)")
    return backup_path

def fix_db(db_path: str):
    print(f"[*] Remediating database: {db_path}")
    backup_db(db_path)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Recreate table without NOT NULL constraint on confidence if present
    c.execute("PRAGMA table_info(phd_discovery_cache)")
    cols = c.fetchall()
    conf_col = next((col for col in cols if col[1] == "confidence"), None)
    if conf_col and conf_col[3] == 1:
        print("[*] Recreating phd_discovery_cache to allow NULL confidence...")
        c.execute("""
            CREATE TABLE phd_discovery_cache_tmp (
                id               TEXT    PRIMARY KEY,
                source_id        TEXT    NOT NULL,
                source_name      TEXT    NOT NULL,
                fetch_timestamp  TEXT    NOT NULL,
                institution      TEXT,
                country          TEXT,
                program          TEXT,
                field_keywords   TEXT,
                funding_type     TEXT,
                stipend_info     TEXT,
                deadline_raw     TEXT,
                deadline_parsed  TEXT,
                deadline_status  TEXT    NOT NULL DEFAULT 'unknown',
                supervisor       TEXT,
                lab_url          TEXT,
                application_url  TEXT,
                language_req     TEXT,
                eligibility_intl INTEGER NOT NULL DEFAULT -1,
                confidence       REAL    DEFAULT NULL,
                raw_json         TEXT,
                is_stale         INTEGER NOT NULL DEFAULT 0,
                last_verified    TEXT,
                saved_opp_id     TEXT,
                record_type      TEXT NOT NULL DEFAULT 'verified_vacancy',
                verification_status TEXT NOT NULL DEFAULT 'unconfirmed'
            )
        """)
        c.execute("INSERT INTO phd_discovery_cache_tmp SELECT * FROM phd_discovery_cache")
        c.execute("DROP TABLE phd_discovery_cache")
        c.execute("ALTER TABLE phd_discovery_cache_tmp RENAME TO phd_discovery_cache")
        c.execute("CREATE INDEX IF NOT EXISTS idx_phd_disc_source ON phd_discovery_cache (source_id, fetch_timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_phd_disc_country ON phd_discovery_cache (country)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_phd_disc_stale ON phd_discovery_cache (is_stale, fetch_timestamp)")

    # 1. Clear generic placeholder institution texts to NULL
    c.execute("""
        UPDATE phd_discovery_cache
        SET institution = NULL
        WHERE institution LIKE '%Netherlands Research Univ%'
           OR institution LIKE '%European Research Institu%'
    """)
    print(f"[*] Cleared placeholder institutions: {c.rowcount} rows updated")

    # 2. Reset confidence to NULL for adapter records
    adapter_sources = (
        'jobs_ac_uk', 'academictransfer', 'euraxess', 'euraxess_rss',
        'findaphd', 'daad_phdgermany', 'academicpositions',
        'campusfrance', 'msca', 'nature_careers'
    )
    placeholders = ",".join(f"'{s}'" for s in adapter_sources)
    c.execute(f"""
        UPDATE phd_discovery_cache
        SET confidence = NULL
        WHERE source_id IN ({placeholders})
    """)
    print(f"[*] Reset confidence to NULL for adapters: {c.rowcount} rows updated")

    # 3. Where deadline_parsed is NULL or empty, set deadline_status = 'unknown'
    c.execute("""
        UPDATE phd_discovery_cache
        SET deadline_status = 'unknown'
        WHERE (deadline_parsed IS NULL OR deadline_parsed = '')
          AND deadline_status != 'unknown'
    """)
    print(f"[*] Set deadline_status='unknown' for null deadlines: {c.rowcount} rows updated")

    # 4. If verified_vacancy but deadline or institution is missing, downgrade
    c.execute("""
        UPDATE phd_discovery_cache
        SET verification_status = CASE WHEN verification_status = 'verified_vacancy' THEN 'unverified_lead' ELSE verification_status END,
            record_type = 'vacancy_lead'
        WHERE (verification_status = 'verified_vacancy' OR record_type = 'verified_vacancy')
          AND (deadline_parsed IS NULL OR deadline_parsed = '' OR institution IS NULL OR institution = '')
    """)
    print(f"[*] Downgraded verified_vacancy with missing deadline/institution: {c.rowcount} rows updated")

    # 5. Tag non-doctoral roles as 'rejected_non_doctoral'
    c.execute("SELECT id, program, verification_status FROM phd_discovery_cache")
    all_rows = c.fetchall()
    rejected_count = 0
    unconfirmed_count = 0

    for rid, title, v_status in all_rows:
        t_lower = (title or "").lower()
        has_non_doc = any(re.search(r'\b' + re.escape(t) + r'\b', t_lower) for t in NON_DOC_TERMS)
        has_strict_doc = any(re.search(r'\b' + re.escape(d) + r'\b', t_lower) for d in STRICT_DOC_TERMS)

        if has_non_doc and not has_strict_doc:
            c.execute("""
                UPDATE phd_discovery_cache
                SET verification_status = 'rejected_non_doctoral',
                    record_type = 'rejected_non_doctoral'
                WHERE id = ?
            """, (rid,))
            rejected_count += 1
        elif "student – scholarship" in t_lower or "student - scholarship" in t_lower:
            c.execute("""
                UPDATE phd_discovery_cache
                SET verification_status = 'unconfirmed',
                    record_type = 'vacancy_lead'
                WHERE id = ?
            """, (rid,))
            unconfirmed_count += 1

    print(f"[*] Tagged non-doctoral roles as 'rejected_non_doctoral': {rejected_count} rows")
    print(f"[*] Tagged ambiguous student scholarships as 'unconfirmed': {unconfirmed_count} rows")

    # 6. Deduplicate EURAXESS records in DB by external job ID
    c.execute("SELECT id, source_id FROM phd_discovery_cache WHERE source_id LIKE 'euraxess%'")
    eur_rows = c.fetchall()
    seen_keys = {}
    deleted_dups = 0
    for rid, src in eur_rows:
        m = re.search(r'eurx_(\d+)', rid)
        job_key = m.group(1) if m else rid
        if job_key in seen_keys:
            c.execute("DELETE FROM phd_discovery_cache WHERE id = ?", (rid,))
            deleted_dups += 1
        else:
            seen_keys[job_key] = rid
    print(f"[*] Deduplicated EURAXESS duplicate records in DB: {deleted_dups} duplicate rows removed")

    # 7. Normalize record_type for literature and grant APIs
    c.execute("""
        UPDATE phd_discovery_cache
        SET record_type = 'research_lead'
        WHERE source_id = 'openalex_api' AND record_type != 'research_lead'
    """)
    c.execute("""
        UPDATE phd_discovery_cache
        SET record_type = 'funded_project'
        WHERE source_id = 'nsf_grants_api' AND record_type != 'funded_project'
    """)
    print(f"[*] Normalized record_types for openalex and nsf: {c.rowcount} rows updated")

    conn.commit()
    conn.close()
    print(f"[+] Remediation completed for {db_path} successfully.\n")

if __name__ == "__main__":
    candidates = ["backend/securax.db", "securax.db"]
    for path in candidates:
        if os.path.exists(path):
            fix_db(path)
