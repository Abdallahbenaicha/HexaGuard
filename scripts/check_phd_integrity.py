#!/usr/bin/env python3
"""scripts/check_phd_integrity.py

Integrity audit script for PhD discovery cache and opportunities database.
Checks for:
  (a) verified_vacancy without real deadline OR without real institution.
  (b) deadline_status='active' when deadline is null.
  (c) Fixed/hardcoded confidence (0.70, 0.85, 0.90, 0.95...) in adapter records.
  (d) Fallback placeholder institutions ('Netherlands Research Univ', 'European Research Institu'...).
  (e) Duplicate EURAXESS records sharing the same external ID.
  (f) Titles of lecturer/professor/postdoc/teaching assistant without 'PhD/doctoral/studentship' in the title itself.

Exits with non-zero code if any integrity violation is found.
"""

import sys
import os
import sqlite3
import re
import json

def get_db_path():
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        return sys.argv[1]
    candidates = ["backend/securax.db", "securax.db"]
    for c in candidates:
        if os.path.exists(c):
            return c
    print("ERROR: Could not find securax.db", file=sys.stderr)
    sys.exit(2)

def check_phd_integrity(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    violations = []

    # Check if phd_discovery_cache table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='phd_discovery_cache'")
    if not c.fetchone():
        print(f"Table phd_discovery_cache not found in {db_path}", file=sys.stderr)
        return 2

    # Query all records
    c.execute("""
        SELECT id, source_id, program, institution, deadline_parsed, deadline_status,
               confidence, verification_status, record_type, raw_json
        FROM phd_discovery_cache
    """)
    rows = c.fetchall()
    print(f"[*] Auditing {len(rows)} records in {db_path}...")

    # (a) verified_vacancy without deadline or without real institution
    placeholder_orgs = ["netherlands research univ", "european research institu", "unknown", "null"]
    v_a = []
    for r in rows:
        v_status = (r["verification_status"] or "").strip().lower()
        rec_type = (r["record_type"] or "").strip().lower()
        if "verified_vacancy" in (v_status, rec_type):
            dl = r["deadline_parsed"]
            inst = (r["institution"] or "").strip()
            inst_lower = inst.lower()
            is_placeholder = any(p in inst_lower for p in placeholder_orgs)
            if not dl or not inst or is_placeholder:
                v_a.append((r["id"], r["source_id"], r["program"], inst, dl, v_status))
    if v_a:
        violations.append(("(a) verified_vacancy without real deadline or without real institution", len(v_a), v_a))

    # (b) deadline_status=active with deadline null
    v_b = []
    for r in rows:
        dl_status = (r["deadline_status"] or "").strip().lower()
        dl = r["deadline_parsed"]
        if dl_status == "active" and (dl is None or dl == ""):
            v_b.append((r["id"], r["source_id"], r["program"], dl_status, dl))
    if v_b:
        violations.append(("(b) deadline_status='active' with null deadline", len(v_b), v_b))

    # (c) confidence fixed/hardcoded in adapter records
    adapter_sources = {
        "jobs_ac_uk", "academictransfer", "euraxess", "euraxess_rss",
        "findaphd", "daad_phdgermany", "academicpositions",
        "campusfrance", "msca", "nature_careers"
    }
    v_c = []
    for r in rows:
        src = (r["source_id"] or "").strip().lower()
        conf = r["confidence"]
        if src in adapter_sources and conf is not None:
            v_c.append((r["id"], src, r["program"], conf))
    if v_c:
        violations.append(("(c) Fixed/hardcoded confidence in adapter records", len(v_c), v_c))

    # (d) institution from fallback placeholder text
    v_d = []
    for r in rows:
        inst = (r["institution"] or "").strip()
        inst_lower = inst.lower()
        if any(p in inst_lower for p in ["netherlands research univ", "european research institu"]):
            v_d.append((r["id"], r["source_id"], r["program"], inst))
    if v_d:
        violations.append(("(d) Institution contains generic fallback placeholder text", len(v_d), v_d))

    # (e) duplicate EURAXESS records with same external id
    euraxess_ids = {}
    v_e = []
    for r in rows:
        src = (r["source_id"] or "").strip().lower()
        if "euraxess" in src:
            rid = r["id"]
            m = re.search(r'eurx_(\d+)', rid)
            job_key = m.group(1) if m else rid
            euraxess_ids.setdefault(job_key, []).append(rid)
    for job_key, ids in euraxess_ids.items():
        if len(ids) > 1:
            v_e.append((job_key, ids))
    if v_e:
        violations.append(("(e) Duplicate EURAXESS records with the same external ID", len(v_e), v_e))

    # (f) titles of lecturer/professor/postdoc/teaching assistant without PhD/doctoral/studentship in title itself
    non_doc_terms = [
        "lecturer", "senior lecturer", "assistant professor", "associate professor",
        "professor", "chair", "faculty position", "postdoctoral", "postdoc",
        "post-doctoral", "teaching assistant", "research fellow", "teaching fellow"
    ]
    doc_required = ["phd", "doctoral", "doctorate", "studentship", "doctorat", "dphil"]
    v_f = []
    for r in rows:
        v_status = (r["verification_status"] or "").strip().lower()
        # Only check active/verified/unverified leads, skip already rejected
        if v_status == "rejected_non_doctoral":
            continue
        title = (r["program"] or "").strip().lower()
        has_non_doc = any(re.search(r'\b' + re.escape(t) + r'\b', title) for t in non_doc_terms)
        has_doc = any(re.search(r'\b' + re.escape(d) + r'\b', title) for d in doc_required)
        if has_non_doc and not has_doc:
            v_f.append((r["id"], r["source_id"], r["program"], v_status))
    if v_f:
        violations.append(("(f) Non-doctoral academic roles without doctoral keyword in title", len(v_f), v_f))

    # Print Report
    print("=" * 70)
    print("PHD DISCOVERY CACHE INTEGRITY REPORT")
    print("=" * 70)
    if not violations:
        print("[PASS] All integrity checks PASSED! Zero violations detected.")
        print("=" * 70)
        return 0

    print(f"[FAIL] {len(violations)} integrity violation categories detected:\n")
    for category, count, items in violations:
        print(f"[-] Category: {category} (Violations: {count})")
        for item in items[:5]:
            print(f"    - {item}")
        if count > 5:
            print(f"    ... and {count - 5} more items")
        print()

    print("=" * 70)
    return 1

if __name__ == "__main__":
    db = get_db_path()
    code = check_phd_integrity(db)
    sys.exit(code)
