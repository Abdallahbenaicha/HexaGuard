#!/usr/bin/env python3
import sys
import os
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
from blueprints.phd import (
    _run_jobs_ac_uk_adapter,
    _run_academictransfer_adapter,
    _run_euraxess_adapter,
    _run_top_cyber_labs_adapter,
    _run_nsf_adapter,
    _run_openalex_adapter,
)

sys.stdout.reconfigure(encoding='utf-8')

print("="*80)
print("LIVE DISCOVERY RUN ACCOUNTING (AFTER SEPARATED DOCTORAL & TOPIC FILTERS)")
print("="*80)

sources = [
    ("jobs_ac_uk", _run_jobs_ac_uk_adapter),
    ("academictransfer", _run_academictransfer_adapter),
    ("euraxess", _run_euraxess_adapter),
]

total_raw = 0
total_accepted = 0
total_rejected = 0

for name, fn in sources:
    items, success, err, http_code, raw_count, rejected_count = fn("cybersecurity", fetch_details=True, max_details=5)
    total_raw += raw_count
    total_accepted += len(items)
    total_rejected += rejected_count
    print(f"\nSource: {name}")
    print(f"  Raw count: {raw_count}")
    print(f"  Accepted:  {len(items)}")
    print(f"  Rejected:  {rejected_count}")
    print(f"  Math check: {len(items)} accepted + {rejected_count} rejected == {raw_count} raw: {len(items) + rejected_count == raw_count}")
    for it in items:
        print(f"    [ACCEPTED] {it['id']} | {it['program']} | {it['institution']} | {it['deadline']} | {it['verification_status']}")

labs, _, _, _, lab_raw, _ = _run_top_cyber_labs_adapter("cybersecurity")
nsf, _, _, _, nsf_raw, _ = _run_nsf_adapter("cybersecurity")
alex, _, _, _, alex_raw, _ = _run_openalex_adapter("cybersecurity")

print(f"\ntop_cyber_labs (Directory): Raw: {lab_raw}, Accepted: {len(labs)}, Rejected: 0")
print(f"nsf_grants_api (Projects): Raw: {nsf_raw}, Accepted: {len(nsf)}, Rejected: 0")
print(f"openalex_api (Literature): Raw: {alex_raw}, Accepted: {len(alex)}, Rejected: 0")

grand_raw = total_raw + lab_raw + nsf_raw + alex_raw
grand_accepted = total_accepted + len(labs) + len(nsf) + len(alex)
grand_rejected = total_rejected

print("="*80)
print(f"GRAND TOTAL RAW:      {grand_raw}")
print(f"GRAND TOTAL ACCEPTED: {grand_accepted}")
print(f"GRAND TOTAL REJECTED: {grand_rejected}")
print(f"MATHEMATICAL RECONCILIATION: {grand_accepted} + {grand_rejected} == {grand_raw}: {grand_accepted + grand_rejected == grand_raw}")
print("="*80)
