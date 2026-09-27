# POST-PHASE-11 DECISIONS
**Recorded:** 2026-09-27  
**Branch:** `fix/critical-repair`

---

## 1. Phase 11 accepted

Phase 11 is accepted in full. The existing Bounty Radar authorization behavior
must not be modified.

---

## 2. IDEA #12 — PERMANENTLY REJECTED

DNS wildcard resolution must NEVER be used to:
- upgrade `asset_type`
- change scope classification
- affect Recon availability
- affect execution authorization

DNS observations may be stored only as non-authoritative observations with no
downstream effect on any authorization or capability decision.

This rejection is permanent. Do not revisit.

---

## 3. IDEA #2 — Terminology constraint

The term "notarized" must not be used in any future design or implementation
of timestamped provenance records.

If implemented, call it: **internal timestamped provenance record**.

Any stronger evidentiary mechanism (legal weight, external notarization, etc.)
must be separately designed and explicitly approved.

---

## 4. IDEA #9 — Already in deferred backlog

Policy Change Alerts already exist in the deferred backlog.
Do not present it as a new idea in any future session.

---

## 5. Candidate near-term work

Only the following may be considered for near-term implementation.
None are approved for implementation yet — explicit instruction required.

| ID | Name | Constraint |
|----|------|------------|
| #4 | Backend-derived "Why Recon?" explanation | Backend field → frontend tooltip |
| #8 | Passive CT-log monitoring | crt.sh only, zero active probing, bookmarked targets only |
| #11 | Aggregated source feed | Benchmark actual performance gain before claiming it; do not state gains speculatively |

---

## 6. Implementation gate

None of the above candidates may be implemented without explicit instruction.

---

## 7. Invariant — Five-layer separation

The following five layers are permanently distinct. No observation, inference,
or enrichment may collapse any two of them without explicit design review:

```
Discovery != Scope != Policy != Capability != Authorization != Execution
```

---

## 8. Idea generation moratorium

No future idea generation unless explicitly requested by the user.
