# Architecture Decision Records (ADR)

> **Project**: SecuraX  
> **Methodology**: [Michael Nygard's ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)

## What is an ADR?

An Architecture Decision Record (ADR) documents a significant architectural decision,
the context that led to it, the options considered, and the consequences of the choice.

ADRs are **immutable once accepted** — they are never deleted, only superseded by new ADRs.
This creates a permanent audit trail of why the system is designed the way it is.

---

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](ADR-001-flask-vs-fastapi.md) | Backend Framework: Flask vs FastAPI | **Accepted** | 2026-01-15 |
| [ADR-002](ADR-002-sqlite-vs-postgresql.md) | Database: SQLite vs PostgreSQL | **Accepted** | 2026-01-20 |
| [ADR-003](ADR-003-multi-dimensional-scoring.md) | Risk Scoring: Multi-Dimensional vs CVSS-Only | **Accepted** | 2026-02-01 |
| [ADR-004](ADR-004-plugin-sdk-design.md) | Scanner Architecture: Plugin SDK | **Accepted** | 2026-03-10 |
| [ADR-005](ADR-005-synthetic-vs-real-dataset.md) | Dataset Strategy: Synthetic-First | **Accepted** | 2026-07-01 |
| [ADR-006](ADR-006-floor-calibration.md) | Risk Score Floor Calibration v3.1.0 | **Accepted** | 2026-08-15 |

---

## ADR Lifecycle

```
Proposed → Accepted → Deprecated → Superseded
              ↓
           Rejected (if abandoned)
```

---

## Contributing

To propose a new ADR:
1. Create `ADR-NNN-short-title.md` from the template below
2. Set status to `Proposed`
3. Open a PR and request review from `@Abdallahbenaicha`
4. After consensus, change status to `Accepted`

### Template

```markdown
# ADR-NNN — Title

**Status**: Proposed  
**Date**: YYYY-MM-DD  
**Deciders**: [list of people]

## Context
## Decision
## Consequences
### Positive
### Negative
### Neutral
## References
```
