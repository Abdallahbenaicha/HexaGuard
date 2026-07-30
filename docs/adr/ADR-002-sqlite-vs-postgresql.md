# ADR-002 — Database: SQLite (WAL mode) vs PostgreSQL

**Status**: Accepted  
**Date**: 2026-01-20  
**Deciders**: Abdallah Benaicha  
**Supersedes**: N/A

---

## Context

SecuraX needs a persistent database for:
- User accounts and sessions
- Scan job metadata and status
- Vulnerability findings (can be large — 1,000+ findings per scan)
- Risk scores and ARIA remediation outputs
- Audit logs

The system is initially a research prototype / PFE project, deployed on free-tier hosting.

### Option A: SQLite in WAL mode

**Pros**:
- Zero configuration — single file, no server process
- WAL (Write-Ahead Logging) mode supports concurrent readers + 1 writer
- Free tier compatible (Render, PythonAnywhere)
- Easy backup (copy the `.db` file)
- SQLAlchemy support identical to PostgreSQL (same ORM code)
- Ideal for research reproducibility — embed the database in the git repo for demos

**Cons**:
- Single writer limit (no true concurrent writes)
- No row-level locking
- Not suitable for >10 simultaneous scan workers
- File-based — not suitable for multi-instance deployment

### Option B: PostgreSQL

**Pros**:
- True concurrent writes (MVCC)
- Row-level locking
- Full-text search, JSONB, advanced indexing
- Suitable for production multi-instance deployment

**Cons**:
- Requires a PostgreSQL server (cost on free tier)
- More complex local development setup
- Supabase free tier has 500MB limit and pauses inactive projects

---

## Decision

**SQLite in WAL mode for development and research; PostgreSQL planned for production.**

The current workload is sequential: one scan job runs per user session.
SQLite WAL mode handles this with zero configuration and perfect reproducibility.

A migration path to PostgreSQL is maintained via:
- SQLAlchemy ORM (same code, different `DATABASE_URI`)
- Alembic migrations (`backend/migrations/`)
- `supabase_schema.sql` for PostgreSQL DDL

---

## Consequences

### Positive
- Zero-configuration local development
- Database file can be committed as a fixture for testing
- Research reproducibility: embed `hexaguard.db` in test environments

### Negative
- Cannot scale to multiple simultaneous scan workers without migration
- WAL files (`.db-wal`, `.db-shm`) must be excluded from git

### Neutral
- All queries use SQLAlchemy ORM — switching to PostgreSQL requires only changing
  `DATABASE_URI` in `.env`

---

## References

- [SQLite WAL mode](https://www.sqlite.org/wal.html)
- [SQLAlchemy dialects](https://docs.sqlalchemy.org/en/20/dialects/)
- [Supabase PostgreSQL](https://supabase.com/docs/guides/database)
