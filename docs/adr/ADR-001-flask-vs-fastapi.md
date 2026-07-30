# ADR-001 — Backend Framework: Flask vs FastAPI

**Status**: Accepted  
**Date**: 2026-01-15  
**Deciders**: Abdallah Benaicha (lead developer)  
**Supersedes**: N/A

---

## Context

SecuraX requires a Python backend REST API that:
1. Serves a React SPA frontend
2. Manages long-running scan jobs asynchronously
3. Integrates with multiple external APIs (Gemini, NVD, CISA KEV)
4. Supports session-based authentication with role-based access control
5. Can be deployed on low-cost hosting (Render free tier, PythonAnywhere)

The two primary Python web framework candidates are **Flask** and **FastAPI**.

### Option A: Flask 3.1

**Pros**:
- Mature ecosystem (14 years of production use)
- Flask-Login for session management (well-documented)
- Flask-Migrate + SQLAlchemy for database migrations
- Sync-friendly — easier integration with blocking scanner tools (nmap, etc.)
- Broad deployment support (Gunicorn, Render, PythonAnywhere, Heroku)
- Lower learning curve for contributors unfamiliar with async Python

**Cons**:
- No built-in async support (requires threading/gevent for concurrency)
- No automatic OpenAPI documentation
- More boilerplate for request validation

### Option B: FastAPI

**Pros**:
- Native async/await — better for concurrent I/O-heavy operations
- Automatic OpenAPI/Swagger documentation generation
- Pydantic validation built-in
- Type hints enforced at runtime

**Cons**:
- Async complicates integration with blocking scanner tools (subprocess, socket)
- Less mature session management ecosystem
- Starlette-based deployment less familiar to team
- Would require more refactoring if starting from an existing codebase

---

## Decision

**Flask 3.1 with Gunicorn (sync workers).**

The scanners are inherently I/O-blocking (nmap, socket connections, HTTP requests).
Running them in async context would require extensive `run_in_executor` wrapping.
Flask's sync model is a better fit for this workload pattern.

Concurrency is handled at the Gunicorn level (multiple workers) and via threading
in the job manager (`job_manager.py`).

---

## Consequences

### Positive
- Simpler integration with blocking scanner libraries
- Team familiar with Flask patterns
- Broad deployment compatibility

### Negative
- No automatic API documentation (mitigated by manual OpenAPI spec in `docs/`)
- Request validation requires manual `from marshmallow import ...` or inline checks

### Neutral
- If concurrency becomes a bottleneck (>100 simultaneous scans), can switch to
  Gunicorn async workers (gevent) without changing application code

---

## References

- [Flask documentation](https://flask.palletsprojects.com/)
- [FastAPI documentation](https://fastapi.tiangolo.com/)
- [Gunicorn worker types](https://docs.gunicorn.org/en/stable/design.html#worker-types)
