"""Modular Database Package for SecuraX.

Provides specialized modules for:
- connection: Database connection pooling, SQLite/MySQL adaptation, migrations, init_db
- users: User credentials, roles, target locking, authentication tokens
- audit: Security events, audit logging, and forensic statistics
- reports: Scan findings, job queues, triage metadata, dashboard stats
- schedules: Recurring background scan jobs
- subscriptions: SaaS tiers, scan quotas, and AI consumption tracking
"""

try:
    from db.connection import *
    from db.users import *
    from db.audit import *
    from db.reports import *
    from db.schedules import *
    from db.subscriptions import *
except ImportError:
    from backend.db.connection import *
    from backend.db.users import *
    from backend.db.audit import *
    from backend.db.reports import *
    from backend.db.schedules import *
    from backend.db.subscriptions import *
