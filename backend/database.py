"""SecuraX Database Module — Backward-Compatibility Facade (v3).

This module preserves 100% backward compatibility for all existing callers,
blueprints, background schedulers, and unit tests while delegating core
persistence logic to the modularized `backend.db` package:
  - backend.db.connection: Connection pooling, SQLite/MySQL adaptation, migrations
  - backend.db.users:      Credentials, access roles, target locking, auth tokens
  - backend.db.audit:      Security event logging and forensic metrics
  - backend.db.reports:    Scan findings, jobs, triage notes, and dashboard stats
  - backend.db.schedules:  Automated recurring scan tasks
  - backend.db.subscriptions: SaaS tiers, scan quotas, and AI consumption
"""

from __future__ import annotations

import os
import sys

try:
    import db
    from db.connection import (
        _MySQLAdapter,
        _make_mysql_conn,
        _get_db,
        _resolve_db_path,
        _exec,
        init_db,
        _bootstrap_admin,
        _norm,
        _count_severities,
        _local,
        _USE_MYSQL,
        _MYSQL_HOST,
        _UNSET,
        DB_PATH,
    )
    from db.users import *
    from db.audit import *
    from db.reports import *
    from db.schedules import *
    from db.subscriptions import *
except ImportError:
    from backend import db
    from backend.db.connection import (
        _MySQLAdapter,
        _make_mysql_conn,
        _get_db,
        _resolve_db_path,
        _exec,
        init_db,
        _bootstrap_admin,
        _norm,
        _count_severities,
        _local,
        _USE_MYSQL,
        _MYSQL_HOST,
        _UNSET,
        DB_PATH,
    )
    from backend.db.users import *
    from backend.db.audit import *
    from backend.db.reports import *
    from backend.db.schedules import *
    from backend.db.subscriptions import *

# Module-level attribute fallback
def __getattr__(name: str):
    if hasattr(db, name):
        return getattr(db, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
