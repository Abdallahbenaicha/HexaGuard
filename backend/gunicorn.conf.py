# gunicorn.conf.py — SecuraX production server config
# ─────────────────────────────────────────────────────
# SQLite + WAL mode supports concurrent readers but ONLY ONE writer at a time.
# Using a single PROCESS (not multiple workers) eliminates write contention.
# We compensate with threads for I/O concurrency (scans, AI calls, etc.)

import os

# Binding — Render injects PORT, default 5000 for local dev
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# Single process → no SQLite write conflicts across workers
workers     = 1
worker_class = "gthread"
threads     = 4          # async I/O for concurrent scan + AI requests

# Timeouts — tuned to longest scanner execution (DAST Nikto proc limit 390s + 30s margin = 420s)
timeout     = 420        # 7 min limit per request (reduced from 600s to mitigate connection exhaustion)
keepalive   = 5
graceful_timeout = 30

# Limits
max_requests        = 1000
max_requests_jitter = 100

# Logging — stdout/stderr only (no file I/O; Render captures logs automatically)
accesslog   = "-"        # stdout
errorlog    = "-"        # stderr
loglevel    = "info"
capture_output = True

# Process name shown in Render logs
proc_name   = "securax"

