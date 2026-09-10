#!/usr/bin/env python3
"""sync_hf_push.py -- Synchronise backend/ to .hf_push/ for HuggingFace Space deployment.

Usage:
    python scripts/sync_hf_push.py [--dry-run] [--commit] [--push]

Why this exists
---------------
Manual Copy-Item per-file in each session was silently leaving .hf_push out of
sync whenever a file was added, renamed, or deleted in backend/.  This script
syncs the entire backend/ directory with a consistent exclusion list so GitHub
and HuggingFace Space are always at the same revision.

Exclusions (never copied to .hf_push)
---------------------------------------
- Directories: __pycache__, .git, tests, .venv, venv, env
- Files      : *.db, *.db-shm, *.db-wal, *.sqlite*, .env, .env.*, *.pyc,
               *.log, *.tmp, *.bak, benchmark_results.json, *.pid
"""
from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
from fnmatch import fnmatch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC       = REPO_ROOT / "backend"
DST       = REPO_ROOT / ".hf_push"

EXCLUDED_DIRS  = {
    "__pycache__", ".git", "tests", ".venv", "venv", "env",
    ".pytest_cache", ".ruff_cache", "archive_non_runtime", "dev_tools",
}
EXCLUDED_FILES = {
    "*.db", "*.db-shm", "*.db-wal", "*.sqlite", "*.sqlite3",
    ".env", ".env.*", "*.pyc", "*.pyo",
    "*.log", "*.tmp", "*.bak",
    "benchmark_results.json", "*.pid",
}


def _excluded_file(name: str) -> bool:
    return any(fnmatch(name, p) for p in EXCLUDED_FILES)


def sync(dry_run: bool = False) -> tuple[int, int, int]:
    """Copy src->dst, return (copied, skipped, deleted) counts."""
    copied = skipped = deleted = 0

    # ── Forward pass: copy new/changed files ─────────────────────────────────
    for src_dir, dirs, files in os.walk(SRC):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        rel  = Path(src_dir).relative_to(SRC)
        ddir = DST / rel
        for f in files:
            if _excluded_file(f):
                skipped += 1
                continue
            sf, df = Path(src_dir) / f, ddir / f
            if df.exists() and sf.read_bytes() == df.read_bytes():
                skipped += 1
                continue
            if dry_run:
                print(f"  [DRY] copy  {sf.relative_to(REPO_ROOT)}")
            else:
                ddir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(sf, df)
            copied += 1

    # ── Reverse pass: delete stale files in dst ───────────────────────────────
    for dds, dirs, files in os.walk(DST):
        dirs[:] = [d for d in dirs if d != ".git"]
        rel = Path(dds).relative_to(DST)
        for f in files:
            if not (SRC / rel / f).exists():
                df = Path(dds) / f
                if dry_run:
                    print(f"  [DRY] del   {df.relative_to(REPO_ROOT)}")
                else:
                    df.unlink(missing_ok=True)
                deleted += 1

    return copied, skipped, deleted


def git_ops(push: bool) -> None:
    """Stage, commit, and optionally push changes in .hf_push."""
    st = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=DST, capture_output=True, text=True
    ).stdout.strip()
    if not st:
        print("OK  .hf_push already in sync -- nothing to commit.")
        return
    subprocess.run(["git", "add", "-A"], cwd=DST, check=True)
    ts  = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M")
    msg = f"chore(sync): auto-sync backend/ at {ts}"
    subprocess.run(["git", "commit", "-m", msg], cwd=DST, check=True)
    print(f"Committed: {msg}")
    if push:
        subprocess.run(["git", "push", "space", "master"], cwd=DST, check=True)
        print("Pushed to HuggingFace Space.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="Preview changes without writing")
    p.add_argument("--commit",  action="store_true", help="Git commit after syncing")
    p.add_argument("--push",    action="store_true", help="Push to HF Space (implies --commit)")
    a = p.parse_args()
    if a.push:
        a.commit = True

    label = "[DRY RUN] " if a.dry_run else ""
    print(f"{label}Syncing {SRC.relative_to(REPO_ROOT)} -> {DST.relative_to(REPO_ROOT)}")
    c, s, d = sync(a.dry_run)
    print(f"  copied={c}  skipped={s}  deleted={d}")

    if not a.dry_run and a.commit:
        git_ops(push=a.push)


if __name__ == "__main__":
    main()
