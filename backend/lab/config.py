"""SecuraX Evaluation Lab — Configuration & Feature Flag Module.

Governed by Master Specification v5:
  - LAB_MODE is default OFF.
  - Enforced strictly in BACKEND.
  - Forced OFF in public demo profiles.
  - Remote scanning is strictly OFF by default.
"""

from __future__ import annotations

import os


def is_demo_profile() -> bool:
    """Return True if running in a public demo environment.

    Cloudflare Pages, Oracle Free VM, or explicitly declared demo flags
    force demo profile.
    """
    demo_vars = ["DEMO_MODE", "PUBLIC_DEMO", "IS_DEMO", "CF_PAGES"]
    for var in demo_vars:
        if os.environ.get(var, "0").lower().strip() in ("1", "true", "yes", "on"):
            return True
    return False


def is_lab_mode_enabled() -> bool:
    """Return True if Evaluation Lab mode is permitted and active.

    Default: OFF (False).
    Forced OFF in public demo profiles under all circumstances.
    """
    if is_demo_profile():
        return False

    val = os.environ.get("LAB_MODE", "0").lower().strip()
    return val in ("1", "true", "yes", "on")


def is_lab_remote_scanning_enabled() -> bool:
    """Return True if remote scanning of authorized public targets is allowed.

    Default: OFF (False).
    Requires explicit LAB_MODE=1 AND ALLOW_LAB_REMOTE_SCANNING=1.
    """
    if not is_lab_mode_enabled():
        return False

    val = os.environ.get("ALLOW_LAB_REMOTE_SCANNING", "0").lower().strip()
    return val in ("1", "true", "yes", "on")


def is_lab_2fa_enforced() -> bool:
    """Return True if admin TOTP 2FA is mandatory to access Evaluation Lab endpoints.

    Default: ON (True).
    """
    val = os.environ.get("LAB_ENFORCE_2FA", "1").lower().strip()
    return val not in ("0", "false", "no", "off")
