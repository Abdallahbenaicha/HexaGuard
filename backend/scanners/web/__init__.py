from __future__ import annotations
"""Modular Web Application Assessment Package for SecuraX."""

try:
    from scanners.web.constants import *
    from scanners.web.utils import *
    from scanners.web.utils import (
        _make_session, _norm_url, _resolve_ip, _is_private, _vuln, _dedup_key,
        _404_fingerprint, _is_soft_404
    )
    from scanners.web.intel_apis import *
    from scanners.web.local_checks import *
    from scanners.web.engine import *
except ImportError:
    from backend.scanners.web.constants import *
    from backend.scanners.web.utils import *
    from backend.scanners.web.utils import (
        _make_session, _norm_url, _resolve_ip, _is_private, _vuln, _dedup_key,
        _404_fingerprint, _is_soft_404
    )
    from backend.scanners.web.intel_apis import *
    from backend.scanners.web.local_checks import *
    from backend.scanners.web.engine import *
