# ADR-004 — Scanner Architecture: Plugin SDK

**Status**: Accepted  
**Date**: 2026-03-10  
**Deciders**: Abdallah Benaicha  
**Supersedes**: N/A  
**Related**: [docs/PLUGIN_SDK.md](../PLUGIN_SDK.md)

---

## Context

SecuraX v1 implemented 11 scanner modules as standalone Python files:
```
web_scanner.py, dast_scanner.py, sast_scanner.py, netscan_scanner.py,
ssl_scanner.py, dep_scanner.py, server_int.py, server_ext.py,
docker_scanner.py, dns_scanner.py, wordpress_scanner.py
```

As the platform grew, several problems emerged:

1. **No unified interface** — each scanner had a different function signature.
   Adding a new scanner required understanding all existing patterns.
2. **No normalization contract** — scanners returned slightly different dict shapes,
   causing ad-hoc normalization code in `risk_engine.py`.
3. **No versioning** — impossible to know which scanner version produced a given finding.
4. **Difficult to test** — each scanner required different mock setup.
5. **No extensibility** — external contributors could not add scanners without
   understanding the entire backend.

### Option A: Continue with ad-hoc scanner files

**Pros**: No migration needed; existing code works.  
**Cons**: All problems listed above persist; technical debt compounds.

### Option B: Introduce a Plugin SDK (Abstract Base Class + Registry)

Define a `ScannerPlugin` abstract base class with lifecycle methods:
```
register() → validate() → scan() → normalize() → report()
```

A `PluginRegistry` singleton auto-discovers and instantiates plugins.
New scanners are written in minutes by implementing the interface.

**Pros**:
- Uniform interface → simpler risk engine integration
- `normalize()` contract guarantees consistent `Finding` schema
- `scanner_version` always attached to output → reproducible datasets
- External contributors can add scanners without reading internal code
- Mockable for unit testing (`validate()` can return False in test mode)

**Cons**:
- Migration effort: existing scanners need refactoring (planned for v4.0)
- Abstract classes add indirection layer

---

## Decision

**Introduce the Plugin SDK (`backend/scanners/sdk/`) as the target architecture.**

Existing scanners remain functional (backward compatible). New scanners are written
using the SDK. Existing scanners are gradually migrated as they receive updates.

The SDK is documented in `docs/PLUGIN_SDK.md` with a complete worked example.

---

## Migration Plan

| Phase | Action | Version |
|-------|--------|---------|
| v3.0 (current) | SDK infrastructure created; no migration yet | ✅ Done |
| v3.1 | Migrate `web_scanner.py` and `ssl_scanner.py` as pilots | Planned |
| v3.2 | Migrate remaining 9 scanners | Planned |
| v4.0 | Remove legacy scanner functions; SDK is the only interface | Planned |

---

## Consequences

### Positive
- Clear scanner contract enables external contributions
- Dataset reproducibility: `scanner_version` is always recorded
- Testability: `validate()` + `_empty_result()` pattern simplifies mocking

### Negative
- Existing scanners not yet migrated (hybrid state during transition)
- Two interface patterns coexist until v4.0

### Neutral
- The `PluginRegistry` singleton ensures only one registry per process

---

## References

- [PEP-3119] Python ABC documentation: https://docs.python.org/3/library/abc.html
- [OWASP-ASVS] OWASP Application Security Verification Standard v4.0
- [NIST-SP800-115] NIST. "Technical Guide to Information Security Testing and Assessment." 2008.
- [SecuraX-ARCH] `docs/ARCHITECTURE.md` — Scanner Pipeline section
