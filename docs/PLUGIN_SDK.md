# SecuraX Scanner Plugin SDK

> **Version**: 1.0.0 | **Location**: `backend/scanners/sdk/`

## What is the Plugin SDK?

The SecuraX Scanner Plugin SDK is an **abstract interface** that allows you to integrate
any vulnerability scanner into SecuraX in **under 30 minutes**.

It defines:
1. A **standardised lifecycle** for scanner execution
2. A **normalised finding schema** (`Finding` dataclass)
3. An **automatic discovery registry** (`PluginRegistry`)

---

## Quick Start

### 1. Create your scanner file

```python
# backend/scanners/plugins/my_scanner.py

from backend.scanners.sdk import ScannerPlugin, Finding

class MyScanner(ScannerPlugin):
    name        = "my_scanner"
    version     = "1.0.0"
    description = "Detects XYZ vulnerabilities in web applications"
    supported_scan_types = ["web"]
    references  = ["https://owasp.org/..."]

    def register(self) -> dict:
        return {
            "name":    self.name,
            "version": self.version,
            "description": self.description,
            "supported_scan_types": self.supported_scan_types,
        }

    def validate(self, target: str) -> bool:
        """Return True if the target is reachable."""
        try:
            import requests
            r = requests.head(target, timeout=5)
            return r.status_code < 500
        except Exception:
            return False

    def scan(self, target: str, **options) -> dict:
        """Perform the actual scan. Return raw results."""
        # Your scanning logic here
        return {"target": target, "raw_findings": []}

    def normalize(self, raw_output: dict) -> list[Finding]:
        """Convert raw output to Finding objects."""
        findings = []
        for item in raw_output.get("raw_findings", []):
            findings.append(Finding(
                check       = item["check_id"],
                title       = item["title"],
                severity    = item["severity"],   # must be: critical/high/medium/low/info
                description = item["description"],
                evidence    = item.get("evidence", ""),
                cve_ids     = item.get("cve_ids", []),
                cwe_id      = item.get("cwe_id"),
                remediation = item.get("remediation", ""),
            ))
        return findings

    def report(self, findings: list[Finding], target: str, scan_type: str = None) -> dict:
        """Build the SecuraX-compatible scan result."""
        return {
            "scan_type":       scan_type or self.supported_scan_types[0],
            "target":          target,
            "scanner":         self.name,
            "scanner_version": self.version,
            "vulnerabilities": [f.to_dict() for f in findings],
        }
```

### 2. Register and run

```python
from backend.scanners.sdk import registry

# Manual registration
from backend.scanners.plugins.my_scanner import MyScanner
registry.register(MyScanner)

# Auto-discover all plugins in a directory
registry.discover("backend/scanners/plugins/")

# Run the scanner
result = registry.run("my_scanner", target="http://example.com")
print(result)
# {
#   "scan_type": "web",
#   "target": "http://example.com",
#   "scanner": "my_scanner",
#   "scanner_version": "1.0.0",
#   "vulnerabilities": [...]
# }
```

---

## Plugin Lifecycle

```
User calls plugin.run(target)
         ↓
   validate(target)  → False → return empty result
         ↓ True
    scan(target)     → raw dict (tool-specific format)
         ↓
  normalize(raw)     → list[Finding] (SecuraX schema)
         ↓
  report(findings)   → dict (risk_engine input)
         ↓
Risk engine receives the result
```

---

## The `Finding` Schema

All scanners must produce `Finding` objects with these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check` | str | ✅ | Unique check identifier (e.g. `"xss"`, `"sql_injection"`) |
| `title` | str | ✅ | Human-readable finding title |
| `severity` | str | ✅ | One of: `critical`, `high`, `medium`, `low`, `info` |
| `description` | str | ✅ | Technical description of the finding |
| `evidence` | str | ➖ | Raw evidence (HTTP response fragment, etc.) |
| `cve_ids` | list[str] | ➖ | CVE IDs (e.g. `["CVE-2021-44228"]`) |
| `cwe_id` | str | ➖ | CWE identifier (e.g. `"CWE-89"`) |
| `owasp` | str | ➖ | OWASP category (e.g. `"A03:2021-Injection"`) |
| `remediation` | str | ➖ | Actionable remediation guidance |
| `references` | list[str] | ➖ | Reference URLs |
| `metadata` | dict | ➖ | Scanner-specific extra data |

---

## PluginRegistry API

```python
from backend.scanners.sdk import registry, PluginRegistry

# Singleton access
registry = PluginRegistry.instance()

# Register a plugin class
registry.register(MyScanner)

# Auto-discover from directory
count = registry.discover("backend/scanners/plugins/")

# Get plugin class
cls = registry.get("my_scanner")   # returns None if not found

# Instantiate a plugin
plugin = registry.create("my_scanner")  # raises KeyError if not found

# Run (instantiate + full pipeline)
result = registry.run("my_scanner", target="http://example.com")

# List all registered plugins
plugins = registry.list_plugins()
# [{"name": "my_scanner", "version": "1.0.0", ...}]

# Count registered plugins
len(registry)  # → int
```

---

## Requirements

A plugin **must**:
1. Subclass `ScannerPlugin`
2. Define `name` and `version` class attributes
3. Implement all 5 abstract methods: `register`, `validate`, `scan`, `normalize`, `report`
4. Return `Finding` objects from `normalize()` with valid severity values
5. Return a `scan_type` that matches one of SecuraX's known types

A plugin **should**:
1. Handle network errors gracefully in `validate()` and `scan()` (return False / empty)
2. Include `scanner_version` in the `report()` output
3. Include `cwe_id` for known vulnerability types
4. Include `references` for traceability

---

## Security Considerations

When writing scanner plugins:

1. **Never execute untrusted input** — sanitise all target URLs before passing to subprocesses
2. **Validate targets** — block private IPs (10.x, 192.168.x, 172.16-31.x) unless explicitly configured
3. **Set timeouts** — always use `timeout=` in `requests.get()` and socket operations
4. **Don't log secrets** — never log HTTP headers that may contain `Authorization` tokens
5. **Handle adversarial targets** — scan targets may return malformed responses to crash parsers

---

## References

- [OWASP-ASVS] OWASP Application Security Verification Standard v4.0
- [NIST-SP800-115] NIST Guide to Information Security Testing, 2008
- [SecuraX-ARCH] `docs/ARCHITECTURE.md` — Scanner Pipeline section
- [ADR-004] `docs/adr/ADR-004-plugin-sdk-design.md` — Design decisions
