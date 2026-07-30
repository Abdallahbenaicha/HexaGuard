"""
SecuraX Scanner Plugin SDK
============================
Exports the public API for scanner plugin development.

Quick start:
    from backend.scanners.sdk import ScannerPlugin, Finding, registry

    class MyScanner(ScannerPlugin):
        name = "my_scanner"
        version = "1.0.0"
        description = "Detects XYZ vulnerabilities"
        supported_scan_types = ["web"]

        def register(self): ...
        def validate(self, target): ...
        def scan(self, target, **opts): ...
        def normalize(self, raw): ...
        def report(self, findings, target, scan_type=None): ...

    registry.register(MyScanner)
"""

from backend.scanners.sdk.base import ScannerPlugin, Finding
from backend.scanners.sdk.registry import PluginRegistry, registry

__all__ = ["ScannerPlugin", "Finding", "PluginRegistry", "registry"]
__version__ = "1.0.0"
