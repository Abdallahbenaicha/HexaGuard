"""
SecuraX Scanner Plugin SDK
============================
Abstract base class and protocol for all SecuraX scanner plugins.

Any scanner that implements the ScannerPlugin interface can be registered
with the PluginRegistry and will be automatically discovered and invoked
by the SecuraX scan engine.

Plugin lifecycle:
    1. register()   → declares metadata (name, version, supported_scan_types)
    2. validate()   → checks if the target is reachable/valid
    3. scan()       → performs the actual scan, returns raw output
    4. normalize()  → converts raw output to SecuraX finding schema
    5. report()     → builds the final scan_result dict for the risk engine

Writing a new scanner plugin:
    See docs/PLUGIN_SDK.md for the full guide.

    Minimal example:
        from backend.scanners.sdk.base import ScannerPlugin

        class MyScanner(ScannerPlugin):
            name = "my_scanner"
            version = "1.0.0"
            supported_scan_types = ["web"]

            def register(self) -> dict: ...
            def validate(self, target: str) -> bool: ...
            def scan(self, target: str, **options) -> dict: ...
            def normalize(self, raw_output: dict) -> list[dict]: ...
            def report(self, findings: list[dict]) -> dict: ...

References:
    [OWASP-ASVS]     OWASP Application Security Verification Standard v4.0
    [NIST-SP800-115]  NIST Guide to Information Security Testing, 2008
    [SecuraX-ARCH]    docs/ARCHITECTURE.md — Scanner Pipeline section

Version: 1.0.0
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Finding schema
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    Normalised vulnerability finding.
    All scanners must produce findings in this schema.

    Fields:
        check       Unique check identifier (e.g. "xss", "sql_injection")
        title       Human-readable title
        severity    One of {critical, high, medium, low, info}
        description Technical description
        evidence    Raw evidence string (HTTP response fragment, code snippet, etc.)
        cve_ids     List of CVE IDs if known (e.g. ["CVE-2021-44228"])
        cwe_id      CWE identifier if applicable (e.g. "CWE-89")
        owasp       OWASP category (e.g. "A03:2021-Injection")
        remediation Actionable remediation guidance
        references  List of reference URLs
        metadata    Scanner-specific extra data (dict)
    """
    check:       str
    title:       str
    severity:    str
    description: str
    evidence:    str          = ""
    cve_ids:     list[str]   = field(default_factory=list)
    cwe_id:      Optional[str] = None
    owasp:       Optional[str] = None
    remediation: str          = ""
    references:  list[str]   = field(default_factory=list)
    metadata:    dict        = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise to SecuraX vulnerability dict format."""
        return {
            "check":       self.check,
            "title":       self.title,
            "severity":    self.severity.lower(),
            "description": self.description,
            "evidence":    self.evidence,
            "cve_ids":     self.cve_ids,
            "cwe_id":      self.cwe_id,
            "owasp":       self.owasp,
            "remediation": self.remediation,
            "references":  self.references,
            "metadata":    self.metadata,
        }

    def __post_init__(self):
        # Validate severity
        valid = {"critical", "high", "medium", "low", "info", "informational"}
        if self.severity.lower() not in valid:
            raise ValueError(
                f"Finding '{self.check}': invalid severity '{self.severity}'. "
                f"Must be one of {valid}"
            )
        self.severity = self.severity.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Plugin base class
# ─────────────────────────────────────────────────────────────────────────────

class ScannerPlugin(abc.ABC):
    """
    Abstract base class for all SecuraX scanner plugins.

    Subclass this and implement all abstract methods to create a scanner
    that integrates with the SecuraX risk engine pipeline.

    Class attributes (must be defined on the subclass):
        name                Unique scanner identifier (snake_case)
        version             Semantic version string (e.g. "1.0.0")
        description         One-sentence description of what this scanner detects
        supported_scan_types List of scan type strings this scanner can produce
                            (e.g. ["web", "api"])
    """

    #: Unique identifier for this scanner (snake_case, e.g. "web_scanner")
    name: str = ""

    #: Semantic version (e.g. "1.0.0")
    version: str = "0.0.0"

    #: Human-readable description
    description: str = ""

    #: Scan types this plugin outputs (must match risk_engine expected types)
    supported_scan_types: list[str] = []

    #: References to standards this scanner implements
    references: list[str] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Validate required class attributes
        if not cls.name:
            raise TypeError(f"{cls.__name__}: 'name' class attribute is required")
        if not cls.version:
            raise TypeError(f"{cls.__name__}: 'version' class attribute is required")

    # ── Required methods ──────────────────────────────────────────────────────

    @abc.abstractmethod
    def register(self) -> dict:
        """
        Return plugin registration metadata.

        Returns:
            dict with keys: name, version, description, supported_scan_types, references
        """
        ...

    @abc.abstractmethod
    def validate(self, target: str) -> bool:
        """
        Validate that the target is reachable and supported by this scanner.

        Args:
            target: URL, IP address, or path to scan.

        Returns:
            True if the target can be scanned; False otherwise.

        Raises:
            Should NOT raise — return False with an internal log instead.
        """
        ...

    @abc.abstractmethod
    def scan(self, target: str, **options) -> dict:
        """
        Perform the scan and return raw output.

        This method performs the actual security assessment. It may:
        - Send HTTP requests
        - Run subprocess tools (nmap, nikto, etc.)
        - Parse source code
        - Query APIs

        Args:
            target:   URL, IP address, or file path to scan.
            **options: Scanner-specific configuration options.

        Returns:
            Raw scanner output as a dict (tool-specific format).
        """
        ...

    @abc.abstractmethod
    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert raw scanner output to a list of normalised Finding objects.

        This is the most important method — it maps tool-specific output to
        the SecuraX finding schema so the risk engine can process it uniformly.

        Args:
            raw_output: The dict returned by scan().

        Returns:
            List of Finding objects. May be empty if no findings.
        """
        ...

    @abc.abstractmethod
    def report(self, findings: list[Finding], target: str, scan_type: str = None) -> dict:
        """
        Build the final scan_result dict for the SecuraX risk engine.

        Args:
            findings:  List of Finding objects from normalize().
            target:    Original scan target.
            scan_type: Scan type string (defaults to supported_scan_types[0]).

        Returns:
            SecuraX-compatible scan_result dict:
            {
                "scan_type": str,
                "target": str,
                "scanner": str,
                "scanner_version": str,
                "vulnerabilities": [finding.to_dict() for finding in findings]
            }
        """
        ...

    # ── Convenience methods (optional override) ───────────────────────────────

    def run(self, target: str, **options) -> dict:
        """
        Full pipeline: validate → scan → normalize → report.

        This is the primary entry point for the scan engine.

        Args:
            target:    Target to scan.
            **options: Passed to scan().

        Returns:
            SecuraX-compatible scan_result dict.
        """
        logger.info("[%s v%s] Starting scan: %s", self.name, self.version, target)

        if not self.validate(target):
            logger.warning("[%s] Target validation failed: %s", self.name, target)
            return self._empty_result(target)

        try:
            raw = self.scan(target, **options)
            findings = self.normalize(raw)
            result = self.report(findings, target)
            logger.info(
                "[%s] Scan complete: %d findings on %s",
                self.name, len(findings), target
            )
            return result
        except Exception as exc:
            logger.error("[%s] Scan failed for %s: %s", self.name, target, exc, exc_info=True)
            return self._empty_result(target, error=str(exc))

    def _empty_result(self, target: str, error: str = None) -> dict:
        """Return an empty result dict (used on validation failure or error)."""
        result = {
            "scan_type":       self.supported_scan_types[0] if self.supported_scan_types else "unknown",
            "target":          target,
            "scanner":         self.name,
            "scanner_version": self.version,
            "vulnerabilities": [],
        }
        if error:
            result["error"] = error
        return result

    def __repr__(self) -> str:
        return f"<ScannerPlugin name={self.name!r} version={self.version!r}>"
