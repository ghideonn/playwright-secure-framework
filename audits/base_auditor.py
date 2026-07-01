"""
Base auditor contract: shared data structures for all security audits.

Every auditor (headers, cookies, CORS, etc.) produces an AuditResult
containing a list of Findings. This gives us a uniform structure for
reporting, severity assessment, and CI integration.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity levels aligned with common security rating conventions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security check result.

    Attributes:
        check: Human-readable name of what was checked.
        passed: True if the check passed (secure), False if it failed (vulnerable).
        severity: Risk level IF the check failed. INFO for passing checks.
        detail: Human-readable explanation of the result.
        remediation: Actionable guidance on how to fix a failed check.
    """
    check: str
    passed: bool
    severity: Severity
    detail: str
    remediation: str = ""


@dataclass
class AuditResult:
    """Aggregated result of a single auditor run against one target.

    Attributes:
        auditor: Name of the auditor that produced this result.
        target: The URL that was audited.
        findings: List of individual Finding objects.
    """
    auditor: str
    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True only if every finding passed."""
        return all(f.passed for f in self.findings)

    @property
    def failures(self) -> list[Finding]:
        """Return only the failed findings (the vulnerabilities)."""
        return [f for f in self.findings if not f.passed]

    def summary(self) -> str:
        """Short human-readable summary line."""
        total = len(self.findings)
        failed = len(self.failures)
        return f"{self.auditor} on {self.target}: {total - failed}/{total} passed, {failed} issue(s)"