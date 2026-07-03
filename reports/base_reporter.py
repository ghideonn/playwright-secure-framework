"""
Base reporter contract and shared aggregation logic.

Reporters take a list of AuditResult objects (from all auditors) and
render them into a specific output format. This module defines the
BaseReporter interface plus a ReportSummary that aggregates statistics
across all results — shared by every concrete reporter.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from audits.base_auditor import AuditResult, Finding, Severity


@dataclass
class ReportSummary:
    """Aggregated statistics across all audit results.

    Computed once and reused by any reporter to avoid duplicating the
    counting logic in every output format.
    """
    total_findings: int = 0
    passed: int = 0
    failed: int = 0
    by_severity: dict = field(default_factory=dict)

    @classmethod
    def from_results(cls, results: list[AuditResult]) -> "ReportSummary":
        """Build a summary by aggregating all findings across results."""
        summary = cls()
        # Initialize severity buckets for failed findings
        summary.by_severity = {sev.value: 0 for sev in Severity}

        for result in results:
            for finding in result.findings:
                summary.total_findings += 1
                if finding.passed:
                    summary.passed += 1
                else:
                    summary.failed += 1
                    summary.by_severity[finding.severity.value] += 1

        return summary


class BaseReporter(ABC):
    """Abstract base for all reporters (Strategy pattern).

    Concrete reporters implement render() to produce their specific
    output format from a list of AuditResult objects.
    """

    @abstractmethod
    def render(self, results: list[AuditResult]) -> str:
        """Render the given audit results into this reporter's format.

        Args:
            results: List of AuditResult objects from all auditors.

        Returns:
            The rendered report as a string.
        """
        ...

    @staticmethod
    def collect_failures(results: list[AuditResult]) -> list[Finding]:
        """Helper: collect all failed findings across all results."""
        failures = []
        for result in results:
            failures.extend(result.failures)
        return failures