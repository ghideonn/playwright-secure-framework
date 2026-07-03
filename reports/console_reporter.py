"""
Console reporter: human-readable plain-text output for the terminal.

Renders audit results as a summary header followed by grouped findings.
Uses simple ASCII markers (no color codes) for CI-log compatibility.
"""

from audits.base_auditor import AuditResult
from reports.base_reporter import BaseReporter, ReportSummary


class ConsoleReporter(BaseReporter):
    """Renders audit results as plain text for terminal display."""

    def render(self, results: list[AuditResult]) -> str:
        summary = ReportSummary.from_results(results)
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append("SECURITY AUDIT REPORT")
        lines.append("=" * 60)

        # Summary block
        lines.append(f"Auditors run:    {len(results)}")
        lines.append(f"Total checks:    {summary.total_findings}")
        lines.append(f"Passed:          {summary.passed}")
        lines.append(f"Failed:          {summary.failed}")

        # Severity breakdown (only show non-zero buckets)
        active_severities = {
            sev: count for sev, count in summary.by_severity.items() if count > 0
        }
        if active_severities:
            breakdown = ", ".join(
                f"{sev}: {count}" for sev, count in active_severities.items()
            )
            lines.append(f"By severity:     {breakdown}")

        lines.append("-" * 60)

        # Per-auditor findings
        for result in results:
            lines.append(f"\n[{result.auditor}] {result.target}")
            for finding in result.findings:
                marker = "PASS" if finding.passed else "FAIL"
                sev = "" if finding.passed else f" ({finding.severity.value.upper()})"
                lines.append(f"  [{marker}]{sev} {finding.check}")
                lines.append(f"         {finding.detail}")

        # Failures section with remediation
        failures = self.collect_failures(results)
        if failures:
            lines.append("\n" + "-" * 60)
            lines.append("ISSUES REQUIRING ATTENTION")
            lines.append("-" * 60)
            for finding in failures:
                lines.append(f"[{finding.severity.value.upper()}] {finding.check}")
                lines.append(f"    Detail: {finding.detail}")
                if finding.remediation:
                    lines.append(f"    Fix:    {finding.remediation}")

        lines.append("=" * 60)
        return "\n".join(lines)