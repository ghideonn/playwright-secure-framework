"""
Markdown reporter: human-readable output for GitHub, PRs, and docs.

Renders audit results as Markdown with a summary table and per-finding
sections. Suitable for posting as a PR comment or committing as a report
artifact that renders nicely on GitHub.
"""

from audits.base_auditor import AuditResult, Severity
from reports.base_reporter import BaseReporter, ReportSummary


class MarkdownReporter(BaseReporter):
    """Renders audit results as Markdown."""

    # Emoji-free status indicators keep output clean in all Markdown renderers
    _PASS = "PASS"
    _FAIL = "FAIL"

    def render(self, results: list[AuditResult]) -> str:
        summary = ReportSummary.from_results(results)
        lines = []

        # Title
        lines.append("# Security Audit Report")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Auditors run | {len(results)} |")
        lines.append(f"| Total checks | {summary.total_findings} |")
        lines.append(f"| Passed | {summary.passed} |")
        lines.append(f"| Failed | {summary.failed} |")
        lines.append("")

        # Severity breakdown table (only non-zero)
        active = {s: c for s, c in summary.by_severity.items() if c > 0}
        if active:
            lines.append("### Findings by Severity")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev, count in active.items():
                lines.append(f"| {sev.upper()} | {count} |")
            lines.append("")

        # Per-auditor detail
        lines.append("## Detailed Results")
        lines.append("")
        for result in results:
            overall = "PASS" if result.passed else "FAIL"
            lines.append(f"### {result.auditor} — {overall}")
            lines.append(f"Target: `{result.target}`")
            lines.append("")
            lines.append("| Status | Severity | Check | Detail |")
            lines.append("|--------|----------|-------|--------|")
            for f in result.findings:
                status = self._PASS if f.passed else self._FAIL
                sev = "-" if f.passed else f.severity.value.upper()
                # Escape pipe characters in text to avoid breaking the table
                detail = f.detail.replace("|", "\\|")
                lines.append(f"| {status} | {sev} | {f.check} | {detail} |")
            lines.append("")

        # Remediation section
        failures = self.collect_failures(results)
        if failures:
            lines.append("## Remediation")
            lines.append("")
            for f in failures:
                lines.append(f"- **[{f.severity.value.upper()}] {f.check}**")
                lines.append(f"  - Detail: {f.detail}")
                if f.remediation:
                    lines.append(f"  - Fix: {f.remediation}")
            lines.append("")

        return "\n".join(lines)