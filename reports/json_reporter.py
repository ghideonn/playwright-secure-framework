"""
JSON reporter: machine-readable output for CI and integrations.

Renders audit results as structured JSON that pipelines can parse to
gate builds, feed dashboards, or trigger alerts. Includes summary
statistics and full per-finding detail.
"""

import json

from audits.base_auditor import AuditResult
from reports.base_reporter import BaseReporter, ReportSummary


class JsonReporter(BaseReporter):
    """Renders audit results as structured JSON."""

    def render(self, results: list[AuditResult]) -> str:
        summary = ReportSummary.from_results(results)

        report = {
            "summary": {
                "auditors_run": len(results),
                "total_checks": summary.total_findings,
                "passed": summary.passed,
                "failed": summary.failed,
                "by_severity": summary.by_severity,
            },
            "results": [
                {
                    "auditor": result.auditor,
                    "target": result.target,
                    "passed": result.passed,
                    "findings": [
                        {
                            "check": f.check,
                            "passed": f.passed,
                            "severity": f.severity.value,
                            "detail": f.detail,
                            "remediation": f.remediation,
                        }
                        for f in result.findings
                    ],
                }
                for result in results
            ],
        }

        # indent=2 for readability; sort_keys for deterministic output
        return json.dumps(report, indent=2, sort_keys=False)