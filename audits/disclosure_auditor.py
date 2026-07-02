"""
Information disclosure auditor: detects headers that leak stack details.

Response-driven (Type A) auditor. Checks for the presence of response
headers that reveal server/framework/version information useful to an
attacker. Unlike security headers (which SHOULD be present), these
headers should NOT be present — their presence is a finding.
"""

from audits.base_auditor import AuditResult, Finding, Severity


class DisclosureAuditor:
    """Audits response headers for information disclosure."""

    NAME = "DisclosureAuditor"

    def audit(self, headers: dict, config: dict, target: str) -> AuditResult:
        """Run the information disclosure audit.

        Args:
            headers: Response headers (keys treated case-insensitively).
            config: The 'disclosure_policy' section from the site config.
                    Contains 'forbidden_headers' mapping header names to
                    {severity, remediation}.
            target: The URL being audited (for reporting context).

        Returns:
            AuditResult with one Finding per checked forbidden header.
        """
        result = AuditResult(auditor=self.NAME, target=target)

        # Normalize response header keys to lowercase for case-insensitive lookup
        normalized = {k.lower(): v for k, v in headers.items()}

        forbidden_headers = config.get("forbidden_headers", {})

        for header_name, rules in forbidden_headers.items():
            severity = Severity(rules.get("severity", "info"))
            remediation = rules.get("remediation", "")

            header_value = normalized.get(header_name.lower())
            is_present = header_value is not None

            if is_present:
                # Forbidden header is present — this is a disclosure finding
                finding = Finding(
                    check=f"{header_name} disclosure",
                    passed=False,
                    severity=severity,
                    detail=f"Leaks information: {header_name}: {header_value}",
                    remediation=remediation,
                )
            else:
                # Forbidden header is absent — good, no disclosure
                finding = Finding(
                    check=f"{header_name} disclosure",
                    passed=True,
                    severity=Severity.INFO,
                    detail=f"{header_name} header not present (no disclosure).",
                )

            result.findings.append(finding)

        return result