"""
Headers auditor: validates HTTP security headers against site config.

Response-driven (Type A) auditor. Takes a response's headers and the
site's expected-header rules, then produces an AuditResult with one
Finding per configured header.
"""

from audits.base_auditor import AuditResult, Finding, Severity


class HeadersAuditor:
    """Audits HTTP response headers against configured security expectations."""

    NAME = "HeadersAuditor"

    def audit(self, headers: dict, config: dict, target: str) -> AuditResult:
        """Run the headers audit.

        Args:
            headers: Response headers (keys treated case-insensitively).
            config: The 'security_headers' section from the site config.
                    Each entry maps a header name to {required, severity, remediation}.
            target: The URL being audited (for reporting context).

        Returns:
            AuditResult containing one Finding per configured header.
        """
        result = AuditResult(auditor=self.NAME, target=target)

        # Normalize response header keys to lowercase for case-insensitive lookup
        # HTTP header names are case-insensitive per RFC 7230
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for header_name, rules in config.items():
            required = rules.get("required", False)
            severity = Severity(rules.get("severity", "info"))
            remediation = rules.get("remediation", "")

            header_value = normalized_headers.get(header_name.lower())
            is_present = header_value is not None

            if is_present:
                # Header found — this is a pass regardless of required flag
                finding = Finding(
                    check=f"{header_name} header",
                    passed=True,
                    severity=Severity.INFO,
                    detail=f"Present: {header_value}",
                )
            elif required:
                # Missing AND required — this is a failed check (vulnerability)
                finding = Finding(
                    check=f"{header_name} header",
                    passed=False,
                    severity=severity,
                    detail="Missing (required header not present)",
                    remediation=remediation,
                )
            else:
                # Missing but optional — pass, but note it as informational
                finding = Finding(
                    check=f"{header_name} header",
                    passed=True,
                    severity=Severity.INFO,
                    detail="Missing (optional header, not enforced)",
                    remediation=remediation,
                )

            result.findings.append(finding)

        return result