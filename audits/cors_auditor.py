"""
CORS auditor: detects overly permissive Cross-Origin Resource Sharing.

Response-driven (Type A) auditor. Inspects Access-Control-* response
headers and flags misconfigurations such as a wildcard Allow-Origin,
especially when combined with credentials.
"""

from audits.base_auditor import AuditResult, Finding, Severity


class CorsAuditor:
    """Audits CORS response headers for permissive misconfigurations."""

    NAME = "CorsAuditor"

    def audit(self, headers: dict, config: dict, target: str) -> AuditResult:
        """Run the CORS audit.

        Args:
            headers: Response headers (keys treated case-insensitively).
            config: The 'cors_policy' section from the site config.
            target: The URL being audited (for reporting context).

        Returns:
            AuditResult with CORS-related Findings.
        """
        result = AuditResult(auditor=self.NAME, target=target)

        # Normalize header keys to lowercase (HTTP headers are case-insensitive)
        normalized = {k.lower(): v for k, v in headers.items()}

        allow_origin = normalized.get("access-control-allow-origin")
        allow_credentials = normalized.get("access-control-allow-credentials")

        is_wildcard = allow_origin == "*"
        credentials_enabled = (
            allow_credentials is not None and allow_credentials.lower() == "true"
        )

        # Check 1: wildcard Allow-Origin
        wildcard_rules = config.get("disallow_wildcard_origin", {})
        if is_wildcard:
            result.findings.append(
                Finding(
                    check="CORS Allow-Origin wildcard",
                    passed=False,
                    severity=Severity(wildcard_rules.get("severity", "medium")),
                    detail="Access-Control-Allow-Origin is '*' (any origin allowed).",
                    remediation=wildcard_rules.get("remediation", ""),
                )
            )
        else:
            result.findings.append(
                Finding(
                    check="CORS Allow-Origin wildcard",
                    passed=True,
                    severity=Severity.INFO,
                    detail=(
                        f"Access-Control-Allow-Origin: {allow_origin}"
                        if allow_origin
                        else "No Access-Control-Allow-Origin header (CORS not enabled)."
                    ),
                )
            )

        # Check 2: wildcard origin combined with credentials (critical)
        combo_rules = config.get("disallow_wildcard_with_credentials", {})
        if is_wildcard and credentials_enabled:
            result.findings.append(
                Finding(
                    check="CORS wildcard with credentials",
                    passed=False,
                    severity=Severity(combo_rules.get("severity", "high")),
                    detail="Allow-Origin '*' combined with Allow-Credentials 'true'.",
                    remediation=combo_rules.get("remediation", ""),
                )
            )
        else:
            result.findings.append(
                Finding(
                    check="CORS wildcard with credentials",
                    passed=True,
                    severity=Severity.INFO,
                    detail="No dangerous wildcard+credentials combination detected.",
                )
            )

        return result