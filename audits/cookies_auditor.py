"""
Cookies auditor: validates cookie security flags against site config.

Response-driven auditor. Takes the cookies set by a target
(via context.cookies()) and the site's cookie policy, then produces an
AuditResult with one Finding per (cookie, required-flag) pair.
"""

from audits.base_auditor import AuditResult, Finding, Severity


class CookiesAuditor:
    """Audits cookie security flags against configured expectations."""

    NAME = "CookiesAuditor"

    def audit(self, cookies: list[dict], config: dict, target: str) -> AuditResult:
        """Run the cookie security audit.

        Args:
            cookies: List of cookie dicts from Playwright context.cookies().
                     Each has keys like name, secure, httpOnly, sameSite.
            config: The 'cookie_policy' section from the site config.
                    Contains 'enforce_on' and 'required_flags'.
            target: The URL being audited (for reporting context).

        Returns:
            AuditResult with one Finding per (cookie, required-flag) pair.
        """
        result = AuditResult(auditor=self.NAME, target=target)

        enforce_on = config.get("enforce_on", "all")
        required_flags = config.get("required_flags", {})

        # Determine which cookies to check
        if enforce_on == "all":
            cookies_to_check = cookies
        else:
            # enforce_on is a list of specific cookie names
            cookies_to_check = [c for c in cookies if c.get("name") in enforce_on]

        # No cookies present — informational, not a failure
        if not cookies_to_check:
            result.findings.append(
                Finding(
                    check="Cookie presence",
                    passed=True,
                    severity=Severity.INFO,
                    detail="No cookies found to audit.",
                )
            )
            return result

        # Check each cookie against each required flag
        for cookie in cookies_to_check:
            cookie_name = cookie.get("name", "<unnamed>")

            for flag_name, rules in required_flags.items():
                severity = Severity(rules.get("severity", "info"))
                remediation = rules.get("remediation", "")

                flag_present = self._has_flag(cookie, flag_name)

                if flag_present:
                    finding = Finding(
                        check=f"Cookie '{cookie_name}' — {flag_name}",
                        passed=True,
                        severity=Severity.INFO,
                        detail=f"'{flag_name}' flag is set.",
                    )
                else:
                    finding = Finding(
                        check=f"Cookie '{cookie_name}' — {flag_name}",
                        passed=False,
                        severity=severity,
                        detail=f"'{flag_name}' flag is missing.",
                        remediation=remediation,
                    )

                result.findings.append(finding)

        return result

    @staticmethod
    def _has_flag(cookie: dict, flag_name: str) -> bool:
        """Check whether a cookie has a given security flag set.

        Playwright normalizes flags to: 'secure' (bool), 'httpOnly' (bool),
        'sameSite' (str: 'Strict'/'Lax'/'None'). We map our config flag
        names to these Playwright keys.
        """
        if flag_name == "secure":
            return cookie.get("secure", False) is True
        if flag_name == "httponly":
            return cookie.get("httpOnly", False) is True
        if flag_name == "samesite":
            # SameSite is considered set if it's Strict or Lax (not None/absent)
            same_site = cookie.get("sameSite", "None")
            return same_site in ("Strict", "Lax")
        return False