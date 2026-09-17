# Playwright Security Framework

A configuration-driven security testing framework for web applications, built with Python, Playwright, and pytest. It audits a target for common security misconfigurations — missing security headers, permissive CORS, insecure cookies, and information disclosure — and demonstrates UI-driven security tests (authentication, SQL injection) through a Page Object Model, with findings reported in multiple formats and validated in CI.

![Security Audit](https://github.com/ghideonn/playwright-secure-framework/actions/workflows/security-audit.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.14-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## Overview

This framework treats security checks as **reusable, configuration-driven auditors** rather than one-off scripts. Each auditor inspects one aspect of a target's security posture and produces severity-rated findings with remediation guidance. Adding a new target is a matter of writing a YAML config — no auditor code changes.

It is built around two complementary testing styles:

- **Response-driven auditors** inspect HTTP responses (headers, cookies, CORS, information disclosure). They work against any URL and are site-agnostic.
- **Interaction-driven tests** drive the browser through a Page Object Model to exercise real user flows (login, SQL injection attempts) and then audit the resulting session.

The framework is built with clean, testable automation engineering practices: a layered architecture, separation of logic from configuration, a strategy-based reporting layer, and a CI pipeline that runs the whole suite against a containerized target on every push.

---

## Features

- **Four security auditors** — HTTP security headers, CORS misconfiguration, cookie security flags, and information disclosure, each producing structured findings with severity and remediation.
- **Page Object Model** — UI-driven authentication tests, including a SQL-injection auth-bypass demonstration and post-login session cookie auditing.
- **BDD layer** — login security scenarios written in human-readable Gherkin, backed by step definitions that reuse the page objects and auditors.
- **Multi-format reporting** — the same findings rendered to the console, JSON, and Markdown via a strategy-pattern reporting layer.
- **Configuration-driven** — targets, selectors, header rules, and attack payloads live in YAML. A new target needs a config file and a Docker service, not new code.
- **Containerized target** — the application under test runs in Docker for reproducible, deterministic results locally and in CI.
- **CI/CD** — a GitHub Actions pipeline starts the target, runs the audit and test suite, renders the report into the job summary, and uploads reports as artifacts.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.14 |
| Browser automation | Playwright (Sync API) |
| Test runner | pytest |
| BDD | pytest-bdd (Gherkin) |
| Containerization | Docker Compose |
| CI/CD | GitHub Actions |
| Target application | OWASP Juice Shop |

---

## Architecture

The framework separates **logic** (code) from **data** (configuration). Auditors and page objects contain only behavior; everything target-specific — URLs, selectors, header policies, payloads — lives in YAML.

```
playwright-secure-framework/
├── audits/                     # Response-driven auditors
│   ├── base_auditor.py         #   Finding / AuditResult / Severity types
│   ├── headers_auditor.py
│   ├── cookies_auditor.py
│   ├── cors_auditor.py
│   └── disclosure_auditor.py
├── pages/                      # Page Object Model (interaction-driven)
│   ├── base_page.py            #   Navigation, overlay handling
│   └── juice_shop/
│       └── login_page.py       #   Login selectors + actions (from config)
├── reports/                    # Strategy-pattern reporting layer
│   ├── base_reporter.py
│   ├── console_reporter.py
│   ├── json_reporter.py
│   └── markdown_reporter.py
├── config/
│   └── sites/
│       └── juice_shop.yaml      # All target-specific data
├── tests/
│   ├── universal/               # Site-agnostic auditor tests
│   ├── juice_shop/              # Site-specific UI tests
│   ├── features/                # Gherkin .feature files (specs)
│   └── steps/                   # BDD step definitions
├── docker/
│   └── docker-compose.juice_shop.yml
├── .github/workflows/
│   └── security-audit.yml       # CI pipeline
├── conftest.py                  # Fixtures (target selection, config loading)
├── pytest.ini
├── requirements.txt
└── run_audit.py                 # Standalone audit runner
```

**Adding a new target:** write `config/sites/<target>.yaml` describing its base URL, header policy, cookie policy, selectors, and payloads, add a Docker service for it, and run the existing auditors against it with `--target <target>`. No auditor code changes.

---

## Getting Started

### Prerequisites

- Python 3.14+
- Docker (for the target application)
- A POSIX shell (Linux / macOS / WSL)

### Installation

```bash
# Clone the repository
git clone https://github.com/ghideonn/playwright-secure-framework.git
cd playwright-secure-framework

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies and the Playwright browser
pip install -r requirements.txt
playwright install chromium
```

### Start the target application

The suite runs against a local OWASP Juice Shop instance in Docker.

```bash
docker compose -f docker/docker-compose.juice_shop.yml up -d
curl -sI http://localhost:3000   # expect: HTTP/1.1 200 OK
```

### Run the audit

```bash
# Standalone audit — prints a report and writes JSON + Markdown
python run_audit.py --target juice_shop
```

### Run the test suite

```bash
# All tests against the configured target
pytest --target=juice_shop -v

# Only the site-agnostic auditor tests
pytest tests/universal/ --target=juice_shop -v

# Only the BDD login scenarios
pytest tests/steps/ --target=juice_shop -v
```

---

## Example Output

Running `python run_audit.py --target juice_shop` against a local Juice Shop produces:

```
============================================================
SECURITY AUDIT REPORT
============================================================
Auditors run:    4
Total checks:    16
Passed:          12
Failed:          4
By severity:     high: 3, medium: 1
------------------------------------------------------------

[HeadersAuditor] http://localhost:3000
  [FAIL] (HIGH) Content-Security-Policy header
         Missing (required header not present)
  ...

[CookiesAuditor] http://localhost:3000
  [FAIL] (HIGH) Cookie 'language' — secure
         'secure' flag is missing.
  [FAIL] (HIGH) Cookie 'language' — httponly
         'httponly' flag is missing.
  ...

[CorsAuditor] http://localhost:3000
  [FAIL] (MEDIUM) CORS Allow-Origin wildcard
         Access-Control-Allow-Origin is '*' (any origin allowed).

------------------------------------------------------------
ISSUES REQUIRING ATTENTION
------------------------------------------------------------
[HIGH] Content-Security-Policy header
    Fix: Define a Content-Security-Policy to mitigate XSS and data injection attacks.
[HIGH] Cookie 'language' — httponly
    Fix: Set the 'HttpOnly' flag to prevent JavaScript access (XSS mitigation).
[MEDIUM] CORS Allow-Origin wildcard
    Fix: Avoid 'Access-Control-Allow-Origin: *'. Specify explicit trusted origins.
```

These are real findings against OWASP Juice Shop, which is intentionally vulnerable. Against a deliberately vulnerable target the audit is expected to report findings — for a production target, the pipeline would gate on a severity threshold instead.

The same findings are also written as JSON (for machine consumption) and Markdown (rendered into the CI job summary).

---

## Continuous Integration

Every push runs a GitHub Actions pipeline that:

1. Starts the containerized target using the same Compose file as local runs.
2. Installs dependencies and the Chromium browser.
3. Runs the audit, generating console, JSON, and Markdown reports.
4. Runs the pytest suite.
5. Renders the Markdown report into the GitHub job summary and uploads all reports as artifacts.

Because the target is intentionally vulnerable, findings are **documented rather than used to gate the build** — the pipeline validates that the framework runs and reports correctly. For a real target, a severity threshold would fail the build.

---

## Roadmap

The core framework is functional. Planned enhancements:

- **Plain-language finding explanations** — use an LLM to turn technical findings into clear explanations (impact + remediation) so non-experts understand what each issue means.
- **User-supplied target URLs** — allow auditing a user-provided site (with an explicit *authorized targets only* safeguard), aimed at small teams who want a quick self-audit of their own site.
- **Additional auditors** — expand coverage (e.g. additional injection checks) as reusable, configuration-driven modules.

---

## Disclaimer

This project is for **educational and authorized security testing only**. It is designed to be run against applications you own or have explicit permission to test. OWASP Juice Shop is used as a deliberately vulnerable target for demonstration. Do not use this tool against systems you are not authorized to assess — doing so may be illegal.

---

## License

Released under the [MIT License](LICENSE).
