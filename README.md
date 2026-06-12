# Playwright Security Framework

Production-shaped security testing framework using Playwright + Pytest + BDD, targeting [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) to validate security controls (HTTP headers, authentication, input validation) with CI/CD integration.

> **Status**: In active development. Built as a learning + portfolio project demonstrating security-focused QA automation.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.14 |
| Browser automation | Playwright (Sync API) |
| Test runner | Pytest |
| BDD layer | pytest-bdd (Gherkin) |
| Target application | OWASP Juice Shop |
| CI/CD | GitHub Actions |

---

## Project Goals

This framework validates security controls of web applications through automated testing. Focus areas:

- **HTTP Security Headers** — CSP, X-Frame-Options, X-Content-Type-Options, HSTS
- **Authentication & Authorization** — login flows, session handling, brute-force resistance
- **Input Validation** — XSS, SQL injection, command injection detection
- **Configuration Audits** — TLS, CORS, cookie flags

Secondary focus: performance and functional UI testing patterns.

---

## Project Structure   
playwright-secure-framework/

├── pages/                  # Page Object Model (POM) layer

│   ├── base_page.py

│   └── login_page.py

├── tests/

│   ├── features/           # Gherkin .feature files (BDD)

│   │   └── login.feature

│   ├── test_security_headers.py

│   └── test_ui_functional.py

├── utils/                  # Shared helpers (TBD)

├── .github/workflows/      # CI/CD pipelines (TBD)

├── conftest.py             # Pytest fixtures and hooks

├── pytest.ini              # Pytest configuration

└── requirements.txt        # Pinned dependencies

---

## Setup

### Prerequisites

- Python 3.14+
- Git
- A POSIX shell (Linux / macOS / WSL)

### Installation

```bash
# Clone the repository
git clone https://github.com/ghideonn/playwright-secure-framework.git
cd playwright-secure-framework

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium
```

---

## Running Tests

```bash
# Run all tests
pytest

# Run only security header tests
pytest tests/test_security_headers.py -v

# Run with detailed output
pytest -vv -s

# Run BDD scenarios only (after step definitions are added)
pytest tests/features/
```

---

## Roadmap

- [x] Project scaffolding and dependency management
- [x] HTTP security headers audit test
- [ ] Page Object Model implementation
- [ ] BDD step definitions for login scenarios
- [ ] Authentication security tests (SQL injection, brute force)
- [ ] GitHub Actions CI/CD pipeline
- [ ] Test reporting (HTML reports, JUnit XML)
- [ ] Performance testing layer

---

## License

This project is for educational and portfolio purposes.

OWASP Juice Shop is used as a deliberately vulnerable application **for testing purposes only**. Do not use these techniques on systems you do not own or have explicit permission to test.