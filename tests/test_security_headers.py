import pytest
from playwright.sync_api import Playwright

# Target URL: OWASP Juice Shop vulnerable web application for testing purposes
TARGET_URL = "https://juice-shop.herokuapp.com/"

@pytest.mark.security
def test_security_headers_audit(playwright: Playwright):
    """
    Security Automation Test: Validates that the backend server 
    includes mandatory HTTP Security Headers in the response.
    """
    # Launch the browser in headless mode to optimize performance in CI/CD pipelines
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    
    # Execute the HTTP request and capture the server response
    response = page.goto(TARGET_URL)
    headers = response.headers
    
    # Define a list of mandatory corporate security headers
    security_headers = [
        "X-Frame-Options",          # Protects against Clickjacking attacks
        "X-Content-Type-Options",  # Prevents MIME-sniffing vulnerabilities
        "Content-Security-Policy"  # Mitigates Cross-Site Scripting (XSS) risks
    ]
    
    print("\n\n--- [SecOps Audit] Scanning Target Server Headers ---")
    for header in security_headers:
        # HTTP header keys are case-insensitive, so we fetch using lowercase
        header_value = headers.get(header.lower()) 
        print(f"-> {header}: {header_value}")
        
        # Core Assertion: Verify the security header is present (not None)
        assert header_value is not None, f"SECURITY VULNERABILITY: Missing critical header: {header}"

    # Gracefully close the browser context to release system resources
    browser.close()
