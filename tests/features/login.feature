@security @auth
Feature: Login Security
  As a security tester
  I want to verify the login flow's security posture
  So that authentication weaknesses are surfaced early

  @smoke
  Scenario: Login page is accessible
    Given the login page is open
    Then the login form should be visible

  Scenario: SQL injection authentication bypass
    Given the login page is open
    When a SQL injection payload is submitted to the login form
    Then authentication should be bypassed

  Scenario: Session cookies carry security flags
    Given a session is established through the login form
    When the session cookies are audited
    Then all cookies should have Secure and HttpOnly flags