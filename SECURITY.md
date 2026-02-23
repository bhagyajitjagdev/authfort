# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AuthFort, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Go to the [Security Advisories](https://github.com/bhagyajitjagdev/authfort/security/advisories) page
2. Click **"Report a vulnerability"**
3. Provide a description of the vulnerability, steps to reproduce, and potential impact

### What to Expect

- **Acknowledgment** within 48 hours
- **Status update** within 7 days
- A fix will be developed privately and released as a patch version
- You will be credited in the release notes (unless you prefer otherwise)

### Scope

The following are in scope:

- Authentication bypasses
- Token forgery or manipulation
- Session fixation or hijacking
- OAuth flow vulnerabilities
- SQL injection or other injection attacks
- Sensitive data exposure

### Out of Scope

- Denial of service (rate limiting is the developer's responsibility)
- Vulnerabilities in dependencies (report these to the upstream project)
- Issues requiring physical access to the server

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.x   | Yes       |
