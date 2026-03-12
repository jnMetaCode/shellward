# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in ClawGuard, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **ialanhacker@gmail.com**

Or use [GitHub Security Advisories](https://github.com/jnMetaCode/clawguard/security/advisories/new) to report privately.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **24 hours**: Acknowledgment of your report
- **72 hours**: Initial assessment and severity classification
- **7 days**: Fix development for critical/high severity issues
- **14 days**: Fix development for medium/low severity issues

### Recognition

We credit all reporters in our CHANGELOG (unless you prefer to remain anonymous).

## Security Measures

ClawGuard itself is a security tool. We hold ourselves to a high standard:

- Zero external dependencies (reduced supply chain risk)
- All regex patterns reviewed for ReDoS resistance
- Audit log permissions restricted to owner-only (0600)
- No network calls — all detection is local
