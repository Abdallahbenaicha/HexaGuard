# Security Policy

## Overview

SecuraX practices what it preaches. This document defines how vulnerabilities
in SecuraX itself are reported, triaged, and remediated.

## Supported Versions

| Version | Security Support |
|---------|-----------------|
| 2.x     | ✅ Active        |
| 1.x     | ⚠️ Critical patches only |
| < 1.0   | ❌ End-of-life   |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately to: **innovation.team.dz@gmail.com**

### What to include

- A description of the vulnerability (CWE category if known)
- Step-by-step reproduction instructions
- Affected endpoint(s) or component(s)
- Estimated severity (CVSS v3.1 score if possible)
- Proof-of-concept code or screenshots (if safe to share)

### Our commitments

| Timeline | Action |
|----------|--------|
| **72 hours** | Initial acknowledgement |
| **14 days** | Patch for Critical (CVSS ≥ 9.0) and High (CVSS ≥ 7.0) |
| **30 days** | Patch for Medium (CVSS 4.0–6.9) |
| **90 days** | Patch for Low (CVSS < 4.0) |

We follow responsible disclosure: we will coordinate with you on a public
disclosure timeline after a patch is released.

## Security Architecture

The following controls are implemented in the current release:

| Layer | Implementation |
|-------|---------------|
| **CSRF Protection** | Flask-WTF CSRF token on every state-changing request |
| **Rate Limiting** | Per-user, per-endpoint — login: 10/min · scans: 5/min · AI: 20/hr |
| **Password Storage** | bcrypt (12 rounds) + per-user salt |
| **2FA / TOTP** | RFC 6238 via `pyotp` — QR code setup, per-user enable/disable |
| **Session Security** | HttpOnly · SameSite · Secure (prod) · 30-minute idle timeout |
| **Security Headers** | CSP · HSTS · X-Frame-Options: DENY · X-Content-Type-Options · Referrer-Policy |
| **RBAC** | Admin / Analyst / Viewer + `@require_permission()` on every endpoint |
| **IDOR Prevention** | Every report access verifies `user_id == current_user.id` |
| **Target Locking** | Analysts restricted to admin-approved scan targets |
| **Account Lockout** | 5 failed attempts → 15-minute lockout; constant-time bcrypt comparison |
| **Audit Trail** | IP + user-agent logged for every login, scan, report view, admin action |
| **Input Validation** | URL sanitisation · extension blocklist · ZIP bomb guard (150 MB limit) |

## Known Limitations

- The platform does not yet support hardware security keys (FIDO2/WebAuthn).
- Session tokens are stored in signed cookies, not a server-side session store.
  Redis-backed sessions are on the roadmap.
- The dependency scanner relies on the OSV.dev public API; offline operation
  is not yet supported for CVE lookups.

## Security Standards Followed

- [OWASP Secure Coding Guidelines](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) Level 2

## Scope

This policy covers vulnerabilities in:
- `backend/` — Flask API, risk engine, scanner modules, authentication
- `frontend/` — React SPA
- `docker/` and deployment configuration

This policy does **not** cover:
- Vulnerabilities in third-party scanners invoked by SecuraX (ZAP, Nmap, Bandit, etc.)
- Bugs in findings produced *by* SecuraX about *target systems*
- Social engineering or phishing attacks
