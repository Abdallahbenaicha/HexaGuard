# SecuraX — Threat Model

> **Version**: 1.0.0 | **Last updated**: 2026-07-30  
> **Methodology**: STRIDE (Microsoft) + OWASP Application Threat Modeling

---

## 1. Assumptions

The following assumptions bound this threat model. If any assumption is violated,
the threat model must be revisited.

| ID | Assumption |
|----|-----------|
| A1 | SecuraX is deployed by a security team with legitimate authorisation to scan the targets they configure. |
| A2 | The backend API is not directly exposed to the public internet without authentication. |
| A3 | Scan targets are in scope per a written authorisation agreement or internal policy. |
| A4 | The SecuraX database (SQLite / PostgreSQL) is stored on a server with OS-level access controls. |
| A5 | Users are assigned roles (admin / analyst / viewer) and access is enforced by the backend. |
| A6 | TLS is used for all production traffic between frontend and backend. |
| A7 | API keys (Gemini, NVD) are stored in environment variables, not in code or the database. |

---

## 2. Assets

Assets are ordered by business impact (highest first).

| Asset ID | Asset | Description | Confidentiality | Integrity | Availability |
|----------|-------|-------------|-----------------|-----------|--------------|
| AS-01 | Scan Results Database | All vulnerability findings, risk scores, remediation guidance | **High** | **High** | Medium |
| AS-02 | User Credentials | Admin and analyst account hashes | **High** | **High** | Medium |
| AS-03 | Target Configuration | URLs, IPs, credentials of scanned systems | **High** | High | Low |
| AS-04 | AI Agent (ARIA) API Key | Gemini 1.5 Flash API key | High | Medium | Low |
| AS-05 | NVD API Key | NIST vulnerability feed access | Medium | Medium | Low |
| AS-06 | Risk Engine Logic | The scoring algorithm (competitive advantage) | Medium | **High** | Medium |
| AS-07 | Session Tokens | Active user sessions | **High** | High | Low |
| AS-08 | Research Datasets | Ground truth files in datasets/ | Medium | **High** | Medium |

---

## 3. Threat Actors

| Actor | Motivation | Capability | Likelihood |
|-------|-----------|-----------|-----------|
| External attacker (opportunistic) | Data theft, disruption | Low-Medium | Medium |
| Malicious insider (analyst) | Exfiltrate scan data | Medium | Low |
| Compromised scan target | Exploit scanning activity | Medium | Low |
| Automated bot | Credential brute force | Low | High |
| Researcher (accidental) | Unintended data exposure | Low | Low |

---

## 4. Trust Boundaries

```
┌────────────────────────────────────────────────────────────────┐
│  INTERNET (untrusted)                                          │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  BROWSER (semi-trusted — authenticated user)             │  │
│  │                                                          │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  BACKEND API (trusted — auth enforced)             │  │  │
│  │  │                                                    │  │  │
│  │  │  ┌──────────────────────────────────────────────┐  │  │  │
│  │  │  │  DATABASE (highly trusted — OS access only)  │  │  │  │
│  │  │  └──────────────────────────────────────────────┘  │  │  │
│  │  │                                                    │  │  │
│  │  │  ┌──────────────────────────────────────────────┐  │  │  │
│  │  │  │  SCAN TARGETS (untrusted — adversarial)      │  │  │  │
│  │  │  └──────────────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

**Key Trust Crossings**:
1. Browser → Backend API: Cookie-based session + CSRF token required
2. Backend → Scan Target: Unvalidated responses must be sanitised before storage
3. Backend → External APIs (Gemini, NVD, CISA KEV): HTTPS only, keys in env vars
4. Scan Target → Backend: Scanner output is untrusted input — normalised via SDK schema

---

## 5. Attack Surface

### 5.1 — Authentication Endpoints

| Endpoint | Method | Risk | Controls |
|----------|--------|------|---------|
| `/auth/login` | POST | Brute force, credential stuffing | Rate limiting, bcrypt hashing |
| `/auth/register` | POST | Mass registration, spam | Admin-only in production |
| `/auth/logout` | POST | Session fixation | Server-side session invalidation |

### 5.2 — Scan Management

| Endpoint | Method | Risk | Controls |
|----------|--------|------|---------|
| `/scans/new` | POST | SSRF via target URL | URL validation, private IP blocklist |
| `/scans/<id>/results` | GET | IDOR — access other users' results | User-scoped query |
| `/reports/<id>` | GET | Information disclosure | Auth required, ownership check |

### 5.3 — AI Agent (ARIA)

| Endpoint | Method | Risk | Controls |
|----------|--------|------|---------|
| `/ai/analyze` | POST | Prompt injection, cost attack | Input sanitisation, rate limiting |
| `/ai/chat` | POST | Context leakage between users | Session isolation |

### 5.4 — Scanner Inputs (Most Critical Surface)

The scanner engines receive **untrusted data from scan targets**:

- **HTTP responses** from web targets may contain adversarial content (e.g. `<script>`, `'; DROP TABLE`)
- **SSL certificates** from targets may contain malformed fields
- **File uploads** sent to SAST targets may contain malicious filenames
- **Network packets** from targets may trigger scanner parsing bugs

**Mitigation**: All scanner output passes through the `normalize()` step (SDK) before
storage. The schema validates severity, check name, and evidence fields.

### 5.5 — Research Datasets

| Risk | Description | Mitigation |
|------|-------------|-----------|
| Ground truth tampering | Modifying `ground_truth.json` invalidates results | SHA-256 manifest + git history |
| Dataset poisoning | Injecting mislabelled entries | Expert review + provenance documentation |
| Version confusion | Running wrong dataset version | Manifest `VERSION` field in all results |

---

## 6. STRIDE Analysis

### Spoofing
| Threat | Asset | Control |
|--------|-------|---------|
| Session token forgery | AS-07 | HttpOnly cookie, secure flag, CSRF token |
| JWT algorithm confusion | AS-02 | Explicit algorithm whitelist (HS256 only) |

### Tampering
| Threat | Asset | Control |
|--------|-------|---------|
| Risk score manipulation via API | AS-01 | Input validation, parameterised SQL |
| Ground truth tampering | AS-08 | SHA-256 manifest verification |

### Repudiation
| Threat | Asset | Control |
|--------|-------|---------|
| Unauthenticated scan initiation | AS-03 | All endpoints require auth token |
| Deleted audit logs | Audit trail | Append-only audit table |

### Information Disclosure
| Threat | Asset | Control |
|--------|-------|---------|
| IDOR on scan results | AS-01 | User-scoped DB queries |
| Error message leakage | All | Generic error messages in production |
| API key in logs | AS-04, AS-05 | Log redaction middleware |

### Denial of Service
| Threat | Asset | Control |
|--------|-------|---------|
| Scan flood (many expensive scans) | Backend | Rate limiting, job queue |
| ARIA cost attack | AS-04 | Per-user token budget |

### Elevation of Privilege
| Threat | Asset | Control |
|--------|-------|---------|
| Analyst → Admin escalation | AS-02 | Role checked on every protected endpoint |
| SSRF via scan target | Backend | Private IP blocklist in scanner |

---

## 7. Out of Scope

The following are explicitly **out of scope** for this threat model:

1. **Physical security** of the server running SecuraX
2. **Supply chain attacks** on Python dependencies (mitigated by `pip-audit` in CI)
3. **Side-channel attacks** on the risk engine algorithm
4. **Social engineering** of SecuraX administrators
5. **Vulnerabilities in scan targets** — SecuraX detects these but does not exploit them

---

## 8. Residual Risks

| Risk | Likelihood | Impact | Accepted? | Rationale |
|------|-----------|--------|----------|-----------|
| SSRF via webhook URL | Low | High | Yes | URL blocklist implemented; real-world SSRF requires bypass |
| Prompt injection in ARIA | Medium | Medium | Yes | ARIA output is advisory only, not executed |
| Scanner DoS via malformed target | Low | Low | Yes | Timeout and exception handling in all scanners |

---

## 9. References

- [STRIDE] Shostack, A. "Threat Modeling: Designing for Security." Wiley, 2014.
- [OWASP-TM] OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- [NIST-SP800-30] NIST. "Guide for Conducting Risk Assessments (SP 800-30 Rev. 1)." 2012.
- [FAIR] The Open Group. "Factor Analysis of Information Risk (FAIR)." 2009.
