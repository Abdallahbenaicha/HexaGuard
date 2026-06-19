# Class Diagram الصحيح — مبني 100% على الكود الفعلي

## ما يجب حذفه أو تصحيحه من الدياغرام القديم

| الدياغرام القديم | الحقيقة في الكود | القرار |
|---|---|---|
| `class ARIA` | تحذفه أنت — موافق | ✅ محذوف |
| `User.email` | غير موجود في الكود أبداً | ❌ احذفه |
| `User.created_at` | موجود في DB لكن **ليس في User class** | ❌ احذفه من الـ class |
| `RiskBreakdown` غير موجودة | موجودة وأساسية | ✅ أضفها |
| `ConfigFinding` غير موجودة | موجودة في server_int.py | ✅ أضفها |
| `ConfigScanResult` غير موجودة | موجودة في server_int.py | ✅ أضفها |
| `Severity` enum غير موجودة | موجودة | ✅ أضفها |
| علاقة User→ScanReport في الكود | User لا يرى ScanReport مباشرة — يمر عبر database.py | ⚠️ صحح العلاقة |

---

## الدياغرام الصحيح — جاهز للصق في Mermaid

```mermaid
classDiagram

%% ═══════════════════════════════
%%  models.py
%% ═══════════════════════════════

class UserMixin {
    <<Flask-Login>>
}

class User {
    +int id
    +str username
    -str _pass_hash
    +str role
    -set _permissions
    +Optional~str~ totp_secret
    +bool totp_enabled
    +int failed_attempts
    +Optional~str~ locked_until
    +bool _is_active
    +Optional~str~ last_login
    +int login_count
    +check_password(password: str) bool
    +has_permission(permission: str) bool
    +verify_totp(token: str) bool
    +is_active() bool
    +is_admin() bool
    +is_locked() bool
    +lock_seconds_remaining() int
}

class AuthHelpers {
    <<module: models.py>>
    +authenticate_user(username, password) tuple
    +load_user_from_db(user_id) User|None
    -_row_to_user(row: dict) User
}

User --|> UserMixin
AuthHelpers ..> User : creates

%% ═══════════════════════════════
%%  risk_engine.py
%% ═══════════════════════════════

class RiskBreakdown {
    <<dataclass>>
    +float raw_score
    +float base_score
    +float temporal_score
    +float env_score
    +float final_score
    +str risk_level
    +float confidence
    +dict severity_counts
    +str highest_sev
    +list top_findings
    +list~str~ recommendations
    +list~str~ attack_chains
    +list~str~ cisa_kev_findings
}

class RiskEngine {
    <<module: risk_engine.py>>
    +calculate_risk_v2(scan_result, criticality, exploit_known, internet_facing, has_pii, has_payment) RiskBreakdown
    -_detect_attack_chains(vulns, internet_facing) list~str~
    -get_kev_set() frozenset
    -_kev_background_worker() None
}

RiskEngine ..> RiskBreakdown : returns

%% ═══════════════════════════════
%%  scanners/server_int.py
%% ═══════════════════════════════

class Severity {
    <<Enum + str>>
    CRITICAL
    HIGH
    MEDIUM
    LOW
    INFO
}

class ConfigFinding {
    <<dataclass>>
    +str check
    +Severity severity
    +str title
    +str description
    +str evidence
    +str remediation
    +int line_number
    +str fixed_directive
}

class ConfigScanResult {
    <<dataclass>>
    +str config_file
    +str apache_version
    +str scanned_at
    +list~ConfigFinding~ vulnerabilities
    +list~ConfigFinding~ info
    +Optional~str~ error
    +int total_lines
    +to_dict() dict
}

class ServerConfigEngine {
    <<module: server_int.py — 2339 lines>>
    +run_server_config_scan(config_path: str) dict
    +generate_fixed_config(original: str, vulns: list) tuple
    -_detect_config_type(content: str) str
    -_parse_config(content: str) list~tuple~
    -_get_directive_value(parsed, name) tuple|None
    -_get_all_directive_values(parsed, name) list
    -_check_server_tokens(parsed) list~ConfigFinding~
    -_check_server_signature(parsed) list~ConfigFinding~
    -_check_directory_listing(parsed) list~ConfigFinding~
    -_check_follow_symlinks(parsed) list~ConfigFinding~
    -_check_ssl_settings(parsed) list~ConfigFinding~
    -_check_dangerous_modules(parsed) list~ConfigFinding~
    -_check_trace_method(parsed) list~ConfigFinding~
    -_check_access_control(parsed) list~ConfigFinding~
    -_check_security_headers(parsed, raw) list~ConfigFinding~
    -_check_limit_request_body(parsed) list~ConfigFinding~
    -_check_allow_override(parsed) list~ConfigFinding~
    -_check_exec_cgi(parsed) list~ConfigFinding~
    -_check_mod_security(parsed, raw) list~ConfigFinding~
    -_check_mpm_mode(content) list~ConfigFinding~
    -_check_mod_rewrite_security(content) list~ConfigFinding~
    -_scan_nginx_config(path, content, result) dict
    -_apply_options_fix(line, check) str
}

ConfigFinding --> Severity : uses
ConfigScanResult "1" --> "0..*" ConfigFinding : contains
ServerConfigEngine ..> ConfigScanResult : builds
ServerConfigEngine ..> ConfigFinding : produces

%% ═══════════════════════════════
%%  database.py
%% ═══════════════════════════════

class Database {
    <<module: database.py — thread-local SQLite WAL>>
    +init_db() None
    +get_user_by_username(username) dict|None
    +get_user_by_id(user_id) dict|None
    +get_all_users(page, per_page) list
    +create_user(username, password, role, permissions, created_by) tuple
    +update_user(uid, **kwargs) tuple
    +update_last_login(user_id) None
    +update_user_totp(user_id, secret, enabled) tuple
    +store_report(result, risk_score, original_content, user_id, username) str
    +get_report(token) dict|None
    +get_user_reports(user_id, limit) list
    +get_all_reports(limit, **filters) list
    +get_dashboard_stats(user_id) dict
    +get_system_stats() dict
    +log_event(action, username, **kwargs) None
    +get_audit_log(**filters) tuple
}

Database ..> User : hydrates via _row_to_user
AuthHelpers ..> Database : calls get_user_by_username

%% ═══════════════════════════════
%%  app.py — orchestration
%% ═══════════════════════════════

class FlaskApp {
    <<app.py — orchestrator>>
    +start_scan() Response
    +fix_config_bridge() Response
    +api_login() Response
    +api_register() Response
    +api_totp_verify() Response
    +download_report_pdf() Response
    +download_report_csv() Response
    +platform_stats() Response
}

FlaskApp ..> ServerConfigEngine : calls run_server_config_scan
FlaskApp ..> RiskEngine : calls calculate_risk_v2
FlaskApp ..> Database : calls store_report / log_event
FlaskApp ..> AuthHelpers : calls authenticate_user
```

---

## الفروق الجوهرية عن الدياغرام القديم

### 1. User — ما تغيّر
**يُحذف:** `email`, `created_at`  
**يُضاف:** `login_count`, `last_login`, `failed_attempts`, `locked_until`, `totp_secret`, `totp_enabled`  
**يُصحَّح:** `_pass_hash` private (بشرطة سفلية) — `_permissions` private كـ `set` لا `list`  
**يُضاف:** methods `verify_totp()`, `is_locked()`, `lock_seconds_remaining()`

### 2. يُضاف بالكامل
- `RiskBreakdown` dataclass — قلب نظام التقييم
- `ConfigFinding` + `ConfigScanResult` + `Severity` — نظام server_int
- `ServerConfigEngine` — 15+ method الحقيقية
- `Database` module — كل دوال الـ persistence
- `FlaskApp` orchestrator — يوضح كيف ترتبط الكلاسات

### 3. العلاقات الصحيحة
- `User` لا يتصل بـ `ScanReport` مباشرة — `Database.store_report()` تربطهما
- `ServerConfigEngine` تُنتج `ConfigFinding` وليس `Vulnerability` مباشرة
- `RiskEngine` تأخذ dict وترجع `RiskBreakdown` — لا تعرف شيئاً عن `User`

