# خصائص سريعة — 5 دقائق لكل واحدة

## الحالة الحقيقية للكود الآن:
- attack_chains موجودة في RiskBreakdown لكن **غير مُرسَلة** في response
- cisa_kev_findings موجودة في RiskBreakdown لكن **غير مُرسَلة** في response  
- scan_duration غير موجودة أبداً
- change_log في fix_config يُرسَل فقط كـ header عدد وليس كـ JSON
- confidence موجودة في response لكن غير ظاهرة في الـ frontend

---

## الخاصية 1 — scan_duration (وقت الفحص)
**أين:** `app.py` — دالة `start_scan()`  
**التعديل:**

```python
# قبل try: اضف هذا السطر
import time
scan_start_time = time.perf_counter()

# بعد result = run_server_config_scan(tmp_path) وكل result الأخرى، وقبل calculate_risk_v2:
scan_duration_seconds = round(time.perf_counter() - scan_start_time, 2)

# في الـ return jsonify أضف:
"scan_duration_seconds": scan_duration_seconds,
```

**في `server_int.py`:** أضف `scan_duration_seconds` لـ `to_dict()`:
```python
"scan_duration_seconds": 0,  # يُملأ من app.py
```

**لماذا مفيد:** يُظهر للمستخدم مدة الفحص. للـ server_int عادة أقل من ثانية — وهذا يُثبت للجنة أن الـ static analysis سريع جداً مقارنة بـ DAST (دقائق).

---

## الخاصية 2 — attack_chains في الـ response (موجودة في الكود وغير مُرسَلة)
**أين:** `app.py` — دالة `start_scan()` — في `result["risk_breakdown"]`  
**التعديل — سطر واحد فقط:**

```python
# في result["risk_breakdown"] أضف:
result["risk_breakdown"] = {
    "base_score":       breakdown.base_score,
    "temporal_score":   breakdown.temporal_score,
    "env_score":        breakdown.env_score,
    "final_score":      breakdown.final_score,
    "risk_level":       breakdown.risk_level,
    "confidence":       breakdown.confidence,
    "recommendations":  breakdown.recommendations,
    "attack_chains":    breakdown.attack_chains,        # ← هذا السطر فقط
    "cisa_kev_findings": breakdown.cisa_kev_findings,  # ← وهذا
}
```

**وفي return jsonify أضف:**
```python
"attack_chains":      breakdown.attack_chains,
"cisa_kev_findings":  breakdown.cisa_kev_findings,
```

**لماذا مفيد:** attack_chains يكشف مسارات الهجوم المركّبة (XSS بدون CSP، SQLi، RCE). هذا أقوى ما في الـ risk engine ولا يظهر للمستخدم الآن.

---

## الخاصية 3 — change_log كـ JSON في fix_config (بدل header فقط)
**أين:** `app.py` — route `/fix_config` و `/start-scan` عند server_int  
**الحالة الآن:** `change_log` موجود لكن يُرسَل فقط كـ header: `"X-Changes-Count": str(len(change_log))`  
**التعديل:**

```python
# بدل Response(fixed_content, ...) أرجع JSON:
return jsonify({
    "fixed_config":  fixed_content,
    "change_log":    change_log,          # قائمة التعديلات
    "changes_count": len(change_log),
    "filename":      "httpd_securax_fixed.conf",
})
```

**لماذا مفيد:** الـ frontend يمكنه الآن يعرض جدول "ما الذي تغيّر" — before/after لكل سطر. هذا يُثبت للجنة أن الـ remediation engine شفاف وقابل للمراجعة.

---

## الخاصية 4 — severity_summary في نتيجة server_int
**أين:** `server_int.py` — دالة `to_dict()`  
**التعديل — في `ConfigScanResult.to_dict()`:**

```python
def to_dict(self) -> dict:
    # أضف هذا الحساب:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in self.vulnerabilities:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    for f in self.info:
        sev_counts["info"] += 1

    return {
        "scan_type":       "server_config",
        "config_file":     self.config_file,
        "server_type":     self.server_type if hasattr(self, "server_type") else "apache",
        "apache_version":  self.apache_version,
        "scanned_at":      self.scanned_at,
        "total_lines":     self.total_lines,
        "severity_summary": sev_counts,        # ← جديد
        "checks_run":      32,                 # ← جديد
        "vulnerabilities": [...],
        "info":            [...],
        "error":           self.error,
    }
```

**لماذا مفيد:** يعطي dashboard فوري — Critical: 2, High: 5, Medium: 8... بدون أن يعدّ الـ frontend يدوياً.

---

## الخاصية 5 — server_type في ConfigScanResult
**أين:** `server_int.py` — `ConfigScanResult` + `run_server_config_scan()`  
**التعديل:**

```python
# في ConfigScanResult dataclass أضف حقل:
server_type: str = "apache"   # "apache" أو "nginx"

# في run_server_config_scan() بعد detect:
result.server_type = config_type  # "apache" أو "nginx"

# في _scan_nginx_config() أضف:
result.server_type = "nginx"
```

**لماذا مفيد:** الـ frontend والـ report يمكنهما يعرضان "Apache Audit" أو "Nginx Audit" بدل اسم الملف فقط.


