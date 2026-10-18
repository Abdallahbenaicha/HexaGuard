# forms.py
"""
Flask-WTF forms with input validation.
"""

import os
import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileSize
from wtforms import BooleanField, PasswordField, RadioField, StringField
from wtforms.validators import AnyOf, DataRequired, Length, ValidationError


class LoginForm(FlaskForm):
    username = StringField(
        "اسم المستخدم",
        validators=[
            DataRequired(message="اسم المستخدم مطلوب."),
            Length(min=2, max=80, message="اسم المستخدم بين 2 و 80 حرفاً."),
        ],
    )
    password = PasswordField(
        "كلمة المرور",
        validators=[DataRequired(message="كلمة المرور مطلوبة.")],
    )


class TOTPForm(FlaskForm):
    token = StringField(
        "رمز المصادقة",
        validators=[
            DataRequired(message="رمز المصادقة مطلوب."),
            Length(min=6, max=8, message="رمز المصادقة 6 أرقام."),
        ],
    )


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "كلمة المرور الحالية",
        validators=[DataRequired(message="كلمة المرور الحالية مطلوبة.")],
    )
    new_password = PasswordField(
        "كلمة المرور الجديدة",
        validators=[
            DataRequired(message="كلمة المرور الجديدة مطلوبة."),
            Length(min=10, message="كلمة المرور على الأقل 10 أحرف."),
        ],
    )


_COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "data", "common_passwords.txt")
_COMMON_PASSWORDS_SET: set[str] = set()


def _load_common_passwords() -> set[str]:
    global _COMMON_PASSWORDS_SET
    if not _COMMON_PASSWORDS_SET:
        fallback = {
            "password123!", "password1234!", "password!", "admin@2024!", "analyst@2024!",
            "qwerty1234!", "qwerty123!", "welcome123!", "changeme123!", "iloveyou123!",
            "administrator", "adminadmin1!", "securax123!", "hexaguard123!",
            "welcome2024!", "summer2024!!", "abcd1234!@#$", "password1!", "admin1234567!@",
        }
        if os.path.exists(_COMMON_PASSWORDS_FILE):
            try:
                with open(_COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
                    _COMMON_PASSWORDS_SET = {line.strip().lower() for line in f if line.strip()}
            except Exception:
                _COMMON_PASSWORDS_SET = fallback
        else:
            _COMMON_PASSWORDS_SET = fallback
    return _COMMON_PASSWORDS_SET


_COMMON_PATTERN = re.compile(
    r"^(?:password|welcome|summer|winter|spring|autumn|qwerty|admin|abcd|1234|pass|user)[@#$0-9!~*_\-+=]+$",
    re.IGNORECASE,
)


def check_password_complexity(password: str, username: str = "") -> tuple[bool, str]:
    if len(password) < 12:
        return False, "كلمة المرور يجب أن تكون 12 أحرف على الأقل."
    if not re.search(r"[A-Z]", password):
        return False, "يجب أن تحتوي على حرف كبير (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "يجب أن تحتوي على حرف صغير (a-z)."
    if not re.search(r"\d", password):
        return False, "يجب أن تحتوي على رقم."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password):
        return False, "يجب أن تحتوي على رمز خاص مثل (!@#$%^&*)."

    lower_pw = password.lower()
    common_set = _load_common_passwords()
    if lower_pw in common_set:
        return False, "كلمة المرور شائعة وسهلة التخمين، يرجى اختيار كلمة مرور أكثر تعقيداً."

    if _COMMON_PATTERN.match(lower_pw):
        return False, "كلمة المرور شائعة وسهلة التخمين (نمط كلمات شائعة مع أرقام ورموز)، يرجى اختيار كلمة مرور أكثر تعقيداً."

    if any(root in lower_pw for root in ("password", "qwerty", "123456", "admin123")):
        return False, "كلمة المرور تحتوي على كلمات أو تسلسلات محظورة شائعة."

    if username and len(username) >= 3 and username.lower() in lower_pw:
        return False, "كلمة المرور لا يمكن أن تحتوي على اسم المستخدم."

    if re.search(r"(.)\1{3,}", password):
        return False, "كلمة المرور تحتوي على أحرف متكررة بشكل مفرط."

    return True, ""


def validate_target_value(form, field):
    value = (field.data or "").strip()

    scan_type = getattr(form, "scan_type", None)
    scan_val  = getattr(scan_type, "data", None) if scan_type else None
    if scan_val in ("dependencies", "server_int", "sast"):
        return

    cleaned = re.sub(r"^https?://", "", value)
    cleaned = cleaned.split("/")[0].split("?")[0]

    domain_regex = re.compile(r"^(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})(:\d+)?$")
    ip_regex     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

    if not (domain_regex.match(cleaned) or ip_regex.match(cleaned)):
        raise ValidationError("أدخل نطاقاً صالحاً (example.com) أو عنوان IP (192.168.1.1)")

    if ip_regex.match(cleaned):
        ip_part = cleaned.split(":")[0]
        if any(int(p) > 255 for p in ip_part.split(".")):
            raise ValidationError("عنوان IP غير صالح.")


class ScanForm(FlaskForm):
    target = StringField(
        "الهدف",
        validators=[
            DataRequired(message="الهدف مطلوب."),
            Length(min=4, max=253, message="الهدف بين 4 و 253 حرفاً."),
            validate_target_value,
        ],
    )
    scan_type = RadioField(
        "نوع الفحص",
        choices=[
            ("network_ext",  "فحص شبكات خارجي"),
            ("network_int",  "فحص شبكات داخلي"),
            ("web",          "فحص تطبيق ويب"),
            ("server_ext",   "فحص سيرفر خارجي"),
            ("server_int",   "فحص سيرفر داخلي"),
            ("dependencies", "فحص التبعيات"),
            ("sast",         "فحص SAST (كود مصدري ZIP)"),
            ("dast",         "فحص DAST (تطبيق ويب حي)"),
        ],
        default="network_ext",
        validators=[
            AnyOf(
                ["network_ext","network_int","web","server_ext","server_int",
                 "dependencies","sast","dast"],
                message="نوع فحص غير مدعوم.",
            )
        ],
    )
    criticality = RadioField(
        "مستوى الحساسية",
        choices=[("1","إنتاج حرج"),("0.6","نظام داخلي"),("0.3","بيئة اختبار")],
        default="1",
        validators=[AnyOf(["1","0.6","0.3"], message="قيمة criticality غير صالحة.")],
    )
    deep_scan        = BooleanField("فحص عميق",    default=False)
    cve_check        = BooleanField("فحص CVE",      default=True)
    ssl_check        = BooleanField("فحص SSL/TLS",  default=True)
    pdf_report       = BooleanField("تقرير PDF",     default=False)
    has_pii          = BooleanField("يحتوي على بيانات شخصية (GDPR)", default=False)
    has_payment      = BooleanField("يعالج بيانات دفع (PCI-DSS)",    default=False)
    exploit_known    = BooleanField("يوجد exploit عام معروف",         default=False)
    legal_disclaimer = BooleanField(
        "أتحمّل المسؤولية القانونية وأُقرّ بأنني مُخوَّل لفحص هذا الهدف",
        default=False,
    )
    config_file = FileField(
        "ملف الفحص (httpd.conf أو requirements.txt أو package.json)",
        validators=[
            FileAllowed(["conf","txt","json","toml"], "يُقبل فقط .conf، .txt، .json، .toml"),
            FileSize(max_size=2 * 1024 * 1024, message="حجم الملف لا يتجاوز 2MB"),
        ],
    )
    source_file = FileField(
        "ملف الكود المصدري (.zip)",
        validators=[
            FileAllowed(["zip"], "يُقبل فقط .zip"),
            FileSize(max_size=20 * 1024 * 1024, message="حجم ملف ZIP لا يتجاوز 20MB"),
        ],
    )
