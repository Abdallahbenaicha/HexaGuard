"""SecurAx — authentication blueprint.

Handles both Flask HTML routes (Jinja2 templates) and the JSON API consumed
by the React frontend. All auth logic lives here; the app factory only
registers this blueprint.
"""

import base64
import io
import logging
import re

import bcrypt
import pyotp
import qrcode

from flask import (
    Blueprint, flash, jsonify, redirect, render_template,
    request, session, url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from database import (
    create_user, get_user_by_id, log_event,
    update_last_login, update_user, update_user_totp,
)
from extensions import limiter
from forms import ChangePasswordForm, LoginForm, TOTPForm, check_password_complexity
from models import authenticate_user

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)


# ════════════════════════════════════════════════════════════════════════════
#  HTML AUTH ROUTES  (served via Flask/Jinja2 templates)
# ════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("reports.home"))

    form = LoginForm()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, err, _lock_secs = authenticate_user(username, password)

        if user:
            if user.totp_enabled:
                session["pending_totp_user_id"] = user.id
                log_event("totp_required", username, user.id,
                          category="auth", ip_address=request.remote_addr, status="pending")
                return redirect(url_for("auth.verify_totp"))

            login_user(user, remember=False)
            update_last_login(user.id)
            log_event("login_success", username, user.id,
                      category="auth", ip_address=request.remote_addr,
                      user_agent=request.user_agent.string)
            logger.info("login | user=%s | ip=%s", username, request.remote_addr)

            next_page = request.args.get("next", "")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("reports.home"))

        log_event("login_failed", username, category="auth",
                  ip_address=request.remote_addr, status="failed", details=err)
        logger.warning("login failed | user=%s | ip=%s", username, request.remote_addr)
        flash(err or "اسم المستخدم أو كلمة المرور غير صحيحة.")

    return render_template("login.html", form=form)


@auth_bp.route("/verify-totp", methods=["GET", "POST"])
@limiter.limit("10/minute")
def verify_totp():
    pending_id = session.get("pending_totp_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    form = TOTPForm()
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        row   = get_user_by_id(pending_id)
        if row:
            from models import _row_to_user
            user = _row_to_user(row)
            if user.verify_totp(token):
                session.pop("pending_totp_user_id", None)
                login_user(user, remember=False)
                update_last_login(user.id)
                log_event("totp_verified", user.username, user.id,
                          category="auth", ip_address=request.remote_addr, status="success")
                return redirect(url_for("reports.home"))

        log_event("totp_failed", category="auth",
                  ip_address=request.remote_addr, status="failed")
        flash("رمز المصادقة غير صحيح.")

    return render_template("verify_totp.html", form=form)


@auth_bp.route("/setup-totp", methods=["GET", "POST"])
@login_required
def setup_totp():
    form = TOTPForm()
    if request.method == "GET":
        secret = pyotp.random_base32()
        session["totp_setup_secret"] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.username, issuer_name="SecurAx Security"
        )
        img    = qrcode.make(uri)
        buf    = io.BytesIO()
        img.save(buf, "PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_totp.html", form=form, qr_b64=qr_b64, secret=secret)

    secret = session.get("totp_setup_secret")
    token  = (request.form.get("token") or "").strip()
    if secret and pyotp.TOTP(secret).verify(token, valid_window=1):
        ok, msg = update_user_totp(current_user.id, secret, True)
        if ok:
            session.pop("totp_setup_secret", None)
            log_event("totp_enabled", current_user.username, current_user.id,
                      category="auth", ip_address=request.remote_addr)
            flash("تم تفعيل المصادقة الثنائية بنجاح.")
            return redirect(url_for("reports.home"))
        flash(msg)
    else:
        flash("رمز التحقق غير صحيح. حاول مرة أخرى.")

    return redirect(url_for("auth.setup_totp"))


@auth_bp.route("/disable-totp", methods=["POST"])
@login_required
def disable_totp():
    ok, msg = update_user_totp(current_user.id, "", False)
    log_event("totp_disabled", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr,
              status="success" if ok else "failed")
    flash(msg)
    return redirect(url_for("reports.home"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")

        row = get_user_by_id(current_user.id)
        if not row or not bcrypt.checkpw(current_pw.encode(), row["password_hash"].encode()):
            flash("كلمة المرور الحالية غير صحيحة.")
            return render_template("change_password.html", form=form)

        ok, msg = check_password_complexity(new_pw)
        if not ok:
            flash(msg)
            return render_template("change_password.html", form=form)

        update_user(current_user.id, new_password=new_pw)
        log_event("password_changed", current_user.username, current_user.id,
                  category="auth", ip_address=request.remote_addr)
        flash("تم تغيير كلمة المرور بنجاح.")
        return redirect(url_for("reports.home"))

    return render_template("change_password.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    log_event("logout", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr)
    logger.info("logout | user=%s", current_user.username)
    logout_user()
    return redirect(url_for("auth.login"))


# ════════════════════════════════════════════════════════════════════════════
#  JSON AUTH API  (consumed by the React SPA)
# ════════════════════════════════════════════════════════════════════════════

@auth_bp.route("/api/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    if current_user.is_authenticated:
        return jsonify({"ok": True, "user": {
            "username": current_user.username, "role": current_user.role,
        }})

    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400

    user, err, lock_secs = authenticate_user(username, password)
    if not user:
        log_event("login_failed", username, category="auth",
                  ip_address=request.remote_addr, status="failed", details=err)
        resp = {"ok": False, "error": err or "Invalid credentials."}
        if lock_secs:
            resp["lock_seconds_remaining"] = lock_secs
        return jsonify(resp), 401

    login_user(user, remember=False)
    update_last_login(user.id)
    log_event("login_success", username, user.id, category="auth",
              ip_address=request.remote_addr, user_agent=request.user_agent.string)
    return jsonify({
        "ok":   True,
        "user": {"username": user.username, "role": user.role, "id": user.id},
    })


@auth_bp.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    log_event("logout", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr)
    logout_user()
    return jsonify({"ok": True})


@auth_bp.route("/api/auth/me")
def api_me():
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "user": {
            "id":           current_user.id,
            "username":     current_user.username,
            "role":         current_user.role,
            "is_admin":     current_user.is_admin,
            "permissions":  list(current_user._permissions),
            "totp_enabled": current_user.totp_enabled,
            "is_active":    current_user.is_active,
            "last_login":   current_user.last_login,
            "login_count":  current_user.login_count,
        },
    })


@auth_bp.route("/api/auth/totp-verify", methods=["POST"])
@limiter.limit("10/minute")
def api_totp_verify():
    pending_id = session.get("pending_totp_user_id")
    if not pending_id:
        return jsonify({"ok": False, "error": "No pending TOTP session."}), 400

    data  = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token required."}), 400

    row = get_user_by_id(pending_id)
    if not row:
        session.pop("pending_totp_user_id", None)
        return jsonify({"ok": False, "error": "Session expired."}), 401

    from models import _row_to_user
    user = _row_to_user(row)
    if not user.verify_totp(token):
        log_event("totp_failed", category="auth",
                  ip_address=request.remote_addr, status="failed")
        return jsonify({"ok": False, "error": "Invalid TOTP code."}), 401

    session.pop("pending_totp_user_id", None)
    login_user(user, remember=False)
    update_last_login(user.id)
    log_event("totp_verified", user.username, user.id,
              category="auth", ip_address=request.remote_addr, status="success")
    return jsonify({
        "ok":   True,
        "user": {"username": user.username, "role": user.role, "id": user.id},
    })


@auth_bp.route("/api/auth/totp/setup", methods=["POST"])
@login_required
def api_totp_setup():
    secret = pyotp.random_base32()
    session["totp_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name="SecurAx Security"
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return jsonify({"secret": secret, "qr_b64": qr_b64})


@auth_bp.route("/api/auth/totp/enable", methods=["POST"])
@login_required
def api_totp_enable():
    data   = request.get_json(silent=True) or {}
    token  = (data.get("token") or "").strip()
    secret = session.get("totp_setup_secret")
    if not secret:
        return jsonify({"ok": False, "error": "No TOTP setup session found."}), 400
    if not token:
        return jsonify({"ok": False, "error": "Token required."}), 400
    if not pyotp.TOTP(secret).verify(token, valid_window=1):
        return jsonify({"ok": False, "error": "Invalid verification code."}), 400
    ok, msg = update_user_totp(current_user.id, secret, True)
    if ok:
        session.pop("totp_setup_secret", None)
        log_event("totp_enabled", current_user.username, current_user.id,
                  category="auth", ip_address=request.remote_addr)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)


@auth_bp.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    data       = request.get_json(silent=True) or {}
    current_pw = data.get("current_password", "")
    new_pw     = data.get("new_password", "")

    if not current_pw or not new_pw:
        return jsonify({"ok": False, "error": "current_password and new_password required."}), 400

    row = get_user_by_id(current_user.id)
    if not row or not bcrypt.checkpw(current_pw.encode("utf-8"), row["password_hash"].encode("utf-8")):
        return jsonify({"ok": False, "error": "Current password is incorrect."}), 400

    ok, msg = check_password_complexity(new_pw)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    uid      = current_user.id
    uname    = current_user.username
    update_user(uid, new_password=new_pw)
    logout_user()
    log_event("password_changed", uname, uid,
              category="auth", ip_address=request.remote_addr)
    return jsonify({"ok": True, "message": "Password changed. Please log in again.", "require_relogin": True})


@auth_bp.route("/api/auth/register", methods=["POST"])
@limiter.limit("5/minute")
def api_register():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({"ok": False, "error": "Username must be 3–32 characters."}), 400
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return jsonify({"ok": False, "error": "Username may only contain letters, digits, _ and -."}), 400

    ok, msg = check_password_complexity(password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    ok, msg = create_user(username, password, role="analyst",
                          created_by="self-registration", email=email or None)
    if not ok:
        status = 409 if "already exists" in msg else 500
        return jsonify({"ok": False, "error": msg}), status

    log_event("user_registered", username, category="auth",
              ip_address=request.remote_addr, status="success")
    logger.info("self-registration | user=%s | email=%s | ip=%s",
                username, email or "—", request.remote_addr)
    return jsonify({"ok": True, "message": "Account created. You can now log in."}), 201
