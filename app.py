"""
app.py — SecureAuth Platform — Elite Backend
"""

import os
import time
import json
import logging
from datetime import timedelta, datetime

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
import pyotp

# ── Database ───────────────────────────────────────────────────────
from database.db import (
    create_user_table, get_user, save_user,
    update_last_login, update_security_score,
    get_recent_security_events, log_security_event,
    lock_user, unlock_user
)

# ── OS Integration ─────────────────────────────────────────────────
from os_integration.os_utils import get_os_user, lock_host_system

# ── Security ───────────────────────────────────────────────────────
from security.validation import check_input
from security.attack_detection import (
    log_attack, detect_brute_force, reset_attempts, get_lockout_status
)
from security.roles import check_access, get_role_level, get_role_display, get_role_color
from security.c_bridge import (
    detect_attack_pattern, calculate_security_score, is_c_active
)

# ── Auth ───────────────────────────────────────────────────────────
from auth.login import login_user
from auth.register import register_user
from auth.otp import generate_otp, verify_otp, get_provisioning_uri
from auth.camera import capture_login_attempt

# ── Setup ──────────────────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_dev_key_change_me")
app.permanent_session_lifetime = timedelta(minutes=15)

# Initialise DB (creates tables + runs migrations)
create_user_table()

# Log C engine status
if is_c_active():
    logger.info("🚀 C Security Engine: ACTIVE (libsecurity.so)")
else:
    logger.warning("⚠ C Security Engine: INACTIVE (Python fallback active)")


# ── Helpers ────────────────────────────────────────────────────────

def _format_time_ago(timestamp: float) -> str:
    if not timestamp:
        return "Never"
    diff = time.time() - timestamp
    if diff < 60:
        return "Just now"
    elif diff < 3600:
        m = int(diff / 60)
        return f"{m} minute{'s' if m != 1 else ''} ago"
    elif diff < 86400:
        h = int(diff / 3600)
        return f"{h} hour{'s' if h != 1 else ''} ago"
    else:
        d = int(diff / 86400)
        return f"{d} day{'s' if d != 1 else ''} ago"


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _get_recent_logs_for_template(limit: int = 5):
    """Get last N security events for dashboard template."""
    events = get_recent_security_events(limit=limit)
    # Also try to read from file for compatibility
    file_logs = []
    try:
        with open("logs/attacks.log", "r") as f:
            lines = f.readlines()
            file_logs = [l.strip() for l in reversed(lines[-20:]) if l.strip()]
    except FileNotFoundError:
        pass

    if events:
        return [{
            "message": e["message"],
            "severity": e["severity"],
            "timestamp": datetime.utcfromtimestamp(e["timestamp"]).strftime("%H:%M:%S"),
            "event_type": e["event_type"]
        } for e in events]

    # Fallback to file
    return [{"message": l, "severity": "WARNING" if "ALERT" in l or "LOCKED" in l else "INFO",
             "timestamp": "", "event_type": "FILE_LOG"} for l in file_logs[:limit]]


# ═══════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    attack_warning = False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip       = _get_client_ip()

        # ── 1. Input Validation (C-powered) ───────────────────
        is_valid, reason = check_input({"username": username, "password": password})
        if not is_valid:
            # Check for actual attack patterns
            is_attack_u, flags_u, desc_u = detect_attack_pattern(username)
            is_attack_p, flags_p, desc_p = detect_attack_pattern(password)

            if is_attack_u or is_attack_p:
                desc = desc_u if is_attack_u else desc_p
                log_attack(
                    f"ATTACK DETECTED from {ip} on username '{username}': {desc}",
                    username=username,
                    severity="CRITICAL",
                    event_type="INJECTION_ATTEMPT",
                    flags=flags_u | flags_p
                )
                attack_warning = True
                return render_template("login.html",
                    error="⚠ Malicious pattern detected. Incident logged.",
                    attack_warning=True)

            log_attack(f"Invalid input from {ip} for '{username}': {reason}",
                       username=username, severity="WARNING", event_type="INVALID_INPUT")
            return render_template("login.html", error=f"Invalid input: {reason}")

        # ── 2. Brute-force / Lockout Check ────────────────────
        lockout = get_lockout_status(username)
        if lockout["is_locked"]:
            return render_template("login.html",
                error=f"Account locked. Try again in {lockout['mins_remaining']} minutes.",
                locked=True)

        # ── 3. Authenticate ────────────────────────────────────
        user = get_user(username)
        if login_user(username, password, user):
            reset_attempts(username)
            session['pending_user'] = username

            log_security_event(
                event_type="LOGIN_SUCCESS_STAGE1",
                message=f"Password verified for '{username}' from {ip}",
                username=username,
                severity="INFO"
            )

            # Biometric audit (camera, safe to ignore if no webcam)
            try:
                capture_login_attempt(username)
            except Exception:
                pass

            return redirect(url_for("otp_page"))
        else:
            log_attack(
                f"Failed login for '{username}' from {ip}",
                username=username,
                severity="WARNING",
                event_type="LOGIN_FAILED"
            )
            # Now detect_brute_force to increment counter
            detect_brute_force(username)
            error = "Invalid username or password."

    return render_template("login.html", error=error, attack_warning=attack_warning)


@app.route("/verify-otp", methods=["GET", "POST"])
def otp_page():
    if 'pending_user' not in session:
        return redirect(url_for("login"))

    username = session['pending_user']
    user     = get_user(username)
    error    = None

    current_otp = generate_otp(user['otp_secret'])
    print(f"\n{'═'*50}\n  OTP for [{username}]: {current_otp}\n{'═'*50}\n")

    if request.method == "POST":
        entered_otp = request.form.get("otp_code", "").strip()

        if verify_otp(user['otp_secret'], entered_otp):
            session.pop('pending_user', None)
            session.permanent = True
            session['logged_in_user'] = username

            # Update last login timestamp
            update_last_login(username)

            # Calculate and store security score
            role_level     = get_role_level(user)
            failed_attempts = 0
            score = calculate_security_score(
                has_otp=True,
                role_level=role_level,
                failed_attempts=failed_attempts,
                input_clean=True
            )
            update_security_score(username, score)

            log_security_event(
                event_type="LOGIN_COMPLETE",
                message=f"Full authentication complete for '{username}' (score={score})",
                username=username,
                severity="INFO"
            )

            return redirect(url_for("dashboard", username=username))
        else:
            log_attack(
                f"Invalid OTP attempt for '{username}'",
                username=username,
                severity="WARNING",
                event_type="OTP_FAILED"
            )
            error = "Invalid OTP code. Please try again."

    return render_template("otp.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role             = "user"

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

        is_valid, reason = check_input({"username": username, "password": password})
        if not is_valid:
            error = f"Invalid input: {reason}"
        else:
            existing_user = get_user(username)
            if existing_user:
                error = "Username already taken."
            else:
                try:
                    secure_user_data = register_user(username, password, role)
                    save_user(secure_user_data)

                    log_security_event(
                        event_type="USER_REGISTERED",
                        message=f"New user registered: '{username}'",
                        username=username,
                        severity="INFO"
                    )

                    qr_uri = get_provisioning_uri(secure_user_data["otp_secret"], username)
                    return render_template("setup_2fa.html",
                        qr_uri=qr_uri, secret=secure_user_data["otp_secret"])
                except ValueError as e:
                    error = str(e)

    return render_template("register.html", error=error)


@app.route("/dashboard/<username>")
def dashboard(username):
    if session.get('logged_in_user') != username:
        return redirect(url_for("login"))

    user = get_user(username)
    if not user:
        return redirect(url_for("login"))

    access_level   = check_access(user)
    os_user        = get_os_user()
    recent_logs    = _get_recent_logs_for_template(limit=5)
    last_login_str = _format_time_ago(user.get("last_login", 0))
    role_display   = get_role_display(user)
    role_color     = get_role_color(user)

    # System status
    critical_events = [
        e for e in get_recent_security_events(limit=10)
        if e.get("severity") in ("CRITICAL", "WARNING")
    ]
    system_status = "WARNING" if critical_events else "SECURE"

    return render_template(
        "dashboard.html",
        user=user,
        os_user=os_user,
        access_level=access_level,
        recent_logs=recent_logs,
        last_login=last_login_str,
        role_display=role_display,
        role_color=role_color,
        system_status=system_status,
        c_engine_active=is_c_active()
    )


@app.route("/logout")
def logout():
    username = session.get('logged_in_user', 'unknown')
    log_security_event(
        event_type="LOGOUT",
        message=f"User '{username}' logged out",
        username=username,
        severity="INFO"
    )
    print(f"[*] Session terminated for {username}. Locking hardware...")
    lock_host_system()
    session.clear()
    return redirect(url_for("login"))


# ═══════════════════════════════════════════════════════════════════
#  API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/logs")
def api_logs():
    """Return last 20 security events as JSON."""
    events = get_recent_security_events(limit=20)

    # Enrich with human-readable timestamps
    for e in events:
        ts = e.get("timestamp", 0)
        try:
            e["time_str"] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
            e["time_ago"] = _format_time_ago(ts)
        except Exception:
            e["time_str"] = "Unknown"
            e["time_ago"] = "Unknown"

    return jsonify({
        "status": "ok",
        "count": len(events),
        "events": events,
        "c_engine": is_c_active()
    })


@app.route("/api/security-score/<username>")
def api_security_score(username):
    """Return security score for a user (authenticated only)."""
    if session.get('logged_in_user') != username:
        return jsonify({"error": "Unauthorized"}), 401

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": username,
        "score": user.get("security_score", 0),
        "role_level": get_role_level(user),
        "is_locked": bool(user.get("is_locked", 0)),
        "last_login": _format_time_ago(user.get("last_login", 0))
    })


@app.route("/api/system-status")
def api_system_status():
    """Overall system health status."""
    events = get_recent_security_events(limit=10)
    critical = [e for e in events if e.get("severity") in ("CRITICAL",)]
    warnings = [e for e in events if e.get("severity") == "WARNING"]

    return jsonify({
        "status": "CRITICAL" if critical else ("WARNING" if warnings else "SECURE"),
        "recent_critical": len(critical),
        "recent_warnings": len(warnings),
        "c_engine_active": is_c_active()
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
