"""
security/validation.py — Enhanced Input Validation (C-powered)
"""

import re
import logging
from security.c_bridge import validate_input_fast, validate_username_c, detect_attack_pattern

logger = logging.getLogger(__name__)

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')


def check_input(data: dict) -> tuple[bool, str]:
    """
    Validate login/register input using C engine (with Python fallback).

    Returns:
        (is_valid: bool, reason: str)
    """
    username = data.get("username", "")
    password = data.get("password", "")

    # ── Fast C-powered checks ──────────────────────────────────
    if not validate_input_fast(username, max_len=32):
        logger.debug("check_input: username failed fast validation")
        return False, "Invalid username format"

    if not validate_input_fast(password, max_len=128):
        logger.debug("check_input: password failed fast validation")
        return False, "Invalid password format"

    # ── Username charset check (strict) ───────────────────────
    if not validate_username_c(username):
        return False, "Username must be 3-32 alphanumeric characters"

    # ── Attack pattern detection (C-powered) ──────────────────
    is_attack_u, flags_u, desc_u = detect_attack_pattern(username)
    if is_attack_u:
        logger.warning("check_input: attack detected in username — %s", desc_u)
        return False, f"Malicious pattern detected: {desc_u}"

    is_attack_p, flags_p, desc_p = detect_attack_pattern(password)
    if is_attack_p:
        logger.warning("check_input: attack detected in password — %s", desc_p)
        return False, f"Malicious pattern detected: {desc_p}"

    return True, "OK"


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Check password meets strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[^A-Za-z\d]', password):
        return False, "Password must contain at least one special character"
    return True, "OK"