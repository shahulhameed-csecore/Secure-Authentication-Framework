"""
security/attack_detection.py — Upgraded Attack Detection Engine
"""

import time
import json
import logging
import os
from datetime import datetime

from database.db import (
    get_failed_attempts, increment_failed_attempts,
    reset_failed_attempts, log_security_event
)

logger = logging.getLogger(__name__)

LOG_FILE = "logs/attacks.log"

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

LOCKOUT_THRESHOLD = 3       # attempts before lockout
LOCKOUT_MINUTES   = 30      # lockout duration


def log_attack(message: str, username: str = None, severity: str = "WARNING",
               event_type: str = "ATTACK", flags: int = 0):
    """Write to log file AND database."""
    timestamp = datetime.utcnow().isoformat() + "Z"
    log_entry = f"[{timestamp}] [{severity}] {message}"

    # File log
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        logger.error("Failed to write to log file: %s", e)

    # DB log
    try:
        log_security_event(
            event_type=event_type,
            message=message,
            username=username,
            severity=severity,
            flags=flags
        )
    except Exception as e:
        logger.error("Failed to write security event to DB: %s", e)


def detect_brute_force(username: str) -> bool:
    """
    Check if username is locked out due to brute-force attempts.
    Returns True if account is locked.
    """
    current_time = time.time()
    attempts, last_attempt = get_failed_attempts(username)

    # Currently locked?
    if attempts >= LOCKOUT_THRESHOLD:
        minutes_passed = (current_time - last_attempt) / 60
        if minutes_passed < LOCKOUT_MINUTES:
            mins_left = int(LOCKOUT_MINUTES - minutes_passed)
            log_attack(
                f"LOCKED USER {username} attempted login ({mins_left} mins remaining)",
                username=username,
                severity="CRITICAL",
                event_type="BRUTE_FORCE"
            )
            return True
        else:
            # Cooldown expired — reset
            reset_failed_attempts(username)

    # Record this attempt
    new_attempts = increment_failed_attempts(username, current_time)

    if new_attempts >= LOCKOUT_THRESHOLD:
        log_attack(
            f"ACCOUNT LOCKED: {username} exceeded {LOCKOUT_THRESHOLD} failed attempts",
            username=username,
            severity="CRITICAL",
            event_type="ACCOUNT_LOCKED"
        )
        return True

    return False


def reset_attempts(username: str):
    """Reset failed login attempts on successful login."""
    reset_failed_attempts(username)


def get_lockout_status(username: str) -> dict:
    """Get detailed lockout status for a user."""
    current_time = time.time()
    attempts, last_attempt = get_failed_attempts(username)

    is_locked = attempts >= LOCKOUT_THRESHOLD
    mins_remaining = 0

    if is_locked and last_attempt > 0:
        minutes_passed = (current_time - last_attempt) / 60
        if minutes_passed < LOCKOUT_MINUTES:
            mins_remaining = int(LOCKOUT_MINUTES - minutes_passed)
        else:
            is_locked = False

    return {
        "is_locked": is_locked,
        "attempts": attempts,
        "mins_remaining": mins_remaining,
        "threshold": LOCKOUT_THRESHOLD
    }