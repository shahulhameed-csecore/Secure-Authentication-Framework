"""
security/c_bridge.py
════════════════════
Python ctypes bridge to the C security engine.

Exposes:
  validate_input_fast(input_str, max_len)  → bool
  detect_attack_pattern(input_str)         → (bool is_attack, int flags, str description)
  calculate_security_score(...)            → int 0-100

Falls back to pure-Python implementations if the library is not compiled.
"""

import ctypes
import os
import logging
import platform  # Added for cross-platform support
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Locate shared library (Dynamically detect Extension) ──────────
def _get_lib_name():
    sys_name = platform.system()
    if sys_name == "Windows":
        return "libsecurity.dll"
    elif sys_name == "Darwin":  # macOS
        return "libsecurity.dylib"
    else:  # Linux
        return "libsecurity.so"

_LIB_NAME = _get_lib_name()
_SO_PATH = Path(__file__).parent.parent / "security_c" / _LIB_NAME

_lib = None
_C_AVAILABLE = False

def _load_library():
    global _lib, _C_AVAILABLE
    try:
        # Use absolute path string for Windows compatibility
        _lib = ctypes.CDLL(str(_SO_PATH.resolve()))

        # validate_input_fast(const char*, int) -> int
        _lib.validate_input_fast.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _lib.validate_input_fast.restype  = ctypes.c_int

        # validate_username(const char*) -> int
        _lib.validate_username.argtypes = [ctypes.c_char_p]
        _lib.validate_username.restype  = ctypes.c_int

        # detect_attack_pattern(const char*) -> int
        _lib.detect_attack_pattern.argtypes = [ctypes.c_char_p]
        _lib.detect_attack_pattern.restype  = ctypes.c_int

        # calculate_security_score(int, int, int, int) -> int
        _lib.calculate_security_score.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int
        ]
        _lib.calculate_security_score.restype = ctypes.c_int

        # get_attack_flag_description(int, char*, int) -> void
        _lib.get_attack_flag_description.argtypes = [
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int
        ]
        _lib.get_attack_flag_description.restype = None

        # count_char_repeats(const char*) -> int
        _lib.count_char_repeats.argtypes = [ctypes.c_char_p]
        _lib.count_char_repeats.restype  = ctypes.c_int

        _C_AVAILABLE = True
        logger.info(f"[C-Engine] ✓ {_LIB_NAME} loaded — C acceleration active")
    except OSError as e:
        _C_AVAILABLE = False
        logger.warning(
            f"[C-Engine] ⚠ {_LIB_NAME} not found ({e}). "
            "Please ensure you compiled the C code for your OS. Using Python fallback."
        )

_load_library()


# ── Attack flag constants (mirrors C header) ───────────────────────
ATTACK_FLAG_NONE   = 0
ATTACK_FLAG_LENGTH = 1
ATTACK_FLAG_SQLI   = 2
ATTACK_FLAG_XSS    = 4
ATTACK_FLAG_REPEAT = 8
ATTACK_FLAG_CTRL   = 16

# SQL patterns for Python fallback
_SQLI_TOKENS = [
    "' OR", "' or", '" OR', '" or', "1=1", "DROP ", "SELECT ",
    "INSERT ", "DELETE ", "UPDATE ", "UNION ", "--", "/*", "*/",
    "xp_", "EXEC ", "exec ", "CAST(", "CHAR(", "cast(", "char("
]
_XSS_TOKENS = [
    "<script", "javascript:", "onerror=", "onload=", "onclick=",
    "alert(", "eval(", "<iframe", "<svg", "document.", "window."
]


# ── Pure-Python fallbacks ──────────────────────────────────────────

def _py_validate_input_fast(input_str: str, max_len: int) -> bool:
    if not input_str or len(input_str) > max_len:
        return False
    return all(0x20 <= ord(c) < 0x7F for c in input_str)


def _py_detect_attack_pattern(input_str: str) -> int:
    if not input_str:
        return ATTACK_FLAG_CTRL
    flags = ATTACK_FLAG_NONE
    if len(input_str) > 256:
        flags |= ATTACK_FLAG_LENGTH
    if any(ord(c) < 0x20 for c in input_str if c != '\t'):
        flags |= ATTACK_FLAG_CTRL
    if any(tok in input_str for tok in _SQLI_TOKENS):
        flags |= ATTACK_FLAG_SQLI
    if any(tok in input_str for tok in _XSS_TOKENS):
        flags |= ATTACK_FLAG_XSS
    # Repeated chars
    max_run, run = 1, 1
    for i in range(1, len(input_str)):
        if input_str[i] == input_str[i-1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    if max_run >= 8:
        flags |= ATTACK_FLAG_REPEAT
    return flags


def _py_calculate_security_score(has_otp: int, role_level: int, failed_attempts: int, input_clean: int) -> int:
    score = 0
    if has_otp:          score += 40
    if role_level >= 3:  score += 25
    elif role_level == 2: score += 18
    elif role_level == 1: score += 12
    else:                score += 5
    if input_clean:      score += 20
    score -= failed_attempts * 5
    return max(0, min(100, score))


def _flags_to_description(flags: int) -> str:
    if flags == ATTACK_FLAG_NONE:
        return "CLEAN"
    parts = []
    if flags & ATTACK_FLAG_LENGTH: parts.append("EXCESSIVE_LENGTH")
    if flags & ATTACK_FLAG_CTRL:   parts.append("CONTROL_CHARS")
    if flags & ATTACK_FLAG_SQLI:   parts.append("SQL_INJECTION")
    if flags & ATTACK_FLAG_XSS:    parts.append("XSS_ATTACK")
    if flags & ATTACK_FLAG_REPEAT: parts.append("REPEAT_PATTERN")
    return " | ".join(parts)


# ── Public API ─────────────────────────────────────────────────────

def validate_input_fast(input_str: str, max_len: int = 256) -> bool:
    """High-speed input validation using C engine (or Python fallback)."""
    if _C_AVAILABLE:
        encoded = input_str.encode("utf-8", errors="replace") if input_str else b""
        return bool(_lib.validate_input_fast(encoded, max_len))
    return _py_validate_input_fast(input_str, max_len)


def validate_username_c(username: str) -> bool:
    """Strict username validation: alphanumeric + underscore, 3-32 chars."""
    if _C_AVAILABLE:
        encoded = username.encode("utf-8", errors="replace") if username else b""
        return bool(_lib.validate_username(encoded))
    if not username:
        return False
    import re
    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', username))


def detect_attack_pattern(input_str: str) -> tuple[bool, int, str]:
    """
    Detect attack patterns in the input string.
    Returns: (is_attack, flags, description)
    """
    if _C_AVAILABLE:
        encoded = input_str.encode("utf-8", errors="replace") if input_str else b""
        flags = _lib.detect_attack_pattern(encoded)
        buf = ctypes.create_string_buffer(256)
        _lib.get_attack_flag_description(flags, buf, 256)
        description = buf.value.decode("utf-8", errors="replace")
    else:
        flags = _py_detect_attack_pattern(input_str)
        description = _flags_to_description(flags)

    is_attack = flags != ATTACK_FLAG_NONE
    return is_attack, flags, description


def calculate_security_score(
    has_otp: bool,
    role_level: int,
    failed_attempts: int,
    input_clean: bool
) -> int:
    """Calculate a 0-100 security score using the C engine."""
    if _C_AVAILABLE:
        return _lib.calculate_security_score(
            int(has_otp), role_level, failed_attempts, int(input_clean)
        )
    return _py_calculate_security_score(
        int(has_otp), role_level, failed_attempts, int(input_clean)
    )

def is_c_active() -> bool:
    """Returns True if the C engine is loaded and active."""
    return _C_AVAILABLE