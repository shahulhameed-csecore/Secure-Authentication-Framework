import re
import bcrypt
import pyotp

_MIN_PASSWORD_LENGTH = 8
_PASSWORD_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).+$")
VALID_ROLES = {"admin", "editor", "viewer", "user"}

def register_user(username: str, password: str, role: str) -> dict:
    """Register a new user with a hashed password and a TOTP secret."""
    
    # ── Input Validation ─────────────────────────────────────
    if not username or len(username.strip()) < 3:
        raise ValueError("Username must be at least 3 characters.")

    if not password or len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters.")

    if not _PASSWORD_PATTERN.match(password):
        raise ValueError("Password must contain at least one letter, one digit, and one special character.")

    normalized_role = role.strip().lower()
    if normalized_role not in VALID_ROLES:
        normalized_role = "user" # Default to user if they somehow bypass the UI

    # ── Crypto & User Creation ───────────────────────────────
    password_bytes = password.encode("utf-8")
    hashed_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    hashed_password = hashed_bytes.decode("utf-8")

    otp_secret = pyotp.random_base32()

    # Return a clean dictionary for Member 3's database
    return {
        "username": username.strip(),
        "password": hashed_password,
        "role": normalized_role,
        "otp_secret": otp_secret,
    }