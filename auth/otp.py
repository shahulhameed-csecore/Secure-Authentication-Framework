# auth/otp.py
# ─────────────────────────────────────────────────────────────
# ONE-TIME PASSWORD MODULE  (v2)
# Responsibility: Generate, verify, and provision TOTP codes.
#
# Changes from v1:
#   ✦ valid_window is configurable via parameter (not hardcoded)
#   ✦ get_provisioning_uri() — generates the otpauth:// URL
#     that authenticator apps (Google Auth, Authy) scan via QR
#   ✦ All inputs are guard-checked before touching pyotp
#   ✦ Structured logging
# ─────────────────────────────────────────────────────────────

import logging
import pyotp   # pip install pyotp

logger = logging.getLogger(__name__)

# ── Policy defaults ───────────────────────────────────────────
# Centralised so policy changes touch one line, not many call sites.
_DEFAULT_VALID_WINDOW = 1   # ±1 window = ±30 s clock-skew tolerance
_ISSUER_NAME          = "SecureAuthSystem"   # Shown in authenticator apps


def generate_otp(secret: str) -> str:
    """
    Generate the current TOTP code for the given secret.

    Args:
        secret (str): Base32 TOTP secret (from register_user()).

    Returns:
        str: 6-digit OTP string valid for the current 30-second window.

    Raises:
        ValueError: If secret is blank or None.

    Example:
        otp_code = generate_otp(user.otp_secret)
    """
    if not secret:
        raise ValueError("otp secret must not be blank")

    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_otp(
    secret      : str,
    otp         : str,
    valid_window: int = _DEFAULT_VALID_WINDOW,
) -> bool:
    """
    Verify a TOTP code submitted by the user.

    Args:
        secret       (str): Base32 TOTP secret stored for the user.
        otp          (str): 6-digit code submitted by the user.
        valid_window (int): Number of 30-second windows to accept on
                            either side of the current window.
                            0  → strict: current window only.
                            1  → lenient: ±30 s (production default).
                            2+ → loose: only for degraded environments.

    Returns:
        bool: True if the OTP is valid within the acceptance window.

    Security note on valid_window:
        The default of 1 is the industry-standard balance between
        usability (handles typical clock drift) and security
        (limits replay window to 90 s max).
        Use 0 for the strictest possible enforcement — but expect
        false rejections if any clock skew exists.

    Replay protection note:
        pyotp itself does not prevent an OTP being reused within
        the same 30-second window. To add replay protection, store
        the last accepted OTP (or a "used OTPs" set) in your session
        layer and reject duplicates. This is intentionally out of
        scope for this stateless module.

    Example:
        is_valid = verify_otp(user.otp_secret, "482719")
        is_strict = verify_otp(user.otp_secret, "482719", valid_window=0)
    """
    # ── Guard clauses ─────────────────────────────────────────
    if not secret:
        logger.warning("verify_otp called with blank secret")
        return False

    if not otp or not otp.strip():
        logger.debug("verify_otp rejected: blank OTP submitted")
        return False

    if not isinstance(valid_window, int) or valid_window < 0:
        logger.warning(
            "verify_otp: invalid valid_window=%r, defaulting to %d",
            valid_window, _DEFAULT_VALID_WINDOW,
        )
        valid_window = _DEFAULT_VALID_WINDOW

    # ── Verify ────────────────────────────────────────────────
    totp   = pyotp.TOTP(secret)
    result = totp.verify(otp.strip(), valid_window=valid_window)

    if not result:
        logger.debug("verify_otp: OTP did not match")

    return result


def get_provisioning_uri(secret: str, username: str) -> str:
    """
    Generate the otpauth:// URI used to configure authenticator apps.

    This URI encodes the secret and account info in a standard format.
    Pass it to a QR code library (qrcode, segno) to render a scannable
    code, or send it as a deep link on mobile.

    Args:
        secret   (str): Base32 TOTP secret stored for the user.
        username (str): The username / account identifier to display
                        inside the authenticator app.

    Returns:
        str: An otpauth:// URI.
             Example:
             otpauth://totp/SecureAuthSystem:alice?secret=JBSWY3DP&issuer=SecureAuthSystem

    Raises:
        ValueError: If secret or username is blank.

    Example:
        uri = get_provisioning_uri(user.otp_secret, user.username)

        # Render a QR code in the terminal (requires 'qrcode' package):
        import qrcode, sys
        img = qrcode.make(uri)
        img.save("totp_qr.png")

        # Or print inline to terminal (requires 'qrcode[pil]'):
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.print_ascii(invert=True)
    """
    if not secret:
        raise ValueError("otp secret must not be blank")
    if not username:
        raise ValueError("username must not be blank for provisioning URI")

    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name   = username,
        issuer_name = _ISSUER_NAME,
    )
