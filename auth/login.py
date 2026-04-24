import logging
import bcrypt

logger = logging.getLogger(__name__)

def login_user(username: str, password: str, stored_user: dict) -> bool:
    """Authenticate a user by verifying username and password."""
    
    if not username or not password:
        logger.debug("login rejected: blank username or password supplied")
        return False

    if stored_user is None or not isinstance(stored_user, dict):
        logger.debug("login rejected: stored_user is invalid")
        return False

    required_keys = {"username", "password"}
    if required_keys - stored_user.keys():
        logger.warning("login rejected: stored_user is missing keys")
        return False

    if username != stored_user["username"]:
        logger.debug("login rejected: username mismatch")
        return False

    stored_hash = stored_user["password"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("utf-8") 

    try:
        password_bytes = password.encode("utf-8")
        password_matches = bcrypt.checkpw(password_bytes, stored_hash)
    except Exception as exc:
        logger.warning("login rejected: bcrypt error — %s", exc)
        return False

    if not password_matches:
        logger.debug("login rejected: password mismatch")

    return password_matches