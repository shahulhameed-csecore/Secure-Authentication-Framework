"""
security/roles.py — Role Management
"""

ROLE_LEVELS = {
    "admin":  3,
    "editor": 2,
    "user":   1,
    "guest":  0,
}

ROLE_DISPLAY = {
    "admin":  "ADMINISTRATOR",
    "editor": "EDITOR",
    "user":   "OPERATOR",
    "guest":  "GUEST",
}

ROLE_COLORS = {
    "admin":  "#ff6b35",
    "editor": "#00d4ff",
    "user":   "#7b2ff7",
    "guest":  "#6b7280",
}


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"


def get_role_level(user: dict) -> int:
    return ROLE_LEVELS.get(user.get("role", "guest"), 0)


def get_role_display(user: dict) -> str:
    return ROLE_DISPLAY.get(user.get("role", "guest"), "UNKNOWN")


def get_role_color(user: dict) -> str:
    return ROLE_COLORS.get(user.get("role", "guest"), "#6b7280")


def check_access(user: dict) -> str:
    if is_admin(user):
        return "access_granted_full"
    return "access_granted_limited"