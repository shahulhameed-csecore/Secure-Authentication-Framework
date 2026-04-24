# database/models.py

def create_user_dict(username, password, role="user"):
    """
    Creates a standard dictionary format for a user.
    This ensures our user data looks the same everywhere in the app.
    """
    user = {
        "username": username,
        "password": password,  # In a real app, this should be a hashed password!
        "role": role
    }
    return user