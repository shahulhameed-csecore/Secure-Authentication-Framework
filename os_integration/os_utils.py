# os_integration/os_utils.py
import os

def get_os_user():
    """
    Gets the username of the person currently logged into the computer's OS.
    """
    try:
        # This is the standard way to get the logged-in OS user
        return os.getlogin()
    except Exception:
        # Note for beginners: Sometimes os.getlogin() gets confused if you are 
        # running code inside certain code editors. This is a safe fallback!
        import getpass
        return getpass.getuser()
    
import subprocess
import platform
import ctypes # 🧱 NEW: Native Windows API library

def lock_host_system():
    os_name = platform.system()
    print(f"[*] Attempting to lock host OS: {os_name}")
    
    try:
        if os_name == "Windows":
            # The absolutely bulletproof way to lock Windows via Python
            ctypes.windll.user32.LockWorkStation()
            
        elif os_name == "Linux":
            subprocess.run(["xdg-screensaver", "lock"], check=True)
            
        elif os_name == "Darwin":
            subprocess.run(["pmset", "displaysleepnow"], check=True)
            
        else:
            print(f"[-] OS lock not supported for: {os_name}")
            return False
            
        print("[+] System successfully locked.")
        return True
        
    except Exception as e:
        print(f"[-] Failed to lock system: {e}")
        return False