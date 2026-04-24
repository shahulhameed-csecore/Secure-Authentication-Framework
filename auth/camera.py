import os
import time
try:
    import cv2
    _CV2_AVAILABLE = True
except ImportError:
    _CV2_AVAILABLE = False

def capture_login_attempt(username):
    if not _CV2_AVAILABLE:
        return  # Silently skip if OpenCV not installed
    cam = cv2.VideoCapture(0)
    time.sleep(0.5)
    ret, frame = cam.read()
    if ret:
        save_path = "static/audit_logs"
        os.makedirs(save_path, exist_ok=True)
        filename = f"{save_path}/{username}_attempt_{int(time.time())}.jpg"
        cv2.imwrite(filename, frame)
    cam.release()