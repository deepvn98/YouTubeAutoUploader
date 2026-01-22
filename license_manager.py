# license_manager.py
import firebase_admin
from firebase_admin import credentials, db
from config import FIREBASE_CONFIG, FIREBASE_DB_URL

# Biến toàn cục lưu app instance
firebase_app = None

def init_firebase():
    global firebase_app
    try:
        # Kiểm tra xem app đã được khởi tạo chưa
        if not firebase_admin._apps:
            # FIREBASE_CONFIG giờ là một Dictionary (JSON object), 
            # credentials.Certificate tự động hiểu và xử lý nó.
            cred = credentials.Certificate(FIREBASE_CONFIG)
            
            firebase_app = firebase_admin.initialize_app(cred, {
                'databaseURL': FIREBASE_DB_URL
            })
            print("Firebase Initialized Successfully (Embedded Key).")
        else:
            firebase_app = firebase_admin.get_app()
        return True
    except Exception as e:
        print(f"Firebase Init Error: {e}")
        return False

def check_license_key(key):
    # Đảm bảo Firebase đã được khởi tạo
    if not firebase_admin._apps: 
        if not init_firebase():
            return False, "Connection Error"

    try:
        # 1. Kiểm tra Admin Code (Lấy từ Firebase node 'admin_code')
        admin_ref = db.reference('admin_code')
        remote_admin_code = admin_ref.get()
        
        # So sánh key nhập vào với admin code trên server
        if remote_admin_code and str(key).strip() == str(remote_admin_code):
            return True, "ADMIN"
        
        # 2. Kiểm tra License User (Node 'licenses/<key>')
        ref = db.reference(f'licenses/{key}')
        val = ref.get()
        
        # Giả định cấu trúc trên Firebase: "license_key": true
        # Hoặc "license_key": { "status": "active" ... }
        if val:
            # Nếu giá trị là boolean True hoặc dict có dữ liệu
            return True, "USER"
            
        return False, "INVALID"
    except Exception as e:
        return False, str(e)

def get_all_licenses():
    if not firebase_admin._apps: return {}
    try:
        return db.reference('licenses').get() or {}
    except:
        return {}

def add_license(key):
    if not firebase_admin._apps: return
    try:
        # Lưu key với giá trị True (hoặc có thể lưu ngày tạo nếu muốn)
        db.reference(f'licenses/{key}').set(True)
    except: pass

def delete_license(key):
    if not firebase_admin._apps: return
    try:
        db.reference(f'licenses/{key}').delete()
    except: pass