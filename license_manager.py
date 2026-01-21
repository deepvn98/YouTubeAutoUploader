# license_manager.py
import os
import firebase_admin
from firebase_admin import credentials, db
from config import FIREBASE_KEY, FIREBASE_DB_URL, LICENSE_FILE

firebase_app = None

def init_firebase():
    global firebase_app
    if os.path.exists(FIREBASE_KEY):
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(FIREBASE_KEY)
                firebase_app = firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
            else:
                firebase_app = firebase_admin.get_app()
            return True
        except Exception as e:
            print(f"Firebase Init Error: {e}")
            return False
    else:
        print("Warning: firebase_key.json not found!")
        return False

def check_license_key(key):
    if not firebase_app: return False, "Firebase not initialized"
    try:
        # Check Admin Code
        admin_ref = db.reference('admin_code')
        remote_admin_code = admin_ref.get()
        if remote_admin_code and str(key) == str(remote_admin_code):
            return True, "ADMIN"
        
        # Check Normal License
        ref = db.reference(f'licenses/{key}')
        val = ref.get()
        if val is True:
            return True, "USER"
        return False, "INVALID"
    except Exception as e:
        return False, str(e)

def get_all_licenses():
    if not firebase_app: return {}
    return db.reference('licenses').get() or {}

def add_license(key):
    if not firebase_app: return
    db.reference(f'licenses/{key}').set(True)

def delete_license(key):
    if not firebase_app: return
    db.reference(f'licenses/{key}').delete()