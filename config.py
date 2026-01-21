# config.py
import os
import json
import threading

# --- PATHS ---
TOKEN_DIR = "user_tokens"
SECRET_DIR = "client_secrets"
SETTINGS_FILE = "settings.json"
GRID_STATE_FILE = "grid_state.json"
LICENSE_FILE = "license.key"
FIREBASE_KEY = "firebase_key.json"
FIREBASE_DB_URL = "https://npsang-e678c-default-rtdb.asia-southeast1.firebasedatabase.app/"

# --- GOOGLE SCOPES ---
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/youtube"
]

# --- DATA CONSTANTS ---
YT_CATEGORIES = {
    "Default (From Settings)": "default",
    "Film & Animation": "1",
    "Autos & Vehicles": "2",
    "Music": "10",
    "Pets & Animals": "15",
    "Sports": "17",
    "Travel & Events": "19",
    "Gaming": "20",
    "People & Blogs": "22",
    "Comedy": "23",
    "Entertainment": "24",
    "News & Politics": "25",
    "Howto & Style": "26",
    "Education": "27",
    "Science & Technology": "28",
    "Nonprofits & Activism": "29"
}

YT_LANGUAGES = {
    "English (Global)": "en",
    "English (United States)": "en-US",
    "Vietnamese (Vietnam)": "vi",
    "Japanese (Japan)": "ja",
    "Korean (South Korea)": "ko",
    # ... (Bạn có thể thêm các ngôn ngữ khác từ file gốc vào đây nếu muốn đầy đủ)
}

YT_LOCATIONS = {
    "No Location": {"desc": "", "lat": 0.0, "long": 0.0},
    "United States": {"desc": "United States", "lat": 37.0902, "long": -95.7129},
    "Vietnam": {"desc": "Vietnam", "lat": 14.0583, "long": 108.2772},
    # ... (Copy thêm các location khác từ file gốc)
}

DEFAULT_SETTINGS = {
    "categoryId": "22",
    "languageCode": "en-US",
    "locationKey": "United States"
}

# --- GLOBAL HELPERS ---
file_lock = threading.Lock()

for d in [TOKEN_DIR, SECRET_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

def load_json(filepath, default_val):
    if not os.path.exists(filepath): return default_val
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default_val

def save_json(filepath, data):
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except:
        return False

# Load current settings globally
CURRENT_SETTINGS = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)