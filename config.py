# config.py
import os
import json
import threading

# =============================================================================
# 1. CẤU HÌNH ĐƯỜNG DẪN & FILE HỆ THỐNG
# =============================================================================
TOKEN_DIR = "user_tokens"
SECRET_DIR = "client_secrets"
SETTINGS_FILE = "settings.json"
GRID_STATE_FILE = "grid_state.json"
LICENSE_FILE = "license.key"
FIREBASE_KEY = "firebase_key.json"
# URL Firebase của bạn
FIREBASE_DB_URL = "https://npsang-e678c-default-rtdb.asia-southeast1.firebasedatabase.app/"

# =============================================================================
# 2. QUYỀN TRUY CẬP GOOGLE (SCOPES)
# =============================================================================
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/youtube"  # Quyền quản lý playlist/thêm video
]

# =============================================================================
# 3. DỮ LIỆU HẰNG SỐ (CONSTANTS)
# =============================================================================

# Danh mục YouTube (ID chuẩn API v3)
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

# Danh sách ngôn ngữ phổ biến
YT_LANGUAGES = {
    "English (United States)": "en-US",
    "English (Global)": "en",
    "Vietnamese (Vietnam)": "vi",
    "Japanese (Japan)": "ja",
    "Korean (South Korea)": "ko",
    "Chinese (Simplified)": "zh-CN",
    "Chinese (Traditional)": "zh-TW",
    "German (Germany)": "de",
    "French (France)": "fr",
    "Spanish (Spain)": "es",
    "Portuguese (Brazil)": "pt-BR",
    "Russian (Russia)": "ru",
    "Hindi (India)": "hi",
    "Thai (Thailand)": "th",
    "Indonesian (Indonesia)": "id"
}

# Danh sách vị trí địa lý (Tọa độ Lat/Long tương đối)
YT_LOCATIONS = {
    "No Location": {"desc": "", "lat": 0.0, "long": 0.0},
    "United States": {"desc": "United States", "lat": 37.0902, "long": -95.7129},
    "Vietnam": {"desc": "Vietnam", "lat": 14.0583, "long": 108.2772},
    "Japan": {"desc": "Japan", "lat": 36.2048, "long": 138.2529},
    "South Korea": {"desc": "South Korea", "lat": 35.9078, "long": 127.7669},
    "Germany": {"desc": "Germany", "lat": 51.1657, "long": 10.4515},
    "United Kingdom": {"desc": "United Kingdom", "lat": 55.3781, "long": -3.4360},
    "France": {"desc": "France", "lat": 46.2276, "long": 2.2137},
    "Brazil": {"desc": "Brazil", "lat": -14.2350, "long": -51.9253},
    "India": {"desc": "India", "lat": 20.5937, "long": 78.9629},
    "Australia": {"desc": "Australia", "lat": -25.2744, "long": 133.7751},
    "Canada": {"desc": "Canada", "lat": 56.1304, "long": -106.3468},
    "Russia": {"desc": "Russia", "lat": 61.5240, "long": 105.3188}
}

DEFAULT_SETTINGS = {
    "categoryId": "22",          # Mặc định: People & Blogs
    "languageCode": "en-US",     # Mặc định: Tiếng Anh Mỹ
    "locationKey": "United States"
}

# =============================================================================
# 4. CÁC HÀM HỖ TRỢ (HELPERS)
# =============================================================================

# Khóa luồng để tránh xung đột khi ghi file cùng lúc
file_lock = threading.Lock()

# Tự động tạo thư mục nếu chưa tồn tại
for d in [TOKEN_DIR, SECRET_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

def load_json(filepath, default_val):
    """Đọc file JSON an toàn, trả về default_val nếu lỗi hoặc không tồn tại."""
    if not os.path.exists(filepath): return default_val
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default_val

def save_json(filepath, data):
    """Ghi file JSON an toàn với encoding utf-8."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except:
        return False

# Tải cấu hình ngay khi import file này
CURRENT_SETTINGS = load_json(SETTINGS_FILE, DEFAULT_SETTINGS)