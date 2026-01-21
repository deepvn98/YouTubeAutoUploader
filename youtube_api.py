# youtube_api.py
import os
import json
import datetime
import time
import random
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError

from config import (TOKEN_DIR, SECRET_DIR, SCOPES, file_lock, 
                    YT_LOCATIONS, YT_CATEGORIES, CURRENT_SETTINGS)

def get_client_id_from_file(secret_filename):
    path = os.path.join(SECRET_DIR, secret_filename)
    if not os.path.exists(path): return None
    try:
        with open(path, 'r') as f:
            d = json.load(f)
            return d.get('installed', {}).get('client_id') or d.get('web', {}).get('client_id')
    except: return None

def get_authenticated_service(token_filename, secret_filename):
    token_path = os.path.join(TOKEN_DIR, token_filename)
    secret_path = os.path.join(SECRET_DIR, secret_filename)
    if not os.path.exists(token_path) or not os.path.exists(secret_path): return None

    try:
        with open(token_path, 'r') as f: store = json.load(f)
        if "google_creds" not in store or "client_id" not in store: return None
        target_cid = get_client_id_from_file(secret_filename)
        if target_cid != store["client_id"]: return None

        creds = Credentials.from_authorized_user_info(store["google_creds"], SCOPES)
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                flow = InstalledAppFlow.from_client_secrets_file(secret_path, SCOPES)
                creds.refresh(Request())
                store["google_creds"] = json.loads(creds.to_json())
                with file_lock:
                    with open(token_path, "w") as f: json.dump(store, f, indent=4)
            else: return None
        return build("youtube", "v3", credentials=creds, cache_discovery=False)
    except Exception as e: return None

def create_new_login(secret_filename):
    secret_path = os.path.join(SECRET_DIR, secret_filename)
    cid = get_client_id_from_file(secret_filename)
    if not cid: return None, "Invalid Secret File!"

    try:
        flow = InstalledAppFlow.from_client_secrets_file(secret_path, SCOPES)
        creds = flow.run_local_server(port=0, authorization_prompt_message="", timeout_seconds=60)
        with build("oauth2", "v2", credentials=creds) as oauth_service:
            email = oauth_service.userinfo().get().execute().get('email')
        if not email: return None, "Cannot retrieve Email!"

        fname = f"{email}.json"
        data = {"google_creds": json.loads(creds.to_json()), "client_id": cid, "email": email, "created_at": str(datetime.datetime.now())}
        with open(os.path.join(TOKEN_DIR, fname), "w") as f: json.dump(data, f, indent=4)
        return fname, None
    except Exception as e: return None, f"Error/Timeout: {str(e)}"

def get_user_playlists(youtube):
    try:
        playlists = {}
        # Lấy tối đa 50 playlist gần nhất
        request = youtube.playlists().list(part="snippet", mine=True, maxResults=50)
        response = request.execute()
        for item in response.get("items", []):
            playlists[item["snippet"]["title"]] = item["id"]
        return playlists
    except Exception as e:
        print(f"Error fetching playlists: {e}")
        return {}

def add_video_to_playlist(youtube, video_id, playlist_id):
    if not playlist_id: return False, "No Playlist ID"
    try:
        body = {
            "snippet": {
                "playlistId": str(playlist_id),
                "resourceId": {"kind": "youtube#video", "videoId": str(video_id)}
            }
        }
        youtube.playlistItems().insert(part="snippet", body=body).execute()
        return True, "Success"
    except HttpError as e:
        if e.resp.status == 409: return True, "Already in Playlist" # Bỏ qua lỗi trùng
        return False, f"API Error {e.resp.status}"
    except Exception as e:
        return False, str(e)

def execute_upload(youtube, video_data, publish_time, specific_category, progress_callback, pause_event, log_func):
    from config import CURRENT_SETTINGS 
    cfg = CURRENT_SETTINGS
    
    # --- 1. CHUẨN BỊ METADATA ---
    final_cat = specific_category if (specific_category and specific_category != "default") else cfg.get("categoryId", "22")
    
    # Chuyển đổi thời gian sang chuẩn ISO 8601 UTC cho YouTube
    publish_at = publish_time.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    
    lang_code = cfg.get("languageCode", "en-US")
    loc_key = cfg.get("locationKey", "United States")
    loc_data = YT_LOCATIONS.get(loc_key, YT_LOCATIONS["No Location"])
    
    # Fallback tìm kiếm location gần đúng
    if loc_key not in YT_LOCATIONS:
        for k, v in YT_LOCATIONS.items():
            if k in loc_key or loc_key in k: loc_data = v; break

    # --- LOGIC MỚI: TÌM TÊN CATEGORY TỪ ID ---
    cat_name_display = str(final_cat) # Mặc định hiển thị số ID nếu không tìm thấy tên
    for name, cid in YT_CATEGORIES.items():
        # So sánh ID (chuyển về string để chắc chắn khớp)
        if str(cid) == str(final_cat):
            cat_name_display = name
            break
    # -----------------------------------------

    # Thay {final_cat} bằng {cat_name_display}
    log_func(f"   -> Info: {lang_code} | {loc_data['desc']} | Cat: {cat_name_display}")
    
    body = {
        "snippet": {
            "title": video_data['title'][:100], # YouTube giới hạn 100 ký tự
            "description": video_data['desc'][:5000], # Giới hạn 5000 ký tự
            "tags": video_data['tags'][:500], # Giới hạn tags (tương đối)
            "categoryId": final_cat,
            "defaultLanguage": lang_code,       
            "defaultAudioLanguage": lang_code   
        },
        "status": {
            "privacyStatus": "private", # Bắt buộc 'private' để set 'publishAt'
            "publishAt": publish_at,
            "selfDeclaredMadeForKids": False,
            "containsSyntheticMedia": True,
            "embeddable": True,
            "license": "youtube"
        },
        "recordingDetails": {
            "locationDescription": loc_data["desc"],
            "location": {"latitude": loc_data["lat"], "longitude": loc_data["long"]}
        }
    }
    
    # --- 2. CẤU HÌNH UPLOAD (QUAN TRỌNG) ---
    # Chunk size 4MB (4 * 1024 * 1024) ổn định hơn 1MB
    media = MediaFileUpload(video_data['video'], chunksize=4*1024*1024, resumable=True, mimetype='video/mp4')
    
    request = youtube.videos().insert(
        part="snippet,status,recordingDetails", 
        body=body, 
        media_body=media
    )
    
    response = None
    retry_count = 0
    MAX_RETRIES = 10

    # --- 3. VÒNG LẶP UPLOAD (RESUMABLE) ---
    while response is None:
        # Kiểm tra Pause
        if not pause_event.is_set():
            progress_callback("Paused...")
            pause_event.wait()
            progress_callback("Resuming...")
        
        try:
            status, response = request.next_chunk()
            if status:
                pct = int(status.progress() * 100)
                progress_callback(f"Uploading {pct}%")
        except HttpError as e:
            # Chỉ retry các lỗi server (5xx) hoặc lỗi đường truyền
            if e.resp.status in [500, 502, 503, 504]:
                retry_count += 1
                if retry_count > MAX_RETRIES: 
                    raise Exception(f"Upload Failed: Server Error {e.resp.status}")
                
                sleep_time = (2 ** retry_count) + random.random() # Exponential Backoff
                progress_callback(f"Server Busy. Retry {retry_count}/{MAX_RETRIES} in {int(sleep_time)}s...")
                time.sleep(sleep_time)
                continue
            elif e.resp.status == 403 and "quotaExceeded" in str(e):
                raise Exception("QUOTA_EXCEEDED") # Ném lỗi đặc biệt để xử lý dừng thread
            else:
                raise e # Lỗi client (400, 401...) không nên retry
        except Exception as e:
            retry_count += 1
            if retry_count > MAX_RETRIES: 
                raise Exception(f"Network Error: {str(e)}")
            progress_callback(f"Net Error. Retry {retry_count}...")
            time.sleep(5)
    
    # --- 4. UPLOAD THUMBNAIL (NẾU CÓ) ---
    vid = response.get("id")
    if video_data['thumb'] and os.path.exists(video_data['thumb']):
        try:
            youtube.thumbnails().set(
                videoId=vid, 
                media_body=MediaFileUpload(video_data['thumb'])
            ).execute()
        except Exception as e:
            log_func(f"   -> Warning: Thumb upload failed ({str(e)})")

    return vid