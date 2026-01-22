# utils.py
import os
import glob
import datetime
import json
import time
from googleapiclient.errors import HttpError
from config import YT_CATEGORIES
import youtube_api

# ==============================================================================
# 1. HÀM HỖ TRỢ: QUÉT VIDEO & METADATA
# ==============================================================================
def scan_folder_for_video(folder_path):
    if not os.path.exists(folder_path): return None
    
    # Quét Video
    extensions = ("*.mp4", "*.mov", "*.avi", "*.mkv")
    vids = []
    for ext in extensions:
        vids.extend(glob.glob(os.path.join(folder_path, ext)))
        vids.extend(glob.glob(os.path.join(folder_path, ext.upper())))
        
    if not vids: return None
    
    # Quét Thumbnail
    imgs = glob.glob(os.path.join(folder_path, "*.jpg")) + \
           glob.glob(os.path.join(folder_path, "*.png")) + \
           glob.glob(os.path.join(folder_path, "*.jpeg"))
    
    # Quét Metadata
    txt_files = glob.glob(os.path.join(folder_path, "*.txt"))
    info_path = txt_files[0] if txt_files else None
    
    title = os.path.splitext(os.path.basename(vids[0]))[0]
    title = title.replace("_", " ")
    tags = []; desc = ""
    
    if info_path and os.path.exists(info_path):
        try:
            with open(info_path, "r", encoding="utf-8", errors='ignore') as f: 
                lines = f.readlines()
            
            current_mode = None
            raw_title, raw_desc, raw_tags = [], [], []
            
            for line in lines:
                clean = line.strip()
                if "Title:" in line or "Tiêu đề:" in line:
                    current_mode = "title"; parts = line.split(":", 1)
                    if len(parts) > 1 and parts[1].strip(): raw_title.append(parts[1].strip())
                    continue
                if "Video Description:" in line or "Giới thiệu:" in line:
                    current_mode = "desc"; parts = line.split(":", 1)
                    if len(parts) > 1 and parts[1].strip(): raw_desc.append(parts[1].strip())
                    continue
                if "Tags:" in line or "Thẻ tag video:" in line:
                    current_mode = "tags"; parts = line.split(":", 1)
                    if len(parts) > 1 and parts[1].strip(): raw_tags.append(parts[1].strip())
                    continue
                
                if current_mode == "title" and clean: raw_title.append(clean)
                elif current_mode == "desc": raw_desc.append(line.rstrip())
                elif current_mode == "tags" and clean: raw_tags.append(clean)
            
            if raw_title: title = " ".join(raw_title).strip()
            if raw_desc: desc = "\n".join(raw_desc).strip()
            if raw_tags: 
                full_tag_str = ",".join(raw_tags)
                tags = [t.strip() for t in full_tag_str.split(",") if t.strip()]
                
        except Exception as e: 
            print(f"Parse Text Error ({info_path}): {e}")
            
    return {
        "folder": folder_path, 
        "video": vids[0], 
        "thumb": imgs[0] if imgs else None, 
        "title": title, 
        "tags": tags, 
        "desc": desc
    }

# ==============================================================================
# 2. HÀM MỚI: QUÉT API ĐỂ TÌM GIỜ SCHEDULE XA NHẤT (CHÍNH XÁC TUYỆT ĐỐI)
# ==============================================================================
def get_last_scheduled_time_from_api(yt, log_func=None):
    """
    Gọi YouTube API để tìm xem video nào đang được lên lịch (Scheduled) 
    có thời gian xa nhất trong tương lai.
    """
    try:
        # Bước 1: Lấy danh sách video mới nhất của kênh (bao gồm cả Private/Scheduled)
        # order='date' để lấy cái mới nhất trước
        search_response = yt.search().list(
            part="id",
            forMine=True,
            type="video",
            maxResults=20, # Check 20 video gần nhất là đủ
            order="date"
        ).execute()

        video_ids = [item['id']['videoId'] for item in search_response.get('items', [])]
        
        if not video_ids:
            return None

        # Bước 2: Lấy chi tiết status của các video này để xem 'publishAt'
        videos_response = yt.videos().list(
            part="status",
            id=",".join(video_ids)
        ).execute()

        latest_dt = None
        local_tz = datetime.datetime.now().astimezone().tzinfo # Múi giờ máy tính

        for item in videos_response.get('items', []):
            status = item.get('status', {})
            # Trường 'publishAt' chỉ xuất hiện nếu video được đặt lịch (Scheduled)
            if 'publishAt' in status:
                t_str = status['publishAt'] # Dạng: 2026-01-22T19:00:00Z (Luôn là UTC)
                
                # Parse từ ISO 8601
                # Thay Z bằng +00:00 để fromisoformat hiểu là UTC
                try:
                    dt_utc = datetime.datetime.fromisoformat(t_str.replace('Z', '+00:00'))
                    
                    # QUAN TRỌNG: Đổi từ UTC về Local Time của máy tính
                    dt_local = dt_utc.astimezone(local_tz)
                    
                    if latest_dt is None or dt_local > latest_dt:
                        latest_dt = dt_local
                except:
                    pass
        
        return latest_dt

    except Exception as e:
        if log_func: log_func(f"API Check Error: {e}")
        return None

def calculate_schedule_time(last_time, slots_string, day_gap):
    now = datetime.datetime.now().astimezone()
    
    # Parse slots
    slots = []
    if slots_string:
        for s in slots_string.replace(";", ",").split(","):
            try: slots.append(datetime.datetime.strptime(s.strip(), "%H:%M").time())
            except: pass
    if not slots: slots = [datetime.time(8, 0)]
    slots.sort()
    gap = int(day_gap)

    # TRƯỜNG HỢP 1: KHÔNG CÓ LỊCH SỬ TRÊN KÊNH
    if not last_time:
        base_date = now.date()
        for s in slots:
            dt = datetime.datetime.combine(base_date, s).replace(tzinfo=now.tzinfo)
            if dt > now + datetime.timedelta(minutes=15):
                return dt
        next_dt = datetime.datetime.combine(base_date + datetime.timedelta(days=1), slots[0]).replace(tzinfo=now.tzinfo)
        return next_dt

    # TRƯỜNG HỢP 2: ĐÃ CÓ VIDEO ĐẶT LỊCH -> TÍNH TIẾP TỪ ĐÓ
    base_date = last_time.date()
    for s in slots:
        dt_candidate = datetime.datetime.combine(base_date, s).replace(tzinfo=last_time.tzinfo)
        
        # Chỉ lấy slot lớn hơn thời gian schedule cũ
        if dt_candidate > last_time:
            return dt_candidate 

    # Hết slot trong ngày -> Cộng thêm gap
    days_to_add = 1 + gap
    next_date = base_date + datetime.timedelta(days=days_to_add)
    return datetime.datetime.combine(next_date, slots[0]).replace(tzinfo=last_time.tzinfo)

# ==============================================================================
# 3. LUỒNG CHÍNH
# ==============================================================================
def run_job_thread(row_widgets, config, log_func, pause_event):
    COLOR_MAP = {"primary": "#007bff", "secondary": "#6c757d", "success": "#28a745", "info": "#17a2b8", "warning": "#ffc107", "danger": "#dc3545", "black": "black"}
    
    def ui_update(text, color_key="black"): 
        try:
            row_widgets['stat'].config(text=text, foreground=COLOR_MAP.get(color_key, "black"))
        except: pass
    
    acc_display = config['acc'].replace(".json", "")
    btn_pause = row_widgets['btn_pause']
    
    try:
        # --- KẾT NỐI ---
        try: btn_pause.config(state="normal", text="⏸", bootstyle="primary")
        except: pass
        
        log_func(f"[{acc_display}] Init Process...")
        ui_update("Connecting...", "primary")
        
        # 1. Login YouTube
        yt = youtube_api.get_authenticated_service(config['acc'], config['secret'])
        if not yt: 
            ui_update("Login Error", "danger")
            log_func(f"[{acc_display}] Error: Cannot Login (Check Token/Secret)")
            return

        # --- QUÉT FOLDER ---
        ui_update("Scanning...", "info")
        subfolders = sorted([f.path for f in os.scandir(config['folder']) if f.is_dir()])
        
        if not subfolders:
            check_root = scan_folder_for_video(config['folder'])
            if check_root: subfolders = [config['folder']]

        if not subfolders: 
            ui_update("NO VIDEO", "danger")
            log_func(f"[{acc_display}] Folder empty or no video files!")
            return
            
        pending = [f for f in subfolders if not os.path.exists(os.path.join(f, "done.json"))]
        
        if not pending:
            ui_update("ALL DONE", "success")
            log_func(f"[{acc_display}] All videos uploaded.")
            return
        
        log_func(f"[{acc_display}] Found {len(pending)} videos to upload.")
        
        # ------------------------------------------------------------------
        # 2. CHECK API LỊCH SỬ (LOGIC MỚI - KHÔNG DÙNG LOCAL FILE)
        # ------------------------------------------------------------------
        ui_update("API Check...", "info")
        log_func(f"[{acc_display}] Checking channel schedule via API...")
        
        # Gọi hàm quét API
        last_time_cursor = get_last_scheduled_time_from_api(yt, log_func)
        
        if last_time_cursor:
            log_func(f"[{acc_display}] [API Found] Last Scheduled: {last_time_cursor.strftime('%H:%M %d/%m')}")
        else:
            log_func(f"[{acc_display}] [API] No scheduled videos found. Starting fresh.")
        
        # ------------------------------------------------------------------
        # 3. UPLOAD LOOP
        # ------------------------------------------------------------------
        count_ok = 0
        for idx, folder in enumerate(pending):
            step_str = f"[{idx+1}/{len(pending)}]"
            
            # Pause Check
            if not pause_event.is_set():
                ui_update(f"{step_str} Paused", "warning")
                try: btn_pause.config(text="▶", bootstyle="primary-outline")
                except: pass
                pause_event.wait()
                try: btn_pause.config(text="⏸", bootstyle="primary")
                except: pass

            ui_update(f"{step_str} Ready", "warning")
            
            data = scan_folder_for_video(folder)
            if not data: 
                log_func(f"[{acc_display}] Skip: No valid video in {os.path.basename(folder)}")
                continue
            
            # Tính giờ (dựa trên API Cursor)
            pub_time = calculate_schedule_time(last_time_cursor, config['time'], config['gap'])
            last_time_cursor = pub_time # Update con trỏ bộ nhớ đệm
            
            log_func(f"[{acc_display}] Uploading: {data['title']}")
            log_func(f"   -> Schedule: {pub_time.strftime('%H:%M %d/%m/%Y')}")
            
            try:
                def on_progress(msg): 
                    if "Uploading" in msg:
                        try:
                            pct = msg.split(":")[-1].strip()
                            ui_update(f"{step_str} {pct}", "warning")
                        except: ui_update(f"{step_str} Up...", "warning")
                
                cat_id = YT_CATEGORIES.get(config['cat_name'], "default")
                
                # A. Upload
                vid_id = youtube_api.execute_upload(yt, data, pub_time, cat_id, on_progress, pause_event, log_func)
                
                # B. Playlist
                pl_ids = config.get('playlist_ids', [])
                if pl_ids:
                    ui_update(f"{step_str} Sync PL", "info")
                    time.sleep(2)
                    for pid in pl_ids:
                        try:
                            res_pl, msg_pl = youtube_api.add_video_to_playlist(yt, vid_id, pid)
                            pid_short = pid[-4:] if len(pid) > 4 else pid
                            if res_pl: log_func(f"   -> Added to PL (..{pid_short}): OK")
                            else: log_func(f"   -> Add PL Failed (..{pid_short}): {msg_pl}")
                        except Exception as e_pl: log_func(f"   -> Playlist Error: {e_pl}")

                # C. Save Done (Vẫn lưu để đánh dấu folder này đã xong, tránh upload lại)
                log_data = {
                    "video_id": vid_id, 
                    "status": "Scheduled", 
                    "publish_time": str(pub_time), 
                    "account": config['acc'],
                    "title": data['title']
                }
                with open(os.path.join(folder, "done.json"), "w", encoding="utf-8") as f: 
                    json.dump(log_data, f, indent=4)
                
                log_func(f"[{acc_display}] -> SUCCESS ID: {vid_id}")
                count_ok += 1
                
            except Exception as e:
                err_msg = str(e)
                if "QUOTA_EXCEEDED" in err_msg or "quotaExceeded" in err_msg:
                    ui_update("QUOTA LIMIT", "danger")
                    log_func(f"[{acc_display}] STOPPED: YouTube API Quota Exceeded.")
                    return
                else:
                    ui_update(f"{step_str} Error", "danger")
                    log_func(f"[{acc_display}] Failed: {err_msg}")
                    time.sleep(5)
                    
        ui_update(f"DONE ({count_ok})", "success")
        log_func(f"[{acc_display}] FINISHED. Uploaded {count_ok} videos.")
        
    except Exception as e:
        ui_update("Crash", "danger")
        log_func(f"[{acc_display}] CRASH: {e}")
    finally:
        row_widgets['running'] = False
        try: btn_pause.config(state="disabled")
        except: pass