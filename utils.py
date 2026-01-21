# utils.py
import os
import glob
import datetime
import json
import time
from googleapiclient.errors import HttpError
from config import YT_CATEGORIES
import youtube_api

def scan_folder_for_video(folder_path):
    if not os.path.exists(folder_path): return None
    
    # 1. Chỉ tìm file Video (Bỏ .mp3 vì YouTube API video upload không hỗ trợ audio-only)
    # Các định dạng phổ biến: mp4, mov, avi, mkv
    extensions = ("*.mp4", "*.mov", "*.avi", "*.mkv")
    vids = []
    for ext in extensions:
        vids.extend(glob.glob(os.path.join(folder_path, ext)))
        vids.extend(glob.glob(os.path.join(folder_path, ext.upper()))) # Hỗ trợ đuôi viết hoa
        
    if not vids: return None # Không có video thì bỏ qua
    
    # 2. Tìm Ảnh
    imgs = glob.glob(os.path.join(folder_path, "*.jpg")) + \
           glob.glob(os.path.join(folder_path, "*.png")) + \
           glob.glob(os.path.join(folder_path, "*.jpeg"))
    
    # 3. Tìm file Text
    txt_files = glob.glob(os.path.join(folder_path, "*.txt"))
    info_path = txt_files[0] if txt_files else None
    
    # Mặc định lấy tên file video làm tiêu đề
    title = os.path.splitext(os.path.basename(vids[0]))[0]
    title = title.replace("_", " ") # Làm đẹp tiêu đề
    tags = []; desc = ""
    
    if info_path and os.path.exists(info_path):
        try:
            # Thêm errors='ignore' để tránh crash nếu file text bị lỗi font
            with open(info_path, "r", encoding="utf-8", errors='ignore') as f: 
                lines = f.readlines()
            
            current_mode = None
            raw_title, raw_desc, raw_tags = [], [], []
            
            for line in lines:
                clean = line.strip()
                # Parse từ khóa
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
                
                # Nạp dữ liệu đa dòng
                if current_mode == "title" and clean: raw_title.append(clean)
                elif current_mode == "desc": raw_desc.append(line.rstrip())
                elif current_mode == "tags" and clean: raw_tags.append(clean)
            
            if raw_title: title = " ".join(raw_title).strip()
            if raw_desc: desc = "\n".join(raw_desc).strip()
            if raw_tags: 
                # Xử lý tags: nối lại rồi tách bằng dấu phẩy
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

def calculate_schedule_time(last_time, slots_string, day_gap):
    now = datetime.datetime.now().astimezone()
    
    # Parse danh sách giờ (VD: "08:00, 19:00")
    slots = []
    if slots_string:
        for s in slots_string.replace(";", ",").split(","): # Hỗ trợ cả dấu ;
            try: slots.append(datetime.datetime.strptime(s.strip(), "%H:%M").time())
            except: pass
    
    if not slots: slots = [datetime.time(8, 0)] # Mặc định 8h sáng nếu lỗi
    slots.sort()
    gap = int(day_gap)

    # Trường hợp 1: Chưa có video nào đăng trước đó (Lần chạy đầu tiên)
    if not last_time:
        base_date = now.date()
        # Tìm slot còn trống trong ngày hôm nay
        for s in slots:
            dt = datetime.datetime.combine(base_date, s).replace(tzinfo=now.tzinfo)
            if dt > now + datetime.timedelta(minutes=10): # Phải lớn hơn hiện tại ít nhất 10p
                return dt
        
        # Nếu hôm nay hết slot, sang ngày mai (slot đầu tiên)
        next_dt = datetime.datetime.combine(base_date + datetime.timedelta(days=1), slots[0]).replace(tzinfo=now.tzinfo)
        return next_dt

    # Trường hợp 2: Đã có video đăng trước đó -> Tính tiếp
    base_date = last_time.date()
    # Tìm slot tiếp theo trong cùng ngày của last_time
    for s in slots:
        dt_candidate = datetime.datetime.combine(base_date, s).replace(tzinfo=last_time.tzinfo)
        if dt_candidate > last_time:
            return dt_candidate 

    # Nếu hết slot trong ngày -> Cộng thêm gap ngày
    days_to_add = 1 + gap
    next_date = base_date + datetime.timedelta(days=days_to_add)
    return datetime.datetime.combine(next_date, slots[0]).replace(tzinfo=last_time.tzinfo)

def run_job_thread(row_widgets, config, log_func, pause_event):
    COLOR_MAP = {"primary": "#007bff", "secondary": "#6c757d", "success": "#28a745", "info": "#17a2b8", "warning": "#ffc107", "danger": "#dc3545", "black": "black"}
    
    # Hàm update UI an toàn (thread-safe)
    def ui_update(text, color_key="black"): 
        try:
            row_widgets['stat'].config(text=text, foreground=COLOR_MAP.get(color_key, "black"))
        except: pass
    
    acc_display = config['acc'].replace(".json", "")
    btn_pause = row_widgets['btn_pause']
    
    try:
        # 1. KẾT NỐI
        try:
            btn_pause.config(state="normal", text="⏸", bootstyle="primary")
        except: pass
        
        log_func(f"[{acc_display}] Init Process...")
        ui_update("Connecting...", "primary")
        
        yt = youtube_api.get_authenticated_service(config['acc'], config['secret'])
        if not yt: 
            ui_update("Login Error", "danger")
            log_func(f"[{acc_display}] Error: Cannot Login (Check Token/Secret)")
            return

        # 2. QUÉT FOLDER
        ui_update("Scanning...", "info")
        # Tìm các folder con
        subfolders = sorted([f.path for f in os.scandir(config['folder']) if f.is_dir()])
        
        # Nếu không có folder con, check xem chính folder đó có video không (chế độ single folder)
        if not subfolders:
            check_root = scan_folder_for_video(config['folder'])
            if check_root: subfolders = [config['folder']]

        if not subfolders: 
            ui_update("NO VIDEO", "danger")
            log_func(f"[{acc_display}] Folder empty or no video files!")
            return
            
        # Lọc ra các folder chưa có file done.json
        pending = [f for f in subfolders if not os.path.exists(os.path.join(f, "done.json"))]
        
        if not pending:
            ui_update("ALL DONE", "success")
            log_func(f"[{acc_display}] All videos uploaded.")
            return
        
        log_func(f"[{acc_display}] Found {len(pending)} videos to upload.")
        
        # 3. VÒNG LẶP UPLOAD
        count_ok = 0
        last_time_cursor = None # Dùng để tính giờ video tiếp theo
        
        for idx, folder in enumerate(pending):
            # Check Pause
            if not pause_event.is_set():
                ui_update("Paused", "warning")
                try: btn_pause.config(text="▶", bootstyle="primary-outline")
                except: pass
                pause_event.wait()
                try: btn_pause.config(text="⏸", bootstyle="primary")
                except: pass

            ui_update(f"Up {idx+1}/{len(pending)}", "warning")
            
            # Quét dữ liệu video
            data = scan_folder_for_video(folder)
            if not data: 
                log_func(f"[{acc_display}] Skip: No valid video in {os.path.basename(folder)}")
                continue
            
            # Tính giờ đăng
            pub_time = calculate_schedule_time(last_time_cursor, config['time'], config['gap'])
            last_time_cursor = pub_time
            
            log_func(f"[{acc_display}] Uploading: {data['title']}")
            log_func(f"   -> Schedule: {pub_time.strftime('%H:%M %d/%m/%Y')}")
            
            try:
                def on_progress(msg): 
                    if "Uploading" in msg: ui_update(msg, "warning")
                
                cat_id = YT_CATEGORIES.get(config['cat_name'], "default")
                
                # GỌI API UPLOAD
                vid_id = youtube_api.execute_upload(yt, data, pub_time, cat_id, on_progress, pause_event, log_func)
                
                # THÊM PLAYLIST
                if config.get('playlist_id'):
                    ui_update("Sync PL...", "info")
                    time.sleep(2) # Đợi chút cho YouTube server
                    res_pl, msg_pl = youtube_api.add_video_to_playlist(yt, vid_id, config['playlist_id'])
                    log_func(f"   -> Playlist: {msg_pl}")

                # GHI LOG DONE
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
                    log_func(f"[{acc_display}] STOPPED: YouTube API Quota Exceeded for today.")
                    return # Dừng luôn thread này
                else:
                    ui_update("Error", "danger")
                    log_func(f"[{acc_display}] Failed: {err_msg}")
                    # Không return, thử video tiếp theo
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