# gui.py
import os
import glob
import json
import shutil
import threading
import datetime
import tkinter as tk
from tkinter import filedialog
import tkinter.scrolledtext as st

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.widgets.scrolled import ScrolledFrame

import config
import license_manager
import youtube_api
import utils

class AutoYoutubeApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("YouTube Automation Tool - Stable Version")
        self.geometry("1900x950")
        
        self.is_licensed = False
        self.is_admin = False
        self.row_frames = []
        
        # Quản lý cửa sổ con
        self.win_settings = None
        self.win_secrets = None
        self.win_accounts = None
        self.win_admin_manager = None
        self.win_batch_add = None
        self.win_license = None

        # 1. Khởi tạo giao diện
        self.create_header()
        self.create_grid_header()
        self.create_scrollable_body()
        self.create_log_area()
        
        # 2. Load dữ liệu cũ
        self.load_dynamic_state()
        
        # 3. Kiểm tra bản quyền
        license_manager.init_firebase()
        self.after(500, self.check_local_license)

    # =========================================================================
    # CORE LOGIC: ĐỒNG BỘ DỮ LIỆU TOÀN CỤC
    # =========================================================================
    def refresh_global_ui(self):
        # 1. QUÉT DỮ LIỆU THỰC TẾ TRÊN Ổ CỨNG
        real_secrets = set(os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json")))
        real_tokens = set(os.path.basename(f) for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")))

        # 2. Tạo bản đồ Mapping (Client ID -> Danh sách Token Files)
        token_map = {}
        for t_file in real_tokens:
            full_path = os.path.join(config.TOKEN_DIR, t_file)
            try:
                with open(full_path, 'r') as jf:
                    cid = json.load(jf).get("client_id")
                    if cid:
                        if cid not in token_map: token_map[cid] = []
                        token_map[cid].append(t_file)
            except: pass

        all_secrets_list = sorted(list(real_secrets))
        
        # Danh sách mới để lưu những dòng còn tồn tại
        surviving_rows = []
        rows_changed = False

        # 3. DUYỆT QUA CÁC DÒNG HIỆN TẠI
        for r in self.row_frames:
            cur_sec = r['secret'].get()
            
            # --- KIỂM TRA QUAN TRỌNG: SECRET CÒN TỒN TẠI KHÔNG? ---
            # Nếu dòng này đã chọn Secret, nhưng file Secret đó không còn trên ổ cứng
            if cur_sec and cur_sec not in real_secrets:
                # -> HỦY DÒNG NÀY NGAY LẬP TỨC
                r['frame'].destroy() 
                rows_changed = True
                continue # Bỏ qua, không thêm vào surviving_rows

            # --- NẾU SECRET CÒN (HOẶC CHƯA CHỌN), TIẾP TỤC CẬP NHẬT UI ---
            
            # Cập nhật danh sách Secret trong Combobox
            r['secret']['values'] = all_secrets_list

            # --- CẤP 2: ACCOUNT (Logic Cascade Delete cũ) ---
            cur_acc = r['acc'].get()
            
            # Tính toán danh sách Account hợp lệ cho Secret này
            valid_accs = []
            if cur_sec:
                try:
                    cid = youtube_api.get_client_id_from_file(cur_sec)
                    valid_accs = token_map.get(cid, [])
                except: valid_accs = []
            
            # Cập nhật danh sách Account
            r['acc']['values'] = valid_accs

            # Kiểm tra xem Account có cần bị xóa không (file mất hoặc không khớp secret)
            should_clear_acc = False
            if cur_acc:
                if cur_acc not in real_tokens: should_clear_acc = True
                elif cur_acc not in valid_accs: should_clear_acc = True
            
            if should_clear_acc:
                 r['acc'].set('')
                 
                 # Xóa sạch dữ liệu Playlist (UI + Data)
                 try:
                     p_ent = r['playlist']
                     p_ent.config(state="normal")
                     p_ent.delete(0, tk.END)
                     p_ent.config(state="readonly")
                 except: pass
                 r['playlist_data']['playlist_map'] = {}
                 r['playlist_data']['selected_playlists'] = {}

            # Giữ lại dòng này
            surviving_rows.append(r)

        # 4. CẬP NHẬT LẠI DANH SÁCH QUẢN LÝ
        self.row_frames = surviving_rows

        # 5. NẾU CÓ DÒNG BỊ XÓA -> ĐÁNH SỐ LẠI STT (1, 2, 3...)
        if rows_changed:
            for i, r in enumerate(self.row_frames):
                r['lbl_idx'].config(text=str(i + 1))
            self.update_master_state() # Cập nhật checkbox Master

        self.update_idletasks()

    # =========================================================================
    # GUI COMPONENTS
    # =========================================================================
    def create_header(self):
        header = ttk.Frame(self, padding=10, bootstyle="secondary")
        header.pack(fill=X)
        
        self.lbl_title = ttk.Label(header, text="YOUTUBE AUTO UPLOADER (LOCKED)", 
                                   font=("Helvetica", 14, "bold"), bootstyle="inverse-secondary")
        self.lbl_title.pack(side=LEFT)
        
        bf = ttk.Frame(header, bootstyle="secondary")
        bf.pack(side=RIGHT)
        
        self.btn_admin_manager = ttk.Button(bf, text="🛡 Manager", bootstyle="primary", command=self.open_admin_panel)
        
        ttk.Button(bf, text="▶ START", bootstyle="success", command=self.on_start).pack(side=RIGHT, padx=5)
        ttk.Separator(bf, orient=VERTICAL).pack(side=RIGHT, padx=10, fill=Y)
        ttk.Button(bf, text="⚙ Settings", bootstyle="primary", command=self.open_settings).pack(side=RIGHT, padx=5)
        ttk.Button(bf, text="🔑 Secrets", bootstyle="primary", command=self.open_secret_manager).pack(side=RIGHT, padx=5)
        ttk.Button(bf, text="🗑 Accounts", bootstyle="primary", command=self.open_acc_manager).pack(side=RIGHT, padx=5)
        ttk.Separator(bf, orient=VERTICAL).pack(side=RIGHT, padx=10, fill=Y)
        ttk.Button(bf, text="+ 1 Row", bootstyle="primary", command=lambda: self.add_row()).pack(side=RIGHT, padx=5)
        ttk.Button(bf, text="➕ Batch Add", bootstyle="primary", command=self.open_batch_add).pack(side=RIGHT, padx=5)
        ttk.Button(bf, text="🔑 License", bootstyle="primary", command=self.open_license_dialog).pack(side=RIGHT, padx=5)

    def create_grid_header(self):
        cols_fr = ttk.Frame(self, padding=(10, 5)); cols_fr.pack(fill=X)
        self.master_chk = tk.BooleanVar(value=True)
        ttk.Checkbutton(cols_fr, variable=self.master_chk, command=self.toggle_all_rows).pack(side=LEFT, padx=(5, 10))
        headers = [("#", 3), ("Client Secret", 28), ("Video Folder", 40), ("YouTube Account", 28), ("Playlist", 26), ("Schedule Time", 32), ("Gap", 10), ("Category", 25), ("Status", 18), ("Pause", 8), ("", 5)]
        for text, w in headers: ttk.Label(cols_fr, text=text, width=w, font=("Segoe UI", 9, "bold"), anchor="center").pack(side=LEFT, padx=2)

    def create_scrollable_body(self):
        self.scroll_frame = ScrolledFrame(self, autohide=True); self.scroll_frame.pack(fill=BOTH, expand=True, padx=10)

    def create_log_area(self):
        lf = ttk.Labelframe(self, text="Activity Log", padding=5); lf.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.log_text = st.ScrolledText(lf, height=8, state='disabled', font=("Consolas", 10))
        self.log_text.pack(fill=BOTH, expand=True)
        self.log_text.tag_config("ts", foreground="gray")
        self.log_text.tag_config("INFO", foreground="#007bff")
        self.log_text.tag_config("ERROR", foreground="#dc3545")
        self.log_text.tag_config("msg", foreground="black")

    # =========================================================================
    # SYSTEM NOTIFICATIONS (CHANGED TO LOGS)
    # =========================================================================
    def popup_info(self, title, message):
        self.log(f"[INFO] {title}: {message}", tag="INFO")

    def popup_error(self, title, message):
        self.log(f"[ERROR] {title}: {message}", tag="ERROR")
    
    def popup_confirm(self, title, message):
        w = ttk.Toplevel(self); w.title(title); w.geometry("450x220"); self._center_window(w)
        ttk.Label(w, text=title.upper(), font=("Helvetica", 12, "bold"), bootstyle="warning").pack(pady=(15, 10))
        ttk.Label(w, text=message, font=("Helvetica", 11), wraplength=400, justify="center").pack(pady=10, padx=10)
        res = [False]
        def y(): res[0]=True; w.destroy()
        def n(): w.destroy()
        bf = ttk.Frame(w); bf.pack(pady=20)
        ttk.Button(bf, text="YES", bootstyle="danger", width=12, command=y).pack(side=LEFT, padx=10)
        ttk.Button(bf, text="CANCEL", bootstyle="secondary", width=12, command=n).pack(side=LEFT, padx=10)
        self.wait_window(w)
        return res[0]

    def popup_input(self, title, prompt, initial_value=""):
        w = ttk.Toplevel(self); w.title(title); w.geometry("500x250"); self._center_window(w)
        ttk.Label(w, text=prompt, font=("Helvetica", 11, "bold")).pack(pady=(20,10), padx=20, anchor="w")
        ent = ttk.Entry(w, font=("Helvetica", 11)); ent.pack(fill=X, padx=20, pady=5)
        if initial_value: ent.insert(0, initial_value)
        ent.focus_set(); res = [None]
        def ok(): res[0]=ent.get(); w.destroy()
        def cc(): w.destroy()
        bf = ttk.Frame(w); bf.pack(pady=20)
        ttk.Button(bf, text="OK", bootstyle="primary", width=10, command=ok).pack(side=LEFT, padx=5)
        ttk.Button(bf, text="Cancel", bootstyle="secondary", width=10, command=cc).pack(side=LEFT, padx=5)
        self.wait_window(w)
        return res[0]

    def _center_window(self, win):
        win.update_idletasks()
        try:
            x = self.winfo_x() + (self.winfo_width()//2) - (win.winfo_width()//2)
            y = self.winfo_y() + (self.winfo_height()//2) - (win.winfo_height()//2)
            win.geometry(f"+{x}+{y}")
        except: pass

    # =========================================================================
    # LICENSE LOGIC (FIXED SYNTAX ERROR)
    # =========================================================================
    def check_local_license(self):
        if os.path.exists(config.LICENSE_FILE):
            try:
                with open(config.LICENSE_FILE, "r") as f:
                    self.verify_license_online(f.read().strip(), silent_fail=True)
            except: pass
    
    def open_license_dialog(self):
        # 1. Đóng các cửa sổ khác
        self.close_all_popups()
        
        # 2. Tạo cửa sổ quản lý
        self.win_license = ttk.Toplevel(self)
        w = self.win_license
        w.title("License Information")
        w.geometry("500x300")
        self._center_window(w)
        
        # --- Giao diện chi tiết ---
        
        # Tiêu đề trạng thái
        status_text = "STATUS: ACTIVATED" if self.is_licensed else "STATUS: LOCKED"
        status_color = "success" if self.is_licensed else "danger"
        
        ttk.Label(w, text=status_text, font=("Helvetica", 14, "bold"), bootstyle=status_color).pack(pady=20)
        
        # Đọc key hiện tại
        cur_key = ""
        if os.path.exists(config.LICENSE_FILE):
            try:
                with open(config.LICENSE_FILE, "r") as f:
                    cur_key = f.read().strip()
            except: pass
            
        ttk.Label(w, text="License Key / Admin Code:", font=("Bold", 10)).pack(anchor=W, padx=20)
        
        ent = ttk.Entry(w, font=("Helvetica", 11))
        ent.pack(fill=X, padx=20, pady=5)
        ent.insert(0, cur_key)
        
        def do_verify():
            k = ent.get().strip()
            if not k:
                self.popup_error("Error", "Please enter a key")
                return
            
            # Gọi hàm kiểm tra (đã có sẵn logic update UI)
            self.verify_license_online(k)
            
            # Cập nhật lại giao diện cửa sổ này ngay lập tức
            if self.is_licensed:
                w.destroy() # Đóng luôn nếu thành công (hoặc bạn có thể đổi Label thành Success)
                self.popup_info("Success", "License Activated Successfully!")
            else:
                self.popup_error("Failed", "Invalid License Key!")

        bf = ttk.Frame(w)
        bf.pack(pady=20, fill=X, padx=20)
        
        ttk.Button(bf, text="CHECK / ACTIVATE", bootstyle="primary", command=do_verify).pack(fill=X, pady=5)
        
        if self.is_licensed:
             ttk.Label(w, text="✔ Your application is fully functional.", foreground="green").pack()
        else:
             ttk.Label(w, text="⚠ Features are restricted.", foreground="red").pack()

    def verify_license_online(self, key, silent_fail=False):
        v, m = license_manager.check_license_key(key)
        if v:
            if m == "ADMIN":
                self.is_licensed=True; self.is_admin=True
                self.lbl_title.config(text="YOUTUBE UPLOADER (ADMIN MODE)")
                self.btn_admin_manager.pack(side=RIGHT, padx=5)
                if not silent_fail: self.log(f"License: Admin Access Granted.", tag="INFO")
            else:
                self.is_licensed=True; self.is_admin=False; self.btn_admin_manager.pack_forget()
                self.lbl_title.config(text=f"ACTIVATED: {key}")
                if not silent_fail: self.log(f"License: Key '{key}' Validated.", tag="INFO")
            with open(config.LICENSE_FILE, "w") as f: f.write(key)
        else:
            self.is_licensed=False; self.lbl_title.config(text="LOCKED")
            if not silent_fail: self.log(f"License Check Failed: {m}", tag="ERROR")

    def check_access(self):
        if not self.is_licensed: 
            self.log("Access Denied: Please enter a valid License first.", tag="ERROR")
            return False
        return True

    # =========================================================================
    # LOGIC GRID & ROWS
    # =========================================================================
    def add_row(self, initial_data=None):
        idx = len(self.row_frames) + 1
        data = initial_data if initial_data else {}
        
        fr = ttk.Frame(self.scroll_frame, padding=(0, 2)); fr.pack(fill=X)
        
        chk_var = tk.BooleanVar(value=data.get('chk', True))
        ttk.Checkbutton(fr, variable=chk_var, command=self.update_master_state).pack(side=LEFT, padx=(5, 10))
        lbl_idx = ttk.Label(fr, text=str(idx), width=3, anchor="center"); lbl_idx.pack(side=LEFT)
        
        # --- 1. SECRET ---
        sec_cb = ttk.Combobox(fr, state="readonly", width=28); sec_cb.pack(side=LEFT, padx=2)
        try: sec_files = [os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json"))]
        except: sec_files = []
        sec_cb['values'] = sec_files
        saved_sec = data.get('secret')
        if saved_sec and saved_sec in sec_files: sec_cb.set(saved_sec)
        
        # --- 2. FOLDER ---
        fol_ent = ttk.Entry(fr, width=38); fol_ent.pack(side=LEFT, padx=2)
        fol_ent.insert(0, data.get('folder') or "")
        
        def validate_folder(event):
            path = fol_ent.get().strip()
            if not path: return
            try:
                current_norm = os.path.normpath(path).lower()
                for r in self.row_frames:
                    if r['folder'] != fol_ent and r['folder'].get():
                        if os.path.normpath(r['folder'].get()).lower() == current_norm:
                            self.popup_error("Duplicate Folder", f"Folder used in Row {r['lbl_idx'].cget('text')}.")
                            fol_ent.delete(0, tk.END); return
            except: pass
        fol_ent.bind("<FocusOut>", validate_folder)
        ttk.Button(fr, text="📂", width=3, bootstyle="primary-outline", command=lambda: self.browse_folder(fol_ent, idx)).pack(side=LEFT, padx=(0,5))

        # --- 3. ACCOUNT & PLAYLIST (MULTI-SELECT) ---
        acc_cb = ttk.Combobox(fr, state="readonly", width=28); acc_cb.pack(side=LEFT, padx=2)
        playlist_ent = ttk.Entry(fr, state="readonly", width=25); playlist_ent.pack(side=LEFT, padx=2)
        
        row_data = {'playlist_map': {}, 'selected_playlists': {}}

        # --- HÀM CẬP NHẬT LIST ACCOUNT (NEW CHANGE: HIỆN TOÀN BỘ ĐỂ CHECK TRÙNG) ---
        def update_acc_list(e=None):
            sec = sec_cb.get()
            if not sec: 
                acc_cb['values'] = []
                return

            # 1. Lấy Client ID từ file Secret hiện tại
            cid = youtube_api.get_client_id_from_file(sec)
            
            # 2. Tìm tất cả file token trên ổ cứng khớp với Secret này
            all_valid_tokens = []
            if cid:
                for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                    try:
                        # Dùng open thông thường để đọc nhanh
                        if json.load(open(f)).get("client_id") == cid: 
                            all_valid_tokens.append(os.path.basename(f))
                    except: pass
            
            # 3. Tìm các Account đang bị chiếm dụng bởi các dòng KHÁC
            used_accounts = set()
            for r in self.row_frames:
                # Quan trọng: Không tính dòng hiện tại (r['acc'] != acc_cb)
                # Để nếu dòng này đang chọn Account A, thì Account A vẫn hiện trong list
                if r['acc'] != acc_cb:
                    val = r['acc'].get()
                    if val:
                        used_accounts.add(val)

            # 4. Lọc danh sách: Chỉ lấy cái nào KHÔNG nằm trong used_accounts
            final_list = [acc for acc in all_valid_tokens if acc not in used_accounts]
            
            acc_cb['values'] = final_list

        # --- COPY LẠI HÀM open_playlist_selector TỪ CODE CŨ (GIỮ NGUYÊN) ---
        # (Để ngắn gọn tôi không paste lại đoạn Playlist Selector dài dòng ở đây, 
        # bạn hãy giữ nguyên logic Playlist Selector như code trước của bạn)
        def open_playlist_selector(e=None):
            # --- BƯỚC 1: KIỂM TRA ĐIỀU KIỆN ---
            current_acc = acc_cb.get()
            
            # Nếu chưa chọn Account: Chặn luôn + Xóa rác
            if not current_acc: 
                self.popup_error("Error", "Please select an Account first.")
                row_data['playlist_map'] = {}
                row_data['selected_playlists'] = {}
                playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END); playlist_ent.config(state="readonly")
                return

            # Nếu có Account nhưng chưa có dữ liệu Playlist (Loading hoặc Lỗi)
            if not row_data['playlist_map']:
                status_text = playlist_ent.get()
                
                # Nếu đang loading hoặc lỗi API -> Không mở cửa sổ
                if status_text in ["Loading...", "Login Error", "API Error"]: 
                    return
                
                # Nếu trống trơn (do lỗi mạng trước đó), thử tải lại
                self.popup_info("Info", "No playlists found or list is empty. Trying to reload...")
                load_pl(current_acc, sec_cb.get())
                return

            # --- BƯỚC 2: KHỞI TẠO CỬA SỔ (TÀNG HÌNH) ---
            p = ttk.Toplevel(self)
            p.attributes('-alpha', 0.0) # Ẩn để vẽ layout trước
            p.title("Playlist Selector")
            
            # --- Header: Tìm kiếm ---
            head_fr = ttk.Frame(p, padding=10)
            head_fr.pack(fill=X)
            
            search_var = tk.StringVar()
            entry_search = ttk.Entry(head_fr, textvariable=search_var, font=("Segoe UI", 10))
            entry_search.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
            entry_search.insert(0, "Search...")
            
            def on_focus_in(e):
                if entry_search.get() == "Search...": entry_search.delete(0, tk.END)
            entry_search.bind("<FocusIn>", on_focus_in)

            # --- Body: Danh sách cuộn ---
            body_fr = ScrolledFrame(p, autohide=True)
            body_fr.pack(fill=BOTH, expand=True, padx=10)
            
            # --- Footer: Nút bấm ---
            foot_fr = ttk.Frame(p, padding=10, bootstyle="light")
            foot_fr.pack(fill=X, side=BOTTOM)
            
            lbl_count = ttk.Label(foot_fr, text="Selected: 0", font=("Bold", 10), bootstyle="inverse-light")
            lbl_count.pack(side=LEFT)

            # --- Logic Render List ---
            vars_map = {} 
            # Khởi tạo trạng thái checkbox dựa trên dữ liệu đã lưu
            for pid in row_data['playlist_map'].values():
                is_selected = pid in row_data['selected_playlists']
                vars_map[pid] = tk.BooleanVar(value=is_selected)

            def update_count():
                cnt = sum(1 for v in vars_map.values() if v.get())
                lbl_count.config(text=f"Selected: {cnt}")

            def render_list(filter_text=""):
                for widget in body_fr.winfo_children(): widget.destroy()
                filter_text = filter_text.lower() if filter_text != "search..." else ""
                
                items_to_draw = []
                for name, pid in row_data['playlist_map'].items():
                    if filter_text and filter_text not in name.lower(): continue
                    items_to_draw.append((name, pid))
                
                if not items_to_draw:
                    ttk.Label(body_fr, text="No matches found").pack(pady=10)

                for name, pid in items_to_draw:
                    row = ttk.Frame(body_fr, padding=(5, 5))
                    row.pack(fill=X, pady=1)
                    
                    var = vars_map[pid]
                    chk = ttk.Checkbutton(row, text=name, variable=var, command=update_count)
                    chk.pack(side=LEFT, fill=X, expand=True)
                    
                    # Hiệu ứng hover
                    row.bind("<Enter>", lambda e, r=row: r.configure(bootstyle="info"))
                    row.bind("<Leave>", lambda e, r=row: r.configure(bootstyle="default"))
                    
                    # Click vào dòng cũng tích vào checkbox
                    def toggle(e, v=var): v.set(not v.get()); update_count()
                    row.bind("<Button-1>", toggle)

            # Trigger vẽ lần đầu
            search_var.trace("w", lambda *args: render_list(search_var.get()))

            # --- Các nút chức năng ---
            def select_all():
                for v in vars_map.values(): v.set(True)
                update_count()
            def clear_all():
                for v in vars_map.values(): v.set(False)
                update_count()

            btn_all = ttk.Button(head_fr, text="All", width=4, bootstyle="secondary-outline", command=select_all)
            btn_all.pack(side=RIGHT)
            ttk.Button(head_fr, text="None", width=5, bootstyle="secondary-outline", command=clear_all).pack(side=RIGHT, padx=2)

            def save_selection():
                new_selected = {}
                display_names = []
                
                # Tạo map ngược ID -> Name để lấy tên hiển thị
                pid_to_name = {pid: name for name, pid in row_data['playlist_map'].items()}
                
                for pid, var in vars_map.items():
                    if var.get():
                        name = pid_to_name.get(pid, "Unknown")
                        new_selected[pid] = name
                        display_names.append(name)
                
                # Cập nhật dữ liệu vào memory của dòng này
                row_data['selected_playlists'] = new_selected
                
                # Cập nhật hiển thị ra Entry bên ngoài
                playlist_ent.config(state="normal")
                playlist_ent.delete(0, tk.END)
                
                if not display_names: 
                    playlist_ent.insert(0, "No Playlist")
                elif len(display_names) == 1: 
                    playlist_ent.insert(0, display_names[0])
                else: 
                    playlist_ent.insert(0, f"{len(display_names)} Playlists selected")
                
                playlist_ent.config(state="readonly")
                p.destroy()

            ttk.Button(foot_fr, text="SAVE SELECTION", bootstyle="success", command=save_selection).pack(side=RIGHT)

            render_list()
            update_count()
            
            # --- BƯỚC 3: HIỂN THỊ (SHOW) ---
            p.update_idletasks() # Tính toán layout
            
            width = 450
            height = 550
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            x = (screen_width // 2) - (width // 2)
            y = (screen_height // 2) - (height // 2)
            
            p.geometry(f"{width}x{height}+{x}+{y}")
            p.attributes('-alpha', 1.0) # Hiện hình
            
            p.transient(self)
            p.grab_set()
            p.focus_set()
            self.wait_window(p)

        def load_pl(acc, sec):
            if not acc or not sec: return
            playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END); playlist_ent.insert(0, "Loading..."); playlist_ent.config(state="readonly")
            def t():
                try:
                    yt = youtube_api.get_authenticated_service(acc, sec)
                    if yt: self.after(0, lambda: _apply(youtube_api.get_user_playlists(yt)))
                    else: self.after(0, lambda: _err("Login Error"))
                except: self.after(0, lambda: _err("API Error"))
            
            def _err(tx):
                playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END); playlist_ent.insert(0, tx); playlist_ent.config(state="readonly")

            def _apply(pls):
                row_data['playlist_map'] = pls
                saved_ids = data.get('playlist_ids', []) or ([data.get('playlist_id')] if data.get('playlist_id') else [])
                cur_sel = {pid: name for name, pid in pls.items() if pid in saved_ids}
                row_data['selected_playlists'] = cur_sel
                names = list(cur_sel.values())
                playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END)
                if not names: playlist_ent.insert(0, "No Playlist")
                elif len(names) == 1: playlist_ent.insert(0, names[0])
                else: playlist_ent.insert(0, f"{len(names)} Playlists selected")
                playlist_ent.config(state="readonly")
            threading.Thread(target=t, daemon=True).start()

        # --- NEW CHANGE: HÀM KIỂM TRA TRÙNG LẶP KHI CHỌN ---
        def on_acc_select(e):
            val = acc_cb.get()
            
            # --- TRƯỜNG HỢP 1: Tài khoản bị xóa về rỗng ---
            # (Người dùng xóa text hoặc chọn dòng trống)
            if not val:
                # 1. Xóa dữ liệu trong bộ nhớ (Quan trọng)
                row_data['playlist_map'] = {}
                row_data['selected_playlists'] = {}
                
                # 2. Xóa hiển thị trên giao diện
                playlist_ent.config(state="normal")
                playlist_ent.delete(0, tk.END)
                playlist_ent.config(state="readonly")
                return

            # --- TRƯỜNG HỢP 2: Kiểm tra trùng lặp trên Grid ---
            for r in self.row_frames:
                # Bỏ qua chính dòng hiện tại
                if r['acc'] == acc_cb: continue
                
                # Nếu tìm thấy dòng khác đang dùng tài khoản này
                if r['acc'].get() == val:
                    used_at_row = r['lbl_idx'].cget('text')
                    self.popup_error("Duplicate Account", f"Account '{val}' is already active at Row {used_at_row}.")
                    
                    # Reset ô Account về rỗng
                    acc_cb.set('')
                    
                    # Xóa sạch dữ liệu Playlist (để không lưu rác của acc trùng)
                    row_data['playlist_map'] = {}
                    row_data['selected_playlists'] = {}
                    
                    # Reset ô Playlist về rỗng
                    playlist_ent.config(state="normal")
                    playlist_ent.delete(0, tk.END)
                    playlist_ent.config(state="readonly")
                    return 

            # --- TRƯỜNG HỢP 3: Hợp lệ -> Tải Playlist từ API ---
            load_pl(val, sec_cb.get())

        playlist_ent.bind("<Button-1>", open_playlist_selector)
        sec_cb.bind("<<ComboboxSelected>>", lambda e: [acc_cb.set(''), update_acc_list()])
        acc_cb.bind("<<ComboboxSelected>>", on_acc_select)
        acc_cb.bind("<Button-1>", update_acc_list)

        if sec_cb.get():
            update_acc_list()
            # Logic load lại trạng thái cũ cũng cần kiểm tra trùng
            if data.get('acc') and data.get('acc') in acc_cb['values']:
                acc_cb.set(data.get('acc')); load_pl(data.get('acc'), sec_cb.get())

        # --- NEW CHANGE: HÀM THÊM MỚI TÀI KHOẢN (+) ---
        def qa():
            s = sec_cb.get()
            if not s: self.popup_error("Err", "Select Secret"); return
            def t():
                n, e = youtube_api.create_new_login(s) # n là tên file token
                if n: 
                    # Logic kiểm tra sau khi đăng nhập thành công
                    def check_and_set():
                        # 1. Quét xem file n này có đang dùng ở dòng nào không
                        used_in_row = None
                        for r in self.row_frames:
                             if r['acc'].get() == n:
                                 used_in_row = r['lbl_idx'].cget('text')
                                 break
                        
                        self.refresh_global_ui() # Làm mới list trước

                        if used_in_row:
                            self.popup_error("Exists", f"Login successful but Account '{n}' is already used at Row {used_in_row}.")
                            # Không set vào ô này để tránh trùng
                        else:
                            self.popup_info("OK", f"Added New Account: {n}")
                            acc_cb.set(n)
                            load_pl(n, s)

                    self.after(0, check_and_set)

            threading.Thread(target=t, daemon=True).start()

        ttk.Button(fr, text="+", width=3, bootstyle="primary-outline", command=qa).pack(side=LEFT, padx=(0,5))

        # --- (PHẦN CÒN LẠI GIỮ NGUYÊN) ---
        tm = ttk.Entry(fr, width=33, justify="center"); tm.pack(side=LEFT, padx=2); tm.insert(0, data.get('time', "08:00, 19:00"))
        gap = ttk.Spinbox(fr, from_=0, to=30, width=5, justify="center"); gap.pack(side=LEFT, padx=2); gap.set(data.get('gap', 0))
        cat = ttk.Combobox(fr, state="readonly", values=list(config.YT_CATEGORIES.keys()), width=25); cat.pack(side=LEFT, padx=2)
        cat.set(data.get('cat', "Default (From Settings)"))
        stat = ttk.Label(fr, text="Ready", foreground="gray", width=22, anchor="center"); stat.pack(side=LEFT, padx=5)
        pe = threading.Event(); pe.set()
        
        def toggle_pause():
            if pe.is_set(): pe.clear(); bp.config(text="▶", bootstyle="warning"); stat.config(text="Pausing...", foreground="#ffc107")
            else: pe.set(); bp.config(text="⏸", bootstyle="primary"); stat.config(text="Resuming...", foreground="#007bff")
        bp = ttk.Button(fr, text="⏸", width=4, bootstyle="primary", state="disabled", command=toggle_pause); bp.pack(side=LEFT, padx=2)

        def dele(): 
            fr.destroy(); self.row_frames.remove(row_widgets); self.update_master_state()
            for i,r in enumerate(self.row_frames): r['lbl_idx'].config(text=str(i+1))
        ttk.Button(fr, text="X", width=4, bootstyle="primary-outline", command=dele).pack(side=LEFT, padx=5)

        row_widgets = {
            'frame': fr, 'lbl_idx': lbl_idx, 'chk': chk_var, 
            'secret': sec_cb, 'folder': fol_ent, 'acc': acc_cb, 
            'playlist': playlist_ent, 'playlist_data': row_data, 
            'time': tm, 'gap': gap, 'cat': cat, 'stat': stat, 
            'pause_event': pe, 'btn_pause': bp, 'running': False
        }
        self.row_frames.append(row_widgets)

    def browse_folder(self, entry, idx):
        d = filedialog.askdirectory()
        if d:
            try:
                # Chuẩn hóa đường dẫn để so sánh (chuyển về chữ thường, xử lý dấu gạch chéo)
                np = os.path.normpath(d).lower()
                
                for r in self.row_frames:
                    # Bỏ qua chính dòng đang thao tác (dựa vào idx)
                    if r['lbl_idx'].cget('text') == str(idx): 
                        continue
                    
                    other_path = r['folder'].get()
                    if other_path:
                        try:
                            np_other = os.path.normpath(other_path).lower()
                            if np == np_other:
                                self.popup_error("Duplicate Folder", f"Folder is already used in Row {r['lbl_idx'].cget('text')}.")
                                return # Dừng lại, không điền vào entry
                        except: pass
                
                # Nếu không trùng thì điền vào
                entry.delete(0, tk.END)
                entry.insert(0, d)
            except Exception as e:
                self.log(f"Error checking folder path: {e}", tag="ERROR")

    def load_dynamic_state(self):
        try:
            with open(config.GRID_STATE_FILE, "r") as f:
                saved = json.load(f)
                if isinstance(saved, dict): 
                    for k in sorted(saved.keys(), key=lambda x: int(x)): self.add_row(saved[k])
                else: self.add_row()
        except: self.add_row()
        self.update_master_state()

    def update_master_state(self):
        if not self.row_frames: self.master_chk.set(False); return
        self.master_chk.set(all(r['chk'].get() for r in self.row_frames))

    def toggle_all_rows(self):
        for r in self.row_frames: r['chk'].set(self.master_chk.get())

    def save_state(self):
        state = {}
        for i, r in enumerate(self.row_frames):
            # --- SỬA ĐỔI: Lấy danh sách ID từ biến playlist_data ---
            # r['playlist_data'] là cái dict row_data ta tạo trong add_row
            pl_ids = list(r['playlist_data']['selected_playlists'].keys())
            
            state[str(i+1)] = {
                "secret": r['secret'].get(), 
                "folder": r['folder'].get(), 
                "acc": r['acc'].get(),
                "time": r['time'].get(), 
                "cat": r['cat'].get(), 
                "gap": r['gap'].get(), 
                "chk": r['chk'].get(),
                "playlist_ids": pl_ids # <-- Lưu mảng ID (VD: ['id1', 'id2'])
            }
        config.save_json(config.GRID_STATE_FILE, state)

    # =========================================================================
    # MANAGERS
    # =========================================================================
    def open_batch_add(self):
        # 1. Kiểm tra quyền và đóng các cửa sổ cũ
        if not self.check_access(): return
        self.close_all_popups()
        
        # 2. Khởi tạo cửa sổ Batch Add
        self.win_batch_add = ttk.Toplevel(self)
        w = self.win_batch_add
        w.title("Batch Add Rows")
        w.geometry("500x600")
        self._center_window(w)
        
        # --- PHẦN 1: CHỌN SECRET ---
        ttk.Label(w, text="1. Select Secret (Client config):", font=("Bold", 10)).pack(anchor=W, padx=10, pady=(15, 5))
        
        # Lấy danh sách file secret
        try:
            secs = [os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json"))]
        except: 
            secs = []
            
        sb_secret = ttk.Combobox(w, values=secs, state="readonly", bootstyle="primary")
        sb_secret.pack(fill=X, padx=10)
        
        # --- PHẦN 2: DANH SÁCH TÀI KHOẢN ---
        ttk.Label(w, text="2. Select Accounts to Add:", font=("Bold", 10)).pack(anchor=W, padx=10, pady=(15, 5))
        
        # Khung cuộn chứa Checkbox tài khoản
        list_frame = ScrolledFrame(w, height=300)
        list_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Biến lưu trữ các Checkbox: list chứa tuple (account_filename, variable)
        batch_vars = []
        
        def load_accounts_for_secret(event=None):
            # Xóa danh sách cũ
            for widget in list_frame.winfo_children():
                widget.destroy()
            batch_vars.clear()
            
            secret_file = sb_secret.get()
            if not secret_file: return
            
            # Lấy Client ID từ file Secret để lọc Account tương ứng
            cid = youtube_api.get_client_id_from_file(secret_file)
            if not cid:
                ttk.Label(list_frame, text="Invalid Secret File", foreground="red").pack()
                return
            
            # Tìm các file token khớp với Client ID
            found_count = 0
            for token_path in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                try:
                    with open(token_path, 'r') as f:
                        data = json.load(f)
                        if data.get("client_id") == cid:
                            acc_name = os.path.basename(token_path)
                            
                            # Tạo Checkbox
                            var = tk.BooleanVar(value=True) # Mặc định chọn tất cả
                            
                            # Kiểm tra visual: Nếu account này đã có trên Grid thì đánh dấu màu xám (Optional UX)
                            # Nhưng logic chính vẫn nằm ở nút Add
                            display_text = acc_name
                            
                            chk = ttk.Checkbutton(list_frame, text=display_text, variable=var)
                            chk.pack(anchor=W, pady=2)
                            
                            batch_vars.append((acc_name, var))
                            found_count += 1
                except: pass
                
            if found_count == 0:
                ttk.Label(list_frame, text="No accounts found linked to this secret.", foreground="gray").pack(pady=10)

        # Gán sự kiện khi chọn Secret
        sb_secret.bind("<<ComboboxSelected>>", load_accounts_for_secret)
        
        # --- PHẦN 3: NÚT THÊM LOGIN MỚI ---
        def add_new_login():
            s = sb_secret.get()
            if not s: 
                self.popup_error("Error", "Please select a Secret file first.")
                return
            
            def thread_login():
                # Chạy login trên luồng riêng
                new_acc, err = youtube_api.create_new_login(s)
                if new_acc:
                    # Login thành công -> Refresh lại list để hiện tài khoản mới
                    self.after(0, lambda: [
                        load_accounts_for_secret(), # Tải lại danh sách
                        self.refresh_global_ui(),   # Đồng bộ UI chính
                        self.popup_info("Success", f"Added new account: {new_acc}")
                    ])
                else:
                    self.after(0, lambda: self.popup_error("Login Failed", f"Could not login.\n{err}"))
            
            threading.Thread(target=thread_login, daemon=True).start()

        ttk.Button(w, text="+ Login New Account", command=add_new_login, bootstyle="info-outline").pack(fill=X, padx=10, pady=5)
        
        # --- PHẦN 4: NÚT XÁC NHẬN (ADD TO GRID) ---
        def confirm_add_to_grid():
            secret_val = sb_secret.get()
            # Lấy danh sách các account được tích chọn
            selected_accs = [name for name, var in batch_vars if var.get()]
            
            if not secret_val:
                self.popup_error("Error", "Please select a Secret.")
                return
            if not selected_accs:
                self.popup_error("Error", "Please select at least one Account.")
                return
            
            # --- LOGIC KIỂM TRA TRÙNG LẶP ---
            # 1. Tạo tập hợp các account đang tồn tại trên Grid
            current_grid_accounts = set()
            for r in self.row_frames:
                acc_val = r['acc'].get()
                if acc_val:
                    current_grid_accounts.add(acc_val)
            
            added_count = 0
            skipped_list = []
            
            for acc in selected_accs:
                # 2. Nếu account đã có trên Grid -> Bỏ qua
                if acc in current_grid_accounts:
                    skipped_list.append(acc)
                else:
                    # 3. Nếu chưa có -> Thêm dòng mới
                    self.add_row({
                        "secret": secret_val,
                        "acc": acc,
                        "chk": True # Mặc định tick chọn dòng mới
                    })
                    added_count += 1
                    # Thêm vào set tạm thời để tránh trường hợp file bị duplicate ngay trong list chọn
                    current_grid_accounts.add(acc)
            
            # --- KẾT THÚC ---
            w.destroy()
            self.update_master_state() # Cập nhật checkbox tổng
            
            # Tạo thông báo kết quả
            msg = f"Successfully added {added_count} rows."
            
            if skipped_list:
                msg += f"\n\n⚠ Skipped {len(skipped_list)} accounts (Already on Grid):\n"
                # Liệt kê tối đa 5 account bị trùng để user biết
                preview = skipped_list[:5]
                for s_acc in preview:
                    msg += f"- {s_acc}\n"
                if len(skipped_list) > 5:
                    msg += f"... and {len(skipped_list)-5} others."
            
            if skipped_list and added_count == 0:
                self.popup_error("Batch Result", msg) # Dùng icon lỗi nếu không thêm được dòng nào
            else:
                self.popup_info("Batch Result", msg)

        # Nút hành động chính
        ttk.Separator(w, orient=HORIZONTAL).pack(fill=X, pady=10)
        ttk.Button(w, text="ADD TO GRID", bootstyle="success", command=confirm_add_to_grid).pack(fill=X, padx=10, pady=(0, 20))

    def open_settings(self):
        if not self.check_access(): return
        self.close_all_popups()
        self.win_settings = ttk.Toplevel(self); self.win_settings.title("Settings"); self.win_settings.geometry("450x550"); self._center_window(self.win_settings)
        fr = ttk.Frame(self.win_settings, padding=20); fr.pack(fill=BOTH, expand=True)
        d = config.CURRENT_SETTINGS
        
        ttk.Label(fr, text="Language:").pack(anchor=W)
        cl = ttk.Combobox(fr, values=list(config.YT_LANGUAGES.keys()), state="readonly"); cl.pack(fill=X, pady=(0,10))
        cur_l = d.get("languageCode", "en-US")
        for k,v in config.YT_LANGUAGES.items(): 
            if v == cur_l: cl.set(k); break
            
        ttk.Label(fr, text="Location:").pack(anchor=W)
        clo = ttk.Combobox(fr, values=list(config.YT_LOCATIONS.keys()), state="readonly"); clo.pack(fill=X, pady=(0,10))
        clo.set(d.get("locationKey"))
        
        ttk.Label(fr, text="Category:").pack(anchor=W)
        cc = ttk.Combobox(fr, values=list(config.YT_CATEGORIES.keys()), state="readonly"); cc.pack(fill=X, pady=(0,10))
        cur_c = d.get("categoryId", "22")
        for k,v in config.YT_CATEGORIES.items(): 
            if v == cur_c: cc.set(k); break
            
        ttk.Separator(fr).pack(fill=X, pady=15)
        def dl():
            f = filedialog.asksaveasfilename(parent=self.win_settings, defaultextension=".txt", initialfile="info_mau.txt")
            if f: 
                with open(f,"w",encoding="utf-8") as file: file.write("Title:\nExample Title\n\nVideo Description:\nExample Desc\n\nTags:\ntag1,tag2")
                self.popup_info("OK", f"Template saved to {f}")
        ttk.Button(fr, text="Download Template (info.txt)", bootstyle="info-outline", command=dl).pack(fill=X)
        
        def sv():
            nd = {"categoryId": config.YT_CATEGORIES.get(cc.get(),"22"), "languageCode": config.YT_LANGUAGES.get(cl.get(),"en-US"), "locationKey": clo.get()}
            config.CURRENT_SETTINGS = nd; config.save_json(config.SETTINGS_FILE, nd)
            self.win_settings.destroy(); self.popup_info("OK", "Settings Saved")
        ttk.Separator(fr).pack(fill=X, pady=15)
        ttk.Button(fr, text="SAVE CONFIG", bootstyle="primary", command=sv).pack(fill=X)

    def open_secret_manager(self):
        self.close_all_popups()
        
        self.win_secrets = ttk.Toplevel(self)
        self.win_secrets.title("Secrets Manager (Multi-Select)")
        self.win_secrets.geometry("500x500")
        self._center_window(self.win_secrets)
        
        lb = tk.Listbox(self.win_secrets, font=("Helvetica", 10), selectmode="extended")
        lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json")): 
                lb.insert(tk.END, os.path.basename(f))
            self.refresh_global_ui() 
            
        def ad(): 
            files = filedialog.askopenfilenames(title="Select Secret Files", filetypes=[("JSON Files", "*.json")])
            if files:
                count = 0
                for f in files:
                    try:
                        shutil.copy(f, config.SECRET_DIR)
                        count += 1
                    except: pass
                if count > 0:
                    rf(); self.popup_info("Import Success", f"Successfully imported {count} files.")
            
        def de():
            selection = lb.curselection()
            if not selection: return
            
            files_to_delete = [lb.get(i) for i in selection]
            msg = f"Are you sure you want to delete {len(files_to_delete)} secret file(s)?\n\nWARNING: All linked Accounts will also be deleted!"
            
            if self.popup_confirm("Batch Delete", msg):
                deleted_sec = 0
                deleted_acc = 0
                
                for fn in files_to_delete:
                    # --- XỬ LÝ AN TOÀN TỪNG FILE ---
                    try:
                        # 1. Lấy Client ID (Bọc try/except để tránh crash nếu file lỗi)
                        cid = None
                        try: cid = youtube_api.get_client_id_from_file(fn) 
                        except: pass 
                        
                        # 2. Xóa file Secret
                        secret_path = os.path.join(config.SECRET_DIR, fn)
                        if os.path.exists(secret_path):
                            try:
                                os.remove(secret_path)
                                deleted_sec += 1
                            except: pass # Nếu file đang mở bởi app khác thì bỏ qua

                        # 3. Xóa các Token liên quan (QUAN TRỌNG: Đóng file trước khi xóa)
                        if cid:
                            for af in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                                try:
                                    should_delete = False
                                    # Dùng 'with' để file tự động đóng ngay sau khi đọc xong
                                    with open(af, 'r') as f:
                                        if json.load(f).get("client_id") == cid:
                                            should_delete = True
                                    
                                    # Chỉ xóa khi file đã đóng hoàn toàn
                                    if should_delete:
                                        os.remove(af)
                                        deleted_acc += 1
                                except: pass
                    except Exception:
                        continue # Đảm bảo luôn chạy tiếp sang file sau dù có lỗi
                
                rf() 
                self.popup_info("Delete Complete", f"Deleted {deleted_sec} Secrets and {deleted_acc} linked Accounts.")
                
        bf = ttk.Frame(self.win_secrets)
        bf.pack(fill=X, padx=10, pady=10)
        ttk.Button(bf, text="+ Import (Multi)", command=ad, bootstyle="success").pack(side=LEFT, fill=X, expand=True, padx=5)
        ttk.Button(bf, text="- Delete Selected", command=de, bootstyle="danger").pack(side=RIGHT, fill=X, expand=True, padx=5)
        rf()

    def close_all_popups(self):
        """Đóng tất cả các cửa sổ con đang mở"""
        # Danh sách các biến cửa sổ cần đóng
        popups = [
            'win_settings', 
            'win_secrets', 
            'win_accounts', 
            'win_admin_manager',
            'win_batch_add',
            'win_license'
        ]
        
        for attr in popups:
            # Lấy đối tượng cửa sổ từ tên biến
            w = getattr(self, attr, None)
            
            # Nếu cửa sổ tồn tại -> Hủy nó (Destroy)
            if w and w.winfo_exists():
                w.destroy()
            
            # Reset biến về None
            setattr(self, attr, None)

    def open_acc_manager(self):
        self.close_all_popups()
        
        self.win_accounts = ttk.Toplevel(self)
        self.win_accounts.title("Accounts Manager (Multi-Select)")
        self.win_accounts.geometry("450x450")
        self._center_window(self.win_accounts)
        
        lb = tk.Listbox(self.win_accounts, font=("Helvetica", 10), selectmode="extended")
        lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")): 
                lb.insert(tk.END, os.path.basename(f))
            self.refresh_global_ui()
            
        def de():
            selection = lb.curselection()
            if not selection: return
            
            files_to_delete = [lb.get(i) for i in selection]
            msg = f"Are you sure you want to delete {len(files_to_delete)} account(s)?"
            
            if self.popup_confirm("Batch Delete", msg):
                count = 0
                for fname in files_to_delete:
                    # Bọc try/except từng file để đảm bảo vòng lặp không bị ngắt
                    try:
                        path = os.path.join(config.TOKEN_DIR, fname)
                        if os.path.exists(path):
                            os.remove(path)
                            count += 1
                    except Exception:
                        pass # Nếu không xóa được (do đang chạy chẳng hạn), bỏ qua
                
                rf()
                self.popup_info("Delete Complete", f"Successfully deleted {count} accounts.")
                
        ttk.Button(self.win_accounts, text="Delete Selected", command=de, bootstyle="danger").pack(pady=10, fill=X, padx=20)
        rf()

    def open_admin_panel(self):
            self.close_all_popups()
            
            # 1. Cấu hình cửa sổ
            w = self.win_admin_manager = ttk.Toplevel(self)
            w.title("License Manager (Admin)")
            w.geometry("500x600")
            self._center_window(w)
            
            # 2. Header: Tiêu đề và Nút chức năng
            header_fr = ttk.Frame(w, padding=15, bootstyle="secondary")
            header_fr.pack(fill=X)
            
            ttk.Label(header_fr, text="FIREBASE KEYS", font=("Helvetica", 12, "bold"), bootstyle="inverse-secondary").pack(side=LEFT)
            
            btn_fr = ttk.Frame(header_fr, bootstyle="secondary")
            btn_fr.pack(side=RIGHT)
            
            # 3. Loading Bar (Mặc định ẩn)
            progress = ttk.Progressbar(w, mode='indeterminate', bootstyle="success-striped")
            
            # 4. Khu vực hiển thị danh sách (Cuộn)
            body_fr = ScrolledFrame(w, autohide=True)
            body_fr.pack(fill=BOTH, expand=True, padx=10, pady=10)
            
            lbl_status = ttk.Label(w, text="Ready", font=("Segoe UI", 9), anchor="e", padding=(10, 5))
            lbl_status.pack(fill=X, side=BOTTOM)

            # --- CÁC HÀM XỬ LÝ LOGIC (THREADING) ---
            
            def render_list(data):
                """Hàm vẽ lại giao diện sau khi tải dữ liệu xong (Chạy trên UI Thread)"""
                progress.stop()
                progress.pack_forget()
                
                # Xóa cũ
                for c in body_fr.winfo_children(): c.destroy()
                
                if not data:
                    ttk.Label(body_fr, text="No licenses found or Connection error.", foreground="gray").pack(pady=20)
                    lbl_status.config(text="Total: 0 keys")
                    return

                lbl_status.config(text=f"Total: {len(data)} keys")
                
                # Vẽ từng dòng (Row Design)
                for idx, key in enumerate(data.keys()):
                    # Khung thẻ bài (Card)
                    card = ttk.Frame(body_fr, bootstyle="light", padding=5)
                    card.pack(fill=X, pady=3, padx=5)
                    
                    # STT
                    ttk.Label(card, text=f"#{idx+1}", width=4, foreground="gray").pack(side=LEFT)
                    
                    # Key Value (Copyable Entry)
                    ent = ttk.Entry(card, bootstyle="secondary", width=35)
                    ent.insert(0, key)
                    ent.config(state="readonly") # Chỉ đọc để copy
                    ent.pack(side=LEFT, fill=X, expand=True, padx=5)
                    
                    # Nút Xóa
                    def _del_action(k=key):
                        if self.popup_confirm("Delete Key", f"Are you sure you want to delete:\n{k}?"):
                            threading.Thread(target=lambda: delete_thread(k)).start()

                    ttk.Button(card, text="🗑", bootstyle="danger-outline", width=4, command=_del_action).pack(side=RIGHT)

            def load_data_thread():
                """Hàm tải dữ liệu chạy ngầm"""
                self.after(0, lambda: [progress.pack(fill=X), lbl_status.config(text="Loading from Firebase...")])
                progress.start(10)
                try:
                    # Giả lập delay xíu cho mượt nếu mạng quá nhanh
                    data = license_manager.get_all_licenses()
                    self.after(0, lambda: render_list(data))
                except Exception as e:
                    self.after(0, lambda: [progress.stop(), progress.pack_forget(), self.popup_error("Connection Error", str(e))])

            def add_thread(new_key):
                """Hàm thêm key chạy ngầm"""
                self.after(0, lambda: [progress.pack(fill=X), progress.start(10)])
                try:
                    license_manager.add_license(new_key)
                    self.after(0, lambda: [self.popup_info("Success", f"Added key: {new_key}"), load_data_thread()])
                except Exception as e:
                    self.after(0, lambda: [progress.stop(), self.popup_error("Error", str(e))])

            def delete_thread(target_key):
                """Hàm xóa key chạy ngầm"""
                self.after(0, lambda: [progress.pack(fill=X), progress.start(10)])
                try:
                    license_manager.delete_license(target_key)
                    self.after(0, lambda: load_data_thread())
                except Exception as e:
                    self.after(0, lambda: [progress.stop(), self.popup_error("Error", str(e))])

            # --- NÚT CHỨC NĂNG ---
            def on_refresh():
                threading.Thread(target=load_data_thread, daemon=True).start()
                
            def on_add():
                k = self.popup_input("Generate License", "Enter new License Key:")
                if k:
                    threading.Thread(target=lambda: add_thread(k.strip()), daemon=True).start()

            ttk.Button(btn_fr, text="↻ Refresh", bootstyle="info", command=on_refresh).pack(side=LEFT, padx=5)
            ttk.Button(btn_fr, text="+ Add Key", bootstyle="success", command=on_add).pack(side=LEFT, padx=5)

            # Tải dữ liệu lần đầu
            on_refresh()

    # =========================================================================
    # EXECUTION
    # =========================================================================
    def on_start(self):
        if not self.check_access(): return
        self.save_state()
        
        # 1. Lấy danh sách các tài khoản đang chạy để tránh trùng
        active_accounts = set()
        for r in self.row_frames:
            if r['running'] and r['acc'].get():
                active_accounts.add(r['acc'].get())

        a = 0
        self.log("--- START PROCESS ---", tag="INFO")
        
        for i, r in enumerate(self.row_frames):
            if not r['chk'].get() or r['running']: continue
            
            s, f, ac, t = r['secret'].get(), r['folder'].get(), r['acc'].get(), r['time'].get()
            
            # Kiểm tra thiếu thông tin
            if not all([s, f, ac, t]): 
                self.log(f"Row {i+1}: Missing info.", tag="ERROR")
                continue
            
            # Kiểm tra trùng tài khoản đang chạy
            if ac in active_accounts:
                self.log(f"Row {i+1} Skipped: Account '{ac}' is already running.", tag="ERROR")
                r['stat'].config(text="Acc Busy", foreground="red")
                continue
            
            # Đánh dấu tài khoản này sẽ chạy
            active_accounts.add(ac)

            r['running'] = True
            r['stat'].config(text="Starting...", foreground="#007bff")
            
            # --- SỬA ĐỔI: LẤY LIST PLAYLIST ID ---
            pl_ids = list(r['playlist_data']['selected_playlists'].keys())
            
            cfg = {
                'secret': s, 'folder': f, 'acc': ac, 'time': t, 
                'cat_name': r['cat'].get(), 'gap': int(r['gap'].get() or 0), 
                'playlist_ids': pl_ids # <-- Gửi list ID sang utils.py
            }
            
            th = threading.Thread(target=utils.run_job_thread, args=(r, cfg, self.log, r['pause_event']))
            th.daemon = True; th.start(); a+=1
            
        if a==0: self.log("No new rows started to process.", tag="INFO")
        else: self.log(f"Started {a} new upload threads.", tag="INFO")

    def log(self, t, tag="msg"):
        # Thread-safe logging
        self.after(0, lambda: self._log_safe(t, tag))
    
    def _log_safe(self, t, tag):
        ts = datetime.datetime.now().strftime("[%H:%M:%S] ")
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, ts, "ts")
        self.log_text.insert(tk.END, t+"\n", tag) # Sử dụng tag màu
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def focus_or_create(self, w):
        if w and w.winfo_exists(): w.lift(); return True
        return False
    
    def destroy(self):
        self.save_state()
        super().destroy()