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
        all_secrets = [os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json"))]

        for r in self.row_frames:
            current_sec = r['secret'].get()
            r['secret']['values'] = all_secrets
            
            if current_sec and current_sec not in all_secrets:
                r['secret'].set('')
                r['acc'].set(''); r['acc']['values'] = []
                r['playlist'].set(''); r['playlist']['values'] = []
                continue 

            if current_sec:
                cid = youtube_api.get_client_id_from_file(current_sec)
                valid_accs = []
                if cid:
                    for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                        try:
                            if json.load(open(f)).get("client_id") == cid: valid_accs.append(os.path.basename(f))
                        except: pass
                
                r['acc']['values'] = valid_accs
                
                current_acc = r['acc'].get()
                if current_acc and current_acc not in valid_accs:
                    r['acc'].set('')
                    r['playlist'].set(''); r['playlist']['values'] = []
            else:
                r['acc']['values'] = []
                r['acc'].set('')

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
        
        # Biến quan trọng: Lưu danh sách playlist
        row_data = {'playlist_map': {}, 'selected_playlists': {}}

        def update_acc_list(e=None):
            sec = sec_cb.get()
            if not sec: acc_cb['values'] = []; return
            cid = youtube_api.get_client_id_from_file(sec)
            valid = []
            if cid:
                for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                    try:
                        if json.load(open(f)).get("client_id") == cid: valid.append(os.path.basename(f))
                    except: pass
            used = {r['acc'].get() for r in self.row_frames if r['acc'] != acc_cb and r['acc'].get()}
            acc_cb['values'] = [a for a in valid if a not in used]

        # --- HÀM BẬT CỬA SỔ CHỌN PLAYLIST (PHIÊN BẢN PRO) ---
        # --- HÀM BẬT CỬA SỔ CHỌN PLAYLIST (FIX TRIỆT ĐỂ BẰNG ALPHA CHANNEL) ---
        def open_playlist_selector(e=None):
            # 1. Kiểm tra điều kiện (Logic cũ)
            if not row_data['playlist_map']:
                status = playlist_ent.get()
                if status in ["Loading...", "Login Error", "API Error"]: return
                if not acc_cb.get(): 
                    self.popup_error("Error", "Select Account first.")
                    return
                self.popup_error("Info", "No playlists found.")
                return

            # 2. Tạo cửa sổ và TÀNG HÌNH NGAY LẬP TỨC
            p = ttk.Toplevel(self)
            p.attributes('-alpha', 0.0) # Độ trong suốt = 0 (Tàng hình)
            # Lưu ý: Không dùng withdraw() nữa để tránh xung đột animation
            
            p.title("Playlist Selector")
            
            # 3. Xây dựng giao diện
            # --- HEADER ---
            head_fr = ttk.Frame(p, padding=10)
            head_fr.pack(fill=X)
            
            search_var = tk.StringVar()
            entry_search = ttk.Entry(head_fr, textvariable=search_var, font=("Segoe UI", 10))
            entry_search.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
            entry_search.insert(0, "Search...")
            
            def on_focus_in(e):
                if entry_search.get() == "Search...": entry_search.delete(0, tk.END)
            entry_search.bind("<FocusIn>", on_focus_in)

            # --- BODY ---
            body_fr = ScrolledFrame(p, autohide=True)
            body_fr.pack(fill=BOTH, expand=True, padx=10)
            
            # --- FOOTER ---
            foot_fr = ttk.Frame(p, padding=10, bootstyle="light")
            foot_fr.pack(fill=X, side=BOTTOM)
            
            lbl_count = ttk.Label(foot_fr, text="Selected: 0", font=("Bold", 10), bootstyle="inverse-light")
            lbl_count.pack(side=LEFT)

            # --- LOGIC DỮ LIỆU & VẼ LIST ---
            vars_map = {} 
            for name, pid in row_data['playlist_map'].items():
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
                
                for name, pid in items_to_draw:
                    row = ttk.Frame(body_fr, padding=(5, 5))
                    row.pack(fill=X, pady=1)
                    
                    var = vars_map[pid]
                    chk = ttk.Checkbutton(row, text=name, variable=var, command=update_count)
                    chk.pack(side=LEFT, fill=X, expand=True)
                    
                    row.bind("<Enter>", lambda e, r=row: r.configure(bootstyle="info"))
                    row.bind("<Leave>", lambda e, r=row: r.configure(bootstyle="default"))
                    
                    def toggle(e, v=var): v.set(not v.get()); update_count()
                    row.bind("<Button-1>", toggle)

            search_var.trace("w", lambda *args: render_list(search_var.get()))

            # --- NÚT BẤM ---
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
                
                # Tạo bản đồ ngược ID -> Name để tra cứu
                id_to_name = {}
                for name, pid in row_data['playlist_map'].items():
                    id_to_name[pid] = name

                for pid, var in vars_map.items():
                    if var.get():
                        # Lấy tên từ map ngược, nếu không có thì để Unknown
                        name = id_to_name.get(pid, "Unknown Playlist")
                        new_selected[pid] = name
                        display_names.append(name)
                
                # Cập nhật dữ liệu vào biến chính
                row_data['selected_playlists'] = new_selected
                
                # Cập nhật text hiển thị ra ô Entry bên ngoài
                playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END)
                if not display_names: 
                    playlist_ent.insert(0, "No Playlist")
                elif len(display_names) == 1: 
                    playlist_ent.insert(0, display_names[0])
                else: 
                    playlist_ent.insert(0, f"{len(display_names)} Playlists selected")
                playlist_ent.config(state="readonly")
                
                p.destroy()

            ttk.Button(foot_fr, text="SAVE SELECTION", bootstyle="success", command=save_selection).pack(side=RIGHT)

            # Vẽ giao diện xong xuôi
            render_list()
            update_count()
            
            # 4. TÍNH TOÁN VỊ TRÍ & HIỆN HÌNH (Magic step)
            # Ép hệ thống tính toán xong layout
            p.update_idletasks() 
            
            width = 450
            height = 550
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            x = (screen_width // 2) - (width // 2)
            y = (screen_height // 2) - (height // 2)
            
            # Đặt vị trí
            p.geometry(f"{width}x{height}+{x}+{y}")
            
            # HIỆN NGUYÊN HÌNH (Chuyển alpha từ 0 -> 1)
            p.attributes('-alpha', 1.0) 
            
            # 5. Cài đặt Modal
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

        def on_acc_select(e):
            val = acc_cb.get()
            if not val: return
            for r in self.row_frames:
                if r['acc'] != acc_cb and r['acc'].get() == val:
                    self.popup_error("Duplicate", f"Account '{val}' used."); acc_cb.set(''); 
                    playlist_ent.config(state="normal"); playlist_ent.delete(0, tk.END); playlist_ent.config(state="readonly")
                    return
            load_pl(val, sec_cb.get())

        playlist_ent.bind("<Button-1>", open_playlist_selector)
        sec_cb.bind("<<ComboboxSelected>>", lambda e: [acc_cb.set(''), update_acc_list()])
        acc_cb.bind("<<ComboboxSelected>>", on_acc_select)
        acc_cb.bind("<Button-1>", update_acc_list)

        if sec_cb.get():
            update_acc_list()
            if data.get('acc') and data.get('acc') in acc_cb['values']:
                acc_cb.set(data.get('acc')); load_pl(data.get('acc'), sec_cb.get())

        # --- OTHER WIDGETS ---
        def qa():
            s = sec_cb.get()
            if not s: self.popup_error("Err", "Select Secret"); return
            def t():
                n, e = youtube_api.create_new_login(s)
                if n: self.after(0, lambda: [self.refresh_global_ui(), self.popup_info("OK", f"Added {n}"), acc_cb.set(n), load_pl(n, s)])
            threading.Thread(target=t, daemon=True).start()
        ttk.Button(fr, text="+", width=3, bootstyle="primary-outline", command=qa).pack(side=LEFT, padx=(0,5))

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

        # --- QUAN TRỌNG: LƯU BIẾN VÀO DICT ĐỂ DÙNG SAU ---
        row_widgets = {
            'frame': fr, 'lbl_idx': lbl_idx, 'chk': chk_var, 
            'secret': sec_cb, 'folder': fol_ent, 'acc': acc_cb, 
            'playlist': playlist_ent,   # Lưu widget Entry
            'playlist_data': row_data,  # Lưu dữ liệu danh sách ID
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
        if not self.check_access(): return
        
        # 1. Đóng các popup khác đang mở
        self.close_all_popups() 
        
        # 2. QUAN TRỌNG: Gán cửa sổ vào biến self.win_batch_add để quản lý
        self.win_batch_add = ttk.Toplevel(self)
        w = self.win_batch_add # Dùng biến w cho gọn để code dưới không phải sửa
        
        w.title("Batch Add"); w.geometry("500x550"); self._center_window(w)
        
        ttk.Label(w, text="1. Select Secret:", font=("Bold", 10)).pack(anchor=W, padx=10, pady=10)
        secs = [os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json"))]
        sb = ttk.Combobox(w, values=secs, state="readonly"); sb.pack(fill=X, padx=10)
        
        ttk.Label(w, text="2. Accounts:", font=("Bold", 10)).pack(anchor=W, padx=10, pady=10)
        lf = ScrolledFrame(w, height=250); lf.pack(fill=BOTH, expand=True, padx=10)
        b_vars = []
        
        def ld(e=None):
            for c in lf.winfo_children(): c.destroy()
            b_vars.clear(); s = sb.get()
            if not s: return
            cid = youtube_api.get_client_id_from_file(s)
            if not cid: return
            for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                try:
                    if json.load(open(f)).get("client_id") == cid:
                        n = os.path.basename(f); v = tk.BooleanVar(value=True)
                        ttk.Checkbutton(lf, text=n, variable=v).pack(anchor=W)
                        b_vars.append((n,v))
                except: pass
        sb.bind("<<ComboboxSelected>>", ld)
        
        def qa():
            s = sb.get()
            if not s: self.popup_error("Err", "No Secret"); return
            def t():
                n, e = youtube_api.create_new_login(s)
                if n: self.after(0, lambda: [ld(), self.refresh_global_ui(), self.popup_info("OK", f"Added {n}")])
            threading.Thread(target=t, daemon=True).start()
        ttk.Button(w, text="+ New Login", command=qa, bootstyle="primary-outline").pack(fill=X, padx=10, pady=5)
        
        def cf():
            s = sb.get(); acs = [n for n,v in b_vars if v.get()]
            if not s or not acs: self.popup_error("Err", "Missing Info"); return
            exist = set()
            for r in self.row_frames: 
                if r['secret'].get() and r['acc'].get(): exist.add((r['secret'].get(), r['acc'].get()))
            cnt = 0
            for a in acs:
                if (s,a) in exist: continue
                self.add_row({"secret": s, "acc": a, "chk": True})
                cnt+=1; exist.add((s,a))
            w.destroy(); self.popup_info("OK", f"Batch Added {cnt} rows."); self.update_master_state()
        ttk.Button(w, text="ADD TO GRID", bootstyle="primary", command=cf).pack(fill=X, padx=10, pady=10)

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
        # 1. Đóng các popup khác (để đảm bảo chỉ 1 cửa sổ mở)
        self.close_all_popups()
        
        # 2. Khởi tạo cửa sổ
        self.win_secrets = ttk.Toplevel(self)
        self.win_secrets.title("Secrets Manager (Multi-Select)")
        self.win_secrets.geometry("500x500")
        self._center_window(self.win_secrets)
        
        # 3. Listbox: Thêm selectmode="extended" để chọn nhiều
        lb = tk.Listbox(self.win_secrets, font=("Helvetica", 10), selectmode="extended")
        lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            # Load danh sách file trong thư mục secret
            for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json")): 
                lb.insert(tk.END, os.path.basename(f))
            self.refresh_global_ui() 
            
        def ad(): 
            # 4. Import: Dùng askopenfilenames (có 's' ở cuối) để chọn nhiều file
            files = filedialog.askopenfilenames(
                title="Select Secret Files",
                filetypes=[("JSON Files", "*.json")]
            )
            if files:
                count = 0
                for f in files:
                    try:
                        shutil.copy(f, config.SECRET_DIR)
                        count += 1
                    except: pass
                
                if count > 0:
                    rf() # Làm mới danh sách
                    self.popup_info("Import Success", f"Successfully imported {count} files.")
            
        def de():
            # 5. Delete: Xử lý xóa nhiều file cùng lúc
            selection = lb.curselection()
            if not selection: return
            
            # Lấy danh sách tên file từ các dòng đã chọn
            files_to_delete = [lb.get(i) for i in selection]
            
            msg = f"Are you sure you want to delete {len(files_to_delete)} secret file(s)?\n\nWARNING: All linked Accounts will also be deleted!"
            
            if self.popup_confirm("Batch Delete", msg):
                deleted_sec = 0
                deleted_acc = 0
                
                for fn in files_to_delete:
                    # Lấy Client ID để tìm Token liên quan trước khi xóa file
                    cid = youtube_api.get_client_id_from_file(fn)
                    secret_path = os.path.join(config.SECRET_DIR, fn)
                    
                    # Xóa file Secret
                    if os.path.exists(secret_path):
                        try:
                            os.remove(secret_path)
                            deleted_sec += 1
                        except: continue

                    # Xóa các Token liên quan đến Secret này
                    if cid:
                        for af in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                            try: 
                                if json.load(open(af)).get("client_id") == cid: 
                                    os.remove(af)
                                    deleted_acc += 1
                            except: pass
                
                rf() # Làm mới danh sách
                self.popup_info("Delete Complete", f"Deleted {deleted_sec} Secrets and {deleted_acc} linked Accounts.")
                
        bf = ttk.Frame(self.win_secrets)
        bf.pack(fill=X, padx=10, pady=10)
        
        # Nút Import
        ttk.Button(bf, text="+ Import (Multi)", command=ad, bootstyle="success").pack(side=LEFT, fill=X, expand=True, padx=5)
        # Nút Delete
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
        # 1. Đóng các popup khác trước
        self.close_all_popups()
        
        # 2. Khởi tạo cửa sổ
        self.win_accounts = ttk.Toplevel(self)
        self.win_accounts.title("Accounts Manager (Multi-Select)")
        self.win_accounts.geometry("450x450")
        self._center_window(self.win_accounts)
        
        # 3. Listbox: Thêm selectmode="extended" để chọn nhiều
        lb = tk.Listbox(self.win_accounts, font=("Helvetica", 10), selectmode="extended")
        lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            # Liệt kê file token
            for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")): 
                lb.insert(tk.END, os.path.basename(f))
            
            # Cập nhật lại Grid bên ngoài (nếu lỡ xóa file đang dùng thì grid tự reset)
            self.refresh_global_ui()
            
        def de():
            # 4. Xử lý xóa nhiều file
            selection = lb.curselection()
            if not selection: return
            
            # Lấy danh sách tên file từ các dòng được chọn
            files_to_delete = [lb.get(i) for i in selection]
            
            msg = f"Are you sure you want to delete {len(files_to_delete)} account(s)?"
            
            if self.popup_confirm("Batch Delete", msg):
                count = 0
                for fname in files_to_delete:
                    path = os.path.join(config.TOKEN_DIR, fname)
                    try:
                        os.remove(path)
                        count += 1
                    except: pass
                
                rf() # Làm mới danh sách
                self.popup_info("Delete Complete", f"Successfully deleted {count} accounts.")
                
        # Nút Xóa (Màu đỏ)
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