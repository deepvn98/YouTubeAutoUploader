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
        cur = ""
        if os.path.exists(config.LICENSE_FILE):
            try:
                with open(config.LICENSE_FILE, "r") as f:
                    cur = f.read().strip()
            except: pass
            
        res = self.popup_input("License Check", "Enter License Key (or Admin Code):", initial_value=cur)
        if res: self.verify_license_online(res.strip())

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
        
        # Secret
        sec_cb = ttk.Combobox(fr, state="readonly", width=28); sec_cb.pack(side=LEFT, padx=2)
        sec_cb['values'] = [os.path.basename(f) for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json"))]
        if data.get('secret') in sec_cb['values']: sec_cb.set(data.get('secret'))
        
        # Folder
        fol_ent = ttk.Entry(fr, width=38); fol_ent.pack(side=LEFT, padx=2)
        fol_ent.insert(0, data.get('folder', ''))
        
        # --- LOGIC MỚI: KIỂM TRA TRÙNG FOLDER KHI NHẬP TAY ---
        def validate_folder(event):
            path = fol_ent.get().strip()
            if not path: return
            try:
                current_norm = os.path.normpath(path).lower()
                for r in self.row_frames:
                    # So sánh object widget để bỏ qua chính nó
                    if r['folder'] != fol_ent and r['folder'].get():
                        other_norm = os.path.normpath(r['folder'].get()).lower()
                        if current_norm == other_norm:
                            self.popup_error("Duplicate Folder", f"Folder is already used in Row {r['lbl_idx'].cget('text')}.")
                            fol_ent.delete(0, tk.END) # Xóa nội dung trùng
                            return
            except: pass
            
        fol_ent.bind("<FocusOut>", validate_folder) # Gắn sự kiện kiểm tra khi rời chuột
        # -----------------------------------------------------

        ttk.Button(fr, text="📂", width=3, bootstyle="primary-outline", command=lambda: self.browse_folder(fol_ent, idx)).pack(side=LEFT, padx=(0,5))
        # Account & Playlist
        acc_cb = ttk.Combobox(fr, state="readonly", width=28); acc_cb.pack(side=LEFT, padx=2)
        playlist_cb = ttk.Combobox(fr, state="readonly", width=23); playlist_cb.pack(side=LEFT, padx=2)
        playlist_map = {} 

        def update_acc_list(e=None):
            sec = sec_cb.get()
            if not sec: 
                acc_cb['values'] = []
                return
            
            # 1. Lấy danh sách tất cả tài khoản hợp lệ với Secret này (như cũ)
            cid = youtube_api.get_client_id_from_file(sec)
            potential_accs = []
            if cid:
                for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                    try:
                        if json.load(open(f)).get("client_id") == cid: 
                            potential_accs.append(os.path.basename(f))
                    except: pass
            
            # 2. LOGIC MỚI: Lọc bỏ các tài khoản đang được dùng ở dòng khác
            used_elsewhere = set()
            for r in self.row_frames:
                # r['acc'] != acc_cb: Không tính chính dòng đang thao tác (để giữ lại giá trị hiện tại)
                if r['acc'] != acc_cb: 
                    val = r['acc'].get()
                    if val: used_elsewhere.add(val)
            
            # Chỉ hiển thị những account chưa bị dùng ở nơi khác
            final_values = [acc for acc in potential_accs if acc not in used_elsewhere]
            
            acc_cb['values'] = final_values


        def load_pl(acc, sec):
            if not acc or not sec: return
            
            # 1. Báo hiệu đang tải để người dùng biết
            playlist_cb.set("Loading...")
            playlist_cb['values'] = ["Loading..."]
            
            def t():
                try:
                    yt = youtube_api.get_authenticated_service(acc, sec)
                    if yt:
                        pls = youtube_api.get_user_playlists(yt)
                        # Gọi callback update UI trên luồng chính
                        self.after(0, lambda: _apply_pl(pls))
                    else:
                        # Nếu login lỗi
                        self.after(0, lambda: [playlist_cb.set("Login Error"), playlist_cb.configure(values=[])])
                except Exception as e:
                    print(f"Error loading playlist: {e}")
                    self.after(0, lambda: playlist_cb.set("API Error"))

            def _apply_pl(pls):
                # Reset danh sách playlist
                playlist_cb['values'] = ["No Playlist"] + list(pls.keys())
                row_widgets['playlist_map'] = pls
                
                # --- LOGIC KHÔI PHỤC THÔNG MINH ---
                found = False
                
                # Ưu tiên 1: Tìm theo ID (Chính xác nhất, kể cả khi đổi tên)
                saved_id = data.get('playlist_id')
                if saved_id:
                    for name, pid in pls.items():
                        if pid == saved_id:
                            playlist_cb.set(name)
                            found = True
                            break
                
                # Ưu tiên 2: Nếu không tìm thấy ID, mới tìm theo Tên (Fallback)
                if not found:
                    saved_name = data.get('playlist_name')
                    if saved_name and saved_name in pls:
                        playlist_cb.set(saved_name)
                        found = True
                
                # Nếu không tìm thấy gì cả (hoặc dữ liệu mới), set mặc định
                if not found:
                    # Nếu trước đó chọn "No Playlist" hoặc chưa chọn gì
                    if data.get('playlist_name') == "No Playlist" or not data.get('playlist_name'):
                        playlist_cb.set("No Playlist")
                    else:
                        # Trường hợp playlist cũ bị xóa trên Youtube, hiển thị lại tên cũ để user biết
                        playlist_cb.set(data.get('playlist_name', ''))
            
            # Chạy trên luồng phụ để không đơ giao diện
            threading.Thread(target=t, daemon=True).start()

        def on_acc_select(event):
            val = acc_cb.get()
            if not val: return
            
            # Quét tất cả các dòng hiện có để tìm trùng lặp
            for r in self.row_frames:
                # r['acc'] != acc_cb: Đảm bảo không so sánh với chính dòng đang thao tác
                if r['acc'] != acc_cb and r['acc'].get() == val:
                    self.popup_error("Duplicate Error", f"Account '{val}' is already used in Row {r['lbl_idx'].cget('text')}.")
                    acc_cb.set('') # Xóa lựa chọn vừa chọn
                    playlist_cb.set('')
                    playlist_cb['values'] = []
                    return

            # Nếu không trùng, tải playlist bình thường
            load_pl(val, sec_cb.get())

        sec_cb.bind("<<ComboboxSelected>>", lambda e: [acc_cb.set(''), update_acc_list()])
        acc_cb.bind("<<ComboboxSelected>>", on_acc_select) # Đã thay thế lambda cũ bằng hàm kiểm tra
        acc_cb.bind("<Button-1>", update_acc_list)

        if sec_cb.get():
            update_acc_list()
            if data.get('acc') in acc_cb['values']:
                acc_cb.set(data.get('acc'))
                load_pl(data.get('acc'), sec_cb.get())

        def quick_add():
            s = sec_cb.get()
            if not s: self.popup_error("Err", "Select Secret First"); return
            def t():
                new, err = youtube_api.create_new_login(s)
                if new: 
                    self.after(0, lambda: [self.refresh_global_ui(), self.popup_info("OK", f"Added: {new}"), acc_cb.set(new), load_pl(new, s)])
                else: 
                    self.after(0, lambda: self.popup_error("Err", err))
            threading.Thread(target=t, daemon=True).start()
        ttk.Button(fr, text="+", width=3, bootstyle="primary-outline", command=quick_add).pack(side=LEFT, padx=(0,5))

        tm = ttk.Entry(fr, width=33, justify="center"); tm.pack(side=LEFT, padx=2)
        tm.insert(0, data.get('time', "08:00, 19:00"))
        
        gap = ttk.Spinbox(fr, from_=0, to=30, width=5, justify="center"); gap.pack(side=LEFT, padx=2)
        gap.set(data.get('gap', 0))
        
        cat = ttk.Combobox(fr, state="readonly", values=list(config.YT_CATEGORIES.keys()), width=25); cat.pack(side=LEFT, padx=2)
        cat.set(data.get('cat', "Default (From Settings)"))
        
        stat = ttk.Label(fr, text="Ready", foreground="gray", width=22, anchor="center"); stat.pack(side=LEFT, padx=5)
        
        pe = threading.Event(); pe.set()
        
        # --- LOGIC MỚI: PAUSE CÓ PHẢN HỒI NGAY LẬP TỨC ---
        def toggle_pause():
            if pe.is_set():
                # Nếu đang chạy -> Bấm để Tạm dừng
                pe.clear()
                bp.config(text="▶", bootstyle="warning") # Đổi sang màu vàng, icon Play
                stat.config(text="Pausing...", foreground="#ffc107") # Báo hiệu ngay
                self.log(f"Row {idx}: Pause requested.", tag="INFO")
            else:
                # Nếu đang dừng -> Bấm để Tiếp tục
                pe.set()
                bp.config(text="⏸", bootstyle="primary") # Đổi về màu xanh
                stat.config(text="Resuming...", foreground="#007bff")
                self.log(f"Row {idx}: Resumed.", tag="INFO")

        bp = ttk.Button(fr, text="⏸", width=4, bootstyle="primary", state="disabled", command=toggle_pause)
        bp.pack(side=LEFT, padx=2)
        
        def dele(): 
            fr.destroy(); self.row_frames.remove(row_widgets)
            for i,r in enumerate(self.row_frames): r['lbl_idx'].config(text=str(i+1))
            self.update_master_state()
        ttk.Button(fr, text="X", width=4, bootstyle="primary-outline", command=dele).pack(side=LEFT, padx=5)

        row_widgets = {'frame': fr, 'lbl_idx': lbl_idx, 'chk': chk_var, 'secret': sec_cb, 'folder': fol_ent, 'acc': acc_cb, 'playlist': playlist_cb, 'playlist_map': playlist_map, 'time': tm, 'gap': gap, 'cat': cat, 'stat': stat, 'pause_event': pe, 'btn_pause': bp, 'running': False}
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
            pl_name = r['playlist'].get()
            pl_id = r['playlist_map'].get(pl_name, "")
            state[str(i+1)] = {
                "secret": r['secret'].get(), "folder": r['folder'].get(), "acc": r['acc'].get(),
                "time": r['time'].get(), "cat": r['cat'].get(), "gap": r['gap'].get(), "chk": r['chk'].get(),
                "playlist_name": pl_name, "playlist_id": pl_id
            }
        config.save_json(config.GRID_STATE_FILE, state)

    # =========================================================================
    # MANAGERS
    # =========================================================================
    def open_batch_add(self):
        if not self.check_access(): return
        w = ttk.Toplevel(self); w.title("Batch Add"); w.geometry("500x550"); self._center_window(w)
        
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
        if self.focus_or_create(self.win_settings): return
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
        if self.focus_or_create(self.win_secrets): return
        self.win_secrets = ttk.Toplevel(self); self.win_secrets.title("Secrets"); self.win_secrets.geometry("450x450"); self._center_window(self.win_secrets)
        lb = tk.Listbox(self.win_secrets, font=("Helvetica", 10)); lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            for f in glob.glob(os.path.join(config.SECRET_DIR, "*.json")): lb.insert(tk.END, os.path.basename(f))
            self.refresh_global_ui() 
            
        def ad(): 
            f = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
            if f: shutil.copy(f, config.SECRET_DIR); rf(); self.popup_info("OK", f"Imported: {os.path.basename(f)}")
            
        def de():
            if not lb.curselection(): return
            fn = lb.get(lb.curselection()[0])
            if self.popup_confirm("Delete", f"Delete {fn}?\nWARNING: WILL DELETE ALL LINKED ACCOUNTS!"):
                cid = youtube_api.get_client_id_from_file(fn)
                try: os.remove(os.path.join(config.SECRET_DIR, fn))
                except: pass
                cnt = 0
                if cid:
                    for af in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")):
                        try: 
                            if json.load(open(af)).get("client_id") == cid: os.remove(af); cnt+=1
                        except: pass
                rf(); self.popup_info("OK", f"Deleted Secret and {cnt} linked accounts.")
                
        bf = ttk.Frame(self.win_secrets); bf.pack(fill=X, padx=10, pady=10)
        ttk.Button(bf, text="+ Import", command=ad, bootstyle="success").pack(side=LEFT, fill=X, expand=True, padx=5)
        ttk.Button(bf, text="- Delete", command=de, bootstyle="danger").pack(side=RIGHT, fill=X, expand=True, padx=5)
        rf()

    def open_acc_manager(self):
        if self.focus_or_create(self.win_accounts): return
        self.win_accounts = ttk.Toplevel(self); self.win_accounts.title("Accounts"); self.win_accounts.geometry("450x450"); self._center_window(self.win_accounts)
        lb = tk.Listbox(self.win_accounts, font=("Helvetica", 10)); lb.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def rf(): 
            lb.delete(0, tk.END)
            for f in glob.glob(os.path.join(config.TOKEN_DIR, "*.json")): lb.insert(tk.END, os.path.basename(f))
            self.refresh_global_ui()
            
        def de():
            if lb.curselection() and self.popup_confirm("Delete", f"Delete {lb.get(lb.curselection()[0])}?"):
                fname = lb.get(lb.curselection()[0])
                os.remove(os.path.join(config.TOKEN_DIR, fname))
                rf(); self.popup_info("OK", f"Deleted account: {fname}")
                
        ttk.Button(self.win_accounts, text="Delete Selected", command=de, bootstyle="danger").pack(pady=10)
        rf()

    def open_admin_panel(self):
        if self.focus_or_create(self.win_admin_manager): return
        w = self.win_admin_manager = ttk.Toplevel(self); w.title("Admin"); w.geometry("400x500"); self._center_window(w)
        lf = ScrolledFrame(w, height=300); lf.pack(fill=BOTH, expand=True, padx=10)
        def rf():
            for c in lf.winfo_children(): c.destroy()
            d = license_manager.get_all_licenses()
            for k in d.keys():
                r = ttk.Frame(lf); r.pack(fill=X, pady=2)
                ttk.Label(r, text=k, width=30).pack(side=LEFT)
                ttk.Button(r, text="X", width=3, command=lambda k=k: [license_manager.delete_license(k), rf()]).pack(side=RIGHT)
        def ad():
            k = self.popup_input("New", "Key:"); 
            if k: license_manager.add_license(k); rf()
        ttk.Button(w, text="Refresh", command=rf).pack(pady=5)
        ttk.Button(w, text="+ Add", command=ad).pack(pady=5)
        rf()

    # =========================================================================
    # EXECUTION
    # =========================================================================
    def on_start(self):
        if not self.check_access(): return
        self.save_state(); a = 0; self.log("--- START PROCESS ---", tag="INFO")
        for r in self.row_frames:
            if not r['chk'].get() or r['running']: continue
            s,f,ac,t = r['secret'].get(), r['folder'].get(), r['acc'].get(), r['time'].get()
            if not all([s,f,ac,t]): continue
            
            r['running'] = True
            r['stat'].config(text="Starting...", foreground="#007bff")
            
            pl_id = r['playlist_map'].get(r['playlist'].get(), "")
            
            cfg = {
                'secret': s, 'folder': f, 'acc': ac, 'time': t, 
                'cat_name': r['cat'].get(), 'gap': int(r['gap'].get()or 0), 'playlist_id': pl_id
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