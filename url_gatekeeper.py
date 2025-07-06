# ✅ Final Modern UI + All Original Features Integrated
# 🚫 URL Gatekeeper with customtkinter + Project Info + Full Unblock List + Admin Check + Import from JSON

import customtkinter as ctk
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import json
import os
import platform
import subprocess
import ctypes
import sys
import threading
from tkinter import filedialog

BLOCKED_URLS_FILE = "blocked_urls.json"
BLOCKED_URLS_TXT = "blocked_urls.txt"


class URLGatekeeperApp(ctk.CTkToplevel):
    def __init__(self,master = ctk.CTkToplevel):
        super().__init__(master=master())  # Use Toplevel to avoid admin check issues
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("🚫 URL Gatekeeper")
        self.geometry("700x750")
        self.configure(fg_color="#0F111A")

        self.blocked_urls = self.load_blocked_urls()
        

        self.create_title_bar()
        self.display_main_screen()

    def create_title_bar(self):
        self.title_label = ctk.CTkLabel(self, text="🚫 URL Gatekeeper", font=("Segoe UI", 22, "bold"), text_color="#00F0FF")
        self.title_label.pack(pady=15)
        

    def display_main_screen(self):
        self.clear_widgets()

        self.url_entry = ctk.CTkEntry(self, placeholder_text="e.g. facebook.com",
                                      fg_color="#1A1D2E", text_color="#E0E0E0",
                                      placeholder_text_color="#555555",
                                      border_color="#00F0FF", border_width=2, font=("Segoe UI", 14))
        self.url_entry.pack(padx=20, pady=10, ipady=10, fill="x")

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=5)

        ctk.CTkButton(btn_frame, text="🚫 Block", command=self.block_url, fg_color="#A259FF", font=("Segoe UI", 13, "bold")).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="✅ Unblock", command=self.unblock_url, fg_color="#00FFAB", text_color="#0F111A", font=("Segoe UI", 13, "bold")).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔁 Refresh DNS", command=self.flush_dns, fg_color="#007BFF", font=("Segoe UI", 13, "bold")).pack(side="left", padx=10)
        import_frame = ctk.CTkFrame(self, fg_color="transparent")
        import_frame.pack(pady=5)
        ctk.CTkButton(import_frame, text="📥 Import Blocklist (TXT)",
                      command=self.import_block_list_from_txt,
                      fg_color="#2E8B57", text_color="white",
                      font=("Segoe UI", 13, "bold")).pack(side="left", padx=10)
        ctk.CTkButton(import_frame, text="📤 Import Unblock List (TXT)",
                      command=self.import_unblock_list_from_txt,
                      fg_color="#FF5722", text_color="white",
                      font=("Segoe UI", 13, "bold")).pack(side="left", padx=10)


        
        ctk.CTkLabel(self, text="🚫 Blocked URLs", font=("Segoe UI", 14, "bold"), text_color="#FF5E5E").pack(pady=(20, 5))

        self.url_listbox = ctk.CTkTextbox(self, height=120, font=("Consolas", 12), fg_color="#1A1D2E", text_color="#00F0FF")
        self.url_listbox.pack(padx=20, fill="both", expand=False)
        self.url_listbox.configure(state="disabled")

        self.status_label = ctk.CTkLabel(self, text="Ready", font=("Segoe UI", 11, "italic"), text_color="#00FFAB")
        self.status_label.pack(pady=(10, 5))

        ctk.CTkButton(self, text="Unblock Selected", command=self.unblock_selected, fg_color="#FFC107", text_color="#0F111A").pack(pady=5)
        ctk.CTkButton(self, text="📄 Export Blocked URLs", command=self.export_blocked_urls_to_txt, fg_color="#9C27B0", text_color="white").pack(pady=5)
        
        self.refresh_blocked_list()


        exit_button = ctk.CTkButton(self, text="\u274c Exit", fg_color="gold", text_color="black", command=self.destroy)
        exit_button.pack(pady=10)


    
    
    def clear_widgets(self):
        for widget in self.winfo_children():
            if widget != self.title_label:
                widget.destroy()


    def block_url(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self._block_url_logic(url)

    def _block_url_logic(self, url):
        clean_url = url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        entry = f"\n# Blocked by URL Gatekeeper\n127.0.0.1 {clean_url}\n127.0.0.1 www.{clean_url}\n"

        try:
            with open(self.get_hosts_file(), 'r') as f:
                content = f.read()
            if clean_url in content:
                self.set_status(f"{clean_url} already blocked", "#FFC107")
                return
            with open(self.get_hosts_file(), 'a') as f:
                f.write(entry)
            if clean_url not in self.blocked_urls:
                self.blocked_urls.append(clean_url)
                self.save_blocked_urls()
            self.refresh_blocked_list()
            self.flush_dns()
            self.set_status(f"{clean_url} blocked", "#00FFAB")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Block failed", "#FF4444")



    def unblock_url(self):
        url = self.url_entry.get().strip()
        self._unblock_logic(url)

    def unblock_selected(self):
        selected = self.url_entry.get().strip()
        self._unblock_logic(selected)

    def _unblock_logic(self, url):
        clean_url = url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        try:
            with open(self.get_hosts_file(), 'r') as f:
                lines = f.readlines()
            lines = [line for line in lines if clean_url not in line and "# Blocked by URL Gatekeeper" not in line]
            with open(self.get_hosts_file(), 'w') as f:
                f.writelines(lines)
            if clean_url in self.blocked_urls:
                self.blocked_urls.remove(clean_url)
                self.save_blocked_urls()
            self.refresh_blocked_list()
            self.flush_dns()
            self.set_status(f"{clean_url} unblocked", "#00FFAB")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Unblock failed", "#FF4444")

    def import_block_list_from_txt(self):
        filepath = filedialog.askopenfilename(title="Select Blocklist TXT File", filetypes=[("Text Files", "*.txt")])
        if not filepath:
            return
        try:
            with open(filepath, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            count = 0
            for url in urls:
                clean_url = url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
                if clean_url and clean_url not in self.blocked_urls:
                    self._block_url_logic(clean_url)
                    count += 1
                    
            self.set_status(f"{count} URLs imported and blocked", "#00FFAB")
        
        except Exception as e:
            messagebox.showerror("Import Error", str(e))
            self.set_status("Blocklist import failed", "#FF4444")

    def import_unblock_list_from_txt(self):
        filepath = filedialog.askopenfilename(title="Select Unblock TXT File", filetypes=[("Text Files", "*.txt")])
        if not filepath:
            return
        try:
            with open(filepath, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            count = 0
            for url in urls:
                clean_url = url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
                if clean_url in self.blocked_urls:
                    self._unblock_logic(clean_url)
                    count += 1
                    
            self.set_status(f"{count} URLs unblocked from TXT", "#00FFAB")
            
        except Exception as e:
            messagebox.showerror("Import Error", str(e))
            self.set_status("Unblocklist import failed", "#FF4444")



    def flush_dns(self):
        try:
            if platform.system().lower() == "windows":
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
            self.set_status("DNS cache flushed", "#00FFAB")
        except:
            self.set_status("DNS flush error", "#FF4444")

    def refresh_blocked_list(self):
        self.url_listbox.configure(state="normal")
        self.url_listbox.delete("1.0", "end")
        if not self.blocked_urls:
            self.url_listbox.insert("end", "No URLs are currently blocked\n")
        else:
            for url in self.blocked_urls:
                self.url_listbox.insert("end", url + "\n")
        self.url_listbox.configure(state="disabled")

    def set_status(self, msg, color):
        self.status_label.configure(text=msg, text_color=color)

    def get_hosts_file(self):
        return r"C:\\Windows\\System32\\drivers\\etc\\hosts" if platform.system().lower() == "windows" else "/etc/hosts"

    def load_blocked_urls(self):
        if os.path.exists(BLOCKED_URLS_FILE):
            try:
                with open(BLOCKED_URLS_FILE, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_blocked_urls(self):
        with open(BLOCKED_URLS_FILE, 'w') as f:
            json.dump(self.blocked_urls, f, indent=2)

    def export_blocked_urls_to_txt(self):
        if not self.blocked_urls:
            messagebox.showinfo("No URLs", "There are no blocked URLs to export.")
            return
        try:
            with open(BLOCKED_URLS_TXT, 'w') as f:
                f.write("🚫 Blocked URLs Export\n")
                f.write("========================\n\n")
                for url in self.blocked_urls:
                    f.write(f"- {url}\n")

            # Open the TXT file with default editor
            if platform.system().lower() == "windows":
                os.startfile(BLOCKED_URLS_TXT)
            elif platform.system().lower() == "darwin":
                subprocess.run(["open", BLOCKED_URLS_TXT])
            else:
                subprocess.run(["xdg-open", BLOCKED_URLS_TXT])
                
            self.set_status("Blocked URLs exported to TXT", "#00FFAB")
            
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            self.set_status("Export failed", "#FF4444")

def run_gatekeeper_app():
    # Use Toplevel instead of CTk root
    gatekeeper_window = URLGatekeeperApp()
    gatekeeper_window.focus_force()
    gatekeeper_window.grab_set()

    """app = URLGatekeeperApp()
    app.mainloop()"""

#if __name__ == "__main__":    main()