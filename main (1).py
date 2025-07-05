import customtkinter as ctk #gui
import os #to get files
import json #to store data
from tkinter import messagebox 
from mal_web import run_scanner_app #url scanner
from url_gatekeeper import run_gatekeeper_app #url blocker
import bcrypt
import datetime
import time

#theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class ToolLauncherApp(ctk.CTk):
    def __init__(self):
        super().__init__() #gui 
        self.is_authenticated = False
        self.failed_attempts = 0
        self.lockout_until = None
        self.title("🔧 Tool Launcher")
        self.geometry("700x700")
        self.configure(fg_color="#0F111A")
        self.show_launcher()
    
    #to auth user
    def authenticate_user(self):
        auth_window = ctk.CTkToplevel(self)
        auth_window.title("Authentication")
        auth_window.geometry("350x300")
        auth_window.resizable(False, False)
        auth_window.lift()
        auth_window.focus_force()
        auth_window.grab_set()
        auth_mode = ctk.StringVar(value="Sign In")

        #for sign in 
        def switch_mode(): 
            current = auth_mode.get()
            auth_mode.set("Sign Up" if current == "Sign In" else "Sign In")
            mode_label.configure(text=auth_mode.get())
            action_btn.configure(text=auth_mode.get())
        #to input user creds
        def perform_action(): 
            nonlocal result_label
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            creds = self.load_credentials()
            # Check if currently locked out
            if self.lockout_until:
                remaining = (self.lockout_until - datetime.datetime.now()).total_seconds()
                if remaining > 0:
                    result_label.configure(text=f"Locked out. Try again in {int(remaining)}s", text_color="orange")
                    return
                else:
                    self.failed_attempts = 0
                    self.lockout_until = None
            if not username or not password:
                result_label.configure(text="Username and password required.", text_color="red")
                return
            
            if auth_mode.get() == "Sign In":
                if username in creds and creds[username] == password:
                    self.is_authenticated = True
                    self.failed_attempts = 0
                    self.lockout_until = None
                    auth_window.destroy()
                    ctk.CTkMessagebox(title="Success", message="Authentication successful.", icon="check")
                    
                else:
                    self.failed_attempts += 1
                    if self.failed_attempts >= 3:
                        self.lockout_until = datetime.datetime.now() + datetime.timedelta(seconds=30)
                        result_label.configure(text="Too many failed attempts. Locked for 30 seconds.", text_color="red")
                    else:
                        attempts_left = 3 - self.failed_attempts
                        result_label.configure(text=f"Invalid credentials. {attempts_left} attempt(s) left.", text_color="red")
                        
            else:  # Sign Up
                if username in creds:
                    result_label.configure(text="Username already exists.", text_color="orange")
                    
                else:
                    creds[username] = password
                    self.save_credentials(creds)
                    result_label.configure(text="Account created! You can now sign in.", text_color="green")

           
        #login window
        mode_label = ctk.CTkLabel(auth_window, text=auth_mode.get(), font=("Segoe UI", 20, "bold"))
        mode_label.pack(pady=(20, 10))

        username_entry = ctk.CTkEntry(auth_window, placeholder_text="Username")
        username_entry.pack(pady=10, padx=30)

        password_entry = ctk.CTkEntry(auth_window, placeholder_text="Password", show="*")
        password_entry.pack(pady=10, padx=30)

        action_btn = ctk.CTkButton(auth_window, text=auth_mode.get(), command=perform_action)
        action_btn.pack(pady=10)

        switch_btn = ctk.CTkButton(auth_window, text="Switch to Sign Up / Sign In", command=switch_mode, fg_color="gray")
        switch_btn.pack(pady=5)

        result_label = ctk.CTkLabel(auth_window, text="", text_color="white")
        result_label.pack(pady=10)

    #to load creds 
    def load_credentials(self):
        if os.path.exists("credentials.json"):
            with open("credentials.json", "r") as f:
                return json.load(f)
        return {}
    #to save creds
    def save_credentials(self, creds):
        with open("credentials.json", "w") as f:
            json.dump(creds, f)
    #this def runs if user is authenticated
    def run_if_authenticated(self, func):
        if self.is_authenticated:
            func()
        else:
            messagebox.showwarning("Access Denied", "Please authenticate first.")

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()
    #main gui
    def show_launcher(self):
        self.clear_widgets()

        title_label = ctk.CTkLabel(
            self, text="🛠 Tool Launcher",
            font=("Segoe UI", 24, "bold"), text_color="#00F0FF", cursor="hand2"
        )
        title_label.pack(pady=30)
        title_label.bind("<Button-1>", lambda e: self.show_project_info())

        auth_btn = ctk.CTkButton(
            self, text="🔐 Authenticate", command=self.authenticate_user,
            fg_color="#00F0FF", text_color="#0F111A", font=("Segoe UI", 14, "bold"),
            width=220, height=40
        )
        auth_btn.pack(pady=10)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=10)

        #button for url scanner
        ctk.CTkButton(
            btn_frame, text="🛡 Malicious URL Scanner",
            command=lambda: self.run_if_authenticated(run_scanner_app),
            fg_color="#4ea8de", text_color="white", font=("Segoe UI", 16, "bold"),
            width=220, height=50
        ).pack(pady=10)

        #button for url bloacker
        ctk.CTkButton(
            btn_frame, text="🚫 URL Gatekeeper",
            command=lambda: self.run_if_authenticated(run_gatekeeper_app),
            fg_color="#ff5c5c", text_color="white", font=("Segoe UI", 16, "bold"),
            width=220, height=50
        ).pack(pady=10)

        ctk.CTkButton(
            self, text="❌ Exit", command=self.destroy,
            fg_color="#FFC107", text_color="#0F111A", font=("Segoe UI", 14, "bold"),
            width=120
        ).pack(pady=30)
    #to show internship project details
    def show_project_info(self):
        self.clear_widgets()

        scroll_frame = ctk.CTkScrollableFrame(self, width=460, height=400)
        scroll_frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkButton(
            self, text="⬅ Back", command=self.show_launcher,
            fg_color="#007bff", font=("Segoe UI", 14, "bold")
        ).pack(pady=10)

        sections = {
            "📊 Project Details": [
                ("Project Name", "Blocking Malicious Websites"),
                ("Description", "Firewall app to block malicious websites for security"),
                ("Start Date", "22--2025"),
                ("End Date", "18-JULY-2025"),
                ("Status", "Completed")
            ],
            "👨‍💻 Developer Details": [
                ("Name", "CHARUNETHRA K"),
                ("        Employee ID", "ST#IS#7854"),
                ("        Email", "charunethra1@gmail.com"),
                ("Name", "LAL KRISHNA O"),
                ("        Employee ID", "ST#IS#7855"),
                ("        Email", "lal593988@gmail.com"),
                ("Name", "MITRA K R"),
                ("        Employee ID", "ST#I$#7856"),
                ("        Email", "mithrakr21@gmail.com"),
                ("Name", "P HANUSHREE"),
                ("        Employee ID", "ST#I$#7857"),
                ("        Email", "hanushree@gmail.com"),
                ("Name", "SANJAY GANESH K BARADE"),
                ("        Employee ID", "ST#I$#7858"),
                ("        Email", "sgbarade@gmail.com"), 
                
            ],
            "🏢 Company Details": [
                ("Name", "Supraja Technologies")
            ]
        }
        #scroll feature for info
        for title, rows in sections.items():
            ctk.CTkLabel(scroll_frame, text=title, font=("Segoe UI", 15, "bold"), text_color="#00F0FF")\
                .pack(anchor="w", padx=10, pady=(20, 5))
            for key, value in rows:
                ctk.CTkLabel(scroll_frame, text=f"{key}: {value}", font=("Segoe UI", 12), text_color="#E0E0E0")\
                    .pack(anchor="w", padx=30)

        

if __name__ == "__main__":
    app = ToolLauncherApp()
    app.mainloop()

