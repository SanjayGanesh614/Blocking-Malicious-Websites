import customtkinter as ctk #gui
import os #to get files
import json #to store data
from tkinter import messagebox 
from mal_web import run_scanner_app #url scanner
from url_gatekeeper import run_gatekeeper_app #url blocker
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
        auth_window.geometry("450x600")
        auth_window.resizable(False, False)
        auth_window.lift()
        auth_window.focus_force()
        auth_window.grab_set()
        auth_mode = ctk.StringVar(value="Sign In")
        # 🔷 Define shared fields
        username_entry = ctk.CTkEntry(auth_window, placeholder_text="Username")
        password_entry = ctk.CTkEntry(auth_window, placeholder_text="Password", show="*")
        result_label = ctk.CTkLabel(auth_window, text="", text_color="white")
        # 🔷 Define Sign-Up specific widgets
        email_entry = ctk.CTkEntry(auth_window, placeholder_text="Email")
        confirm_password_entry = ctk.CTkEntry(auth_window, placeholder_text="Confirm Password", show="*")
        terms_checkbox = ctk.CTkCheckBox(auth_window, text="I agree to the ")
        terms_label = ctk.CTkLabel(auth_window, text="Terms and Conditions", text_color="cyan", cursor="hand2", font=("Segoe UI", 12, "underline"))
        def show_terms_dialog(event=None):
            terms_text = (
                "🔒 Terms and Conditions\n\n"
                "1. You agree not to share your login credentials.\n"
                "2. This tool is intended for security testing only.\n"
                "3. You are responsible for how you use the scanner/blocker.\n"
                "4. We do not collect or store any personal browsing data.\n"
                "5. By using this app, you consent to these terms."
            )
            messagebox.showinfo("Terms and Conditions", terms_text)

        terms_label.bind("<Button-1>", show_terms_dialog)



        

        #for sign in 
        # 🔷 Toggle between Sign In and Sign Up
        def switch_mode():
            current = auth_mode.get()
            auth_mode.set("Sign Up" if current == "Sign In" else "Sign In")
            mode_label.configure(text=auth_mode.get())
            action_btn.configure(text=auth_mode.get())
            if auth_mode.get() == "Sign Up":
                username_entry.pack(pady=5, padx=30)
                email_entry.pack(pady=5, padx=30)
                password_entry.pack(pady=5, padx=30)
                confirm_password_entry.pack(pady=5, padx=30)
                terms_checkbox.pack(pady=2)
                terms_label.pack(pady=(0, 5))

                
            else:
                email_entry.pack_forget()
                confirm_password_entry.pack_forget()
                terms_checkbox.pack_forget()
                username_entry.pack(pady=10, padx=30)
                password_entry.pack(pady=10, padx=30)

        #to input user creds
        # 🔷 Sign In or Sign Up action
        def perform_action():
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
                if username in creds and creds[username]["password"]== password:
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



                # Sign-Up mode        
            else:
                email = email_entry.get().strip()
                confirm_password = confirm_password_entry.get().strip()
                
                if not all([username, email, password, confirm_password]):
                    result_label.configure(text="All fields are required.", text_color="red")
                    return
                
                if not email.endswith("@gmail.com"):
                    result_label.configure(text="Only Gmail addresses are allowed.", text_color="red")
                    return

                
                if password != confirm_password:
                    result_label.configure(text="Passwords do not match.", text_color="red")
                    return
                
                if not terms_checkbox.get():
                    result_label.configure(text="You must accept the Terms.", text_color="red")
                    return
                
                if username in creds:
                    result_label.configure(text="Username already exists.", text_color="orange")
                    
                else:
                     
                    creds[username] = {
                        "email": email,
                        "password": password
                    }
                    self.save_credentials(creds)
                    result_label.configure(text="Account created! You can now sign in.", text_color="green")


        # 🔷 Build layout
        mode_label = ctk.CTkLabel(auth_window, text=auth_mode.get(), font=("Segoe UI", 20, "bold"))
        mode_label.pack(pady=(20, 10))
        
        username_entry.pack(pady=10, padx=30)
        password_entry.pack(pady=10, padx=30)
        
        action_btn = ctk.CTkButton(auth_window, text=auth_mode.get(), command=perform_action)
        action_btn.pack(pady=10)
        
        switch_btn = ctk.CTkButton(auth_window, text="Switch to Sign Up / Sign In", command=switch_mode, fg_color="gray")
        switch_btn.pack(pady=5)
        
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

