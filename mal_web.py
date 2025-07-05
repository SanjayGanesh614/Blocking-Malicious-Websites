import requests
import time
import difflib
import base64
import os
import json
import webbrowser
import datetime
import winsound
from urllib.parse import urlparse
import customtkinter as ctk
from tkinter import messagebox, filedialog


from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("API_KEY")


BLACKLIST_FILE = "blacklist.txt"
EXPORT_TXT = "scan_results.txt"
SAFE_DOMAINS = ["google.com", "facebook.com", "youtube.com", "amazon.com", "microsoft.com", "wikipedia.org"]
SUSPICIOUS_TLDS = [".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".ru", ".biz", ".info",".pk"]

headers = {"x-apikey": API_KEY}

class URLScanner:
    def __init__(self):
        self.blacklisted_domains = {
            "malicious.com", "phishing-site.org", "badwebsite.ru",
            "freegiveaway.tk", "account-update.xyz", "eicar.org",
            "amtso.org", "phishing.test", "malicious-example.com"
        }
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm', 'password', 'bank','tech','techsupport','scam'
        ]
        self.suspicious_extensions = SUSPICIOUS_TLDS

    def url_id(self, url):
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def get_url_verdict(self, encoded_url):
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data['last_analysis_stats']
                results = data['last_analysis_results']
                rating = data.get('reputation', 0)
                community_score = data.get('total_votes', {})
                malicious = stats['malicious']
                suspicious = stats['suspicious']
                return malicious > 0 or suspicious > 0, malicious, suspicious, results, rating, community_score
        except Exception as e:
            print(f"[Error] get_url_verdict: {e}")
        return False, 0, 0, {}, 0, {}

    def suggest_url_correction(self, url):
        try:
            domain = url.replace("http://", "").replace("https://", "").split("/")[0]
            closest = difflib.get_close_matches(domain, SAFE_DOMAINS, n=1, cutoff=0.6)
            if closest:
                return url.replace(domain, closest[0])
        except:
            pass
        return None

    def heuristic_check(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        if domain in self.blacklisted_domains:
            return True, f"⚠️ Domain '{domain}' is blacklisted."
        for keyword in self.suspicious_keywords:
            if keyword in path:
                return True, f"⚠️ Suspicious keyword '{keyword}' detected in path."
        for ext in self.suspicious_extensions:
            if domain.endswith(ext):
                return True, f"⚠️ Suspicious domain extension '{ext}' detected."
        return False, ""

    def sound_alert(self):
        winsound.Beep(1000, 500)
        winsound.Beep(1200, 300)
        winsound.Beep(1000, 500)

    def save_to_blacklist(self, url):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(BLACKLIST_FILE, "a") as f:
            f.write(f"{url} - {timestamp}\n")

    def export_to_txt(self, url, malicious, suspicious, verdicts, rating, community_score):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if malicious > 0:
            reason = "Detected as malicious by VirusTotal"
            score = f"Malicious: {malicious}, Suspicious: {suspicious}"
            
        elif suspicious > 0:
            reason = "Detected as suspicious by VirusTotal"
            score = f"Suspicious: {suspicious}"
            
        else:
            heuristic_flag, heuristic_reason = self.heuristic_check(url)
            if heuristic_flag:
                reason = heuristic_reason
                score = "Heuristic Flagged"
            else:
                reason = "No threat detected"
                score = "0"
                
        entry = (
        f"URL     : {url}\n"
        f"Time    : {timestamp}\n"
        f"Reason  : {reason}\n"
        f"Score   : {score}\n"
        f"{'-'*40}\n"
        )
        try:
            with open(EXPORT_TXT, 'a') as f:
                f.write(entry)
        except Exception as e:
            print(f"[TXT Export Error] {e}")


scanner = URLScanner()
root = ctk.CTk()
root.title("Malicious URL Scanner")
root.geometry("600x550")
root.resizable(False, False)

def update_result(text):
    result_box.configure(state="normal")
    result_box.delete("1.0", "end")
    result_box.insert("end", text)
    result_box.configure(state="disabled")

def show_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            contents = f.read()
        messagebox.showinfo("Blacklist", contents)
    else:
        messagebox.showinfo("Blacklist", "No blacklisted URLs yet.")

def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return
    corrected = scanner.suggest_url_correction(url)
    if corrected and corrected != url:
        messagebox.showinfo("Suggestion", f"Did you mean: {corrected}?")

     # Check if URL was previously self-reported
    if os.path.exists(EXPORT_TXT):
        with open(EXPORT_TXT, 'r') as f:
            lines = f.readlines()
            for i in range(0, len(lines), 5):  # each entry block is 5 lines (4 content + 1 separator)
                if i + 2 < len(lines):
                    url_line = lines[i].strip()
                    reason_line = lines[i + 2].strip()
                    
                    if url_line.startswith("URL") and reason_line.endswith("Self-reported as malicious"):
                        entry_url = url_line.split(":", 1)[1].strip()
                        if entry_url == url:
                            update_result("⚠️ This URL was self-reported as malicious.")
                            scanner.save_to_blacklist(url)
                            scanner.sound_alert()
                            return

    """# Continue with normal scanning (if not self-reported)
    scanner.perform_scan(url)"""



    try:
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        time.sleep(15)
        encoded = scanner.url_id(url)
        is_malicious, malicious, suspicious, verdicts, rating, community_score = scanner.get_url_verdict(encoded)
        scanner.export_to_txt(url, malicious, suspicious, verdicts, rating, community_score)

        if is_malicious:
            scanner.save_to_blacklist(url)
            scanner.sound_alert()
            update_result(f"🚫 Malicious: {malicious}, Suspicious: {suspicious}, rating: {rating}, community score: {community_score}\nOpening VirusTotal...")
            webbrowser.open(f"https://www.virustotal.com/gui/url/{encoded}")
        else:
            suspicious_flag, reason = scanner.heuristic_check(url)
            if suspicious_flag:
                scanner.save_to_blacklist(url)
                scanner.sound_alert()
                update_result(reason)
            else:
                update_result(f"✅ Safe. Malicious: {malicious}, Suspicious: {suspicious}")

    except Exception as e:
        messagebox.showerror("Scan Error", str(e))

def scan_bulk():
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not filepath:
        return

    with open(filepath, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    result_box.configure(state="normal")
    result_box.delete("1.0", "end")
    result_box.insert("end", "🔁 Starting bulk scan...\n")
    root.update_idletasks()

    for index, url in enumerate(urls, start=1):
        try:
            result_box.insert("end", f"\n🔽 [{index}/{len(urls)}] Scanning: {url}\n")
            root.update_idletasks()

            # Step 1: Submit URL
            submission = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            if submission.status_code not in [200, 202]:
                raise Exception(f"Failed to submit URL: {submission.status_code}")

            # Step 2: Wait for analysis
            time.sleep(15)

            # Step 3: Get encoded ID
            encoded = scanner.url_id(url)

            # Step 4: Get verdict
            is_malicious, malicious, suspicious, verdicts, rating, community_score = scanner.get_url_verdict(encoded)

            # Step 5: Save results
            scanner.export_to_txt(url, malicious, suspicious, verdicts, rating, community_score)

            # Step 6: Show result
            if is_malicious:
                scanner.save_to_blacklist(url)
                scanner.sound_alert()
                msg = f"🚫 MALICIOUS | Malicious: {malicious}, Suspicious: {suspicious}"
            else:
                heuristic_flag, reason = scanner.heuristic_check(url)
                if heuristic_flag:
                    scanner.save_to_blacklist(url)
                    scanner.sound_alert()
                    msg = f"🟡 Heuristic Alert: {reason}"
                else:
                    msg = f"✅ Safe | Malicious: {malicious}, Suspicious: {suspicious}"

            result_box.insert("end", msg + "\n")
            root.update_idletasks()

        except Exception as e:
            error = f"❌ Error scanning {url}: {e}"
            result_box.insert("end", error + "\n")
            root.update_idletasks()

    result_box.insert("end", "\n✅ Bulk scan completed.\n")
    result_box.configure(state="disabled")
    messagebox.showinfo("Bulk Scan Complete", f"Finished scanning {len(urls)} URLs.")
def report_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL to report.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data = {
        "url": url,
        "time": timestamp,
        "reason": "Self-reported as malicious",
        "score": "Reported by user"
    }

    try:
        if os.path.exists(EXPORT_TXT):
            with open(EXPORT_TXT, 'r') as f:
                content = f.read().strip()
                all_data = json.loads(content) if content else []
        else:
            all_data = []

        all_data.append(data)

        with open(EXPORT_TXT, 'w') as f:
            json.dump(all_data, f, indent=4)

        messagebox.showinfo("Reported", f"{url} was reported as malicious.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not report URL: {e}")


title_label = ctk.CTkLabel(root, text="\u26d4 Malicious URL Scanner", font=("Arial", 24, "bold"), text_color="cyan")
title_label.pack(pady=20)

url_entry = ctk.CTkEntry(root, placeholder_text="e.g. example.com", width=400)
url_entry.pack(pady=10)

button_frame = ctk.CTkFrame(root, fg_color="transparent")
button_frame.pack(pady=10)

scan_button = ctk.CTkButton(button_frame, text="Scan URL", fg_color="purple", command=scan_url)
scan_button.grid(row=0, column=0, padx=10)

bulk_button = ctk.CTkButton(button_frame, text="Bulk Scan", fg_color="orange", command=scan_bulk)
bulk_button.grid(row=0, column=1, padx=10)


report_button = ctk.CTkButton(button_frame,text="📝 Report URL",fg_color="red", command=report_url)
report_button.grid(row=1,column=0,padx=10,pady=10)

blacklist_button = ctk.CTkButton(root, text="View Blacklist", fg_color="blue", command=show_blacklist)
blacklist_button.place(x=310,y=166)

result_label = ctk.CTkLabel(root, text="\ud83d\udcc3 Scan Results", text_color="red", font=("Arial", 16, "bold"))
result_label.pack()

result_text = ctk.StringVar()
result_box = ctk.CTkTextbox(root, width=550, height=200)
result_box.pack(pady=10)


exit_button = ctk.CTkButton(root, text="\u274c Exit", fg_color="gold", text_color="black", command=root.destroy)
exit_button.pack(pady=10)

def run_scanner_app():
    root.mainloop()
