# Blocking Malicious Websites

A modern Python GUI toolkit built using CustomTkinter that provides tools to enhance user cybersecurity by:

- Scanning for malicious URLs using VirusTotal + heuristic checks.
- Blocking/unblocking websites via local hosts file.
- Providing user authentication with lockout protection and sign-up validation.

---

## Features

User Authentication:
- Sign-In and Sign-Up system with input validation.
- Password confirmation, email domain (@gmail.com) check.
- Lockout for 30 seconds after 3 failed attempts.
- Terms & Conditions modal dialog.

Malicious URL Scanner:
- Analyze URLs using VirusTotal API.
- Detects phishing or unsafe links using AI-assisted heuristics.
- Supports single and bulk scan.
- Allows users to report malicious URLs manually.
- Saves results and blacklists to file.

URL Gatekeeper (Blocker):
- Block websites by modifying the system’s hosts file.
- Unblock manually or via imported list.
- Import URLs from a .txt file to block/unblock in bulk.
- Auto refreshes DNS.
- Persistent blocked list (saved to JSON).

Internship Info:
- “Project Info” window displays team and project details as part of an internship project.

---

## How to Run

🔧 Prerequisites:
- Python 3.10+
- Install required packages:

```bash
pip install customtkinter requests python-dotenv
```

You must have a valid VirusTotal API key:
- Create a .env file in the root folder:
```
API_KEY=your_virustotal_api_key_here
```

▶️ To run the project:

```bash
python "main (1).py"
```

---

## How to Use

1. Click “Authenticate” and Sign In or Sign Up.
   - Use a valid Gmail address.
   - Read and accept Terms & Conditions (hover/click).
2. Use “Malicious URL Scanner” to:
   - Enter a URL and scan.
   - Bulk scan from .txt file.
   - Report malicious URLs manually.
3. Use “URL Gatekeeper” to:
   - Block/unblock websites by name.
   - Import/export block lists.
   - View blocked URLs.
4. Click on “Tool Launcher” title to view project details.

---

Built by Team Supraja Technologies for the Internship Project — July 2025  
🎓 Powered by Python, CustomTkinter, and Cybersecurity APIs.


