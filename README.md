# 🚀 Browser Data & Credential Extractor — No Admin Rights Needed

## 📌 Overview
This is a **security research tool** that demonstrates how **browser cookies, saved passwords, and other sensitive data** can be extracted **without administrator permissions**.

The purpose is to **raise awareness** of local data exposure risks and help developers, researchers, and IT teams improve endpoint security.

⚠️ **Disclaimer:**  
This project is for **educational and ethical testing purposes only**. Do **NOT** use it on systems or accounts you do not own or have explicit permission to test. The author is **not responsible** for any misuse.

---

## ✨ Key Capabilities
- **No Admin Rights Required** — works under standard user privileges.
- **Cookie Extraction** — from supported browsers.
- **Saved Credential Extraction** — usernames, emails, passwords (if accessible), session tokens.
- **Cross-Browser Support** — tested with **Microsoft Edge** and **Google Chrome**.
- **Detailed Metadata** — includes flags like `is_secure` and `is_httponly`.

---

## 📂 Data Collected

### 1. **Cookies**
- **browser** — Browser name (Edge, Chrome, etc.)
- **profile** — Path to browser profile data.
- **host** — Domain or subdomain of the cookie.
- **name** — Cookie name.
- **value** — Cookie value (may be encrypted or empty).
- **path** — Cookie path scope.
- **expires_utc** — Expiration timestamp in UTC.
- **is_secure** — Boolean, sent only over HTTPS.
- **is_httponly** — Boolean, inaccessible to JavaScript.

---

### 2. **Saved Credentials**
- **browser** — Browser name.
- **profile** — Path to profile folder.
- **origin_url** — URL of login page or site.
- **username** — Stored username/email.
- **password** — Stored password (Edge supports plaintext retrieval, Chrome returns encrypted/masked values).
- **other data (Chrome)** — Session links, stored emails, mobile numbers, addresses.

---

## 📝 Example Extracted Data

### Cookies Example
Browser: Edge
Profile Path: C:\Users\USER\AppData\Local\Microsoft\Edge\User Data\Default
Host: .bing.com, .microsoft.com, .google.com, .doubleclick.net
Cookie Names: MUID, SRCHD, _EDGE_V, MC1, IDE, UID, _ga
Flags: is_secure=true, is_httponly=true

### Credentials Example
Browser: Edge, Chrome
Profile Paths:
C:\Users\USER\AppData\Local\Microsoft\Edge\User Data\Default
C:\Users\USER\AppData\Local\Google\Chrome\User Data\Default
C:\Users\USER\AppData\Local\Google\Chrome\User Data\Profile 1
Login URLs:
https://login.live.com/
https://accounts.google.com/
https://restream.io/signup
https://www.irctc.co.in/
http://192.168.0.1/
Usernames/Emails:
user@example.com
zoommeetonline
admin
Passwords: Available (Edge) / Masked (Chrome)


---

## 🛠️ Supported Browsers
- **Microsoft Edge** — Fully tested (cookies + passwords).
- **Google Chrome** — Tested (cookies + partial creds/session data).
- Other Chromium-based browsers may work with minimal adjustments.

---

## ⚡ Why This Matters
This project demonstrates:
- Sensitive browser data can be accessed **without admin privileges**.
- Even if passwords are masked, session cookies can allow **account hijacking**.
- Local endpoint security is often **overlooked** in security strategies.

---

## 🔐 Security Recommendations
- Use **strong, unique passwords** + enable **2FA** everywhere.
- Lock your device when unattended.
- Regularly clear browser cookies and saved credentials.
- Keep browsers and OS fully updated.
- Use full-disk encryption.

---

## 📜 License
This project is provided under the **MIT License** for educational purposes only.  
The author does not condone or take responsibility for any illegal activity.

---

## 📢 Disclaimer
By using this code, you acknowledge:
- It is for **security research only**.
- You have explicit permission to test on the target machine.
- The author is not liable for misuse or damages.

---

## 🔗 Connect
For collaborations, research discussions, or security awareness training:  
**[LinkedIn Profile](https://www.linkedin.com/in/sarvesh-patil-9b0573373?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app)** | **#CyberSecurity #DataPrivacy #EthicalHacking**
