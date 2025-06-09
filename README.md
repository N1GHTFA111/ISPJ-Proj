#  ISPJ_PROJ — Global Elite Bank + Sentinel Security Suite

This repository contains **two interconnected Flask-based security applications** developed as part of our Information Security Project Year 2. The apps work in tandem to simulate a realistic environment for banking and enterprise security platforms.

---

##  Overview

###  Global Elite Bank
A secure banking platform integrating:
- Blockchain-secured logs
- Secure transaction flow via Flask + PostgreSQL
- Leverages the Sentinel Security Suite for security features.

###  Sentinel Security Suite
A modular security platform offering:
- Identity Access Management (IAM)
- Secure API requester (AES-GCM + SHA-1024)
- File storage, verification, audit, and SIEM
- Web Application Firewall with ML-based threat detection

---

### Security Highlights
Sentinel Suite:
* AES GCM & SHA-1024 secure APIs

* Secure shared file center with key rotation

* Document verifier (elliptic curve cryptography)

* Federated login system (IAM)

* AI-powered WAF for path traversal & XSS detection

* SIEM with investigation pathway & audit logs

Bank App:
* Blockchain-secured logs

* OTP for checkout inactivity

* CSRF, CAPTCHA, file signature scan via Cloudmersive

* Session management and 2FA

* Rate limiting, HTTPS, secure cookie flags

* Secure file upload with antivirus scan

* Password complexity & account lockout

## ️ Setup Instructions

###   Clone the Repository

```bash
git clone https://github.com/Frostblade-spec/ISPJ-Proj.git
cd ISPJ_Proj

cd Sentinel_api
python -m app

cd Bank_app
python -m app