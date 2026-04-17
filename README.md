SecureNet: Zero-Trust Network Access Control (NAC) Engine
SecureNet is a lightweight, highly secure, Python-based AAA (Authentication, Authorization, and Accounting) backend. It is designed to integrate with edge network devices (OpenWrt, pfSense, GL.iNet) to provide captive portal authentication, session management, and forensic logging.

It is built to separate the application logic from the network edge, ensuring that complex security mechanisms can be updated without touching router firmware.

🛡️ Core Features
Authentication: PBKDF2-SHA256 password hashing with 1M iterations (Crackstation-resistant).
Authorization: Strict Role-Based Access Control (RBAC) for users and administrators.
Accounting: Forensic logging of IP addresses, session durations, and bandwidth usage.
Security Hardening: Immune to SQL Injection (Parameterized Queries), XSS (Output Escaping), and Brute-Force attacks (IP Rate Limiting).
Device Management: Multi-device limit tracking to prevent credential sharing.
Network Awareness: Dual-layer presence detection via HTTP Heartbeats and ARP polling.
🏗️ Architecture
SecureNet operates purely at the Application Layer (Layer 7). It expects the network edge (Router/AP) to handle Layer 2/3 traffic interception and simply forward unauthorized HTTP requests to the SecureNet backend.

Interception: Edge router catches HTTP traffic and redirects to SecureNet.
Validation: SecureNet validates credentials against the MariaDB database.
Enforcement: SecureNet triggers a script/API to open the firewall for that specific IP.
Accounting: SecureNet logs the session and monitors device presence via ARP.
🚀 Quick Start (Local Simulation)
To test the security features and admin dashboard locally without a router:

1. Install Dependencies:

python3 -m venv venvsource venv/bin/activatepip install -r requirements.txt
2. Initialize Database:

bash

sudo apt install mariadb-server
python3 setup_users.py
3. Run the Engine:

bash

sudo python3 app.py
4. Access:
Open http://localhost

Default Admin: admin / admin123
Default User: john_doe / password123
🌐 Hardware Integration Guide (Production)
To deploy SecureNet in a real network environment, it must be paired with a router capable of Captive Portal/DNS interception.

Recommended Hardware: GL.iNet Routers (e.g., MT-300N-V2 "Mango") running OpenWrt.

Integration Steps:

Flash OpenWrt on your edge router.
Install openNDS (Network Detection Service).
Configure openNDS PreAuth to forward all unauthorized traffic to your SecureNet server IP (e.g., http://192.168.1.10:80).
In app.py, replace the simulated firewall rules with actual API calls to openNDS to dynamically authorize MAC addresses.
(Optional) Setup Nginx as a reverse proxy on the server to handle SSL/HTTPS, satisfying modern OS HSTS requirements.
🛡️ Security Implementation Details
This project was built from the ground up to mitigate the OWASP Top 10:

SQLi Prevention: Strict use of PyMySQL parameterized queries (%s).
XSS Prevention: All user inputs are sanitized via html.escape() before rendering.
Brute Force: In-memory IP tracking (5 attempts = 15 min ban) without time.sleep() to prevent Thread-DoS.
Credential Storage: Passwords are never stored in plain text or standard SHA. Only PBKDF2 hashes with random 16-byte salts are stored.
