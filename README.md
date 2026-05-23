# 🛡️ NetSentry SOC Platform | MikroTik Network Security & Monitoring

NetSentry is an advanced, high-performance Security Operations Center (SOC) dashboard and device fingerprinting system designed specifically for **MikroTik RouterOS** networks. It provides real-time traffic statistics, dynamic subnet scanning, vulnerability checks, automated threat logging, and interactive router-level diagnostics—all packaged into a premium, responsive glassmorphism dark-mode web interface.

---

## 🚀 Key Features

### 1. 📊 Real-Time Operations Monitoring
- **Dual-Tier Real-Time Updates**: Leverages WebSockets to push metrics.
  - **Fast Tier (3s)**: Interface rates (Mbps RX/TX), device CPU load, ping latency to WAN (8.8.8.8), and active connection states.
  - **Slow Tier (15s)**: Complete routing tables, DNS cache records, DHCP leases, system packages, wireless registrations, VPN tunnels, and audit logs.
- **Dynamic Charting**: Visualizes network throughput, CPU, and latency graphs using responsive Chart.js plots with hardware-glowing palettes.

### 2. 🔍 Subnet Scanning & Advanced Port Fingerprinting
- **Active Subnet Ping Sweep**: Scans any /24 subnet using high-speed concurrent TCP-probes, automatically extracting hostname and active states.
- **Port Scanner & Fingerprinting**: Probes common ports and grabs active banners (HTTP, SSH, FTP, etc.). Analyzes banners to classify identified vendors (e.g. *MikroTik, Dahua, Hikvision, QNAP*) and device categories (e.g. *IP Cameras, NAS, Printers, VoIP Phones*), displaying customized class icons.

### 3. 🔍 Live Persistent Table Filters
- **Real-Time Search**: Seamlessly filter large tables (DHCP leases, ARP, active connections, firewall logs, routing records, etc.) instantly.
- **WebSocket State Persistence**: Your search filter query remains actively cached and reapplied on the fly as WebSocket updates refresh the page content.

### 4. 🛠️ Interactive Diagnostics Tools
- **Router-Level Ping**: Executes direct, multi-packet pings from the router to any target IP or domain, rendering microsecond response tables.
- **Hybrid DNS lookup**: Resolves hostnames on the router, automatically falling back to the local Python socket resolver if the router API is restricted or offline.

### 5. 🚨 Intelligent Security Alerting & Logs
- **Log Threat Analytics**: Real-time parser scans system logs against 20+ signature rules (brute force attempts, ARP spoofing, network flap/loops, unauthorized config changes).
- **KPI Threat counters**: Visual dashboard showing aggregated **Critical (🔴)**, **High (🟠)**, and **Medium (🟡)** metrics.
- **Attacker Ban**: Single-click firewall blocking to dynamically append rogue IPs into the `NetSentry_Blocklist` address list on the router.

---

## 🛠️ Technology Stack

- **Backend**: Python, FastAPI, RouterOS API (`routeros_api`), WebSockets, JWT (Authentication), PyJWT.
- **Frontend**: Vanilla HTML5, Modern CSS (Glassmorphism layout, vibrant glowing colors), JavaScript (Vanilla ES6), FontAwesome 6, Chart.js.
- **Database / Storage**: RouterOS dynamic config (direct API query), stateful memory cache.

---

## 📦 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/G30RG3-GJ/NetSentry.git
cd NetSentry
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory (based on `.env.example`):
```env
# MikroTik Router Connection
MIKROTIK_HOST=192.168.88.1
MIKROTIK_USER=admin
MIKROTIK_PASSWORD=your_router_password
MIKROTIK_PORT=8728
MIKROTIK_USE_SSL=False

# Dashboard Auth Configurations
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=admin
SECRET_KEY=generate_a_secure_jwt_token_here_32chars
ALGORITHM=HS256

# API Port
PORT=8000
```
> [!IMPORTANT]
> The `.env` file is excluded in `.gitignore` to prevent publishing your private router password to GitHub.

### 3. Set Up Virtual Environment & Install Dependencies
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 4. Start the Application
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser and log in with your dashboard credentials.

---

## 🔒 Security Notice
NetSentry is built with security best practices:
- **Protected Environment**: Excludes `.env`, `.venv`, and `__pycache__` via `.gitignore`.
- **JWT Session tokens**: Authenticated REST API and WebSocket handshakes.
- **Sanitized Inputs**: Regex checks on diagnostic pings and subnets to prevent remote command injections.
