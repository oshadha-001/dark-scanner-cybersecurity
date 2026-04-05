# 🔍 Dark Scanner v4.1

**Elite Network Intelligence Suite** — A fast, multi-method network scanner with a dark-themed GUI, real-time packet capture, anomaly detection, and a built-in web dashboard.

> Created by **Oshadha Thinura**

---

## ✨ Features

| Tab | Feature | Description |
|-----|---------|-------------|
| `[>] Discovery` | Device Discovery | ARP broadcast + ICMP ping + TCP probe + nmap sweep |
| `[B] OS Detect` | OS Fingerprinting | Detect OS of any device using nmap |
| `[P] Port Scan` | Port Scanner | Full / Top 1000 / Top 100 / Custom port scan with service detection |
| `[V] Vuln Scan` | Vulnerability Scan | nmap NSE scripts (vuln, exploit, smb-vuln*, http-vuln*, etc.) |
| `[C] Capture` | Packet Sniffer | Live traffic capture with TCP/UDP/DNS/ICMP/ARP filters |
| `[A] ARP Spoof` | ARP Spoof Detection | Real-time MITM / ARP poisoning detection |
| `[AI] Anomaly` | Anomaly Scoring | Scores IPs by suspicious port/protocol activity |
| `[G] Graphs` | Live Graphs | Packets/sec chart, Protocol mix pie, Top anomaly IPs bar chart |
| `[!] Alerts` | Attack Alerts | Auto-refreshing alert table with severity color coding |
| `[W] Dashboard` | Web Dashboard | Browser-based live dashboard at `http://<your-ip>:5000` |

---

## 🖥️ System Requirements

### Operating System
- ✅ **Linux** (Ubuntu, Debian, Kali, Arch — recommended)
- ✅ **Windows 10/11**
- ✅ **macOS**

### Python Version
- **Python 3.7 or higher** is required
- Check your version:
  ```bash
  python3 --version
  ```

### Run Privileges
- **Linux / macOS** — Must run as **root** (`sudo`) for ARP scanning and packet sniffing
- **Windows** — Must run as **Administrator** for raw socket access

---

## 📦 What You Need to Install

### Step 1 — Python Packages

Install all required and optional Python packages:

```bash
pip install scapy requests matplotlib flask
```

Or install them one by one:

```bash
pip install scapy       # ARP scanning, packet sniffing, ARP spoof detection
pip install requests    # MAC vendor lookup, IP geolocation
pip install matplotlib  # Live traffic graphs (Tab 8)
pip install flask       # Web dashboard (Tab 10)
```

> **tkinter** is used for the GUI and is **built into Python** on most systems.
> If it's missing on Linux, install it with:
> ```bash
> sudo apt install python3-tk
> ```

---

### Step 2 — System Tool: nmap

`nmap` is a **system-level tool** (not a Python package). It is required for:
- OS Detection tab (`[B] OS Detect`)
- Port Scanner tab (`[P] Port Scan`)
- Vulnerability Scanner tab (`[V] Vuln Scan`)
- Optional 3rd-pass network sweep in Discovery

**Install nmap:**

| OS | Command |
|----|---------|
| Ubuntu / Debian | `sudo apt install nmap` |
| Kali Linux | pre-installed |
| Arch Linux | `sudo pacman -S nmap` |
| macOS | `brew install nmap` |
| Windows | Download from [https://nmap.org/download.html](https://nmap.org/download.html) |

Verify installation:
```bash
nmap --version
```

---

### Step 3 — Optional System Tools (Linux only)

These improve WiFi auto-detection in the **"Scan My Network"** feature:

```bash
sudo apt install iw wireless-tools network-manager
```

| Tool | Purpose |
|------|---------|
| `iw` | Detect WiFi SSID and interface |
| `iwconfig` | Fallback WiFi detection |
| `nmcli` (NetworkManager) | Preferred WiFi detection method |

---

## 📋 Full Dependency Summary

| Dependency | Type | Purpose | Required? |
|------------|------|---------|-----------|
| Python 3.7+ | Runtime | Run the script | ✅ Yes |
| `tkinter` | Python built-in | GUI window and all widgets | ✅ Yes |
| `scapy` | pip package | ARP scan, packet sniffing, ARP spoof detection | ⭐ Recommended |
| `requests` | pip package | MAC vendor lookup (macvendors.com) + IP geolocation (ip-api.com) | Optional |
| `matplotlib` | pip package | Live graphs — packets/sec, protocol mix, anomaly score chart | Optional |
| `flask` | pip package | Web dashboard accessible from any browser on the network | Optional |
| `nmap` | System tool | OS detection, port scan, vulnerability scan, nmap sweep | Optional* |
| `iw` / `iwconfig` | System tool | WiFi SSID and interface auto-detection on Linux | Optional |
| `nmcli` | System tool | WiFi detection via NetworkManager on Linux | Optional |

> *nmap is listed as optional but **most analysis tabs won't work without it**.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/dark-scanner.git
cd dark-scanner
```

### 2. Install everything

```bash
# Python packages
pip install scapy requests matplotlib flask

# nmap (Linux/Debian/Ubuntu)
sudo apt install nmap

# tkinter if missing (Linux)
sudo apt install python3-tk

# Optional: WiFi tools for better auto-detection (Linux)
sudo apt install iw wireless-tools network-manager
```

### 3. Run Dark Scanner

**Linux / macOS:**
```bash
sudo python3 dark_scanner.py
```

**Windows (run terminal as Administrator):**
```bash
python dark_scanner.py
```

---

## 🗺️ How to Use

1. **Launch** the app — network range and interface are auto-detected in the top bar
2. Go to **`[>] Discovery`** → click **"Scan My Network"** to find all devices
3. **Click a row** in the device table to lock it as the target for all other tabs
4. Use the tabs to analyse the selected device:
   - Detect OS → `[B] OS Detect`
   - Scan ports → `[P] Port Scan`
   - Find vulnerabilities → `[V] Vuln Scan`
   - Watch live traffic → `[C] Capture`
   - Monitor for ARP attacks → `[A] ARP Spoof`
   - View anomaly scores → `[AI] Anomaly`
   - Watch live charts → `[G] Graphs`
   - See all security alerts → `[!] Alerts`
5. **Launch Web Dashboard** from `[W] Dashboard` for browser access from any device

---

## 🌐 Web Dashboard

Start from the **`[W] Dashboard`** tab, then open in any browser on your network:

```
http://<your-local-ip>:5000
```

- Auto-refreshes every 3 seconds
- Shows discovered devices, alerts, and recent traffic
- JSON API endpoint: `http://localhost:5000/api`

---

## 🔍 Scan Methods (Discovery)

Dark Scanner uses 3 layered methods for maximum coverage:

1. **ARP Broadcast** (Scapy) — fastest, best for WiFi, finds phones/tablets/IoT
2. **Ping + TCP Probe** — 64-thread fallback using ICMP + common ports (80, 443, 22, 8080, 135, 445...)
3. **nmap Sweep** — optional final pass using `nmap -sn`

---

## 🚨 Anomaly Scoring Rules

| Score | Trigger |
|-------|---------|
| +50 | High-risk port activity (4444, 31337, 12345, 5555, 9999) |
| +15 | Suspicious port (22, 23, 25, 8080, 3389, 3306, 6379, 27017, 1433) |
| +20 | Outbound SSH / Telnet / RDP (lateral movement indicator) |
| +5  | ICMP traffic (ping sweep indicator) |

🔴 Score ≥ 50 → **DANGER** &nbsp;|&nbsp; 🟡 Score 20–49 → **SUSPICIOUS** &nbsp;|&nbsp; 🟢 Score < 20 → **Normal**

---

## ⚠️ Disclaimer

This tool is intended **for educational purposes and authorized network auditing only**. Only use Dark Scanner on networks you own or have explicit permission to test. Unauthorized scanning may be illegal in your country.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — Packet manipulation library
- [nmap](https://nmap.org/) — Port scanning and OS detection
- [ip-api.com](http://ip-api.com) — IP geolocation
- [macvendors.com](https://macvendors.com) — MAC address vendor lookup
