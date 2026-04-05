#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
#   DARK SCANNER  —  v4.1  |  Elite Network Intelligence Suite
#   Fast ARP+ICMP+Socket multi-method scanner. No emoji required.
#   Run:  sudo python3 dark_scanner.py
#   Deps: pip install scapy requests matplotlib flask
#   Created by: Oshadha Thinura
# ╚══════════════════════════════════════════════════════════════════╝

import os, re, socket, threading, ipaddress, subprocess, collections, platform, shutil
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

# ── Optional imports ────────────────────────────────────────────────
try:
    import requests as req_lib
    HAS_REQ = True
except ImportError:
    HAS_REQ = False

try:
    from scapy.all import sniff, ARP, DNS, IP, TCP, UDP, ICMP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import matplotlib; matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

try:
    from flask import Flask, render_template_string, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# ── Root/Admin check ────────────────────────────────────────────────
if platform.system() == "Linux":
    try:
        if os.geteuid() != 0:
            print("[!] Run with:  sudo python3 dark_scanner.py")
            exit(1)
    except AttributeError:
        pass
elif platform.system() == "Windows":
    import ctypes
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] Run as Administrator on Windows")
    except Exception:
        pass

# ════════════════════════════════════════════════════════════════════
#  SHARED STATE
# ════════════════════════════════════════════════════════════════════
STATE = {
    "devices":        [],
    "selected_ip":    None,
    "selected_iface": "eth0",
    "capture_run":    False,
    "dns_cache":      {},
    "arp_table":      {},
    "traffic_log":    [],
    "attack_alerts":  [],
    "anomaly_scores": collections.defaultdict(int),
    "scan_stop":      False,
}

# ════════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════════
def get_local_ip():
    try:
        if platform.system() == "Windows":
            return socket.gethostbyname(socket.gethostname())
        r = subprocess.run(["ip","route","get","1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        parts = r.stdout.split()
        if "src" in parts:
            return parts[parts.index("src") + 1]
        return "127.0.0.1"
    except Exception:
        return "127.0.0.1"

def get_interface():
    try:
        if platform.system() == "Windows":
            return "eth0"
        r = subprocess.run(["ip","route","get","1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        p = r.stdout.split()
        return p[p.index("dev") + 1] if "dev" in p else "eth0"
    except Exception:
        return "eth0"

def auto_network():
    ip = get_local_ip()
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def get_wifi_info():
    """Returns (ssid, interface, ip, network_cidr) for the connected WiFi."""
    ssid, iface, ip, net = "Unknown", "Unknown", "Unknown", None
    sys = platform.system()
    try:
        if sys == "Linux":
            for cmd in [["iw","dev"], ["iwconfig"]]:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    m_iface = re.search(r"Interface\s+(\S+)", r.stdout)
                    m_ssid  = re.search(r"ssid\s+(.+)", r.stdout)
                    if not m_ssid:
                        m_ssid = re.search(r'ESSID:"([^"]+)"', r.stdout)
                    if m_iface: iface = m_iface.group(1).strip()
                    if m_ssid:  ssid  = m_ssid.group(1).strip()
                    if ssid != "Unknown": break
                except Exception:
                    pass
            try:
                r2 = subprocess.run(
                    ["nmcli","-t","-f","active,ssid,device,type","dev","wifi"],
                    capture_output=True, text=True, timeout=5)
                for line in r2.stdout.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 3 and parts[0] == "yes":
                        ssid  = parts[1] or ssid
                        iface = parts[2] or iface
                        break
            except Exception:
                pass
            if iface != "Unknown":
                try:
                    r3 = subprocess.run(["ip","addr","show",iface],
                        capture_output=True, text=True, timeout=5)
                    m_ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", r3.stdout)
                    if m_ip:
                        ip     = m_ip.group(1)
                        prefix = m_ip.group(2)
                        net    = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
                except Exception:
                    pass
        elif sys == "Darwin":
            try:
                r = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework"
                     "/Versions/Current/Resources/airport","-I"],
                    capture_output=True, text=True, timeout=5)
                m = re.search(r"\s+SSID:\s+(.+)", r.stdout)
                if m: ssid = m.group(1).strip()
            except Exception:
                pass
            try:
                r2 = subprocess.run(["networksetup","-getairportnetwork","en0"],
                    capture_output=True, text=True, timeout=5)
                m2 = re.search(r"Current Wi-Fi Network:\s*(.+)", r2.stdout)
                if m2: ssid = m2.group(1).strip()
                iface = "en0"
            except Exception:
                pass
            ip = get_local_ip()
        elif sys == "Windows":
            try:
                r = subprocess.run(["netsh","wlan","show","interfaces"],
                    capture_output=True, text=True, timeout=5)
                m_ssid  = re.search(r"SSID\s*:\s*(.+)", r.stdout)
                m_iface = re.search(r"Name\s*:\s*(.+)", r.stdout)
                if m_ssid:  ssid  = m_ssid.group(1).strip()
                if m_iface: iface = m_iface.group(1).strip()
            except Exception:
                pass
            ip = get_local_ip()
    except Exception:
        pass
    if net is None:
        try:
            base = ip if ip != "Unknown" else get_local_ip()
            net = str(ipaddress.ip_network(base + "/24", strict=False))
        except Exception:
            net = auto_network()
    return ssid, iface, ip, net

# ── Fast multi-method host discovery ────────────────────────────────
def ping_host(ip, timeout=0.6):
    """Returns True if host responds to ICMP ping."""
    try:
        flag = "-n" if platform.system() == "Windows" else "-c"
        r = subprocess.run(
            ["ping", flag, "1", "-W", "1", str(ip)],
            capture_output=True, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False

def tcp_probe(ip, ports=(80, 443, 22, 8080, 135, 139, 445, 62078), timeout=0.4):
    """Returns True if any common TCP port is open/connectable."""
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass
    return False

def arp_scan_scapy(network_str, iface, cb_found, cb_log, stop_ref):
    """ARP broadcast -- fastest method for local WiFi network."""
    try:
        cb_log(f"  [ARP] Broadcasting on {network_str} via {iface}...\n", "info")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_str)
        ans, _ = srp(pkt, iface=iface, timeout=4, verbose=0)
        for _, rcv in ans:
            if stop_ref[0]: return
            ip  = rcv[ARP].psrc
            mac = rcv[ARP].hwsrc
            STATE["arp_table"][ip] = mac
            cb_found(ip, mac)
    except Exception as ex:
        cb_log(f"  [ARP] Error: {ex}\n", "warn")

def fallback_scan(network_str, cb_found, cb_log, stop_ref):
    """Threaded ping + TCP probe for hosts not found by ARP."""
    try:
        net   = ipaddress.ip_network(network_str, strict=False)
        hosts = list(net.hosts())
        total = len(hosts)
        cb_log(f"  [SWEEP] Probing {total} hosts with ping+TCP (64 threads)...\n", "info")
        sem = threading.Semaphore(64)

        def probe(host):
            if stop_ref[0]: return
            ip = str(host)
            if any(d["ip"] == ip for d in STATE["devices"]): return
            with sem:
                alive = ping_host(ip, 0.5) or tcp_probe(ip)
            if alive and not any(d["ip"] == ip for d in STATE["devices"]):
                mac = get_mac_for_ip(ip)
                STATE["arp_table"][ip] = mac
                cb_found(ip, mac)

        threads = [threading.Thread(target=probe, args=(h,), daemon=True) for h in hosts]
        for t in threads: t.start()
        for t in threads: t.join(timeout=2)
    except Exception as ex:
        cb_log(f"  [SWEEP] Error: {ex}\n", "warn")

def nmap_scan(network_str, cb_found, cb_log, stop_ref):
    """nmap -sn with per-host timeout -- optional 3rd pass."""
    try:
        cb_log(f"  [NMAP] nmap sweep on {network_str}...\n", "info")
        res = subprocess.run(
            ["nmap","-sn","--host-timeout","5s","-T4", network_str],
            capture_output=True, text=True, timeout=60)
        already = {d["ip"] for d in STATE["devices"]}
        for b in re.split(r"(?=Nmap scan report for)", res.stdout):
            if stop_ref[0]: return
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", b)
            if not ip_m: continue
            ip = ip_m.group(1)
            if ip in already: continue
            mac = get_mac_for_ip(ip)
            cb_found(ip, mac)
    except subprocess.TimeoutExpired:
        cb_log("  [NMAP] Timed out after 60s\n", "warn")
    except FileNotFoundError:
        cb_log("  [NMAP] nmap not installed -- skipped\n", "warn")
    except Exception as ex:
        cb_log(f"  [NMAP] Error: {ex}\n", "warn")

def get_vendor(mac):
    if not HAS_REQ or mac in ("N/A","Unknown",""):
        return "Unknown"
    try:
        resp = req_lib.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if resp.status_code == 200:
            return resp.text.strip()[:30]
        return "Unknown"
    except Exception:
        return "Unknown"

def ip_to_domain(ip):
    if ip in STATE["dns_cache"]:
        return STATE["dns_cache"][ip]
    try:
        d = socket.gethostbyaddr(ip)[0]
    except Exception:
        d = ip
    STATE["dns_cache"][ip] = d
    return d

def get_geo(ip):
    if not HAS_REQ:
        return "Unknown","??"
    try:
        j = req_lib.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return j.get("country","?"), j.get("countryCode","??")
    except Exception:
        return "Unknown","??"

def detect_os(ip):
    try:
        if not shutil.which("nmap"):
            return "Unknown"
        r = subprocess.run(["nmap","-O","--osscan-limit",ip],
                           capture_output=True, text=True, timeout=30)
        m = re.search(r"Running: (.+)", r.stdout)
        return m.group(1).strip() if m else "Unknown"
    except subprocess.TimeoutExpired:
        return "Unknown (timeout)"
    except Exception as ex:
        return f"Unknown ({type(ex).__name__})"

def get_mac_for_ip(ip):
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["arp","-a",ip], capture_output=True, text=True, timeout=5)
            m = re.search(r"(([0-9a-f]{2}-){5}[0-9a-f]{2})", r.stdout, re.I)
            if m: return m.group(1).replace("-",":")
            return "N/A"
        r = subprocess.run(["arp","-n",ip], capture_output=True, text=True, timeout=5)
        m = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", r.stdout, re.I)
        return m.group(1) if m else "N/A"
    except Exception:
        return "N/A"

def check_arp_spoof(src_ip, src_mac):
    known = STATE["arp_table"].get(src_ip)
    if known and known.lower() != src_mac.lower():
        return True, known
    STATE["arp_table"][src_ip] = src_mac
    return False, None

def ai_anomaly_score(ip, port, proto, is_out):
    HIGH = {4444,31337,12345,5555,1234,9999}
    SUSP = {22,23,25,8080,3389,6379,27017,1433,3306}
    score = 0
    if port in HIGH:    score += 50
    elif port in SUSP:  score += 15
    if proto == "ICMP": score += 5
    if is_out and port in {22,23,3389}: score += 20
    STATE["anomaly_scores"][ip] += score
    return score

# ════════════════════════════════════════════════════════════════════
#  DARK THEME
# ════════════════════════════════════════════════════════════════════
BG   = "#050811"
BG2  = "#090e1a"
BG3  = "#0d1526"
BG4  = "#121e35"
G    = "#00ff9f"
R    = "#ff2d55"
Y    = "#ffcc00"
C    = "#00f5ff"
OR   = "#ff6b35"
PU   = "#bd93f9"
FG   = "#c8d8f0"
FG2  = "#4a6080"
BORDER = "#1a2d50"
MONO = "Courier New"

def _btn(parent, text, cmd, col=G, w=None, pad=6):
    b = tk.Button(parent, text=text, command=cmd,
        bg=BG4, fg=col, activebackground=col, activeforeground=BG,
        relief="flat", bd=0, font=(MONO,9,"bold"),
        cursor="hand2", pady=pad, padx=12)
    if w: b.config(width=w)
    b.bind("<Enter>", lambda e: b.config(bg=col, fg=BG))
    b.bind("<Leave>", lambda e: b.config(bg=BG4, fg=col))
    return b

def _label(parent, text, col=FG2, size=9, bold=False):
    return tk.Label(parent, text=text, bg=BG, fg=col,
                    font=(MONO, size, "bold" if bold else "normal"))

def _entry(parent, w=24, val=""):
    e = tk.Entry(parent, bg=BG3, fg=Y, insertbackground=Y,
                 font=(MONO,9), relief="flat", width=w,
                 highlightthickness=1, highlightbackground=BORDER)
    e.insert(0, val)
    return e

def _log(parent, h=12, col=G):
    return scrolledtext.ScrolledText(parent, bg=BG2, fg=col,
        insertbackground=col, font=(MONO,9), relief="flat",
        highlightthickness=1, highlightbackground=BORDER,
        wrap="word", height=h)

def _tree(parent, cols, widths, height=8):
    t = ttk.Treeview(parent, columns=cols, show="headings",
                     height=height, style="DS.Treeview")
    for c,w in zip(cols,widths):
        t.heading(c, text=c)
        t.column(c, width=w, anchor="w")
    t.tag_configure("hi",  foreground=R)
    t.tag_configure("med", foreground=Y)
    t.tag_configure("ok",  foreground=G)
    sb = ttk.Scrollbar(parent, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=sb.set)
    return t, sb

def _section(parent, title, col=C):
    f = tk.Frame(parent, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
    tk.Label(f, text=f"  >> {title}", bg=BG3, fg=col,
             font=(MONO,8,"bold")).pack(anchor="w", padx=4, pady=(4,2))
    inner = tk.Frame(f, bg=BG3)
    inner.pack(fill="both", expand=True, padx=6, pady=(0,6))
    return f, inner

# ════════════════════════════════════════════════════════════════════
#  ROOT WINDOW
# ════════════════════════════════════════════════════════════════════
root = tk.Tk()
root.title("[ DARK SCANNER v4.1 ] -- Elite Network Intelligence")
root.geometry("1340x880")
root.configure(bg=BG)
root.resizable(True, True)

nst = ttk.Style()
nst.theme_use("clam")
nst.configure("TNotebook",      background=BG, borderwidth=0)
nst.configure("TNotebook.Tab",  background=BG3, foreground=FG2,
    font=(MONO,9,"bold"), padding=[14,6])
nst.map("TNotebook.Tab",
    background=[("selected",BG4)], foreground=[("selected",C)])
nst.configure("DS.Treeview",    background=BG2, foreground=FG,
    fieldbackground=BG2, rowheight=22, font=(MONO,9))
nst.configure("DS.Treeview.Heading", background=BG3, foreground=C,
    font=(MONO,9,"bold"))
nst.map("DS.Treeview", background=[("selected",BG4)], foreground=[("selected",C)])
nst.configure("TCombobox", fieldbackground=BG3, background=BG3,
    foreground=Y, selectbackground=BG4, font=(MONO,9))
nst.configure("TScrollbar", background=BG3, troughcolor=BG2,
    arrowcolor=FG2, borderwidth=0)

# ════════════════════════════════════════════════════════════════════
#  HEADER
# ════════════════════════════════════════════════════════════════════
hdr = tk.Frame(root, bg=BG, height=58)
hdr.pack(fill="x")
hdr.pack_propagate(False)

logo_frame = tk.Frame(hdr, bg=BG)
logo_frame.pack(side="left", padx=14, pady=8)
tk.Label(logo_frame, text="[*]", bg=BG, fg=C, font=(MONO,16,"bold")).pack(side="left", padx=(0,8))
title_col = tk.Frame(logo_frame, bg=BG)
title_col.pack(side="left")
tk.Label(title_col, text="DARK SCANNER",
         bg=BG, fg=G, font=(MONO,17,"bold")).pack(anchor="w")
tk.Label(title_col, text="Elite Network Intelligence Suite  v4.1",
         bg=BG, fg=FG2, font=(MONO,7)).pack(anchor="w")

gcfg = tk.Frame(hdr, bg=BG)
gcfg.pack(side="left", padx=20)
tk.Label(gcfg, text="NET:", bg=BG, fg=FG2, font=(MONO,8)).grid(row=0, column=0, sticky="w")
g_net = _entry(gcfg, 22, auto_network())
g_net.grid(row=0, column=1, padx=4)
tk.Label(gcfg, text="IFACE:", bg=BG, fg=FG2, font=(MONO,8)).grid(row=0, column=2, sticky="w", padx=(12,0))
g_iface = _entry(gcfg, 10, get_interface())
g_iface.grid(row=0, column=3, padx=4)

status_var = tk.StringVar(value="[+] IDLE")
sf = tk.Frame(hdr, bg=BG)
sf.pack(side="right", padx=16)
tk.Label(sf, text="SYSTEM STATUS", bg=BG, fg=FG2, font=(MONO,6,"bold")).pack()
status_lbl = tk.Label(sf, textvariable=status_var,
    bg=BG4, fg=G, font=(MONO,9,"bold"), padx=14, pady=4,
    highlightthickness=1, highlightbackground=BORDER)
status_lbl.pack()

def set_status(t, col=G):
    status_var.set(f"[+] {t}")
    status_lbl.config(fg=col)

tk.Frame(root, bg=C, height=1).pack(fill="x")

sel_bar = tk.Frame(root, bg=BG3, height=28)
sel_bar.pack(fill="x")
sel_bar.pack_propagate(False)
sel_var = tk.StringVar(value="  [ ] No device selected -- run Discovery first, then click a row")
tk.Label(sel_bar, textvariable=sel_var,
    bg=BG3, fg=Y, font=(MONO,9,"bold")).pack(side="left", padx=14, pady=4)

def update_sel_banner():
    ip = STATE["selected_ip"]
    if ip:
        d = next((x for x in STATE["devices"] if x["ip"] == ip), {})
        sel_var.set(f"  [>] TARGET: {ip}  |  {d.get('host','?')}  |  OS: {d.get('os','?')}  |  {d.get('vendor','?')}")
    else:
        sel_var.set("  [ ] No device selected -- run Discovery first, then click a row")

tk.Frame(root, bg=BORDER, height=1).pack(fill="x")

nb = ttk.Notebook(root)
nb.pack(fill="both", expand=True, padx=6, pady=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 1 -- DEVICE DISCOVERY
# ════════════════════════════════════════════════════════════════════
t1 = tk.Frame(nb, bg=BG)
nb.add(t1, text="  [>] Discovery  ")

ins_c, ins_i = _section(t1, "HOW TO OPERATE  --  Start here", Y)
ins_c.pack(fill="x", padx=10, pady=6)
tk.Label(ins_i,
    text="[ 1 ] Set Network range above  ->  [ 2 ] Click 'Scan My Network'  ->  "
         "[ 3 ] Click a row to lock target  ->  [ 4 ] Analyze in other tabs",
    bg=BG3, fg=FG, font=(MONO,9)).pack(anchor="w", pady=2)

t1_btns = tk.Frame(t1, bg=BG)
t1_btns.pack(fill="x", padx=10, pady=4)

_label(t1,"  >> Discovered Devices  (click a row to lock target for all tabs)",
       C, 8, True).pack(anchor="w", padx=10, pady=(4,1))
t1_tf = tk.Frame(t1, bg=BG)
t1_tf.pack(fill="x", padx=10)
t1_tree, t1_sb = _tree(t1_tf,
    ("IP","Hostname","MAC","Vendor","OS","Score"),
    [120,170,140,150,180,80], height=9)
t1_tree.pack(side="left", fill="x", expand=True)
t1_sb.pack(side="right", fill="y")

def on_t1_select(e):
    sel = t1_tree.selection()
    if not sel: return
    ip = t1_tree.item(sel[0], "values")[0]
    STATE["selected_ip"] = ip
    STATE["selected_iface"] = g_iface.get()
    update_sel_banner()
    sync_combos()
    set_status(f"Target locked: {ip}", Y)

t1_tree.bind("<<TreeviewSelect>>", on_t1_select)

_label(t1, "  >> Scan Log", C, 8, True).pack(anchor="w", padx=10, pady=(6,1))
t1_log = _log(t1, h=9)
t1_log.pack(fill="both", expand=True, padx=10, pady=(0,6))
for tag,col in [("ok",G),("info",C),("warn",Y),("err",R)]:
    t1_log.tag_configure(tag, foreground=col)

def t1_write(msg, tag=None):
    root.after(0, _t1_write_safe, msg, tag)

def _t1_write_safe(msg, tag=None):
    if tag is None:
        tag = ("ok"   if any(x in msg for x in ["[OK]","found","DONE"]) else
               "warn" if "[!]" in msg else
               "err"  if any(x in msg for x in ["[X]","error","Error","failed"]) else "info")
    t1_log.insert(tk.END, msg, tag)
    t1_log.see(tk.END)

scan_running = {"v": False}

def on_device_found(ip, mac):
    """Called by any scanner method when a live host is confirmed."""
    if any(d["ip"] == ip for d in STATE["devices"]):
        return
    host = "Unknown"
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    vendor  = get_vendor(mac)
    os_name = detect_os(ip)
    d = {"ip":ip,"mac":mac,"host":host,"vendor":vendor,"os":os_name}
    STATE["devices"].append(d)
    sc  = STATE["anomaly_scores"].get(ip, 0)
    tag = "hi" if sc >= 50 else "med" if sc >= 20 else "ok"
    root.after(0, lambda d=d, sc=sc, tag=tag: (
        t1_tree.insert("","end",
            values=(d["ip"],d["host"],d["mac"],d["vendor"],d["os"],sc),
            tags=(tag,)),
        t1_write(f"  [OK] {d['ip']}  host={d['host']}  mac={d['mac']}\n")
    ))

def do_discovery():
    if scan_running["v"]: return
    def run():
        scan_running["v"]  = True
        STATE["scan_stop"] = False
        STATE["devices"].clear()
        root.after(0, lambda: [t1_tree.delete(r) for r in t1_tree.get_children()])
        root.after(0, lambda: t1_log.delete("1.0","end"))
        net   = g_net.get().strip()
        iface = g_iface.get().strip()
        stop_ref = [False]
        set_status("Scanning...", C)
        t1_write(f"[{datetime.now():%H:%M:%S}]  Dark Scanner v4.1 -- sweep: {net}\n\n","info")

        # Method 1: ARP broadcast (best for WiFi -- finds phones, tablets, etc.)
        if HAS_SCAPY:
            t1_write("  [*] Method 1: ARP broadcast scan...\n","info")
            try:
                arp_scan_scapy(net, iface, on_device_found, t1_write, stop_ref)
                t1_write(f"  [OK] ARP done -- {len(STATE['devices'])} device(s) so far.\n","ok")
            except Exception as ex:
                t1_write(f"  [!] ARP scan error: {ex}\n","warn")
        else:
            t1_write("  [!] scapy not installed -- ARP scan skipped\n"
                     "      Run: pip install scapy\n","warn")

        # Method 2: Threaded ping + TCP probe
        if not STATE["scan_stop"]:
            t1_write("  [*] Method 2: Ping + TCP probe (64 threads)...\n","info")
            fallback_scan(net, on_device_found, t1_write, stop_ref)
            t1_write(f"  [OK] Sweep done -- {len(STATE['devices'])} device(s) so far.\n","ok")

        # Method 3: nmap (if available)
        if not STATE["scan_stop"] and shutil.which("nmap"):
            t1_write("  [*] Method 3: nmap final sweep...\n","info")
            nmap_scan(net, on_device_found, t1_write, stop_ref)

        n = len(STATE["devices"])
        t1_write(f"\n  [OK] DONE -- {n} device(s) found. Click a row to select.\n","ok")
        set_status(f"{n} devices found", G)
        root.after(0, sync_combos)
        scan_running["v"] = False
    threading.Thread(target=run, daemon=True).start()

def stop_discovery():
    STATE["scan_stop"] = True
    set_status("Scan stopped", Y)

def do_scan_my_network():
    if scan_running["v"]:
        messagebox.showinfo("Busy","A scan is already running. Please wait.")
        return
    def detect_and_scan():
        set_status("Detecting WiFi...", C)
        root.after(0, lambda: t1_log.delete("1.0","end"))
        t1_write(f"[{datetime.now():%H:%M:%S}]  AUTO-DETECT: finding your connected network...\n\n","info")
        ssid, iface, ip, net = get_wifi_info()
        t1_write(f"  [OK] SSID      : {ssid}\n","ok")
        t1_write(f"  [OK] Interface : {iface}\n","ok")
        t1_write(f"  [OK] Your IP   : {ip}\n","ok")
        t1_write(f"  [OK] Network   : {net}\n\n","ok")
        root.after(0, lambda: (g_net.delete(0,tk.END),   g_net.insert(0,net)))
        root.after(0, lambda: (g_iface.delete(0,tk.END), g_iface.insert(0, iface if iface != "Unknown" else get_interface())))
        if ssid == "Unknown":
            t1_write("  [!] SSID not detected -- using IP-derived range.\n"
                     "      Try: sudo apt install network-manager iw\n\n","warn")
        else:
            t1_write(f"  [*] Launching multi-method scan on '{ssid}' ({net})...\n\n","info")
        do_discovery()
    threading.Thread(target=detect_and_scan, daemon=True).start()

_btn(t1_btns,"[>] Scan Network",    do_discovery,       G, 18).pack(side="left",padx=4)
_btn(t1_btns,"[W] Scan My Network", do_scan_my_network, C, 20).pack(side="left",padx=4)
_btn(t1_btns,"[X] Stop",            stop_discovery,     R, 10).pack(side="left",padx=4)
_btn(t1_btns,"CLR Clear Log",
     lambda: t1_log.delete("1.0","end"),                FG2,12).pack(side="left",padx=4)
_label(t1_btns,"   <- click any row to lock target",    Y,  8).pack(side="left",padx=8)

# ════════════════════════════════════════════════════════════════════
#  TAB 2 -- OS DETECTION
# ════════════════════════════════════════════════════════════════════
t2 = tk.Frame(nb,bg=BG)
nb.add(t2, text="  [B] OS Detect  ")

_label(t2,"  >> Target Device",C,8,True).pack(anchor="w",padx=10,pady=(10,2))
t2_cfg=tk.Frame(t2,bg=BG); t2_cfg.pack(fill="x",padx=10,pady=4)
tk.Label(t2_cfg,text="Target IP:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=0,sticky="w")
t2_combo=ttk.Combobox(t2_cfg,width=20,font=(MONO,9),state="readonly")
t2_combo.grid(row=0,column=1,padx=6)
_label(t2_cfg,"  (auto-filled from Discovery)",FG2,8).grid(row=0,column=2,sticky="w")

t2_btns=tk.Frame(t2,bg=BG); t2_btns.pack(fill="x",padx=10,pady=4)

_label(t2,"  >> OS Fingerprint Output",C,8,True).pack(anchor="w",padx=10,pady=(4,1))
t2_log=_log(t2,h=26); t2_log.pack(fill="both",expand=True,padx=10,pady=(0,8))
for tag,col in [("info",C),("hi",G),("norm",FG),("err",R)]:
    t2_log.tag_configure(tag,foreground=col)

def do_os_detect():
    ip=t2_combo.get() or STATE["selected_ip"]
    if not ip: messagebox.showinfo("No Target","Select a device first."); return
    if not shutil.which("nmap"):
        messagebox.showerror("Missing","nmap not installed.\n\nLinux: sudo apt install nmap"); return
    STATE["selected_ip"]=ip; update_sel_banner(); t2_log.delete("1.0","end")
    def run():
        set_status(f"OS scan: {ip}",C)
        t2_log.insert(tk.END,f"[{datetime.now():%H:%M:%S}]  OS detection on {ip}...\n\n","info")
        try:
            p=subprocess.Popen(["nmap","-O","--osscan-guess",ip],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            for line in p.stdout:
                tag="hi" if any(x in line for x in ["Running:","OS details:","OS CPE:"]) else "norm"
                t2_log.insert(tk.END,line,tag); t2_log.see(tk.END)
            p.wait()
        except FileNotFoundError:
            t2_log.insert(tk.END,"Error: nmap not found\n","err")
        except Exception as ex:
            t2_log.insert(tk.END,f"Error: {ex}\n","err")
        set_status("OS scan complete",G)
    threading.Thread(target=run,daemon=True).start()

_btn(t2_btns,"[B] Run OS Detection",do_os_detect,C,20).pack(side="left",padx=4)
_btn(t2_btns,"CLR Clear",lambda:t2_log.delete("1.0","end"),FG2,10).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 3 -- PORT SCANNER
# ════════════════════════════════════════════════════════════════════
t3=tk.Frame(nb,bg=BG)
nb.add(t3,text="  [P] Port Scan  ")

_label(t3,"  >> Target & Options",C,8,True).pack(anchor="w",padx=10,pady=(10,2))
t3_cfg=tk.Frame(t3,bg=BG); t3_cfg.pack(fill="x",padx=10,pady=4)
tk.Label(t3_cfg,text="Target IP:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=0,sticky="w")
t3_combo=ttk.Combobox(t3_cfg,width=18,font=(MONO,9),state="readonly")
t3_combo.grid(row=0,column=1,padx=6)
tk.Label(t3_cfg,text="Mode:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=2,sticky="w",padx=(14,4))
t3_mode=ttk.Combobox(t3_cfg,width=16,font=(MONO,9),state="readonly",
    values=["Full scan (-p-)","Top 1000 ports","Top 100 ports","Custom ports"])
t3_mode.current(0); t3_mode.grid(row=0,column=3,padx=4)
tk.Label(t3_cfg,text="Custom:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=4,sticky="w",padx=(14,4))
t3_ports=_entry(t3_cfg,16,"22,80,443,8080"); t3_ports.grid(row=0,column=5)

t3_btns=tk.Frame(t3,bg=BG); t3_btns.pack(fill="x",padx=10,pady=4)
t3_stop={"v":False}

_label(t3,"  >> Open Ports & Services",C,8,True).pack(anchor="w",padx=10,pady=(4,1))
t3_log=_log(t3,h=26); t3_log.pack(fill="both",expand=True,padx=10,pady=(0,8))
for tag,col in [("hdr",C),("port",G),("norm",FG),("err",R)]:
    t3_log.tag_configure(tag,foreground=col)

def do_port_scan():
    ip=t3_combo.get() or STATE["selected_ip"]
    if not ip: messagebox.showinfo("No Target","Select a device first."); return
    if not shutil.which("nmap"):
        messagebox.showerror("Missing","nmap not installed.\n\nLinux: sudo apt install nmap"); return
    STATE["selected_ip"]=ip; update_sel_banner()
    mode=t3_mode.get()
    if   "Full" in mode:  arg=["-p-"]
    elif "1000" in mode:  arg=["--top-ports","1000"]
    elif "100"  in mode:  arg=["--top-ports","100"]
    else:                  arg=["-p",t3_ports.get()]
    t3_log.delete("1.0","end"); t3_stop["v"]=False
    def run():
        set_status(f"Port scan: {ip}",C)
        t3_log.insert(tk.END,f"[{datetime.now():%H:%M:%S}]  {mode} on {ip}\n\n","hdr")
        try:
            p=subprocess.Popen(["nmap"]+arg+["-T4","--open","-sV",ip],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            for line in p.stdout:
                if t3_stop["v"]: p.terminate(); break
                tag=("port" if re.search(r"\d+/(tcp|udp)",line) else
                     "hdr"  if re.match(r"PORT|Nmap",line) else "norm")
                t3_log.insert(tk.END,line,tag); t3_log.see(tk.END)
            p.wait()
        except FileNotFoundError:
            t3_log.insert(tk.END,"Error: nmap not found\n","err")
        except Exception as ex:
            t3_log.insert(tk.END,f"Error: {ex}\n","err")
        set_status("Port scan complete",G)
    threading.Thread(target=run,daemon=True).start()

_btn(t3_btns,"[P] Start Port Scan",do_port_scan,G,18).pack(side="left",padx=4)
_btn(t3_btns,"[X] Stop",lambda:(t3_stop.__setitem__("v",True),set_status("Stopped",Y)),R,10).pack(side="left",padx=4)
_btn(t3_btns,"CLR Clear",lambda:t3_log.delete("1.0","end"),FG2,10).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 4 -- VULNERABILITY SCAN
# ════════════════════════════════════════════════════════════════════
t4=tk.Frame(nb,bg=BG)
nb.add(t4,text="  [V] Vuln Scan  ")

_label(t4,"  >> Target & Script",C,8,True).pack(anchor="w",padx=10,pady=(10,2))
t4_cfg=tk.Frame(t4,bg=BG); t4_cfg.pack(fill="x",padx=10,pady=4)
tk.Label(t4_cfg,text="Target IP:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=0,sticky="w")
t4_combo=ttk.Combobox(t4_cfg,width=18,font=(MONO,9),state="readonly")
t4_combo.grid(row=0,column=1,padx=6)
tk.Label(t4_cfg,text="Script:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=2,sticky="w",padx=(14,4))
t4_scripts=ttk.Combobox(t4_cfg,width=26,font=(MONO,9),state="readonly",
    values=["vuln","exploit","auth","default,vuln","vuln,safe","smb-vuln*","http-vuln*","ftp-vuln*"])
t4_scripts.current(0); t4_scripts.grid(row=0,column=3,padx=4)

t4_btns=tk.Frame(t4,bg=BG); t4_btns.pack(fill="x",padx=10,pady=4)
t4_stop={"v":False}

_label(t4,"  >> Vulnerability Results",C,8,True).pack(anchor="w",padx=10,pady=(4,1))
t4_log=_log(t4,h=26); t4_log.pack(fill="both",expand=True,padx=10,pady=(0,8))
for tag,col in [("hdr",C),("vuln",R),("warn",Y),("norm",FG),("err",R)]:
    t4_log.tag_configure(tag,foreground=col)

def do_vuln_scan():
    ip=t4_combo.get() or STATE["selected_ip"]
    if not ip: messagebox.showinfo("No Target","Select a device first."); return
    if not shutil.which("nmap"):
        messagebox.showerror("Missing","nmap not installed.\n\nLinux: sudo apt install nmap"); return
    STATE["selected_ip"]=ip; update_sel_banner(); t4_log.delete("1.0","end"); t4_stop["v"]=False
    scr=t4_scripts.get()
    def run():
        set_status(f"Vuln scan: {ip}",R)
        t4_log.insert(tk.END,f"[{datetime.now():%H:%M:%S}]  --script {scr} on {ip}\n\n","hdr")
        try:
            p=subprocess.Popen(["nmap","--script",scr,ip],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            for line in p.stdout:
                if t4_stop["v"]: p.terminate(); break
                tag=("vuln" if "VULNERABLE" in line or "CVE" in line else
                     "hdr"  if line.startswith("|") else
                     "warn" if "WARNING" in line.upper() else "norm")
                t4_log.insert(tk.END,line,tag); t4_log.see(tk.END)
            p.wait()
        except FileNotFoundError:
            t4_log.insert(tk.END,"Error: nmap not found\n","err")
        except Exception as ex:
            t4_log.insert(tk.END,f"Error: {ex}\n","err")
        set_status("Vuln scan complete",G)
    threading.Thread(target=run,daemon=True).start()

_btn(t4_btns,"[V] Start Vuln Scan",do_vuln_scan,R,18).pack(side="left",padx=4)
_btn(t4_btns,"[X] Stop",lambda:(t4_stop.__setitem__("v",True),set_status("Stopped",Y)),Y,10).pack(side="left",padx=4)
_btn(t4_btns,"CLR Clear",lambda:t4_log.delete("1.0","end"),FG2,10).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 5 -- PACKET CAPTURE
# ════════════════════════════════════════════════════════════════════
t5=tk.Frame(nb,bg=BG)
nb.add(t5,text="  [C] Capture  ")

_label(t5,"  >> Capture Settings",C,8,True).pack(anchor="w",padx=10,pady=(10,2))
t5_cfg=tk.Frame(t5,bg=BG); t5_cfg.pack(fill="x",padx=10,pady=4)
tk.Label(t5_cfg,text="Target IP:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=0,sticky="w")
t5_combo=ttk.Combobox(t5_cfg,width=18,font=(MONO,9),state="readonly")
t5_combo.grid(row=0,column=1,padx=6)
tk.Label(t5_cfg,text="Interface:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=2,sticky="w",padx=(14,4))
t5_iface=_entry(t5_cfg,10,get_interface()); t5_iface.grid(row=0,column=3,padx=4)
tk.Label(t5_cfg,text="Filter:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=4,sticky="w",padx=(14,4))
t5_filter=ttk.Combobox(t5_cfg,width=16,font=(MONO,9),state="readonly",
    values=["All traffic","TCP only","UDP only","DNS only","ICMP only"])
t5_filter.current(0); t5_filter.grid(row=0,column=5,padx=4)

t5_stats=tk.Frame(t5,bg=BG); t5_stats.pack(fill="x",padx=10,pady=4)
t5_cvars={}
for lbl,col in [("Packets",G),("TCP",C),("UDP",Y),("DNS",OR),("Alerts",R)]:
    f=tk.Frame(t5_stats,bg=BG3,padx=18,pady=4,highlightthickness=1,highlightbackground=BORDER)
    f.pack(side="left",padx=4)
    v=tk.StringVar(value="0")
    tk.Label(f,text=lbl,bg=BG3,fg=FG2,font=(MONO,7,"bold")).pack()
    tk.Label(f,textvariable=v,bg=BG3,fg=col,font=(MONO,14,"bold")).pack()
    t5_cvars[lbl]=v

def inc5(k):
    try: t5_cvars[k].set(str(int(t5_cvars[k].get())+1))
    except Exception: pass

t5_btns=tk.Frame(t5,bg=BG); t5_btns.pack(fill="x",padx=10,pady=4)
_label(t5,"  >> Live Traffic  (cyan=ARP  green=TCP  yellow=UDP  purple=ICMP  orange=DNS  red=ALERT)",
       C,8,True).pack(anchor="w",padx=10,pady=(2,1))
t5_log=_log(t5,h=20); t5_log.pack(fill="both",expand=True,padx=10,pady=(0,6))
for tag,col in [("dns",OR),("tcp",G),("udp",Y),("icmp",PU),("arp",C),("alm",R),("norm",FG)]:
    t5_log.tag_configure(tag,foreground=col)

def _pkt_write(msg,tag="norm"):
    try:
        t5_log.insert(tk.END, msg if msg.endswith("\n") else msg+"\n", tag)
        t5_log.see(tk.END)
    except Exception: pass

def _pkt_alert(msg):
    _pkt_write(msg,"alm"); inc5("Alerts")
    STATE["attack_alerts"].append({
        "time":datetime.now().strftime("%H:%M:%S"),"type":msg,"src":"","score":"--"})

def _do_sniff(ip,iface,filt):
    fmap={"TCP only":"tcp","UDP only":"udp","DNS only":"udp port 53","ICMP only":"icmp"}
    bpf=fmap.get(filt,"")
    def process(pkt):
        if not STATE["capture_run"]: return
        ts=datetime.now().strftime("%H:%M:%S"); inc5("Packets")
        if pkt.haslayer(ARP) and pkt[ARP].op==2:
            sip=pkt[ARP].psrc; smac=pkt[ARP].hwsrc
            sp,legit=check_arp_spoof(sip,smac)
            if sp: _pkt_alert(f"[{ts}] [!!] ARP SPOOF! {sip} legit={legit} seen={smac}")
            else:  _pkt_write(f"[{ts}] ARP  {sip} -> {smac}","arp")
            return
        if pkt.haslayer(DNS):
            try:
                qd=pkt[DNS].qd
                if qd is not None:
                    dom=qd.qname.decode(errors="replace").rstrip(".")
                    _pkt_write(f"[{ts}] DNS {dom}","dns"); inc5("DNS")
                    STATE["traffic_log"].append({"time":ts,"proto":"DNS","domain":dom,
                        "direction":"","port":53,"country":""})
            except Exception: pass
            return
        if not pkt.haslayer(IP): return
        src,dst=pkt[IP].src,pkt[IP].dst
        if src!=ip and dst!=ip: return
        is_out=(src==ip); remote=dst if is_out else src; dirn="->" if is_out else "<-"
        domain=ip_to_domain(remote); cntry,cc=get_geo(remote)
        proto,port="IP",0
        if pkt.haslayer(TCP):
            proto="TCP"; port=pkt[TCP].dport if is_out else pkt[TCP].sport; inc5("TCP")
        elif pkt.haslayer(UDP):
            proto="UDP"; port=pkt[UDP].dport if is_out else pkt[UDP].sport; inc5("UDP")
        elif pkt.haslayer(ICMP):
            proto="ICMP"
        score=ai_anomaly_score(remote,port,proto,is_out)
        flag=" [!!]" if score>=20 else ""
        ptag=proto.lower() if proto in ("TCP","UDP","ICMP") else "norm"
        _pkt_write(f"[{ts}] {proto:4s} {dirn} {domain[:36]:<36} [{cc}] :{port}{flag}",ptag)
        STATE["traffic_log"].append({"time":ts,"proto":proto,"direction":dirn,"domain":domain,
            "country":cntry,"port":port,"src":src,"dst":dst})
        if score>=20:
            _pkt_alert(f"[{ts}] [!!] ANOMALY {remote} {proto}:{port} score={score}")
            STATE["attack_alerts"].append({
                "time":ts,"type":f"ANOMALY {proto}:{port}","src":remote,"score":score})
    try:
        sniff(iface=iface,prn=process,store=False,filter=bpf,
              stop_filter=lambda _: not STATE["capture_run"])
    except Exception as ex:
        root.after(0,_pkt_write,f"Sniff error: {ex}","alm")

def start_capture():
    if not HAS_SCAPY: messagebox.showerror("Missing","pip install scapy"); return
    ip=t5_combo.get() or STATE["selected_ip"]
    if not ip: messagebox.showinfo("No Target","Select a device first."); return
    STATE["selected_ip"]=ip; STATE["capture_run"]=True
    update_sel_banner(); set_status(f"Capturing -> {ip}",C)
    iface=t5_iface.get() or g_iface.get()
    threading.Thread(target=_do_sniff,args=(ip,iface,t5_filter.get()),daemon=True).start()

def stop_capture():
    STATE["capture_run"]=False; set_status("Capture stopped",Y)

def clear_capture():
    t5_log.delete("1.0","end"); STATE["traffic_log"].clear()
    for v in t5_cvars.values(): v.set("0")

_btn(t5_btns,"[>] Start Capture",start_capture,G,18).pack(side="left",padx=4)
_btn(t5_btns,"[X] Stop",          stop_capture, R,10).pack(side="left",padx=4)
_btn(t5_btns,"CLR Clear",         clear_capture,FG2,10).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 6 -- ARP SPOOF DETECTION
# ════════════════════════════════════════════════════════════════════
t6=tk.Frame(nb,bg=BG)
nb.add(t6,text="  [A] ARP Spoof  ")

_label(t6,"  >> ARP Monitor Settings",C,8,True).pack(anchor="w",padx=10,pady=(10,2))
t6_cfg=tk.Frame(t6,bg=BG); t6_cfg.pack(fill="x",padx=10,pady=4)
tk.Label(t6_cfg,text="Interface:",bg=BG,fg=FG2,font=(MONO,9)).grid(row=0,column=0,sticky="w")
t6_iface=_entry(t6_cfg,10,get_interface()); t6_iface.grid(row=0,column=1,padx=6)
_label(t6_cfg,"  Monitors ARP replies -- flags when an IP MAC changes (MITM).",FG2,8).grid(row=0,column=2,sticky="w")

t6_btns=tk.Frame(t6,bg=BG); t6_btns.pack(fill="x",padx=10,pady=4)
t6_run={"v":False}

_label(t6,"  >> Known ARP Table",C,8,True).pack(anchor="w",padx=10,pady=(6,1))
t6_tf=tk.Frame(t6,bg=BG); t6_tf.pack(fill="x",padx=10)
t6_tree,t6_sb=_tree(t6_tf,("IP","Known MAC","Status"),(180,200,100),height=6)
t6_tree.pack(side="left",fill="x",expand=True); t6_sb.pack(side="right",fill="y")

t6_pane=tk.Frame(t6,bg=BG); t6_pane.pack(fill="both",expand=True,padx=10,pady=6)
lf6=tk.Frame(t6_pane,bg=BG); lf6.pack(side="left",fill="both",expand=True,padx=(0,4))
rf6=tk.Frame(t6_pane,bg=BG); rf6.pack(side="left",fill="both",expand=True)
_label(lf6,"  >> ARP Traffic",C,8,True).pack(anchor="w",pady=(0,2))
t6_log=_log(lf6,h=8); t6_log.pack(fill="both",expand=True)
t6_log.tag_configure("ok",foreground=G); t6_log.tag_configure("err",foreground=R)
_label(rf6,"  [!!] SPOOF ALERTS",R,8,True).pack(anchor="w",pady=(0,2))
t6_alm=_log(rf6,h=8); t6_alm.pack(fill="both",expand=True)
t6_alm.tag_configure("alm",foreground=R)

def refresh_t6():
    for r in t6_tree.get_children(): t6_tree.delete(r)
    for ip,mac in STATE["arp_table"].items():
        t6_tree.insert("","end",values=(ip,mac,"[OK]"),tags=("ok",))

def start_arp():
    if not HAS_SCAPY: messagebox.showerror("Missing","pip install scapy"); return
    t6_run["v"]=True; iface=t6_iface.get(); set_status(f"ARP monitor: {iface}",C)
    def run():
        def pkt(p):
            if not t6_run["v"]: return
            if not p.haslayer(ARP) or p[ARP].op!=2: return
            sip=p[ARP].psrc; smac=p[ARP].hwsrc; ts=datetime.now().strftime("%H:%M:%S")
            sp,legit=check_arp_spoof(sip,smac)
            if sp:
                msg=f"[{ts}] [!!] SPOOF!  {sip}  real={legit}  fake={smac}"
                root.after(0,lambda m=msg:(t6_alm.insert(tk.END,m+"\n","alm"),t6_alm.see(tk.END)))
                STATE["attack_alerts"].append({"time":ts,"type":"ARP_SPOOF","src":sip,"score":"--"})
            else:
                root.after(0,lambda ts=ts,sip=sip,smac=smac:(
                    t6_log.insert(tk.END,f"[{ts}] [OK] {sip}  {smac}\n","ok"),t6_log.see(tk.END)))
            root.after(0,refresh_t6)
        try:
            sniff(iface=iface,prn=pkt,filter="arp",store=False,
                  stop_filter=lambda _: not t6_run["v"])
        except Exception as ex:
            root.after(0,lambda e=ex:t6_log.insert(tk.END,f"Error: {e}\n","err"))
    threading.Thread(target=run,daemon=True).start()

def stop_arp():
    t6_run["v"]=False; set_status("ARP monitor stopped",Y)

_btn(t6_btns,"[>] Start Monitor",start_arp, G,18).pack(side="left",padx=4)
_btn(t6_btns,"[X] Stop",          stop_arp,  R,10).pack(side="left",padx=4)
_btn(t6_btns,"[R] Refresh Table", refresh_t6,C,14).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 7 -- AI ANOMALY DETECTION
# ════════════════════════════════════════════════════════════════════
t7=tk.Frame(nb,bg=BG)
nb.add(t7,text="  [AI] Anomaly  ")

leg_c,leg_i=_section(t7,"Score Legend",Y)
leg_c.pack(fill="x",padx=10,pady=(10,4))
for lbl,col in [("[ ] 0-19  Normal",G),("[ ] 20-49  Suspicious",Y),("[ ] 50+  DANGER",R)]:
    tk.Label(leg_i,text=f"  {lbl}  ",bg=BG3,fg=col,font=(MONO,10,"bold")).pack(side="left",padx=10)

_label(t7,"  >> Anomaly Scores by IP  (populated by Packet Capture)",C,8,True).pack(anchor="w",padx=10,pady=(8,1))
t7_tf=tk.Frame(t7,bg=BG); t7_tf.pack(fill="x",padx=10)
t7_tree,t7_sb=_tree(t7_tf,("IP","Score","Risk Level","Details"),(160,90,110,250),height=7)
t7_tree.pack(side="left",fill="x",expand=True); t7_sb.pack(side="right",fill="y")

rules_c,rules_i=_section(t7,"Scoring Rules",C)
rules_c.pack(fill="x",padx=10,pady=6)
tk.Label(rules_i,
    text="  +50  Port in HIGH-RISK set (4444, 31337, 12345, 5555, 9999)\n"
         "  +15  Port in SUSPICIOUS set (22, 23, 25, 8080, 3389, DB ports)\n"
         "  +20  Outbound SSH / RDP / Telnet  (lateral movement indicator)\n"
         "   +5  ICMP traffic  (ping sweep indicator)",
    bg=BG3,fg=FG,font=(MONO,9),justify="left").pack(anchor="w")

_label(t7,"  >> Recent Anomaly Events",R,8,True).pack(anchor="w",padx=10,pady=(6,1))
t7_log=_log(t7,h=7); t7_log.pack(fill="both",expand=True,padx=10,pady=(0,6))
for tag,col in [("hi",R),("med",Y),("ok",G)]:
    t7_log.tag_configure(tag,foreground=col)

t7_btns=tk.Frame(t7,bg=BG); t7_btns.pack(fill="x",padx=10,pady=2)

def refresh_t7():
    for r in t7_tree.get_children(): t7_tree.delete(r)
    for ip,sc in sorted(STATE["anomaly_scores"].items(),key=lambda x:-x[1]):
        risk  ="[!!!] DANGER" if sc>=50 else "[!] SUSPECT" if sc>=20 else "[OK]"
        tag   ="hi" if sc>=50 else "med" if sc>=20 else "ok"
        detail="High-risk port activity" if sc>=50 else "Suspicious traffic" if sc>=20 else "--"
        t7_tree.insert("","end",values=(ip,sc,risk,detail),tags=(tag,))
    t7_log.delete("1.0","end")
    for a in reversed(STATE["attack_alerts"][-30:]):
        sc=a.get("score",0)
        try: si=int(sc)
        except (ValueError,TypeError): si=0
        tag="hi" if si>=50 else "med" if si>=20 else "ok"
        t7_log.insert(tk.END,f"[{a['time']}]  {a['type']}  src={a.get('src','--')}  score={sc}\n",tag)
    root.after(3000,refresh_t7)

_btn(t7_btns,"[R] Refresh Now",   refresh_t7,C,14).pack(side="left",padx=4)
_btn(t7_btns,"[D] Reset Scores",
    lambda:(STATE["anomaly_scores"].clear(),refresh_t7()),FG2,14).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 8 -- TRAFFIC GRAPHS
# ════════════════════════════════════════════════════════════════════
t8=tk.Frame(nb,bg=BG)
nb.add(t8,text="  [G] Graphs  ")

if HAS_MPL:
    _label(t8,"  >> Live charts auto-update every second from Packet Capture data",FG2,8).pack(anchor="w",padx=10,pady=6)
    gf=tk.Frame(t8,bg=BG); gf.pack(fill="both",expand=True,padx=10,pady=4)
    lg=tk.Frame(gf,bg=BG); lg.pack(side="left",fill="both",expand=True)
    rg=tk.Frame(gf,bg=BG); rg.pack(side="left",fill="both",expand=True,padx=(6,0))
    fig1=Figure(figsize=(6,3.5),facecolor=BG); ax1=fig1.add_subplot(111)
    ax1.set_facecolor(BG2); ax1.tick_params(colors=FG2)
    for sp in ax1.spines.values(): sp.set_color(BG3)
    ax1.set_title("Packets / second",color=C,fontsize=10)
    cnv1=FigureCanvasTkAgg(fig1,master=lg); cnv1.get_tk_widget().pack(fill="both",expand=True)
    fig2=Figure(figsize=(4,3.5),facecolor=BG); ax2=fig2.add_subplot(111)
    ax2.set_facecolor(BG); ax2.set_title("Protocol Mix",color=C,fontsize=10)
    cnv2=FigureCanvasTkAgg(fig2,master=rg); cnv2.get_tk_widget().pack(fill="both",expand=True)
    fig3=Figure(figsize=(10,2.8),facecolor=BG); ax3=fig3.add_subplot(111)
    ax3.set_facecolor(BG2); ax3.tick_params(colors=FG2)
    for sp in ax3.spines.values(): sp.set_color(BG3)
    ax3.set_title("Anomaly Scores -- Top 10 IPs",color=R,fontsize=10)
    cnv3=FigureCanvasTkAgg(fig3,master=t8); cnv3.get_tk_widget().pack(fill="both",expand=True,padx=10,pady=(0,6))
    _rbuf=[]; _lastn=[0]
    def update_graphs():
        n=len(STATE["traffic_log"]); dt=n-_lastn[0]; _lastn[0]=n
        _rbuf.append(dt)
        if len(_rbuf)>60: _rbuf.pop(0)
        ax1.clear(); ax1.set_facecolor(BG2); ax1.tick_params(colors=FG2)
        for sp in ax1.spines.values(): sp.set_color(BG3)
        ax1.set_title("Packets / second",color=C,fontsize=10)
        ax1.plot(_rbuf,color=G,lw=1.5); ax1.fill_between(range(len(_rbuf)),_rbuf,alpha=0.12,color=G)
        cnv1.draw()
        protos=collections.Counter(e.get("proto","?") for e in STATE["traffic_log"] if e)
        if protos:
            ax2.clear(); ax2.set_facecolor(BG); ax2.set_title("Protocol Mix",color=C,fontsize=10)
            ax2.pie(protos.values(),labels=protos.keys(),
                colors=[G,C,Y,R,PU,OR][:len(protos)],textprops={"color":FG,"fontsize":8})
            cnv2.draw()
        scores=dict(sorted(STATE["anomaly_scores"].items(),key=lambda x:-x[1])[:10])
        if scores:
            ax3.clear(); ax3.set_facecolor(BG2); ax3.tick_params(colors=FG2)
            for sp in ax3.spines.values(): sp.set_color(BG3)
            ax3.set_title("Anomaly Scores -- Top 10 IPs",color=R,fontsize=10)
            keys=list(scores.keys()); vals=list(scores.values())
            ax3.bar(keys,vals,color=[R if v>=50 else Y if v>=20 else G for v in vals])
            ax3.set_xticks(range(len(keys))); ax3.set_xticklabels(keys,rotation=20,fontsize=7,color=FG2)
            cnv3.draw()
        root.after(1000,update_graphs)
    update_graphs()
else:
    tk.Label(t8,text="\n\n  [G]  Install matplotlib for live graphs\n\n"
        "       pip install matplotlib\n\nthen restart",
        bg=BG,fg=FG2,font=(MONO,12),justify="left").pack(expand=True)

# ════════════════════════════════════════════════════════════════════
#  TAB 9 -- ALERTS
# ════════════════════════════════════════════════════════════════════
t9=tk.Frame(nb,bg=BG)
nb.add(t9,text="  [!] Alerts  ")

t9_top=tk.Frame(t9,bg=BG); t9_top.pack(fill="x",padx=10,pady=8)
tk.Label(t9_top,text="[!!!]  REAL-TIME ATTACK ALERTS",bg=BG,fg=R,font=(MONO,13,"bold")).pack(side="left")
t9_btns=tk.Frame(t9,bg=BG); t9_btns.pack(fill="x",padx=10,pady=2)
_label(t9,"  >> Alert Table  (auto-refreshes every 3 seconds)",C,8,True).pack(anchor="w",padx=10,pady=(4,1))
t9_tf=tk.Frame(t9,bg=BG); t9_tf.pack(fill="x",padx=10)
t9_tree,t9_sb=_tree(t9_tf,("Time","Type","Source IP","Score"),(100,260,160,80),height=10)
t9_tree.pack(side="left",fill="x",expand=True); t9_sb.pack(side="right",fill="y")
_label(t9,"  >> Alert Details",C,8,True).pack(anchor="w",padx=10,pady=(6,1))
t9_log=_log(t9,h=9); t9_log.pack(fill="both",expand=True,padx=10,pady=(0,8))
for tag,col in [("arp",OR),("hi",R),("med",Y)]:
    t9_log.tag_configure(tag,foreground=col)

def refresh_alerts():
    for r in t9_tree.get_children(): t9_tree.delete(r)
    for a in reversed(STATE["attack_alerts"][-200:]):
        sc=a.get("score","--")
        try: si=int(sc)
        except (ValueError,TypeError): si=0
        tag="hi" if "ARP" in str(a.get("type","")) or si>=50 else "med"
        t9_tree.insert("","end",values=(a["time"],a["type"],a.get("src","--"),sc),tags=(tag,))
    t9_log.delete("1.0","end")
    for a in reversed(STATE["attack_alerts"][-50:]):
        sc=a.get("score",0)
        try: si=int(sc)
        except (ValueError,TypeError): si=0
        tag="arp" if "ARP" in str(a.get("type","")) else "hi" if si>=50 else "med"
        t9_log.insert(tk.END,f"[{a['time']}]  {a['type']}  src={a.get('src','--')}  score={sc}\n",tag)
    root.after(3000,refresh_alerts)

_btn(t9_btns,"[R] Refresh",  refresh_alerts,C,12).pack(side="left",padx=4)
_btn(t9_btns,"[D] Clear All",
    lambda:(STATE["attack_alerts"].clear(),refresh_alerts()),FG2,12).pack(side="left",padx=4)

# ════════════════════════════════════════════════════════════════════
#  TAB 10 -- WEB DASHBOARD
# ════════════════════════════════════════════════════════════════════
t10=tk.Frame(nb,bg=BG)
nb.add(t10,text="  [W] Dashboard  ")

ctr=tk.Frame(t10,bg=BG); ctr.pack(expand=True)
tk.Label(ctr,text="[W]  Web Dashboard",bg=BG,fg=C,font=(MONO,16,"bold")).pack(pady=(40,8))
tk.Label(ctr,text="Access live scanner data from any browser on your network.",
         bg=BG,fg=FG2,font=(MONO,10)).pack(pady=4)
dash_sv=tk.StringVar(value="Not running")
tk.Label(ctr,textvariable=dash_sv,bg=BG,fg=G,font=(MONO,10,"bold")).pack(pady=8)
t10_url=tk.Label(ctr,text="",bg=BG,fg=Y,font=(MONO,11),cursor="hand2"); t10_url.pack()

DASH_HTML="""<!doctype html><html><head><title>Dark Scanner</title>
<meta http-equiv="refresh" content="3">
<style>*{box-sizing:border-box;margin:0;padding:0}
body{background:#050811;color:#c8d8f0;font-family:'Courier New',monospace;padding:20px}
h1{color:#00ff9f;font-size:1.4em;padding:12px 0 6px}
h2{color:#00f5ff;font-size:1em;padding:10px 0 4px;border-bottom:1px solid #1a2d50;margin-bottom:6px}
table{width:100%;border-collapse:collapse;margin-bottom:16px}
th{background:#0d1526;color:#00f5ff;padding:7px 10px;text-align:left;font-size:.82em}
td{border-bottom:1px solid #090e1a;padding:5px 10px;font-size:.82em}
.r{color:#ff2d55}.g{color:#00ff9f}.y{color:#ffcc00}
</style></head><body>
<h1>[*] DARK SCANNER -- auto refresh 3s -- {{now}}</h1>
<h2>Devices ({{devices|length}})</h2>
<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Score</th></tr>
{% for d in devices %}<tr><td>{{d.ip}}</td><td>{{d.host}}</td><td>{{d.os}}</td>
<td class="{{'r' if scores.get(d.ip,0)>=50 else 'y' if scores.get(d.ip,0)>=20 else 'g'}}">
{{scores.get(d.ip,0)}}</td></tr>{% endfor %}</table>
<h2>Alerts ({{alerts|length}})</h2>
<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Score</th></tr>
{% for a in alerts|reverse %}<tr class="r">
<td>{{a.time}}</td><td>{{a.type}}</td><td>{{a.get('src','')}}</td><td>{{a.get('score','')}}</td>
</tr>{% endfor %}</table>
<h2>Recent Traffic</h2>
<table><tr><th>Time</th><th>Proto</th><th>Dir</th><th>Domain</th><th>Port</th><th>Country</th></tr>
{% for t in traffic[-30:]|reverse %}<tr>
<td>{{t.get('time','')}}</td><td>{{t.get('proto','')}}</td><td>{{t.get('direction','')}}</td>
<td>{{t.get('domain','')}}</td><td>{{t.get('port','')}}</td><td>{{t.get('country','')}}</td>
</tr>{% endfor %}</table>
<p style="color:#4a6080;font-size:.75em;margin-top:20px">Created by Oshadha Thinura</p>
</body></html>"""

_flask_started=False; _flask_thread=None

def _run_flask():
    fa=Flask(__name__)
    @fa.route("/")
    def idx():
        return render_template_string(DASH_HTML,
            devices=STATE["devices"],scores=dict(STATE["anomaly_scores"]),
            alerts=STATE["attack_alerts"][-50:],traffic=STATE["traffic_log"][-100:],
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    @fa.route("/api")
    def api():
        return jsonify({"devices":STATE["devices"],
            "alerts":STATE["attack_alerts"][-50:],"traffic":STATE["traffic_log"][-50:]})
    fa.run(host="0.0.0.0",port=5000,debug=False,use_reloader=False)

def start_dash():
    global _flask_started,_flask_thread
    if not HAS_FLASK: messagebox.showerror("Missing","pip install flask"); return
    if _flask_started: messagebox.showinfo("Running","Already at http://localhost:5000"); return
    _flask_thread=threading.Thread(target=_run_flask,daemon=True)
    _flask_thread.start(); _flask_started=True
    ip=get_local_ip()
    dash_sv.set(f"[OK] Running -> http://{ip}:5000")
    t10_url.config(text=f"http://{ip}:5000")
    set_status("Dashboard running",G)

def open_browser():
    import webbrowser; webbrowser.open("http://localhost:5000")

_btn(ctr,"[>] Launch Dashboard",start_dash,  G,22).pack(pady=12)
_btn(ctr,"[W] Open in Browser", open_browser,C,22).pack(pady=4)
tk.Label(ctr,
    text=("The dashboard auto-refreshes every 3 seconds.\n"
          "Open from any device: http://<your-ip>:5000\n\n"
          "API endpoint: http://localhost:5000/api  (JSON)"),
    bg=BG,fg=FG2,font=(MONO,9),justify="left").pack(pady=14,padx=30,anchor="w")

# ════════════════════════════════════════════════════════════════════
#  COMBO SYNC
# ════════════════════════════════════════════════════════════════════
_all_combos=[t2_combo,t3_combo,t4_combo,t5_combo]

def sync_combos():
    ips=[d["ip"] for d in STATE["devices"]]
    for cb in _all_combos:
        cb["values"]=ips
        if ips and not cb.get(): cb.current(0)
    if STATE["selected_ip"] and STATE["selected_ip"] in ips:
        for cb in _all_combos: cb.set(STATE["selected_ip"])

# ════════════════════════════════════════════════════════════════════
#  FOOTER
# ════════════════════════════════════════════════════════════════════
tk.Frame(root,bg=C,height=1).pack(fill="x",side="bottom")
ft=tk.Frame(root,bg=BG3,height=28); ft.pack(fill="x",side="bottom"); ft.pack_propagate(False)
tk.Label(ft,
    text=f"  [*]  HOST: {get_local_ip()}  |  IFACE: {get_interface()}  |  NET: {auto_network()}"
         f"  |  scapy:{'OK' if HAS_SCAPY else 'NO'}  matplotlib:{'OK' if HAS_MPL else 'NO'}"
         f"  flask:{'OK' if HAS_FLASK else 'NO'}  requests:{'OK' if HAS_REQ else 'NO'}",
    bg=BG3,fg=FG2,font=(MONO,7)).pack(side="left",pady=5,padx=10)
tk.Label(ft,
    text="DARK SCANNER v4.1  |  Created by Oshadha Thinura  [*]  ",
    bg=BG3,fg=C,font=(MONO,7,"bold")).pack(side="right",pady=5,padx=10)

# ── Boot ──────────────────────────────────────────────────────────────
refresh_t7()
refresh_alerts()
root.mainloop()
