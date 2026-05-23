"""
NetSentry Advanced Network Scanner — Device Fingerprinting Engine
Detects: cameras, printers, phones, routers, IoT, PCs, NAS, VoIP, game consoles
"""
import asyncio
import socket
import ipaddress
import re
from typing import List, Dict, Any, Optional, Tuple

# ── MAC OUI → (vendor, device_type, icon) ────────────────────────────────────
OUI_DB: Dict[str, Tuple[str, str, str]] = {
    # MikroTik
    "AC:C1:EE": ("MikroTik", "router",  "🌐"), "E4:8D:8C": ("MikroTik", "router", "🌐"),
    "00:0C:42": ("MikroTik", "router",  "🌐"), "6C:3B:6B": ("MikroTik", "router", "🌐"),
    "D4:CA:6D": ("MikroTik", "router",  "🌐"), "48:8F:5A": ("MikroTik", "router", "🌐"),
    "18:FD:74": ("MikroTik", "router",  "🌐"), "2C:C8:1B": ("MikroTik", "router", "🌐"),
    # Cisco / Meraki
    "00:26:5A": ("Cisco",    "switch",  "🔀"), "00:0D:ED": ("Cisco",    "switch", "🔀"),
    "68:BC:0C": ("Cisco",    "switch",  "🔀"), "00:11:92": ("Cisco",    "router", "🌐"),
    # TP-Link
    "C8:3A:35": ("TP-Link",  "router",  "🌐"), "50:FA:84": ("TP-Link",  "router", "🌐"),
    "A4:77:33": ("TP-Link",  "router",  "🌐"), "C8:5B:76": ("TP-Link",  "router", "🌐"),
    "90:F6:52": ("TP-Link",  "router",  "🌐"),
    # ASUS
    "1C:FA:68": ("ASUS",     "router",  "🌐"), "00:1A:92": ("ASUS",     "router", "🌐"),
    "30:5A:3A": ("ASUS",     "router",  "🌐"),
    # Netgear
    "00:09:5B": ("Netgear",  "router",  "🌐"), "C0:FF:D4": ("Netgear",  "router", "🌐"),
    # Apple
    "00:1C:58": ("Apple",    "laptop",  "💻"), "00:1F:5B": ("Apple",    "laptop",  "💻"),
    "A4:C3:61": ("Apple",    "phone",   "📱"), "F0:18:98": ("Apple",    "phone",   "📱"),
    "8C:85:90": ("Apple",    "phone",   "📱"), "DC:A9:04": ("Apple",    "tablet",  "📱"),
    "3C:15:C2": ("Apple",    "laptop",  "💻"), "00:23:12": ("Apple",    "laptop",  "💻"),
    "00:26:BB": ("Apple",    "phone",   "📱"),
    # Samsung
    "8C:71:F8": ("Samsung",  "phone",   "📱"), "00:16:6C": ("Samsung",  "phone",   "📱"),
    "B4:EF:39": ("Samsung",  "tv",      "📺"), "00:50:C2": ("Samsung",  "phone",   "📱"),
    # Xiaomi
    "CC:2D:E0": ("Xiaomi",   "phone",   "📱"), "FC:64:BA": ("Xiaomi",   "phone",   "📱"),
    "28:6C:07": ("Xiaomi",   "phone",   "📱"),
    # Hikvision / Dahua / Axis / Hanwha (IP cameras)
    "44:19:B6": ("Hikvision", "camera", "📷"), "C4:2F:90": ("Hikvision", "camera", "📷"),
    "D0:0D:BD": ("Hikvision", "camera", "📷"), "BC:AD:28": ("Hikvision", "camera", "📷"),
    "10:12:FB": ("Dahua",    "camera",  "📷"), "70:62:B8": ("Dahua",     "camera", "📷"),
    "E0:50:8B": ("Dahua",    "camera",  "📷"), "00:30:48": ("Axis",      "camera", "📷"),
    "AC:CC:8E": ("Hanwha",   "camera",  "📷"),
    # HP / Canon / Epson / Brother (Printers)
    "00:24:21": ("HP",       "printer", "🖨️"), "FC:15:B4": ("HP",       "printer", "🖨️"),
    "9C:B6:54": ("HP",       "printer", "🖨️"), "00:1E:0B": ("HP",       "printer", "🖨️"),
    "00:00:85": ("Canon",    "printer", "🖨️"), "00:1E:8F": ("Canon",    "printer", "🖨️"),
    "00:26:AB": ("Epson",    "printer", "🖨️"), "00:04:AC": ("Epson",    "printer", "🖨️"),
    "00:80:77": ("Brother",  "printer", "🖨️"), "00:1B:A9": ("Brother",  "printer", "🖨️"),
    # Dell / HP / Lenovo / Intel (PCs/Laptops)
    "A0:EC:F9": ("Dell",     "pc",      "🖥️"), "18:66:DA": ("Dell",     "pc",      "🖥️"),
    "B8:AC:6F": ("Dell",     "laptop",  "💻"), "00:21:70": ("Dell",     "pc",      "🖥️"),
    "00:1A:4B": ("QNAP",     "nas",     "💾"), "24:5E:BE": ("QNAP",     "nas",     "💾"),
    "00:11:32": ("Synology", "nas",     "💾"), "00:50:BA": ("Synology", "nas",     "💾"),
    # VoIP phones
    "00:04:F2": ("Polycom",  "voip",    "☎️"), "00:90:7A": ("Snom",     "voip",    "☎️"),
    "00:04:13": ("Cisco IP", "voip",    "☎️"),
    # Ubiquiti
    "FC:EC:DA": ("Ubiquiti", "ap",      "📶"), "24:A4:3C": ("Ubiquiti", "ap",      "📶"),
    "04:18:D6": ("Ubiquiti", "ap",      "📶"), "00:27:22": ("Ubiquiti", "router",  "🌐"),
    # Gaming consoles
    "00:D9:D1": ("Sony PS",  "console", "🎮"), "00:04:1F": ("Sony PS",  "console", "🎮"),
    "00:0D:3A": ("Xbox",     "console", "🎮"), "7C:ED:8D": ("Nintendo", "console", "🎮"),
    # Smart TV / streaming
    "8C:77:12": ("Roku",     "tv",      "📺"), "B0:A7:37": ("Chromecast","tv",     "📺"),
    "54:60:09": ("Amazon",   "tv",      "📺"),
    # Raspberry Pi / IoT
    "B8:27:EB": ("Raspberry","iot",     "🔧"), "DC:A6:32": ("Raspberry","iot",     "🔧"),
    "E4:5F:01": ("Raspberry","iot",     "🔧"),
    # Vmware / VirtualBox
    "00:50:56": ("VMware",   "vm",      "💻"), "00:0C:29": ("VMware",   "vm",      "💻"),
    "08:00:27": ("VirtualBox","vm",     "💻"), "00:15:5D": ("Hyper-V",  "vm",      "💻"),
    # Microsoft / Windows
    "28:18:78": ("Microsoft","pc",      "🖥️"),
    # Intel NUC/WiFi
    "B4:B5:2F": ("Intel",    "pc",      "🖥️"), "3C:A9:F4": ("Intel",   "pc",      "🖥️"),
}

DEVICE_TYPE_LABELS = {
    "router":  "Router / Gateway",   "switch": "Network Switch",
    "ap":      "Access Point",       "camera": "IP Camera",
    "printer": "Printer",            "phone":  "Mobile Phone",
    "tablet":  "Tablet",             "laptop": "Laptop",
    "pc":      "Desktop PC",         "nas":    "NAS Storage",
    "vm":      "Virtual Machine",    "voip":   "VoIP Phone",
    "tv":      "Smart TV / Streaming","console":"Game Console",
    "iot":     "IoT / Smart Device", "unknown":"Unknown Device",
}

# ── Port → service fingerprints ───────────────────────────────────────────────
PORT_SERVICES = {
    21: "FTP",         22: "SSH",          23: "Telnet",
    25: "SMTP",        53: "DNS",           80: "HTTP",
    110: "POP3",       135: "MSRPC",       139: "NetBIOS",
    143: "IMAP",       161: "SNMP",        443: "HTTPS",
    445: "SMB",        515: "LPR/Print",   554: "RTSP",
    631: "IPP/Print",  993: "IMAPS",       995: "POP3S",
    1883: "MQTT",      1900: "UPnP",       3306: "MySQL",
    3389: "RDP",       5353: "mDNS",       5900: "VNC",
    8080: "HTTP-Alt",  8291: "WinBox",     8443: "HTTPS-Alt",
    8554: "RTSP-Alt",  8728: "RouterOS",   8729: "RouterOS-SSL",
    9100: "RAW-Print", 10554:"RTSP-Alt2",  49152:"UPnP-Alt",
    62078:"iPhone-Sync",5985: "WinRM",     47808:"BACnet/IoT",
}

# Port → device type hint
PORT_DEVICE_HINTS: Dict[int, str] = {
    554: "camera",  8554: "camera", 10554: "camera",
    9100: "printer", 515: "printer", 631: "printer",
    62078: "phone",  5353: "iot",    1883: "iot",
    47808: "iot",    8291: "router", 8728: "router",
    3389: "pc",      5985: "pc",     445: "pc",
    5900: "pc",      1900: "tv",
}


def oui_lookup(mac: str) -> Tuple[str, str, str]:
    """Return (vendor, device_type, icon) from MAC OUI."""
    if not mac:
        return ("Unknown", "unknown", "🖥️")
    clean = mac.upper().replace("-", ":")
    prefix = clean[:8]
    result = OUI_DB.get(prefix)
    if not result:
        prefix6 = clean[:6].replace(":", "")
        for key, val in OUI_DB.items():
            if key.replace(":", "") == prefix6:
                return val
    return result or ("Unknown", "unknown", "🖥️")


def infer_device_type(open_ports: List[int], vendor: str, hostname: str, device_type: str) -> Tuple[str, str]:
    """Refine device type using open ports and hostname hints. Returns (type, icon)."""
    h = hostname.lower()
    v = vendor.lower()

    # Port-based hints (highest priority for specific device types)
    for port in open_ports:
        hint = PORT_DEVICE_HINTS.get(port)
        if hint and hint != "unknown":
            device_type = hint
            break

    # Hostname keyword overrides
    if any(k in h for k in ("camera", "cam", "ipc", "nvr", "dvr", "hikvision", "dahua")):
        device_type = "camera"
    elif any(k in h for k in ("printer", "print", "hp-", "canon", "epson", "brother")):
        device_type = "printer"
    elif any(k in h for k in ("iphone", "android", "galaxy", "pixel", "phone")):
        device_type = "phone"
    elif any(k in h for k in ("nas", "synology", "qnap", "diskstation", "volume")):
        device_type = "nas"
    elif any(k in h for k in ("router", "gateway", "mikrotik", "rb", "rb750")):
        device_type = "router"
    elif any(k in h for k in ("switch", "cisco", "catalyst")):
        device_type = "switch"
    elif any(k in h for k in ("laptop", "macbook", "notebook")):
        device_type = "laptop"
    elif any(k in h for k in ("desktop", "pc-", "-pc", "windows")):
        device_type = "pc"
    elif any(k in h for k in ("xbox", "playstation", "ps4", "ps5")):
        device_type = "console"
    elif any(k in h for k in ("tv", "roku", "firetv", "chromecast", "smart")):
        device_type = "tv"
    elif any(k in h for k in ("raspberry", "pi", "arduino")):
        device_type = "iot"

    icons = {
        "router": "🌐", "switch": "🔀", "ap": "📶", "camera": "📷",
        "printer": "🖨️", "phone": "📱", "tablet": "📱", "laptop": "💻",
        "pc": "🖥️", "nas": "💾", "vm": "💻", "voip": "☎️",
        "tv": "📺", "console": "🎮", "iot": "🔧", "unknown": "🖥️",
    }
    return device_type, icons.get(device_type, "🖥️")


async def grab_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Try to grab a service banner from a TCP port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Send a probe depending on port
        if port == 80 or port == 8080:
            writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetSentry/1.0\r\n\r\n".encode())
        elif port == 22:
            pass  # SSH sends banner first
        elif port == 21:
            pass  # FTP sends banner first
        else:
            writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        text = data.decode("utf-8", errors="ignore").strip()
        return text[:200] if text else None
    except Exception:
        return None


def parse_http_banner(banner: str) -> Dict[str, str]:
    """Extract server, title, device hints from HTTP response."""
    info = {}
    if not banner:
        return info
    m = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
    if m:
        info["server"] = m.group(1).strip()
    m = re.search(r"<title>([^<]{1,80})</title>", banner, re.IGNORECASE)
    if m:
        info["title"] = m.group(1).strip()
    # Detect known camera web UIs
    for keyword in ("hikvision", "dahua", "axis", "hanwha", "amcrest", "reolink",
                    "foscam", "wyze", "camera", "dvr", "nvr"):
        if keyword in banner.lower():
            info["device_hint"] = "camera"
            break
    for keyword in ("printer", "laserjet", "officejet", "deskjet", "pixma",
                    "workcentre", "phaser", "brother"):
        if keyword in banner.lower():
            info["device_hint"] = "printer"
            break
    for keyword in ("routeros", "mikrotik", "winbox"):
        if keyword in banner.lower():
            info["device_hint"] = "router"
            break
    return info


async def full_device_scan(ip: str, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Full device scan: port scan + banner grab + device classification.
    Returns rich device info dict.
    """
    sem = asyncio.Semaphore(25)
    ports = list(PORT_SERVICES.keys())

    async def probe_port(port: int) -> Optional[int]:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
                w.close()
                try: await w.wait_closed()
                except: pass
                return port
            except Exception:
                return None

    # Concurrent port scan
    results = await asyncio.gather(*[probe_port(p) for p in ports])
    open_ports = [p for p in results if p is not None]

    # Service map
    services = [{"port": p, "service": PORT_SERVICES.get(p, "Unknown")} for p in sorted(open_ports)]

    # Banner grab on key ports (HTTP/SSH/FTP/Telnet/RTSP)
    banners: Dict[str, Any] = {}
    for port in (p for p in [80, 8080, 8291, 22, 21, 23, 554, 8554] if p in open_ports):
        b = await grab_banner(ip, port, timeout=1.5)
        if b:
            if port in (80, 8080):
                banners[str(port)] = parse_http_banner(b)
            else:
                banners[str(port)] = {"raw": b[:100]}

    # Reverse DNS
    hostname = await _resolve(ip)

    # Classification & Fingerprinting
    vendor = "Unknown"
    dev_type = "unknown"

    # Match HTTP or protocol banners for well-known signatures
    for port_str, b_info in banners.items():
        if isinstance(b_info, dict):
            # Check if parse_http_banner gave us a device type hint
            hint = b_info.get("device_hint")
            if hint:
                dev_type = hint

            srv = (b_info.get("server") or "").lower()
            ttl = (b_info.get("title") or "").lower()
            raw = (b_info.get("raw") or "").lower()
            combined = f"{srv} {ttl} {raw}"

            if "mikrotik" in combined or "routeros" in combined:
                vendor = "MikroTik"
                dev_type = "router"
            elif "cisco" in combined:
                vendor = "Cisco"
            elif "dahua" in combined:
                vendor = "Dahua"
                dev_type = "camera"
            elif "hikvision" in combined:
                vendor = "Hikvision"
                dev_type = "camera"
            elif "axis" in combined:
                vendor = "Axis"
                dev_type = "camera"
            elif "hp" in combined or "laserjet" in combined:
                vendor = "HP"
                dev_type = "printer"
            elif "canon" in combined:
                vendor = "Canon"
                dev_type = "printer"
            elif "epson" in combined:
                vendor = "Epson"
                dev_type = "printer"
            elif "brother" in combined:
                vendor = "Brother"
                dev_type = "printer"
            elif "apache" in combined or "nginx" in combined or "iis" in combined:
                vendor = "Web Server"

    # Further refine with OUI-like inference using hostname and open ports
    dev_type, icon = infer_device_type(open_ports, vendor, hostname, dev_type)

    return {
        "ip":           ip,
        "hostname":     hostname,
        "open_ports":   open_ports,
        "services":     services,
        "banners":      banners,
        "status":       "online",
        "vendor":       vendor,
        "device_type":  dev_type,
        "device_label": DEVICE_TYPE_LABELS.get(dev_type, "Unknown"),
        "icon":         icon,
    }


async def build_device_map(arp_table: List[Dict], dhcp_leases: List[Dict]) -> List[Dict[str, Any]]:
    """Merge ARP + DHCP into enriched device list with vendor + type detection."""
    # Index DHCP by MAC
    dhcp_by_mac: Dict[str, Dict] = {}
    for lease in dhcp_leases:
        mac = (lease.get("mac-address") or "").upper()
        if mac:
            dhcp_by_mac[mac] = lease

    devices: Dict[str, Dict] = {}
    for entry in arp_table:
        ip  = entry.get("address", "")
        mac = (entry.get("mac-address") or "").upper()
        if not ip:
            continue
        dhcp = dhcp_by_mac.get(mac, {})
        hostname = dhcp.get("host-name") or dhcp.get("comment") or ""
        vendor, dev_type, icon = oui_lookup(mac)
        dev_type, icon = infer_device_type([], vendor, hostname, dev_type)

        devices[ip] = {
            "ip":          ip,
            "mac":         mac,
            "hostname":    hostname,
            "interface":   entry.get("interface", ""),
            "vendor":      vendor,
            "device_type": dev_type,
            "device_label": DEVICE_TYPE_LABELS.get(dev_type, "Unknown"),
            "icon":        icon,
            "status":      "online",
            "dhcp_status": dhcp.get("status", "static"),
            "expires_after": dhcp.get("expires-after", ""),
        }

    # Add DHCP-only offline entries
    for mac, lease in dhcp_by_mac.items():
        ip = lease.get("address", "")
        if ip and ip not in devices:
            vendor, dev_type, icon = oui_lookup(mac)
            hostname = lease.get("host-name") or lease.get("comment") or ""
            dev_type, icon = infer_device_type([], vendor, hostname, dev_type)
            online = lease.get("status") == "bound"
            devices[ip] = {
                "ip":          ip,
                "mac":         mac,
                "hostname":    hostname,
                "interface":   lease.get("server", ""),
                "vendor":      vendor,
                "device_type": dev_type,
                "device_label": DEVICE_TYPE_LABELS.get(dev_type, "Unknown"),
                "icon":        icon,
                "status":      "online" if online else "offline",
                "dhcp_status": lease.get("status", ""),
                "expires_after": lease.get("expires-after", ""),
            }

    result = list(devices.values())
    result.sort(key=lambda d: (d["status"] != "online", _ip_key(d["ip"])))
    return result


async def ping_sweep(subnet: str, timeout: float = 0.5) -> List[Dict[str, Any]]:
    """Async TCP-probe sweep. Returns live hosts with hostname resolution."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return []
    if net.num_addresses > 256:
        net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)

    hosts = list(net.hosts())
    results: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(40)

    async def probe(ip: ipaddress.IPv4Address):
        ip_str = str(ip)
        async with sem:
            alive = await _tcp_alive(ip_str, timeout)
            if alive:
                hostname = await _resolve(ip_str)
                vendor, dev_type, icon = oui_lookup("")
                results.append({
                    "ip": ip_str, "hostname": hostname,
                    "status": "online", "mac": "", "vendor": "Unknown",
                    "device_type": dev_type, "device_label": DEVICE_TYPE_LABELS.get(dev_type, "Unknown"),
                    "icon": icon, "dhcp_status": "", "method": "TCP probe",
                })

    await asyncio.gather(*[probe(h) for h in hosts])
    results.sort(key=lambda d: _ip_key(d["ip"]))
    return results


async def _tcp_alive(ip: str, timeout: float) -> bool:
    for port in (80, 443, 22, 8080, 8291, 53, 554, 9100, 8728):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            w.close()
            try: await w.wait_closed()
            except: pass
            return True
        except Exception:
            continue
    return False


async def _resolve(ip: str) -> str:
    try:
        loop = asyncio.get_running_loop()
        host, *_ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=1.0
        )
        return host
    except Exception:
        return ""


def _ip_key(ip: str):
    try: return [int(x) for x in ip.split(".")]
    except: return [0, 0, 0, 0]
