from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from pydantic import BaseModel
import asyncio
import os
import json
import jwt
import re
from datetime import datetime, timedelta, timezone

from core.mikrotik_client import MikroTikClient
from core.analyzer import LogAnalyzer
from core.scanner import scan_ip
from core.network_scanner import build_device_map, ping_sweep, full_device_scan

load_dotenv()

import sys

# Resolve static directory path dynamically for PyInstaller support
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

static_dir = os.path.join(base_dir, "static")

app = FastAPI(title="NetSentry SOC Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

mikrotik = MikroTikClient()
analyzer = LogAnalyzer()

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ── Auth ──────────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY", "netsentry-supersecret-key-32chars!!")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

DASHBOARD_USER = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username != DASHBOARD_USER:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == DASHBOARD_USER and form_data.password == DASHBOARD_PASSWORD:
        token = create_access_token(data={"sub": form_data.username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "login.html"))

@app.get("/dashboard")
async def dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/api/status")
async def get_status(current_user: str = Depends(get_current_user)):
    identity = mikrotik.get_identity()
    return {"status": "Connected" if identity != "Unknown" else "Disconnected", "identity": identity}

# ── Action Models & Endpoints ─────────────────────────────────────────────────

class BlockRequest(BaseModel):
    ip_address: str

class ScanRequest(BaseModel):
    ip_address: str

@app.post("/api/block_ip")
async def block_ip(req: BlockRequest, current_user: str = Depends(get_current_user)):
    success = mikrotik.block_ip(req.ip_address)
    if success:
        return {"status": "success", "message": f"IP {req.ip_address} blocked."}
    return {"status": "error", "message": "Failed to block IP."}

@app.post("/api/scan_ports")
async def run_scan(req: ScanRequest, current_user: str = Depends(get_current_user)):
    results = await scan_ip(req.ip_address)
    return {"target": req.ip_address, "open_ports": results}

class SubnetRequest(BaseModel):
    subnet: str = "192.168.88.0/24"

class DeviceScanRequest(BaseModel):
    ip_address: str

@app.get("/api/network_map")
async def network_map(current_user: str = Depends(get_current_user)):
    """Merged ARP+DHCP device list with vendor/type detection."""
    arp     = mikrotik.get_arp_table()
    dhcp    = mikrotik.get_dhcp_leases()
    devices = await build_device_map(arp, dhcp)
    return {"devices": devices, "count": len(devices)}

@app.post("/api/ping_sweep")
async def run_ping_sweep(req: SubnetRequest, current_user: str = Depends(get_current_user)):
    """Async TCP-probe sweep of a subnet."""
    hosts = await ping_sweep(req.subnet, timeout=0.4)
    return {"subnet": req.subnet, "hosts": hosts, "count": len(hosts)}

@app.post("/api/device_scan")
async def device_scan(req: DeviceScanRequest, current_user: str = Depends(get_current_user)):
    """Deep scan: ports + banner grab + device fingerprinting for one IP."""
    result = await full_device_scan(req.ip_address, timeout=0.5)
    return result

class PingRequest(BaseModel):
    address: str
    count: int = 4

class DnsLookupRequest(BaseModel):
    domain: str

@app.post("/api/tools/ping")
async def tool_ping(req: PingRequest, current_user: str = Depends(get_current_user)):
    """Ping an address directly from the MikroTik router."""
    if not req.address:
        raise HTTPException(status_code=400, detail="მისამართი აუცილებელია (Address is required)")
    addr = req.address.strip()
    if not re.match(r"^[a-zA-Z0-9.-]+$", addr):
        raise HTTPException(status_code=400, detail="არასწორი მისამართის ფორმატი (Invalid address format)")
    
    if not mikrotik.api:
        if not mikrotik.connect():
            return {"status": "error", "message": "Failed to connect to RouterOS API"}
    try:
        base_res = mikrotik.api.get_resource('/')
        result = base_res.call('ping', {'address': addr, 'count': str(req.count)})
        return {"status": "success", "results": result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/tools/dns_lookup")
async def tool_dns_lookup(req: DnsLookupRequest, current_user: str = Depends(get_current_user)):
    """Perform a DNS lookup query on the MikroTik router with local resolver fallback."""
    if not req.domain:
        raise HTTPException(status_code=400, detail="დომენი აუცილებელია (Domain is required)")
    domain = req.domain.strip()
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise HTTPException(status_code=400, detail="არასწორი დომენის ფორმატი (Invalid domain format)")
    
    # Try local resolver fallback function using gethostbyname_ex
    def local_resolve():
        try:
            import socket
            _, _, ips = socket.gethostbyname_ex(domain)
            return [{"address": ip, "domain": domain} for ip in ips]
        except Exception:
            return []

    if not mikrotik.api:
        if not mikrotik.connect():
            local_res = local_resolve()
            if local_res:
                return {"status": "success", "results": local_res, "note": "Resolved locally (Router disconnected)"}
            return {"status": "error", "message": "Failed to connect to RouterOS API and local resolve failed."}
            
    try:
        # Try root level resolve command
        res = mikrotik.api.get_resource('/').call('resolve', {'domain-name': domain})
        if res:
            return {"status": "success", "results": res}
    except Exception:
        pass

    # Fall back to local resolver
    local_res = local_resolve()
    if local_res:
        return {"status": "success", "results": local_res, "note": "Resolved locally (Router cache resolve triggered)"}
    return {"status": "error", "message": "Failed to resolve domain name."}

@app.post("/api/reboot")
async def reboot_router(current_user: str = Depends(get_current_user)):
    success = mikrotik.reboot()
    if success:
        return {"status": "success", "message": "Reboot command sent. Router will reconnect shortly."}
    return {"status": "error", "message": "Failed to send reboot command."}

@app.get("/api/backup", response_class=PlainTextResponse)
async def download_backup(current_user: str = Depends(get_current_user)):
    config = mikrotik.export_config()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mikrotik_backup_{ts}.rsc"
    return PlainTextResponse(content=config, headers={"Content-Disposition": f"attachment; filename={filename}"})

# ── WebSocket Monitor ─────────────────────────────────────────────────────────

@app.websocket("/ws/monitor")
async def websocket_monitor(websocket: WebSocket):
    await websocket.accept()
    try:
        # Authenticate via first message — with a 15-second grace window
        try:
            auth_msg = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
            token_data = json.loads(auth_msg)
            token = token_data.get("token", "")
            # Manually decode — avoid Depends() complexity in raw WebSocket context
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username or username != DASHBOARD_USER:
                await websocket.send_json({"error": "Unauthorized"})
                await websocket.close()
                return
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as auth_err:
            # If it's a JWT error — reject. Otherwise let it reconnect.
            await websocket.send_json({"error": "Unauthorized"})
            await websocket.close()
            return

        counter = 0
        while True:
            try:
                # ── FAST TIER: Every 3 seconds ────────────────────────────────
                data = {
                    "interfaces":   mikrotik.get_interfaces(),
                    "resources":    mikrotik.get_resources(),
                    "latency":      mikrotik.get_ping_latency("8.8.8.8"),
                    "connections":  mikrotik.get_firewall_connections(50),
                }

                # ── SLOW TIER: Every 15 seconds (counter % 5 == 0) ───────────
                if counter % 5 == 0:
                    full_logs = mikrotik.get_logs(500)
                    alerts    = analyzer.analyze_logs(full_logs)
                    summary   = analyzer.get_summary(alerts)
                    data.update({
                        "recent_logs":      full_logs[-30:],
                        "alerts":           alerts,
                        "threat_summary":   summary,
                        "dhcp_leases":      mikrotik.get_dhcp_leases(),
                        "arp_table":        mikrotik.get_arp_table(),
                        "nat_rules":        mikrotik.get_nat_rules(),
                        "mangle_rules":     mikrotik.get_mangle_rules(),
                        "routes":           mikrotik.get_routes(),
                        "neighbors":        mikrotik.get_neighbors(),
                        "sys_users":        mikrotik.get_system_users(),
                        "active_users":     mikrotik.get_active_users(),
                        "dns_cache":        mikrotik.get_dns_cache(),
                        "vpn_active":       mikrotik.get_active_vpns(),
                        "ppp_secrets":      mikrotik.get_ppp_secrets(),
                        "firewall_filters": mikrotik.get_firewall_filters(),
                        "address_lists":    mikrotik.get_address_lists(),
                        "packages":         mikrotik.get_packages(),
                        "hotspot_active":   mikrotik.get_hotspot_active(),
                        "hotspot_users":    mikrotik.get_hotspot_users(),
                        "ip_services":      mikrotik.get_ip_services(),
                        "ip_addresses":     mikrotik.get_ip_addresses(),
                        "simple_queues":    mikrotik.get_simple_queues(),
                        "wireless_clients": mikrotik.get_wireless_clients(),
                        "scripts":          mikrotik.get_scripts(),
                        "schedulers":       mikrotik.get_schedulers(),
                    })

                await websocket.send_json({"type": "update", "data": data})
            except Exception:
                pass  # Don't crash the loop on one bad tick

            counter += 1
            # Sleep in small chunks so we can drain incoming ping messages
            for _ in range(30):  # 30 × 0.1s = 3 seconds total
                await asyncio.sleep(0.1)
                # Drain any incoming messages (keepalive pings) without blocking
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=0.0)
                except (asyncio.TimeoutError, Exception):
                    pass

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
