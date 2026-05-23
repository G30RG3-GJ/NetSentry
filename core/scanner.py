"""
NetSentry Port Scanner
Fast async TCP port scanner — uses semaphore to avoid blocking asyncio event loop.
"""

import asyncio
from typing import List, Dict

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPCBind",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8291: "WinBox",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}


async def scan_port(ip: str, port: int, sem: asyncio.Semaphore, timeout: float = 0.5) -> Dict[str, any]:
    """Attempt to connect to a single port. Returns result dict."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "open"}
        except Exception:
            return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "closed"}


async def scan_ip(ip: str, timeout: float = 0.5) -> List[Dict[str, any]]:
    """Scan all common ports on a given IP. Returns only open ports."""
    sem = asyncio.Semaphore(20)
    tasks = [scan_port(ip, port, sem, timeout) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r["status"] == "open"]
