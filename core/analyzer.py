"""
NetSentry Advanced Log Analyzer
Detects 20+ threat categories from MikroTik system logs with severity scoring,
IP extraction, deduplication, and human-readable recommendations.
"""

import re
from collections import defaultdict
from typing import List, Dict, Any, Optional
from datetime import datetime

# ── Severity levels ───────────────────────────────────────────────────────────
SEV_CRITICAL = "critical"
SEV_HIGH     = "high"
SEV_MEDIUM   = "medium"
SEV_LOW      = "low"
SEV_INFO     = "info"

# ── Threat Rules ──────────────────────────────────────────────────────────────
RULES = [
    # ── Authentication / Access ───────────────────────────────────────────────
    {
        "id": "AUTH_FAILURE",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"login failure for user (.+?) from (\d[\d.]+)"),
        "description": "Failed admin login attempt",
        "recommendation": "Check if this is a brute-force. Consider blocking the source IP.",
        "category": "Authentication"
    },
    {
        "id": "SSH_BRUTE_FORCE",
        "severity": SEV_CRITICAL,
        "pattern": re.compile(r"ssh.*login fail|ssh.*authentication fail|ssh.*invalid"),
        "description": "SSH brute-force attack suspected",
        "recommendation": "Disable SSH or restrict access to trusted IPs only via /ip/service.",
        "category": "Authentication"
    },
    {
        "id": "WINBOX_FAIL",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"winbox.*login fail|winbox.*authentication"),
        "description": "Winbox login failure detected",
        "recommendation": "Restrict Winbox access to internal IPs only via /ip/service.",
        "category": "Authentication"
    },
    {
        "id": "USER_LOGGED_IN",
        "severity": SEV_INFO,
        "pattern": re.compile(r"logged in from (\d[\d.]+) via (.+)"),
        "description": "Admin user logged in",
        "recommendation": "Verify this login was authorized.",
        "category": "Authentication"
    },
    {
        "id": "USER_LOGGED_OUT",
        "severity": SEV_INFO,
        "pattern": re.compile(r"logged out from (\d[\d.]+) via (.+)"),
        "description": "Admin user logged out",
        "recommendation": None,
        "category": "Authentication"
    },
    # ── Firewall & Network Security ───────────────────────────────────────────
    {
        "id": "FW_DROP",
        "severity": SEV_MEDIUM,
        "pattern": re.compile(r"forward.*drop|input.*drop|output.*drop|firewall.*drop"),
        "description": "Firewall dropped suspicious traffic",
        "recommendation": "Review firewall rules and blocked IPs.",
        "category": "Firewall"
    },
    {
        "id": "PORT_SCAN",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"port.?scan|scanner detect|nmap"),
        "description": "Port scan detected and dropped by firewall",
        "recommendation": "Add the attacker IP to a block list.",
        "category": "Firewall"
    },
    {
        "id": "DDOS_FLOOD",
        "severity": SEV_CRITICAL,
        "pattern": re.compile(r"syn.?flood|udp.?flood|icmp.?flood|dos attack|ddos"),
        "description": "DDoS / flood attack detected",
        "recommendation": "Enable SYN flood protection via /ip/settings and rate-limit ICMP.",
        "category": "Firewall"
    },
    {
        "id": "BLACKLIST_MATCH",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"blacklist|blocklist|address.?list.*block|sentry.?block"),
        "description": "Traffic matched a firewall blocklist",
        "recommendation": "Review the address list and verify the blocking rule.",
        "category": "Firewall"
    },
    # ── Network Stability ─────────────────────────────────────────────────────
    {
        "id": "INTERFACE_DOWN",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"link down|interface (.+?) became disabled"),
        "description": "Network interface went DOWN",
        "recommendation": "Check the physical cable or uplink device.",
        "category": "Network Stability"
    },
    {
        "id": "INTERFACE_UP",
        "severity": SEV_INFO,
        "pattern": re.compile(r"link up|interface (.+?) became active"),
        "description": "Network interface came UP",
        "recommendation": None,
        "category": "Network Stability"
    },
    {
        "id": "NETWORK_LOOP",
        "severity": SEV_CRITICAL,
        "pattern": re.compile(r"host .+? is moving|mac.?address .+? already on|stp|spanning tree|bpdu"),
        "description": "Network loop / MAC flapping detected (STP event)",
        "recommendation": "Enable Spanning Tree Protocol (STP) on bridges. Locate the looping device.",
        "category": "Network Stability"
    },
    {
        "id": "GATEWAY_UNREACHABLE",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"gateway .+? unreachable|route .+? inactive|nexthop .+? unreachable"),
        "description": "Gateway or route became unreachable",
        "recommendation": "Check WAN connection and upstream provider.",
        "category": "Network Stability"
    },
    # ── VPN / Tunnels ─────────────────────────────────────────────────────────
    {
        "id": "VPN_FAILURE",
        "severity": SEV_MEDIUM,
        "pattern": re.compile(r"(ovpn|pptp|l2tp|ipsec|sstp).*fail|vpn.*disconnected|tunnel.*down"),
        "description": "VPN tunnel failure or disconnection",
        "recommendation": "Check VPN credentials and server availability.",
        "category": "VPN"
    },
    {
        "id": "IPSEC_PROPOSAL",
        "severity": SEV_MEDIUM,
        "pattern": re.compile(r"ipsec.*proposal.*mismatch|ipsec.*no.*proposal|ipsec.*phase"),
        "description": "IPSec proposal mismatch or negotiation failure",
        "recommendation": "Verify IPSec proposals match on both peers.",
        "category": "VPN"
    },
    # ── DHCP & ARP ────────────────────────────────────────────────────────────
    {
        "id": "DHCP_POOL_EMPTY",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"dhcp.*no.*free|ip pool.*exhausted|no free leases"),
        "description": "DHCP pool is exhausted — no free IP addresses",
        "recommendation": "Expand the DHCP pool or reduce lease time.",
        "category": "DHCP"
    },
    {
        "id": "ARP_SPOOFING",
        "severity": SEV_CRITICAL,
        "pattern": re.compile(r"arp.*conflict|duplicate.*ip|arp.*poison|gratuitous arp"),
        "description": "ARP spoofing / IP conflict detected",
        "recommendation": "Enable ARP inspection. Investigate the conflicting device.",
        "category": "Security"
    },
    # ── Hardware & System ─────────────────────────────────────────────────────
    {
        "id": "SYS_REBOOT",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"system reboot|router rebooted|system startup|rebooting"),
        "description": "Router reboot detected",
        "recommendation": "Verify this was a planned reboot. Check for power issues.",
        "category": "System"
    },
    {
        "id": "HIGH_CPU",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"cpu.*overload|cpu.?load.*high|cpu usage.*\d{2,3}%"),
        "description": "High CPU usage detected",
        "recommendation": "Identify heavy processes via /tool/profile.",
        "category": "System"
    },
    {
        "id": "CONFIG_CHANGE",
        "severity": SEV_MEDIUM,
        "pattern": re.compile(r"configuration changed|config.*modified|rule.*added|rule.*removed|address.*added|address.*removed"),
        "description": "Router configuration was changed",
        "recommendation": "Verify the change was authorized. Review audit logs.",
        "category": "Audit"
    },
    {
        "id": "UPGRADE_DETECTED",
        "severity": SEV_INFO,
        "pattern": re.compile(r"upgraded|firmware.*update|routeros.*upgrade"),
        "description": "RouterOS firmware upgrade detected",
        "recommendation": "Verify the upgrade was planned and test all services.",
        "category": "System"
    },
    # ── Wireless ──────────────────────────────────────────────────────────────
    {
        "id": "WIFI_DEAUTH",
        "severity": SEV_MEDIUM,
        "pattern": re.compile(r"deauthenticated|disassociated|station.*disconnected"),
        "description": "Wireless client deauthenticated",
        "recommendation": "Investigate if this is a deauth-flood attack.",
        "category": "Wireless"
    },
    {
        "id": "WIFI_ROGUE_AP",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"rogue ap|rogue access point|evil twin"),
        "description": "Rogue access point detected",
        "recommendation": "Investigate and block the unauthorized AP.",
        "category": "Wireless"
    },
    # ── DNS ───────────────────────────────────────────────────────────────────
    {
        "id": "DNS_FLOOD",
        "severity": SEV_HIGH,
        "pattern": re.compile(r"dns.*flood|dns.*amplif|dns.*overflow"),
        "description": "DNS flood or amplification attack detected",
        "recommendation": "Enable DNS rate limiting and restrict DNS to internal clients.",
        "category": "DNS"
    },
]

_SEVERITY_ORDER = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3, SEV_INFO: 4}
_SEVERITY_EMOJI = {SEV_CRITICAL: "🔴", SEV_HIGH: "🟠", SEV_MEDIUM: "🟡", SEV_LOW: "🔵", SEV_INFO: "⚪"}

_IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_RE = re.compile(r"for user (.+?) ")


class LogAnalyzer:
    def __init__(self):
        self.rules = RULES

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Full analysis: matches rules, extracts IPs/users, deduplicates,
        counts occurrences, and sorts by severity.
        """
        raw_alerts: List[Dict[str, Any]] = []
        # Track brute-force: count per (rule_id, attacker_ip)
        occurrence_counter: Dict[str, int] = defaultdict(int)

        for log in logs:
            message = log.get('message', '')
            msg_lower = message.lower()
            topics  = log.get('topics', '')
            time    = log.get('time', '')

            for rule in self.rules:
                match = rule['pattern'].search(msg_lower)
                if not match:
                    continue

                attacker_ip = self._extract_ip(message)
                username    = self._extract_user(message)
                iface       = self._extract_interface(message)
                dedup_key   = f"{rule['id']}|{attacker_ip or 'n/a'}"
                occurrence_counter[dedup_key] += 1

                raw_alerts.append({
                    "rule_id":        rule["id"],
                    "severity":       rule["severity"],
                    "severity_emoji": _SEVERITY_EMOJI.get(rule["severity"], "⚪"),
                    "category":       rule.get("category", "General"),
                    "description":    rule["description"],
                    "recommendation": rule.get("recommendation"),
                    "raw_log":        message,
                    "time":           time,
                    "topics":         topics,
                    "attacker_ip":    attacker_ip,
                    "username":       username,
                    "interface":      iface,
                    "_dedup_key":     dedup_key,
                })
                break  # first matching rule only per log entry

        # Deduplicate — keep most recent, add count
        seen: Dict[str, Dict] = {}
        for alert in raw_alerts:
            key = alert["_dedup_key"]
            if key not in seen:
                seen[key] = alert
            else:
                # keep the latest time
                seen[key] = alert
            seen[key]["count"] = occurrence_counter[key]

        # Sort by severity then time (descending)
        result = list(seen.values())
        result.sort(key=lambda a: (_SEVERITY_ORDER.get(a["severity"], 9), a["time"]))

        # Add brute-force escalation
        result = self._escalate_brute_force(result)

        # Clean internal keys
        for a in result:
            a.pop("_dedup_key", None)

        return result

    def get_summary(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Returns a high-level summary of current threats."""
        by_severity: Dict[str, int] = defaultdict(int)
        by_category: Dict[str, int] = defaultdict(int)
        top_attackers: Dict[str, int] = defaultdict(int)

        for a in alerts:
            by_severity[a["severity"]] += a.get("count", 1)
            by_category[a["category"]] += 1
            if a.get("attacker_ip"):
                top_attackers[a["attacker_ip"]] += a.get("count", 1)

        return {
            "total_events": sum(by_severity.values()),
            "critical":     by_severity.get(SEV_CRITICAL, 0),
            "high":         by_severity.get(SEV_HIGH, 0),
            "medium":       by_severity.get(SEV_MEDIUM, 0),
            "by_category":  dict(by_category),
            "top_attackers": sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:5],
        }

    # ── Private Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_ip(message: str) -> Optional[str]:
        # Prefer IP after "from " or "src=" keywords
        for kw in ("from ", "src=", "source: ", "client: "):
            idx = message.lower().find(kw)
            if idx != -1:
                m = _IP_RE.search(message, idx + len(kw))
                if m:
                    return m.group(1)
        # Fall back to any IP in message
        m = _IP_RE.search(message)
        return m.group(1) if m else None

    @staticmethod
    def _extract_user(message: str) -> Optional[str]:
        m = _USER_RE.search(message.lower())
        return m.group(1).strip() if m else None

    @staticmethod
    def _extract_interface(message: str) -> Optional[str]:
        m = re.search(r"\bether\d+\b|\bwlan\d+\b|\bbridge\d*\b|\bpppoe\S*\b|\bl2tp\S*\b", message, re.IGNORECASE)
        return m.group(0) if m else None

    @staticmethod
    def _escalate_brute_force(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Escalate AUTH_FAILURE to CRITICAL if count >= 5."""
        for a in alerts:
            if a["rule_id"] in ("AUTH_FAILURE", "SSH_BRUTE_FORCE") and a.get("count", 1) >= 5:
                a["severity"]       = SEV_CRITICAL
                a["severity_emoji"] = _SEVERITY_EMOJI[SEV_CRITICAL]
                a["description"]    = f"🚨 BRUTE FORCE ({a['count']} attempts) — {a['description']}"
        return alerts
