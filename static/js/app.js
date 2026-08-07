const token = localStorage.getItem('netsentry_token');
if (!token) window.location.href = '/';
const authHeaders = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

function logout() { localStorage.removeItem('netsentry_token'); window.location.href = '/'; }

// ── WebSocket ─────────────────────────────────────────────────────────────────
let _wsKeepalive = null;

function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws/monitor`);
    const dot = document.querySelector('.pulse-ring');
    const txt = document.getElementById('connection-status');

    ws.onopen = () => {
        dot.classList.remove('disconnected');
        txt.textContent = '● Live';
        ws.send(JSON.stringify({ token }));
        // Keepalive ping every 20s so scans don't kill the connection
        _wsKeepalive = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ ping: true }));
        }, 20000);
    };

    ws.onclose = () => {
        dot.classList.add('disconnected');
        txt.textContent = '○ Reconnecting…';
        clearInterval(_wsKeepalive);
        setTimeout(connectWebSocket, 4000);
    };

    ws.onerror = () => ws.close();

    ws.onmessage = e => {
        try {
            const m = JSON.parse(e.data);
            // Only hard-logout if server explicitly rejects the token
            if (m.error === 'Unauthorized') return logout();
            // Ignore ping-pong or unknown message types gracefully
            if (m.type === 'update') updateDashboard(m.data);
        } catch {}
    };
}

// ── Charts ────────────────────────────────────────────────────────────────────
let trafficChart, cpuChart, latencyChart;
const MAX = 20;

function mkChart(id, datasets, maxY) {
    return new Chart(document.getElementById(id).getContext('2d'), {
        type: 'line',
        data: { labels: [], datasets: datasets.map(d => ({ ...d, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 2, data: [] })) },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' }, ...(maxY ? { max: maxY } : {}) },
                x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8', maxTicksLimit: 8 } }
            }
        }
    });
}

function pushChart(chart, label, ...vals) {
    if (chart.data.labels.length >= MAX) { chart.data.labels.shift(); chart.data.datasets.forEach(d => d.data.shift()); }
    chart.data.labels.push(label);
    vals.forEach((v, i) => chart.data.datasets[i].data.push(v));
    chart.update();
}

// ── Simple table helper & Persistent Search Filters ──────────────────────────
const activeFilters = {};

function filterTable(bodyId, query) {
    activeFilters[bodyId] = query.toLowerCase().trim();
    applyFilter(bodyId);
}

function applyFilter(bodyId) {
    const el = document.getElementById(bodyId);
    if (!el) return;
    const query = activeFilters[bodyId] || '';
    const rows = el.getElementsByTagName('tr');
    
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.querySelector('.empty-state')) continue;
        const text = row.textContent.toLowerCase();
        if (text.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    }
}

function fill(bodyId, data, renderer, cols = 3) {
    const el = document.getElementById(bodyId);
    if (!el || data === undefined) return;
    el.innerHTML = data.length === 0
        ? `<tr><td colspan="${cols}" class="text-center empty-state">No data</td></tr>`
        : renderer(data);
    
    if (activeFilters[bodyId]) {
        applyFilter(bodyId);
    }
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function initTabs() {
    document.querySelectorAll('#nav-tabs li').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('#nav-tabs li').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(tc => { tc.classList.remove('active'); tc.classList.add('hidden'); });
            const t = document.getElementById(tab.dataset.tab);
            if (t) { t.classList.remove('hidden'); t.classList.add('active'); }
            document.getElementById('page-title').textContent = tab.textContent.trim();
        });
    });
}

// ── Status ────────────────────────────────────────────────────────────────────
async function fetchStatus() {
    try {
        const r = await fetch('/api/status', { headers: authHeaders });
        if (r.status === 401) return logout();
        const d = await r.json();
        document.getElementById('router-identity').textContent = `Device: ${d.identity} | ${d.status}`;
    } catch { }
}

// ── Dashboard updater ─────────────────────────────────────────────────────────
let lastRx = {}, lastTx = {}, lastTime = Date.now();

function updateDashboard(data) {
    const now = Date.now();
    const label = new Date().toLocaleTimeString('en-US', { hour12: false });
    const dt = (now - lastTime) / 1000;

    // Resources
    if (data.resources) {
        const r = data.resources;
        const cpu = parseInt(r['cpu-load'] || 0);
        document.getElementById('sys-cpu').textContent = cpu;
        document.getElementById('sys-ram').textContent = Math.round((r['free-memory'] || 0) / 1048576);
        document.getElementById('sys-uptime').textContent = r['uptime'] || '--';
        pushChart(cpuChart, label, cpu);
    }

    if (data.latency !== undefined) pushChart(latencyChart, label, parseFloat(data.latency) || 0);

    // Interfaces
    if (data.interfaces) {
        document.getElementById('kpi-interfaces').textContent = data.interfaces.length;
        let tRx = 0, tTx = 0, topRx = 0, topTx = 0, html = '';
        data.interfaces.forEach(ifc => {
            const rx = parseInt(ifc['rx-byte'] || 0);
            const tx = parseInt(ifc['tx-byte'] || 0);
            tRx += rx; tTx += tx;
            if (lastRx[ifc.name] && dt > 0) {
                const rs = ((rx - lastRx[ifc.name]) * 8) / (1048576 * dt);
                const ts = ((tx - lastTx[ifc.name]) * 8) / (1048576 * dt);
                if (rs + ts > topRx + topTx) { topRx = rs; topTx = ts; }
            }
            lastRx[ifc.name] = rx; lastTx[ifc.name] = tx;
            const up = ifc.running === 'true';
            const disabled = ifc.disabled === 'true';
            const ifcId = ifc['.id'] || ifc.name;
            const toggleBtn = `<button class="btn btn-export" style="padding:2px 6px;font-size:0.72rem;margin-left:6px;${disabled ? 'background:rgba(16,185,129,0.2);color:#10b981;' : 'background:rgba(239,68,68,0.2);color:var(--warning);'}" onclick="toggleInterface('${ifcId}', ${disabled})"><i class="fa-solid ${disabled ? 'fa-play' : 'fa-pause'}"></i> ${disabled ? 'Enable' : 'Disable'}</button>`;
            html += `<tr>
                <td><span class="status-badge ${up ? 'status-up' : 'status-down'}">${up ? 'UP' : 'DOWN'}</span></td>
                <td><strong>${ifc.name}</strong> ${toggleBtn}</td>
                <td><span class="text-muted">${ifc.type || '-'}</span></td>
                <td>${fmtB(rx)}</td><td>${fmtB(tx)}</td>
                <td class="${(ifc['rx-error'] || 0) > 0 ? 'text-warning' : ''}">${ifc['rx-error'] || 0}</td>
                <td class="${(ifc['tx-error'] || 0) > 0 ? 'text-warning' : ''}">${ifc['tx-error'] || 0}</td></tr>`;
        });
        document.getElementById('interfaces-body').innerHTML = html;
        document.getElementById('kpi-rx').textContent = fmtB(tRx);
        document.getElementById('kpi-tx').textContent = fmtB(tTx);
        pushChart(trafficChart, label, Math.max(0, +topRx.toFixed(2)), Math.max(0, +topTx.toFixed(2)));
    }
    lastTime = now;

    // Connections (fast) — also mirrors to sniffer tab
    if (data.connections) {
        let h = '', sh = '';
        if (!data.connections.length) {
            h = `<tr><td colspan="5" class="text-center empty-state">No connections</td></tr>`;
            sh = `<tr><td colspan="4" class="text-center empty-state">No flows</td></tr>`;
        } else {
            data.connections.forEach(c => {
                h += `<tr><td><span class="text-accent">${c.protocol || '-'}</span></td><td>${c['src-address'] || '-'}</td><td>${c['dst-address'] || '-'}</td><td>${c['reply-src-address'] || '-'}</td><td class="text-muted">${c.timeout || '-'}</td></tr>`;
                sh += `<tr><td><span class="text-accent">${c.protocol || '-'}</span></td><td>${c['src-address'] || '-'}</td><td>${c['dst-address'] || '-'}</td><td>${c['reply-src-address'] || '-'}</td></tr>`;
            });
        }
        document.getElementById('connections-body').innerHTML = h;
        document.getElementById('sniffer-body').innerHTML = sh;
    }

    // ── SLOW TIER — explicit ID mapping ──────────────────────────────────────
    
    // Threat Summary Stats Bar
    if (data.threat_summary !== undefined) {
        const ts = data.threat_summary;
        const el = document.getElementById('threat-stats-bar');
        if (el) {
            el.innerHTML = `
                <div class="threat-stat-card" style="border-color:var(--accent)">
                    <h3 style="color:var(--accent);font-size:1.5rem;font-weight:700">${ts.total_events || 0}</h3>
                    <p>Total Alerts</p>
                </div>
                <div class="threat-stat-card" style="border-color:#ef4444">
                    <h3 style="color:#ef4444;font-size:1.5rem;font-weight:700">${ts.critical || 0}</h3>
                    <p>🔴 Critical</p>
                </div>
                <div class="threat-stat-card" style="border-color:#f97316">
                    <h3 style="color:#f97316;font-size:1.5rem;font-weight:700">${ts.high || 0}</h3>
                    <p>🟠 High</p>
                </div>
                <div class="threat-stat-card" style="border-color:#f59e0b">
                    <h3 style="color:#f59e0b;font-size:1.5rem;font-weight:700">${ts.medium || 0}</h3>
                    <p>🟡 Medium</p>
                </div>
            `;
        }
    }

    // Alerts
    if (data.alerts !== undefined) {
        document.getElementById('kpi-alerts').textContent = data.alerts.length;
        const el = document.getElementById('alerts-container');
        if (el) {
            el.innerHTML = data.alerts.length === 0
                ? '<div class="empty-state"><i class="fa-solid fa-shield-check"></i> No threats detected.</div>'
                : data.alerts.map(a => {
                    const sevClass = a.severity === 'critical' ? 'sev-critical' : a.severity === 'high' ? 'sev-high' : a.severity === 'medium' ? 'sev-medium' : 'sev-info';
                    const sevLabel = `<span class="status-badge ${sevClass}">${(a.severity_emoji || '') + ' ' + (a.severity || '').toUpperCase()}</span>`;
                    const countBadge = a.count > 1 ? `<span class="status-badge status-warning" style="margin-left:6px">${a.count}x</span>` : '';
                    const btn = a.attacker_ip ? `<button class="btn btn-block" onclick="blockIp('${a.attacker_ip}')"><i class="fa-solid fa-ban"></i> Block ${a.attacker_ip}</button>` : '';
                    const rec = a.recommendation ? `<p style="color:#64748b;font-size:.78rem;margin-top:.4rem"><i class="fa-solid fa-lightbulb" style="color:#f59e0b"></i> ${a.recommendation}</p>` : '';
                    return `<div class="alert-item ${a.severity || ''}"><div class="alert-header-flex"><h4><i class="fa-solid fa-triangle-exclamation"></i> ${a.description} ${sevLabel}${countBadge}</h4>${btn}</div><p>${a.raw_log || ''}</p>${rec}<span class="time">${a.time || ''} ${a.attacker_ip ? '· IP: ' + a.attacker_ip : ''}</span></div>`;
                }).join('');
        }
    }

    // Logs
    if (data.recent_logs) {
        const el = document.getElementById('logs-container');
        if (el) el.innerHTML = [...data.recent_logs].reverse().map(l =>
            `<div class="log-entry"><span class="log-time">[${l.time}]</span> <span class="log-topics">${l.topics}</span> <span>${l.message}</span></div>`
        ).join('');
    }

    // All table sections — correct body IDs
    fill('dhcp-body', data.dhcp_leases, renderDhcp, 5);
    fill('arp-body', data.arp_table, renderArp, 4);
    fill('nat-body', data.nat_rules, renderNat, 6);
    fill('mangle-body', data.mangle_rules, renderMangle, 6);
    fill('routes-body', data.routes, renderRoutes, 4);
    fill('neighbors-body', data.neighbors, renderNeighbors, 5);
    fill('dns-body', data.dns_cache, renderDns, 4);
    fill('vpn-body', data.vpn_active, renderVpn, 5);
    fill('firewall-body', data.firewall_filters, renderFirewall, 5);
    fill('address-lists-body', data.address_lists, renderAddressLists, 4);
    fill('packages-body', data.packages, renderPackages, 4);
    fill('hotspot-body', data.hotspot_active, renderHotspot, 5);
    fill('services-body', data.ip_services, renderServices, 4);
    fill('ip-addresses-body', data.ip_addresses, renderIpAddresses, 4);
    fill('queues-body', data.simple_queues, renderQueues, 6);
    fill('wireless-body', data.wireless_clients, renderWireless, 6);
    fill('scripts-body', data.scripts, renderScripts, 4);
    fill('schedulers-body', data.schedulers, renderSchedulers, 4);
    fill('users-body', data.sys_users, renderUsers, 3);
    fill('active-users-body', data.active_users, renderActiveUsers, 4);
}

// ── Renderers ─────────────────────────────────────────────────────────────────

const badge = (cls, txt) => `<span class="status-badge ${cls}">${txt}</span>`;

function renderDhcp(d) {
    return d.map(l => `<tr>
        <td><strong>${l.address || '-'}</strong></td>
        <td>${l['mac-address'] || '-'}</td>
        <td>${l.server || '-'}</td>
        <td>${badge(l.status === 'bound' ? 'status-up' : 'status-down', l.status || '-')}</td>
        <td>${l['host-name'] || l.comment || '-'}</td></tr>`).join('');
}

function renderArp(d) {
    return d.map(a => `<tr>
        <td><strong>${a.address || '-'}</strong></td>
        <td>${a['mac-address'] || '-'}</td>
        <td>${a.interface || '-'}</td>
        <td>${badge('status-up', a.status || 'active')}</td></tr>`).join('');
}

function renderNat(d) {
    return d.map(n => `<tr>
        <td><span class="text-accent">${n.chain || '-'}</span></td>
        <td>${n.action || '-'}</td><td>${n.protocol || '-'}</td>
        <td>${n['dst-port'] || '-'}</td>
        <td>${n['to-addresses'] || '-'}</td>
        <td>${n['to-ports'] || '-'}</td></tr>`).join('');
}

function renderMangle(d) {
    return d.map(m => `<tr>
        <td>${badge('status-warning', m.action || '-')}</td>
        <td>${m.chain || '-'}</td><td>${m.protocol || '-'}</td>
        <td>${m['src-address'] || '-'}</td><td>${m['dst-address'] || '-'}</td>
        <td>${fmtB(m.bytes || 0)}</td></tr>`).join('');
}

function renderRoutes(d) {
    return d.map(r => `<tr>
        <td><strong>${r['dst-address'] || '-'}</strong></td>
        <td>${r.gateway || '-'}</td><td>${r.distance || '-'}</td>
        <td>${badge(r.active === 'true' ? 'status-up' : 'status-down', r.active === 'true' ? 'Active' : 'Inactive')}</td></tr>`).join('');
}

function renderNeighbors(d) {
    return d.map(n => `<tr>
        <td><strong>${n.interface || '-'}</strong></td>
        <td>${n.address || '-'}</td><td>${n['mac-address'] || '-'}</td>
        <td>${n.identity || '-'}</td>
        <td><span class="text-muted">${n.platform || '-'}</span></td></tr>`).join('');
}

function renderDns(d) {
    return d.map(dns => `<tr>
        <td><strong>${dns.name || '-'}</strong></td>
        <td>${badge('status-up', dns.type || 'A')}</td>
        <td>${dns.data || dns.address || '-'}</td>
        <td><span class="text-muted">${dns.ttl || '-'}</span></td></tr>`).join('');
}

function renderVpn(d) {
    return d.map(v => `<tr>
        <td><strong>${v.name || '-'}</strong></td>
        <td><span class="text-accent">${v.service || '-'}</span></td>
        <td>${v['caller-id'] || '-'}</td>
        <td>${v.address || '-'}</td>
        <td><span class="text-muted">${v.uptime || '-'}</span></td></tr>`).join('');
}

function renderFirewall(d) {
    return d.map(r => {
        const drop = r.action === 'drop' || r.action === 'reject';
        return `<tr>
            <td>${badge(drop ? 'status-down' : 'status-up', r.action || '-')}</td>
            <td>${r.chain || '-'}</td><td>${r.protocol || '-'}</td>
            <td>${fmtB(r.bytes || 0)}</td><td>${r.packets || '0'}</td></tr>`;
    }).join('');
}

function renderAddressLists(d) {
    return d.map(a => {
        const warn = (a.list || '').toLowerCase().includes('block') || (a.list || '').toLowerCase().includes('ban');
        const unblockBtn = a.address ? `<button class="btn btn-export" style="padding:2px 8px;font-size:0.75rem;background:rgba(16,185,129,0.2);color:#10b981;" onclick="unblockIp('${a.address}')"><i class="fa-solid fa-lock-open"></i> Unblock</button>` : '';
        return `<tr>
            <td><strong class="${warn ? 'text-warning' : ''}">${a.list || '-'}</strong></td>
            <td>${a.address || '-'} ${unblockBtn}</td>
            <td><span class="text-muted">${a.timeout || 'Permanent'}</span></td>
            <td><span class="text-muted">${a.comment || '-'}</span></td></tr>`;
    }).join('');
}

function renderPackages(d) {
    return d.map(p => `<tr>
        <td><strong>${p.name || '-'}</strong></td>
        <td>${p.version || '-'}</td>
        <td><span class="text-muted">${p['build-time'] || '-'}</span></td>
        <td>${badge(p.disabled === 'true' ? 'status-down' : 'status-up', p.disabled === 'true' ? 'Disabled' : 'Active')}</td></tr>`).join('');
}

function renderHotspot(d) {
    return d.map(u => `<tr>
        <td><strong>${u.user || '-'}</strong></td>
        <td>${u.address || '-'}</td><td>${u['mac-address'] || '-'}</td>
        <td><span class="text-muted">${u.uptime || '-'}</span></td>
        <td>${fmtB(u['bytes-in'] || 0)} ↓ / ${fmtB(u['bytes-out'] || 0)} ↑</td></tr>`).join('');
}

function renderServices(d) {
    return d.map(s => {
        const en = s.disabled === 'false' || !s.disabled;
        const warn = en && ['telnet', 'ftp', 'www'].includes(s.name);
        return `<tr>
            <td><strong>${s.name || '-'}</strong> ${warn ? '<i class="fa-solid fa-triangle-exclamation text-warning" title="Insecure protocol!"></i>' : ''}</td>
            <td>${s.port || '-'}</td>
            <td>${s.address || '0.0.0.0/0 (Any)'}</td>
            <td>${badge(en ? (warn ? 'status-warning' : 'status-up') : 'status-down', en ? 'Enabled' : 'Disabled')}</td></tr>`;
    }).join('');
}

function renderIpAddresses(d) {
    return d.map(a => `<tr>
        <td><strong>${a.address || '-'}</strong></td>
        <td>${a.interface || '-'}</td>
        <td>${a.network || '-'}</td>
        <td>${badge(a.disabled === 'true' ? 'status-down' : 'status-up', a.disabled === 'true' ? 'Disabled' : 'Active')}</td></tr>`).join('');
}

function renderQueues(d) {
    return d.map(q => {
        const lim = (q['max-limit'] || '/').split('/');
        const rate = (q['rate'] || '/').split('/');
        return `<tr>
            <td><strong>${q.name || '-'}</strong></td>
            <td>${q.target || '-'}</td>
            <td>${lim[0] || '-'}</td><td>${lim[1] || '-'}</td>
            <td class="text-accent">${rate[0] || '0'}</td>
            <td class="text-accent">${rate[1] || '0'}</td></tr>`;
    }).join('');
}

function renderWireless(d) {
    return d.map(w => {
        const sig = parseInt(w['signal-strength'] || 0);
        return `<tr>
            <td>${w.interface || '-'}</td>
            <td>${w['mac-address'] || '-'}</td>
            <td>${badge(sig > -65 ? 'status-up' : sig > -80 ? 'status-warning' : 'status-down', (w['signal-strength'] || '-') + ' dBm')}</td>
            <td>${w['tx-rate'] || '-'}</td><td>${w['rx-rate'] || '-'}</td>
            <td><span class="text-muted">${w.uptime || '-'}</span></td></tr>`;
    }).join('');
}

function renderScripts(d) {
    return d.map(s => `<tr>
        <td><strong>${s.name || '-'}</strong></td>
        <td><span class="text-muted">${s.policy || '-'}</span></td>
        <td>${s['last-started'] || 'Never'}</td>
        <td><span class="text-muted">${s.comment || '-'}</span></td></tr>`).join('');
}

function renderSchedulers(d) {
    return d.map(s => {
        const ev = s['on-event'] || '-';
        const truncated = ev.length > 60 ? ev.substring(0, 60) + '…' : ev;
        return `<tr>
        <td><strong>${s.name || '-'}</strong></td>
        <td>${s.interval || '-'}</td>
        <td><span class="text-muted">${s.policy || '-'}</span></td>
        <td><code style="font-size:.8rem;color:var(--accent)">${truncated}</code></td></tr>`;
    }).join('');
}

function renderUsers(d) {
    return d.map(u => `<tr>
        <td><strong>${u.name || '-'}</strong></td>
        <td>${badge(u.group === 'full' ? 'status-up' : 'status-warning', u.group || '-')}</td>
        <td><span class="text-muted">${u['last-logged-in'] || 'Never'}</span></td></tr>`).join('');
}

function renderActiveUsers(d) {
    return d.map(u => `<tr>
        <td><strong>${u.name || '-'}</strong></td>
        <td><span class="text-accent">${u.via || u.service || '-'}</span></td>
        <td>${u.address || '-'}</td>
        <td><span class="text-muted">${u.when || u.uptime || '-'}</span></td></tr>`).join('');
}

// ── Actions ───────────────────────────────────────────────────────────────────

async function downloadBackup() {
    try {
        const r = await fetch('/api/backup', { headers: authHeaders });
        if (r.status === 401) return logout();
        const blob = await r.blob();
        const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `mikrotik_${Date.now()}.rsc` });
        document.body.appendChild(a); a.click(); a.remove();
    } catch { alert('Backup failed.'); }
}

async function rebootRouter() {
    if (!confirm('Reboot the MikroTik router?\nNetwork will be briefly interrupted.')) return;
    try {
        const r = await fetch('/api/reboot', { method: 'POST', headers: authHeaders });
        if (r.status === 401) return logout();
        const d = await r.json();
        alert(d.status === 'success' ? '✅ Reboot sent! Dashboard reconnects automatically.' : `❌ ${d.message}`);
    } catch { alert('Reboot command failed.'); }
}

async function startScan() {
    const ip = (document.getElementById('scan-target').value || '').trim();
    if (!ip) return alert('Enter an IP address.');
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
        return alert('შეცდომა: გთხოვთ შეიყვანოთ სწორი IP მისამართი\n(Error: Please enter a valid IP address e.g. 192.168.88.1)');
    }
    document.getElementById('scanner-body').innerHTML = '<tr><td colspan="3" class="text-center">🔍 Scanning…</td></tr>';
    try {
        const r = await fetch('/api/scan_ports', { method: 'POST', headers: authHeaders, body: JSON.stringify({ ip_address: ip }) });
        if (r.status === 401) return logout();
        const d = await r.json();
        document.getElementById('scanner-body').innerHTML = d.open_ports.length
            ? d.open_ports.map(p => `<tr><td><strong>${p.port}</strong></td><td>${p.service}</td><td>${badge('status-up', 'OPEN')}</td></tr>`).join('')
            : `<tr><td colspan="3" class="text-center empty-state">No open ports on ${ip}</td></tr>`;
    } catch { document.getElementById('scanner-body').innerHTML = '<tr><td colspan="3" class="text-center text-warning">Scan failed.</td></tr>'; }
}

// ── Network Map ───────────────────────────────────────────────────────────────

async function loadNetworkMap() {
    const grid = document.getElementById('netmap-device-grid');
    const prog = document.getElementById('netmap-progress');
    const bar  = document.getElementById('netmap-bar');
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><i class="fa-solid fa-spinner fa-spin"></i> Loading devices from MikroTik ARP + DHCP…</div>';
    prog.style.display = 'block'; bar.style.width = '60%';
    try {
        const r = await fetch('/api/network_map', { headers: authHeaders });
        if (r.status === 401) return logout();
        const d = await r.json();
        bar.style.width = '100%';
        document.getElementById('netmap-count').textContent = `${d.count} devices found`;
        renderDeviceGrid('netmap-device-grid', 'netmap-table-body', d.devices, 'arp+dhcp');
    } catch {
        grid.innerHTML = '<div class="empty-state text-warning" style="grid-column:1/-1">Failed to load device map.</div>';
    } finally {
        setTimeout(() => { prog.style.display = 'none'; bar.style.width = '0%'; }, 800);
    }
}

async function runPingSweep() {
    const subnet = (document.getElementById('sweep-subnet').value || '').trim();
    if (!subnet) return alert('Enter a subnet (e.g. 10.21.10.0/24)');
    const subnetRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    if (!subnetRegex.test(subnet)) {
        return alert('შეცდომა: გთხოვთ შეიყვანოთ სწორი Subnet\n(Error: Please enter a valid Subnet in CIDR format e.g. 192.168.88.0/24)');
    }
    const grid = document.getElementById('sweep-device-grid');
    const prog = document.getElementById('sweep-progress');
    const bar  = document.getElementById('sweep-bar');
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1"><i class="fa-solid fa-radar fa-spin"></i> Scanning ' + subnet + ' — this may take 10-30 seconds…</div>';
    prog.style.display = 'block'; bar.style.width = '30%';
    try {
        const r = await fetch('/api/ping_sweep', { method: 'POST', headers: authHeaders, body: JSON.stringify({ subnet }) });
        if (r.status === 401) return logout();
        const d = await r.json();
        bar.style.width = '100%';
        if (!d.hosts.length) {
            grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">No live hosts found in <code>${subnet}</code>.<br>TCP ports 22/80/443/8080/8291/53 all timed out.</div>`;
        } else {
            renderDeviceGrid('sweep-device-grid', null, d.hosts, 'sweep');
        }
    } catch {
        grid.innerHTML = '<div class="empty-state text-warning" style="grid-column:1/-1">Ping sweep failed.</div>';
    } finally {
        setTimeout(() => { prog.style.display = 'none'; bar.style.width = '0%'; }, 800);
    }
}

function renderDeviceGrid(gridId, tableBodyId, devices, source) {
    const grid = document.getElementById(gridId);
    if (!devices.length) {
        grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1">No devices found.</div>';
        return;
    }
    grid.innerHTML = devices.map(d => {
        const online = d.status === 'online';
        const icon   = d.icon || guessDeviceIcon(d.vendor, d.hostname);
        const label  = d.device_label || d.device_type || 'Unknown';
        const actionBtns = source !== 'sweep' ? `
            <div style="margin-top:.7rem;display:flex;gap:5px;flex-wrap:wrap">
                <button class="btn btn-export" style="flex:1;padding:.25rem .4rem;font-size:.78rem"
                    onclick="deepScanDevice('${d.ip}','${(d.hostname||'').replace(/'/g,'')}')" >
                    <i class="fa-solid fa-magnifying-glass"></i> Deep Scan</button>
                <button class="btn btn-export" style="flex:1;padding:.25rem .4rem;font-size:.78rem"
                    onclick="document.getElementById('scan-target').value='${d.ip}'; document.querySelector('[data-tab=scanner-tab]').click()">
                    <i class="fa-solid fa-radar"></i> Port Scan</button>
                <button class="btn btn-block" style="flex:1;padding:.25rem .4rem;font-size:.78rem"
                    onclick="blockIp('${d.ip}')">
                    <i class="fa-solid fa-ban"></i> Block</button>
            </div>` : '';
        return `<div class="device-card ${online ? 'online' : 'offline'}">
            <div class="device-online-dot ${online ? '' : 'offline'}"></div>
            <div style="font-size:1.8rem;margin-bottom:.3rem">${icon}</div>
            <div class="device-ip">
                ${d.ip} 
                <span onclick="copyToClipboard('${d.ip}', this)" style="cursor:pointer;margin-left:6px;font-size:0.8rem;color:var(--text-muted);" title="Copy IP">
                    <i class="fa-solid fa-copy"></i>
                </span>
            </div>
            <div class="device-mac">${d.mac || 'MAC unknown'}</div>
            <div class="device-hostname">${d.hostname || '<span class="text-muted">No hostname</span>'}</div>
            <div class="device-vendor"><i class="fa-solid fa-microchip"></i> ${d.vendor || 'Unknown vendor'}</div>
            <div style="margin-top:.4rem">${badge('status-warning', label)}</div>
            ${d.interface ? `<div style="font-size:.72rem;color:#64748b;margin-top:.2rem"><i class="fa-solid fa-plug"></i> ${d.interface}</div>` : ''}
            ${d.dhcp_status ? `<div style="margin-top:.3rem">${badge(d.dhcp_status==='bound'?'status-up':'status-warning', d.dhcp_status)}</div>` : ''}
            ${actionBtns}
        </div>`;
    }).join('');

    if (tableBodyId) {
        const tb = document.getElementById(tableBodyId);
        if (tb) tb.innerHTML = devices.map(d =>
            `<tr><td>${d.ip}</td><td>${d.hostname||''}</td><td>${d.mac||''}</td><td>${d.vendor||''}</td><td>${d.device_label||d.device_type||''}</td><td>${d.interface||''}</td><td>${d.status}</td><td>${d.dhcp_status||''}</td></tr>`
        ).join('');
    }
}

// ── Deep Scan modal ───────────────────────────────────────────────────────────

async function deepScanDevice(ip, hostname) {
    // Create modal
    const existing = document.getElementById('_dsModal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = '_dsModal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem';
    modal.innerHTML = `
        <div style="background:#0f1729;border:1px solid rgba(255,255,255,.15);border-radius:16px;padding:2rem;max-width:700px;width:100%;max-height:85vh;overflow-y:auto;position:relative">
            <button onclick="document.getElementById('_dsModal').remove()"
                style="position:absolute;top:1rem;right:1rem;background:none;border:none;color:#94a3b8;font-size:1.4rem;cursor:pointer">✕</button>
            <h2 style="margin:0 0 .3rem"><i class="fa-solid fa-magnifying-glass-plus"></i> Deep Device Scan</h2>
            <div style="color:#94a3b8;font-size:.85rem;margin-bottom:1.2rem">${ip}${hostname ? ' · ' + hostname : ''}</div>
            <div id="_dsContent"><div class="empty-state"><i class="fa-solid fa-spinner fa-spin"></i> Scanning ports, grabbing banners…</div></div>
        </div>`;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });

    try {
        const r = await fetch('/api/device_scan', {
            method: 'POST', headers: authHeaders,
            body: JSON.stringify({ ip_address: ip })
        });
        if (r.status === 401) return logout();
        const d = await r.json();

        const portRows = (d.services || []).map(s => {
            const b = d.banners && d.banners[s.port];
            const bannerInfo = b
                ? (b.title ? `<span style="color:#10b981"> · ${b.title}</span>` : b.server ? `<span style="color:#94a3b8"> · ${b.server}</span>` : '')
                : '';
            const deviceHint = b && b.device_hint ? `<span class="status-badge status-warning" style="margin-left:6px">${b.device_hint}</span>` : '';
            return `<tr>
                <td><strong>${s.port}</strong></td>
                <td>${badge('status-up','OPEN')}</td>
                <td>${s.service}${bannerInfo}${deviceHint}</td>
            </tr>`;
        }).join('');

        document.getElementById('_dsContent').innerHTML = `
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:1rem">
                <div><span class="text-muted">IP Address</span><br><strong>${d.ip} <span onclick="copyToClipboard('${d.ip}', this)" style="cursor:pointer;font-size:0.8rem;color:var(--text-muted);" title="Copy IP"><i class="fa-solid fa-copy"></i></span></strong></div>
                <div><span class="text-muted">Hostname</span><br><strong>${d.hostname||'Unknown'}</strong></div>
                <div><span class="text-muted">Device Class</span><br>${badge('status-warning', (d.icon || '🖥️') + ' ' + (d.device_label || d.device_type || 'Unknown'))}</div>
                <div><span class="text-muted">Inferred Vendor</span><br><strong>${d.vendor || 'Unknown'}</strong></div>
                <div><span class="text-muted">Open Ports</span><br><strong style="color:var(--accent)">${d.open_ports.length}</strong></div>
                <div><span class="text-muted">Status</span><br>${badge('status-up','Online')}</div>
            </div>
            ${d.open_ports.length === 0
                ? '<div class="empty-state">No open ports detected on common services.</div>'
                : `<div class="table-container"><table>
                    <thead><tr><th>Port</th><th>Status</th><th>Service / Banner</th></tr></thead>
                    <tbody>${portRows}</tbody>
                </table></div>`}
        `;
    } catch {
        document.getElementById('_dsContent').innerHTML = '<div class="empty-state text-warning">Deep scan failed.</div>';
    }
}

function guessDeviceIcon(vendor, hostname) {
    const v = (vendor || '').toLowerCase();
    const h = (hostname || '').toLowerCase();
    if (v.includes('mikrotik'))   return '🌐';
    if (v.includes('cisco') || v.includes('netgear') || v.includes('ubiquiti')) return '🔀';
    if (v.includes('apple'))      return h.includes('iphone') || h.includes('ipad') ? '📱' : '💻';
    if (v.includes('samsung') || v.includes('xiaomi') || v.includes('huawei')) return '📱';
    if (v.includes('hikvision') || v.includes('dahua') || v.includes('axis') || v.includes('hanwha')) return '📷';
    if (v.includes('canon') || v.includes('epson') || v.includes('hp') || v.includes('brother')) return '🖨️';
    if (v.includes('synology') || v.includes('qnap')) return '💾';
    if (v.includes('vmware') || v.includes('virtualbox')) return '💻';
    if (v.includes('raspberry')) return '🔧';
    if (v.includes('sony') || v.includes('xbox') || v.includes('nintendo')) return '🎮';
    if (v.includes('roku') || v.includes('chromecast') || v.includes('amazon')) return '📺';
    if (h.includes('camera') || h.includes('cam') || h.includes('nvr')) return '📷';
    if (h.includes('printer')) return '🖨️';
    if (h.includes('phone') || h.includes('android') || h.includes('iphone')) return '📱';
    if (h.includes('tv') || h.includes('smart')) return '📺';
    return '🖥️';
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    const bg = type === 'success' ? 'rgba(16, 185, 129, 0.9)' : type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(59, 130, 246, 0.9)';
    toast.style.cssText = `background:${bg};color:white;padding:12px 18px;border-radius:8px;box-shadow:0 10px 25px rgba(0,0,0,0.4);font-size:0.9rem;font-weight:500;pointer-events:auto;transition:all 0.3s ease;transform:translateY(10px);opacity:0;display:flex;align-items:center;gap:10px;backdrop-filter:blur(10px);`;
    const icon = type === 'success' ? 'fa-circle-check' : type === 'error' ? 'fa-circle-xmark' : 'fa-circle-info';
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.transform = 'translateY(0)'; toast.style.opacity = '1'; }, 10);
    setTimeout(() => {
        toast.style.transform = 'translateY(10px)';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

async function blockIp(ip) {
    if (!confirm(`Block IP: ${ip}?\nAdded to NetSentry_Blocklist.`)) return;
    try {
        const r = await fetch('/api/block_ip', { method: 'POST', headers: authHeaders, body: JSON.stringify({ ip_address: ip }) });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') showToast(`✅ ${d.message}`, 'success');
        else showToast(`❌ ${d.message}`, 'error');
    } catch { showToast('Failed to block IP.', 'error'); }
}

async function unblockIp(ip) {
    if (!confirm(`Unblock IP: ${ip}?\nRemove from NetSentry_Blocklist.`)) return;
    try {
        const r = await fetch('/api/unblock_ip', { method: 'POST', headers: authHeaders, body: JSON.stringify({ ip_address: ip }) });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') showToast(`✅ ${d.message}`, 'success');
        else showToast(`❌ ${d.message}`, 'error');
    } catch { showToast('Failed to unblock IP.', 'error'); }
}

async function flushDNS() {
    try {
        const r = await fetch('/api/tools/flush_dns', { method: 'POST', headers: authHeaders });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') showToast(`🧹 ${d.message}`, 'success');
        else showToast(`❌ ${d.message}`, 'error');
    } catch { showToast('Failed to flush DNS cache.', 'error'); }
}

async function toggleInterface(interfaceId, currentlyDisabled) {
    const actionName = currentlyDisabled ? 'enable' : 'disable';
    if (!confirm(`Are you sure you want to ${actionName} interface ${interfaceId}?`)) return;
    try {
        const r = await fetch('/api/interface/toggle', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ interface_id: interfaceId, disabled: !currentlyDisabled })
        });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') showToast(`⚡ Interface ${actionName}d.`, 'success');
        else showToast(`❌ ${d.message}`, 'error');
    } catch { showToast('Failed to toggle interface.', 'error'); }
}

async function removeDHCPLease(leaseId) {
    if (!confirm(`Remove DHCP lease ${leaseId}?`)) return;
    try {
        const r = await fetch('/api/dhcp/remove', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ lease_id: leaseId })
        });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') showToast(`🗑️ ${d.message}`, 'success');
        else showToast(`❌ ${d.message}`, 'error');
    } catch { showToast('Failed to remove lease.', 'error'); }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function copyToClipboard(text, btnEl) {
    navigator.clipboard.writeText(text).then(() => {
        const orig = btnEl.innerHTML;
        btnEl.innerHTML = '<i class="fa-solid fa-check" style="color:var(--accent)"></i>';
        setTimeout(() => { btnEl.innerHTML = orig; }, 1500);
    }).catch(() => {
        alert('Failed to copy.');
    });
}

async function runPingTool() {
    const address = (document.getElementById('ping-tool-address').value || '').trim();
    const count = parseInt(document.getElementById('ping-tool-count').value || 4);
    if (!address) return alert('გთხოვთ შეიყვანოთ მისამართი (Enter address)');
    const out = document.getElementById('ping-tool-output');
    out.innerHTML = '<div class="empty-state">⚡ Ping in progress...</div>';
    try {
        const r = await fetch('/api/tools/ping', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ address, count })
        });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') {
            if (d.results && d.results.length) {
                out.innerHTML = d.results.map(p => {
                    const host = p.host || p.address || address;
                    const time = p.time || '--';
                    const size = p.size || '--';
                    const ttl = p.ttl || '--';
                    const status = p.status || 'reply';
                    if (status.includes('timeout') || status.includes('fail')) {
                        return `<div style="color:var(--warning)">Request timeout from ${host}</div>`;
                    }
                    return `<div style="color:var(--accent)">Reply from ${host}: bytes=${size} time=${time} TTL=${ttl}</div>`;
                }).join('');
            } else {
                out.innerHTML = `<div style="color:var(--warning)">No reply received from ${address}</div>`;
            }
        } else {
            out.innerHTML = `<div style="color:var(--warning)">Error: ${d.message}</div>`;
        }
    } catch {
        out.innerHTML = '<div style="color:var(--warning)">Command failed.</div>';
    }
}

async function runDnsLookupTool() {
    const domain = (document.getElementById('dns-tool-domain').value || '').trim();
    if (!domain) return alert('გთხოვთ შეიყვანოთ დომენი (Enter domain)');
    const out = document.getElementById('dns-tool-output');
    out.innerHTML = '<div class="empty-state">⚡ Querying DNS...</div>';
    try {
        const r = await fetch('/api/tools/dns_lookup', {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ domain })
        });
        if (r.status === 401) return logout();
        const d = await r.json();
        if (d.status === 'success') {
            if (Array.isArray(d.results)) {
                out.innerHTML = d.results.map(item => {
                    const val = Object.entries(item).map(([k, v]) => `${k}: ${v}`).join(', ');
                    return `<div style="color:var(--accent)">${val}</div>`;
                }).join('');
            } else if (typeof d.results === 'object') {
                out.innerHTML = `<div style="color:var(--accent)">${JSON.stringify(d.results, null, 2)}</div>`;
            } else {
                out.innerHTML = `<div style="color:var(--accent)">Resolved: ${d.results}</div>`;
            }
        } else {
            out.innerHTML = `<div style="color:var(--warning)">Error: ${d.message}</div>`;
        }
    } catch {
        out.innerHTML = '<div style="color:var(--warning)">Command failed.</div>';
    }
}

function fmtB(b, dec = 2) {
    if (!+b) return '0 B';
    const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return `${(b / Math.pow(k, i)).toFixed(dec)} ${s[i]}`;
}

function exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const csv = [...table.rows].map(r => [...r.querySelectorAll('td,th')].map(c => `"${c.innerText.replace(/"/g, '""')}"`).join(',')).join('\n');
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: filename });
    document.body.appendChild(a); a.click(); a.remove();
}

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = 'Inter';

    trafficChart = mkChart('trafficChart', [
        { label: 'RX (Mbps)', borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,.1)' },
        { label: 'TX (Mbps)', borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)' }
    ]);
    cpuChart = mkChart('cpuChart', [{ label: 'CPU %', borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,.2)' }], 100);
    latencyChart = mkChart('latencyChart', [{ label: 'Latency ms', borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,.2)' }]);

    fetchStatus();
    initTabs();
    connectWebSocket();

    // Auto-inject Search Filters into all panel headers that have tables
    setTimeout(() => {
        document.querySelectorAll('.panel.glass').forEach(panel => {
            const tbody = panel.querySelector('tbody');
            if (!tbody || !tbody.id) return;
            
            // Skip panels without filter relevance
            if (tbody.id === 'interfaces-body' || tbody.id === 'scanner-body' || tbody.id === 'sniffer-body' || tbody.id === 'ping-tool-output' || tbody.id === 'dns-tool-output') return;
            
            let header = panel.querySelector('.panel-header');
            if (!header) return;
            
            // Ensure header is flex-capable
            header.classList.add('alert-header-flex');
            
            // Look for control box or first button wrapper
            let actionGroup = header.querySelector('div');
            if (!actionGroup) {
                actionGroup = document.createElement('div');
                actionGroup.style.display = 'flex';
                actionGroup.style.gap = '10px';
                actionGroup.style.alignItems = 'center';
                header.appendChild(actionGroup);
            } else {
                actionGroup.style.display = 'flex';
                actionGroup.style.gap = '10px';
                actionGroup.style.alignItems = 'center';
            }
            
            // Create the search input box
            const searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.placeholder = 'ფილტრი / Search...';
            searchInput.className = 'search-input';
            searchInput.style.width = '160px';
            searchInput.style.fontSize = '0.8rem';
            searchInput.style.padding = '0.35rem 0.7rem';
            searchInput.style.borderRadius = '6px';
            
            searchInput.oninput = (e) => filterTable(tbody.id, e.target.value);
            
            // Insert searchInput before any export buttons
            const firstBtn = actionGroup.querySelector('button, a');
            if (firstBtn) {
                actionGroup.insertBefore(searchInput, firstBtn);
            } else {
                actionGroup.appendChild(searchInput);
            }
        });
    }, 100);
});
