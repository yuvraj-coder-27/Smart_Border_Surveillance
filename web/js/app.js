/**
 * app.js — Border Surveillance System C2 Frontend
 * Innovation Architecture v2.0
 *
 * New: Zones, Baseline Engine, AI Assistant, Sync Status, contributing factors,
 *      alert dismiss with recalibration, risk score badges.
 */

const API = '';   // same origin
let ws = null;
let poorConnectivity = false;

// ── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
    const el = document.getElementById('liveClock');
    if (el) el.textContent = new Date().toLocaleTimeString('en-IN', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── Tab switching & Metadata ───────────────────────────────────────────────
const TAB_METADATA = {
    'recon': { title: 'Live C2 Reconnaissance', icon: 'fa-video' },
    'investigation': { title: 'Historical Event Investigation & Dossiers', icon: 'fa-magnifying-glass-chart' },
    'anpr': { title: 'Vehicle ANPR & Threat Watchlist', icon: 'fa-car' },
    'zones': { title: 'Restricted Zones Studio & Geofencing', icon: 'fa-draw-polygon' },
    'baseline': { title: 'Behavioral Baseline Engine & Anomaly Detection', icon: 'fa-chart-line' },
    'assistant': { title: 'Tactical AI Assistant & Offline Edge Sync', icon: 'fa-robot' },
    'blockchain': { title: 'Cryptographic Blockchain Ledger & Proof', icon: 'fa-link' },
    'audit': { title: 'Security Audit & RBAC Access Trail', icon: 'fa-clipboard-check' }
};

function toggleSidebar() {
    const sidebar = document.getElementById('sidebarNav');
    if (sidebar) {
        sidebar.classList.toggle('hidden');
    }
}

function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(s => {
        s.classList.add('hidden');
        s.classList.remove('active');
        s.style.display = 'none';
    });
    document.querySelectorAll('.nav-tab-btn').forEach(b => {
        b.classList.remove('active');
    });
    const section = document.getElementById('tab-' + name);
    if (section) {
        section.classList.remove('hidden');
        section.classList.add('active');
        // recon uses grid layout, others use flex column
        section.style.display = (name === 'recon') ? 'grid' : 'flex';
        section.style.flexDirection = 'column';
        section.style.gap = '14px';
    }
    const btn = document.getElementById('tabBtn-' + name);
    if (btn) btn.classList.add('active');

    // Update topbar breadcrumb
    const titleEl = document.getElementById('activeTabTitle');
    if (titleEl && TAB_METADATA[name]) {
        titleEl.innerHTML = `<i class="fa-solid ${TAB_METADATA[name].icon}"></i> ${TAB_METADATA[name].title}`;
    }

    if (name === 'investigation' || name === 'incidents') searchHistoricalIncidents();
    if (name === 'anpr') loadAnprData();
    if (name === 'audit') loadAuditLogs();
    if (name === 'zones') { loadZones(); redrawZoneCanvas(); }
    if (name === 'baseline') loadBaseline();
    if (name === 'assistant') loadSyncStatus();
    if (name === 'blockchain') loadBlockchain();
}

// ── Snapshot Modal ─────────────────────────────────────────────────────────
function openSnapshotModal(src, metaHtml) {
    const modal = document.getElementById('snapshotModal');
    const img = document.getElementById('modalSnapshotImg');
    const metaEl = document.getElementById('modalSnapshotMeta');
    if (!modal || !img) return;
    img.onerror = () => {
        img.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="250" viewBox="0 0 400 250"><rect fill="%231e293b" width="400" height="250"/><text fill="%2394a3b8" font-family="sans-serif" font-size="14" x="50%" y="50%" text-anchor="middle">Optical snapshot file archived or offline</text></svg>';
    };
    img.src = src;
    if (metaEl) {
        metaEl.innerHTML = metaHtml || '<div class="text-slate-400">Forensic optical evidence captured by autonomous surveillance engine.</div>';
    }
    modal.classList.remove('hidden');

}

function closeSnapshotModal() {
    const modal = document.getElementById('snapshotModal');
    if (modal) modal.classList.add('hidden');
}

async function viewAlertSnapshot(alertId, alertType) {
    try {
        const res = await fetch(`${API}/api/evidence/${alertId}`);
        if (!res.ok) {
            const errData = await res.json().catch(() => ({ detail: `HTTP error ${res.status}` }));
            throw new Error(errData.detail || `HTTP error ${res.status}`);
        }
        const evidenceList = await res.json();
        let snapFile = null;
        if (evidenceList && evidenceList.length) {
            for (const ev of evidenceList) {
                if (ev.snapshot_path) {
                    snapFile = ev.snapshot_path.split(/[\\/]/).pop();
                    break;
                }
            }
        }
        if (snapFile) {
            const snapUrl = `${API}/api/snapshots/${encodeURIComponent(snapFile)}`;
            const meta = `<div><strong class="text-blue-400">INCIDENT #${alertId}</strong> — ${escHtml(alertType)}</div>
                          <div class="text-slate-400 text-[11px] mt-1">Snapshot File: <span class="text-slate-200">${escHtml(snapFile)}</span></div>`;
            openSnapshotModal(snapUrl, meta);
        } else {
            showToast(`No snapshot image stored for Alert #${alertId}`, 'amber');
        }
    } catch (e) {
        showToast(`Could not load evidence: ${e.message}`, 'rose');
    }
}


// ── WebSocket ──────────────────────────────────────────────────────────────
function connectWS() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}/ws`);
    ws.onmessage = (e) => {
        try { handleAlert(JSON.parse(e.data)); } catch {}
    };
    ws.onclose = () => setTimeout(connectWS, 3000);
}

function handleAlert(alert) {
    // Update live counters
    const totalEl = document.getElementById('statTotalAlerts');
    if (totalEl) totalEl.textContent = parseInt(totalEl.textContent || '0') + 1;

    if (alert.status === 'open' || !alert.status) {
        const activeEl = document.getElementById('statActiveThreats');
        if (activeEl) activeEl.textContent = parseInt(activeEl.textContent || '0') + 1;
        updateThreatBadge(alert.alert_type || alert.type || 'threat');
    }

    // Prepend to live alert list
    const list = document.getElementById('liveAlertList');
    if (list) {
        const placeholder = list.querySelector('.text-center');
        if (placeholder) placeholder.remove();
        list.insertAdjacentHTML('afterbegin', buildAlertCard(alert));
        while (list.children.length > 50) list.lastChild.remove();
    }
}

function buildAlertCard(a) {
    const severity = riskSeverityClass(a.risk_score || a.confidence || 0);
    const factors = (a.contributing_factors || []);
    const factorsHtml = factors.length
        ? `<div style="margin-top:6px; display:flex; flex-direction:column; gap:3px;">${factors.map(f =>
            `<div style="font-size:10px; color:var(--c-text-3); display:flex; align-items:center; gap:5px;"><i class="fa-solid fa-angle-right" style="color:var(--c-text-4); font-size:9px;"></i>${escHtml(f)}</div>`
          ).join('')}</div>`
        : '';
    const syncBadge = a.sync_status === 'full_synced'
        ? `<span class="badge badge-ok">Synced</span>`
        : `<span class="badge badge-warn">Meta Only</span>`;
    const riskBadge = a.risk_score
        ? `<span class="badge ${severity.badge}">RISK ${Math.round(a.risk_score)}</span>`
        : '';
    const dismissBtn = a.id
        ? `<button onclick="dismissAlert(${a.id}, this)" class="btn btn-ghost btn-sm" style="padding:3px 8px; font-size:10px;">Dismiss</button>`
        : '';
    const viewBtn = a.snapshot
        ? `<button onclick="openSnapshotModal('/api/snapshots/${encodeURIComponent(a.snapshot)}', 'Incident #${a.id}: ${escHtml(a.alert_type || a.type || 'Threat')}')" class="btn btn-sm" style="padding:3px 8px; font-size:10px;">Snap</button>`
        : (a.id ? `<button onclick="viewAlertSnapshot(${a.id}, '${escHtml(a.alert_type || a.type || 'Threat')}')" class="btn btn-sm" style="padding:3px 8px; font-size:10px;">Snap</button>` : '');

    return `
    <div id="alert-${a.id}" class="alert-item ${severity.itemClass}">
        <div class="alert-item-icon ${severity.iconClass}">
            <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div class="alert-item-body">
            <div class="alert-item-title">${escHtml(a.alert_type || a.type || 'ALERT')}</div>
            <div class="alert-item-meta">${escHtml(a.camera_id || '')} · ${formatTs(a.timestamp)} · ID #${a.id || '--'}</div>
            <div style="font-size:11px; color:var(--c-text-2); margin-top:4px;">${escHtml(a.message || '')}</div>
            ${factorsHtml}
            <div style="display:flex; gap:5px; margin-top:6px; flex-wrap:wrap; align-items:center;">
                ${riskBadge} ${syncBadge} ${viewBtn} ${dismissBtn}
            </div>
        </div>
    </div>`;
}

function riskSeverityClass(score) {
    if (score >= 80) return { badge: 'badge-alert', itemClass: '', iconClass: 'critical' };
    if (score >= 50) return { badge: 'badge-warn',  itemClass: '', iconClass: 'high' };
    if (score >= 25) return { badge: 'badge-warn',  itemClass: '', iconClass: '' };
    return { badge: 'badge-neutral', itemClass: '', iconClass: '' };
}

function updateThreatBadge(type) {
    const badge = document.getElementById('threatBadge');
    const text = document.getElementById('threatStatusText');
    if (!badge || !text) return;
    badge.classList.add('threat');
    // Update the inner dot color
    const dot = badge.querySelector('.threat-dot');
    if (dot) dot.style.background = 'var(--c-alert)';
    text.textContent = `ALERT: ${type.toUpperCase()}`;
}

// ── Alerts table (Tab 2 Historical / Incidents) ───────────────────────────
async function loadAlertsTable() {
    return searchHistoricalIncidents();
}

async function dismissAlert(alertId, btn) {
    try {
        if (btn) { btn.textContent = '…'; btn.disabled = true; }
        const res = await fetch(`${API}/api/alerts/${alertId}/dismiss`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ feedback: '' })
        });
        const data = await res.json();
        if (btn) { btn.textContent = 'Dismissed'; btn.disabled = true; btn.classList.add('opacity-50'); }
        const card = document.getElementById(`alert-${alertId}`);
        if (card) card.style.opacity = '0.5';
        if (data.rows_recalibrated > 0) {
            showToast(`✅ ${data.rows_recalibrated} baseline row(s) recalibrated from this feedback`, 'emerald');
        } else {
            showToast(`Alert #${alertId} dismissed`, 'emerald');
        }
    } catch (e) {
        if (btn) { btn.textContent = 'Error'; btn.disabled = false; }
        showToast(`Dismiss error: ${e.message}`, 'rose');
    }
}

// ── Visual Zones Studio (Tab 4) ─────────────────────────────────────────────
let zonePointsList = [];

function handleZoneMouseMove(event) {
    const canvas = document.getElementById('zoneDrawingCanvas');
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const x = Math.round((event.clientX - rect.left) * scaleX);
    const y = Math.round((event.clientY - rect.top) * scaleY);
    const coordEl = document.getElementById('zoneCoordDisplay');
    if (coordEl) coordEl.textContent = `Cursor: (X: ${Math.max(0, Math.min(640, x))}, Y: ${Math.max(0, Math.min(480, y))})`;
}

function handleZoneCanvasClick(event) {
    const canvas = document.getElementById('zoneDrawingCanvas');
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const x = Math.round(Math.max(0, Math.min(640, (event.clientX - rect.left) * scaleX)));
    const y = Math.round(Math.max(0, Math.min(480, (event.clientY - rect.top) * scaleY)));

    zonePointsList.push([x, y]);
    updateZoneInputsAndCanvas();
}

function undoZonePoint() {
    if (zonePointsList.length > 0) {
        zonePointsList.pop();
        updateZoneInputsAndCanvas();
    }
}

function clearZoneCanvas() {
    zonePointsList = [];
    updateZoneInputsAndCanvas();
}

function applyZonePreset(type) {
    if (type === 'border_strip') {
        zonePointsList = [[40, 240], [600, 240], [600, 360], [40, 360]];
        const nameEl = document.getElementById('zoneName');
        if (nameEl) nameEl.value = 'Zero-Line Buffer Strip';
    } else if (type === 'outpost_box') {
        zonePointsList = [[160, 140], [480, 140], [480, 380], [160, 380]];
        const nameEl = document.getElementById('zoneName');
        if (nameEl) nameEl.value = 'Outpost Security Perimeter';
    } else if (type === 'fence_boundary') {
        zonePointsList = [[20, 360], [620, 360], [620, 460], [20, 460]];
        const nameEl = document.getElementById('zoneName');
        if (nameEl) nameEl.value = 'Barbed Wire Corridor';
    }
    updateZoneInputsAndCanvas();
}

function updateZoneInputsAndCanvas() {
    const input = document.getElementById('zonePoints');
    if (input) input.value = JSON.stringify(zonePointsList);

    const counter = document.getElementById('zoneVertexCounter');
    if (counter) {
        counter.textContent = `Vertices: ${zonePointsList.length} (Min 3)`;
        if (zonePointsList.length >= 3) {
            counter.style.color = 'var(--c-ok)';
            counter.style.borderColor = 'rgba(76,175,121,0.4)';
        } else {
            counter.style.color = 'var(--c-accent)';
            counter.style.borderColor = 'var(--c-border-md)';
        }
    }
    redrawZoneCanvas();
}

function redrawZoneCanvas(highlightPoints = null) {
    const canvas = document.getElementById('zoneDrawingCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const pts = highlightPoints || zonePointsList;
    if (!pts || pts.length === 0) return;

    const isHighlight = Boolean(highlightPoints);
    const strokeColor = isHighlight ? '#10b981' : '#3b82f6';
    const fillColor = isHighlight ? 'rgba(16, 185, 129, 0.25)' : 'rgba(59, 130, 246, 0.25)';

    // Draw boundary path
    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) {
        ctx.lineTo(pts[i][0], pts[i][1]);
    }
    if (pts.length >= 3) {
        ctx.closePath();
        ctx.fillStyle = fillColor;
        ctx.fill();
    }
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = strokeColor;
    ctx.stroke();

    // Draw vertex badges
    pts.forEach((p, idx) => {
        // Outer glow circle
        ctx.beginPath();
        ctx.arc(p[0], p[1], 6, 0, Math.PI * 2);
        ctx.fillStyle = strokeColor;
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 11px monospace';
        ctx.fillText(`P${idx + 1} (${p[0]},${p[1]})`, p[0] + 8, p[1] - 4);
    });
}

async function saveDrawnZone() {
    const camInput = document.getElementById('zoneCamera');
    const cameraId = (camInput.value || '').trim() || 'cam_0';
    const name = (document.getElementById('zoneName').value || '').trim();
    const msg = document.getElementById('zoneMsg');

    if (zonePointsList.length < 3) {
        showMsg(msg, 'Draw at least 3 points on the canvas to form a polygon', 'rose');
        return;
    }
    if (!name) {
        showMsg(msg, 'Please specify a zone name', 'rose');
        return;
    }

    try {
        const res = await fetch(`${API}/api/zones`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ camera_id: cameraId, name, polygon_points: zonePointsList })
        });
        if (!res.ok) throw new Error(await res.text());
        showMsg(msg, `✅ Zone "${name}" committed to AI engine!`, 'emerald');
        clearZoneCanvas();
        document.getElementById('zoneName').value = '';
        loadZones(cameraId);
    } catch (e) {
        showMsg(msg, `Error: ${e.message}`, 'rose');
    }
}

async function loadZones(cam) {
    let cameraId = cam || (document.getElementById('zoneCamera').value || '').trim() || 'cam_0';
    const container = document.getElementById('zonesListContainer');
    if (!container) return;
    container.innerHTML = '<div class="text-center py-4 text-slate-500">Loading…</div>';

    try {
        const res = await fetch(`${API}/api/zones/${cameraId}`);
        const zones = await res.json();
        if (!zones.length) {
            container.innerHTML = `<div style="text-align:center; padding:16px 0; color:var(--c-text-4);">No active zones for camera "${escHtml(cameraId)}". Click canvas above to draw one.</div>`;
            return;
        }
        container.innerHTML = zones.map(z => `
            <div style="padding:8px 10px; display:flex; align-items:center; justify-content:space-between; background:var(--c-surface-2); border:1px solid var(--c-border); border-radius:var(--radius); margin-bottom:6px; cursor:pointer;" onclick='previewZone(${JSON.stringify(z.polygon_points)})'>
                <div>
                    <div style="color:var(--c-text-1); font-weight:600; display:flex; align-items:center; gap:6px;">
                        <span style="width:6px; height:6px; border-radius:50%; background:${z.is_active ? 'var(--c-ok)' : 'var(--c-text-4)'};"></span>
                        ${escHtml(z.name)}
                    </div>
                    <div style="font-size:10px; color:var(--c-text-3); margin-top:2px;">
                        ${(z.polygon_points || []).length} vertices · #${z.id}
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:6px;">
                    <button onclick="event.stopPropagation(); deleteZone(${z.id}, '${escHtml(z.camera_id)}')" class="btn btn-danger btn-sm" style="padding:2px 6px; font-size:9px;">
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = `<div style="text-align:center; padding:16px 0; color:var(--c-alert);">Error: ${e.message}</div>`;
    }
}

function previewZone(points) {
    if (points && points.length) {
        redrawZoneCanvas(points);
        showToast('Highlighting zone coordinates on canvas', 'blue');
    }
}

async function deleteZone(id, camId) {
    try {
        await fetch(`${API}/api/zones/${id}`, { method: 'DELETE' });
        showToast(`Zone #${id} removed`, 'emerald');
        loadZones(camId);
        redrawZoneCanvas();
    } catch (e) {
        showToast(`Delete error: ${e.message}`, 'rose');
    }
}


// ── Baseline (Tab 5) ───────────────────────────────────────────────────────
async function loadBaseline(cam) {
    let cameraId = cam || (document.getElementById('baselineCamera').value || '').trim();
    if (!cameraId) {
        cameraId = 'cam_0';
    }
    const input = document.getElementById('baselineCamera');
    if (input) input.value = cameraId;

    const tbody = document.getElementById('baselineTableBody');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-slate-500">Loading baseline models…</td></tr>';
    try {
        const res = await fetch(`${API}/api/baseline/${cameraId}`);
        const data = await res.json();
        const stats = data.stats || [];
        if (!stats.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">No baseline data yet. Click "Seed Demo" for instant demonstration.</td></tr>';
            return;
        }
        tbody.innerHTML = stats.map(s => `
            <tr>
                <td style="color:var(--c-accent); font-weight:700;">${String(s.hour_bucket).padStart(2,'0')}:00</td>
                <td style="color:var(--c-text-2); text-transform:uppercase;">${s.day_type}</td>
                <td style="color:var(--c-text-2);">${s.avg_person_count !== undefined ? Number(s.avg_person_count).toFixed(1) : '—'} <span style="font-size:10px; color:var(--c-text-4);">±${s.stddev_person_count !== undefined ? Number(s.stddev_person_count).toFixed(1) : '0'}</span></td>
                <td style="color:var(--c-text-2);">${s.avg_vehicle_count !== undefined ? Number(s.avg_vehicle_count).toFixed(1) : '—'} <span style="font-size:10px; color:var(--c-text-4);">±${s.stddev_vehicle_count !== undefined ? Number(s.stddev_vehicle_count).toFixed(1) : '0'}</span></td>
                <td style="color:var(--c-text-2);">${s.typical_dwell_time_seconds !== undefined ? Number(s.typical_dwell_time_seconds).toFixed(0) : '—'}s</td>
                <td style="color:var(--c-text-2);">${s.typical_zone_entries_per_hour !== undefined ? Number(s.typical_zone_entries_per_hour).toFixed(1) : '—'}</td>
                <td style="color:var(--c-text-3);">${s.sample_count ?? 0}</td>
                <td style="${s.dismissed_alert_count > 0 ? 'color:var(--c-warn); font-weight:700;' : 'color:var(--c-text-4);'}">${s.dismissed_alert_count ?? 0}</td>
            </tr>`).join('');

        if (data.recalibration && data.recalibration.total_dismissed > 0) {
            const rsum = document.getElementById('recalibrationSummary');
            const rcont = document.getElementById('recalibrationContent');
            if (rsum && rcont) {
                rsum.classList.remove('hidden');
                rcont.innerHTML = `
                    <div>Total operator dismissals logged: <strong style="color:var(--c-text-1);">${data.recalibration.total_dismissed}</strong></div>
                    <div>Rows auto-widening tolerance: <strong style="color:var(--c-accent);">${data.recalibration.rows_needing_recalibration}</strong></div>
                    <div style="font-size:10px; color:var(--c-text-3); margin-top:4px;">When an alert is dismissed at a given hour, the baseline model widens its standard deviation tolerance (+20%), reducing false positive rate for that time slot.</div>`;
            }
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--c-alert); font-family:\'JetBrains Mono\',monospace;">${e.message}</td></tr>`;
    }
}

async function seedBaseline() {
    const cameraId = (document.getElementById('baselineCamera').value || 'cam_0').trim();
    try {
        await fetch(`${API}/api/baseline/${cameraId}/seed`, { method: 'POST' });
        showToast('✅ Baseline seeded with 48 historical time buckets', 'emerald');
        document.getElementById('baselineCamera').value = cameraId;
        loadBaseline(cameraId);
    } catch (e) {
        showToast(`Error: ${e.message}`, 'rose');
    }
}

// ── AI Assistant (Tab 6) ───────────────────────────────────────────────────
async function sendQuery() {
    const input = document.getElementById('assistantInput');
    const q = input.value.trim();
    if (!q) return;
    input.value = '';

    const chat = document.getElementById('chatMessages');
    chat.insertAdjacentHTML('beforeend', `
        <div class="flex gap-3 justify-end">
            <div class="bg-slate-700 text-slate-100 rounded-lg px-3.5 py-2.5 max-w-lg text-xs font-sans shadow-sm border border-slate-600">
                ${escHtml(q)}
            </div>
        </div>`);
    chat.scrollTop = chat.scrollHeight;

    const botId = 'bot-' + Date.now();
    chat.insertAdjacentHTML('beforeend', `
        <div id="${botId}" class="flex gap-3">
            <div class="w-7 h-7 rounded-md bg-ops-750 border border-slate-700 flex items-center justify-center flex-shrink-0 text-slate-300">
                <i class="fa-solid fa-robot text-xs"></i>
            </div>
            <div class="bg-ops-800 rounded-lg px-3.5 py-2.5 text-slate-300 max-w-lg text-xs font-sans border border-slate-700/60">
                <i class="fa-solid fa-circle-notch animate-spin text-slate-400 mr-1.5"></i> Analyzing telemetry records…
            </div>
        </div>`);
    chat.scrollTop = chat.scrollHeight;

    try {
        const res = await fetch(`${API}/api/assistant/query`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: q })
        });
        const data = await res.json();
        const botEl = document.getElementById(botId);
        if (botEl) {
            const answerText = data.answer || data.detail || data.message || "Intelligence query produced no response.";
            const sourcesHtml = (data.sources || []).length
                ? `<div class="mt-2 pt-2 border-t border-slate-700/60 text-[11px] text-slate-400 font-mono">
                    <span class="font-semibold text-slate-300">Sources:</span>
                    ${data.sources.slice(0, 3).map(s => `<div class="truncate">• [${s.type}] ${s.camera || ''} ${formatTs(s.timestamp)} — ${escHtml(s.label || '')}</div>`).join('')}
                   </div>`
                : '';
            const groundedBadge = data.grounded
                ? `<span class="inline-block mt-1.5 text-[10px] text-emerald-400 font-mono">🛡️ Grounded strictly to event database</span>`
                : `<span class="inline-block mt-1.5 text-[10px] text-amber-400 font-mono">⚠️ Deterministic Database Response</span>`;
            botEl.querySelector('div:last-child').innerHTML = `
                <div class="leading-relaxed">${markedLite(answerText)}</div>
                ${sourcesHtml}
                ${groundedBadge}`;
        }
    } catch (e) {
        const botEl = document.getElementById(botId);
        if (botEl) botEl.querySelector('div:last-child').innerHTML = `<span class="text-rose-400">Error: ${escHtml(e.message)}</span>`;
    }
    chat.scrollTop = chat.scrollHeight;
}

function markedLite(text) {
    if (!text) return '';
    return escHtml(text)
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/^[\*\-]\s+(.*)$/gm, '• $1')
        .replace(/\n/g, '<br>');
}

async function draftReport(targetId) {
    const alertIdInput = document.getElementById('reportAlertId');
    const alertId = targetId || (alertIdInput ? alertIdInput.value : null);
    if (!alertId) { showToast('Enter an Alert ID', 'amber'); return; }
    if (alertIdInput) alertIdInput.value = alertId;
    const out = document.getElementById('reportOutput');
    if (out) {
        out.classList.remove('hidden');
        out.textContent = 'Generating structured incident narrative via AI…';
    }
    try {
        const res = await fetch(`${API}/api/assistant/report/${alertId}`, { method: 'POST' });
        const data = await res.json();
        const text = data.report_text || data.detail || JSON.stringify(data, null, 2);
        if (out) out.textContent = text;
        showToast(`✅ Report generated for Alert #${alertId}`, 'emerald');
    } catch (e) {
        if (out) out.textContent = `Error: ${e.message}`;
        showToast(`Report error: ${e.message}`, 'rose');
    }
}

async function loadSyncStatus() {
    try {
        const res = await fetch(`${API}/api/sync/status`);
        const data = await res.json();
        document.getElementById('syncMetaOnly').textContent = data.metadata_only ?? '--';
        document.getElementById('syncFullSynced').textContent = data.full_synced ?? '--';
        document.getElementById('syncTotal').textContent = data.total ?? '--';
        document.getElementById('syncQueue').textContent = data.pending_queue ?? '--';
    } catch {}
}

async function togglePoorConnectivity() {
    poorConnectivity = !poorConnectivity;
    const btn = document.getElementById('poorConnBtn');
    if (btn) {
        btn.textContent = poorConnectivity ? '📶 Restore Normal Connection' : '📡 Simulate Poor Connectivity';
        btn.className = poorConnectivity
            ? 'ml-auto px-3 py-1 bg-amber-950/40 hover:bg-amber-950/60 border border-amber-600/40 text-amber-300 rounded-md text-xs font-mono'
            : 'ml-auto px-3 py-1 bg-rose-950/40 hover:bg-rose-950/60 border border-rose-700/40 text-rose-300 rounded-md text-xs font-mono';
    }
    try {
        await fetch(`${API}/api/sync/simulate-poor-connectivity`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: poorConnectivity })
        });
        showToast(poorConnectivity ? '⚠️ Poor connectivity simulated — metadata will queue' : '✅ Normal connectivity restored', poorConnectivity ? 'amber' : 'emerald');
        setTimeout(loadSyncStatus, 1000);
    } catch (e) {
        showToast('Sync layer error', 'rose');
    }
}

// ── Video source switching ─────────────────────────────────────────────────
async function changeVideoSource() {
    const select = document.getElementById('sourceSelect');
    const src = select.value;
    const img = document.getElementById('liveFeedImg');
    const badge = document.getElementById('currentSourceBadge');

    let sourceLabel = 'Sample Video 1 (Zero-Line)';
    let badgeText = 'SRC: SAMPLE VIDEO 1';
    if (src === 'sample_2') {
        sourceLabel = 'Sample Video 2 (Sector B 1080p)';
        badgeText = 'SRC: SAMPLE VIDEO 2 (1080p)';
    } else if (src === 'webcam') {
        sourceLabel = 'Primary Webcam';
        badgeText = 'SRC: WEBCAM (0)';
    }

    showToast(`Switching sensor to ${sourceLabel}...`, 'blue');
    try {
        const res = await fetch(`${API}/api/source`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: src })
        });
        const data = await res.json();
        if (badge) {
            badge.textContent = badgeText;
        }
        if (img) {
            img.src = '/api/video_feed?t=' + Date.now();
        }
        showToast(`✅ Video sensor switched to ${sourceLabel}`, 'emerald');
    } catch (e) {
        showToast(`Switch error: ${e.message}`, 'rose');
    }
}

async function toggleStreamPause() {
    const btn = document.getElementById('pauseBtn');
    try {
        const res = await fetch(`${API}/api/control/pause`, { method: 'POST' });
        const data = await res.json();
        const isPaused = Boolean(data.paused);
        if (btn) {
            btn.innerHTML = isPaused
                ? '<i class="fa-solid fa-play"></i> <span>Resume AI Loop</span>'
                : '<i class="fa-solid fa-pause"></i> <span>Pause AI Loop</span>';
        }
        showToast(isPaused ? '⏸️ AI inference loop paused' : '▶️ AI inference loop resumed', isPaused ? 'amber' : 'emerald');
    } catch (e) {
        showToast(`Pause error: ${e.message}`, 'rose');
    }
}

function reloadStreamImage() {
    const img = document.getElementById('liveFeedImg');
    if (img) img.src = '/api/video_feed?t=' + Date.now();
    showToast('Stream connection re-synchronized', 'emerald');
}

function refreshMapIframe() {
    const frame = document.getElementById('mapFrame');
    if (frame) frame.src = '/api/map_file?t=' + Date.now();
    showToast('Tactical map reloaded', 'emerald');
}

// ── Helpers ────────────────────────────────────────────────────────────────
function escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatTs(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString('en-IN', { hour12: false }); }
    catch { return ts; }
}

function showMsg(el, text, color) {
    if (!el) return;
    el.textContent = text;
    const colorMap = { 'emerald': 'var(--c-ok)', 'rose': 'var(--c-alert)', 'amber': 'var(--c-warn)', 'blue': 'var(--c-accent)' };
    el.style.color = colorMap[color] || 'var(--c-text-2)';
    el.style.fontSize = '11px';
    el.style.fontFamily = "'JetBrains Mono', monospace";
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
}

function showToast(msg, color = 'emerald') {
    // Map old color names to semantic types
    const iconMap = {
        emerald: { icon: 'fa-check-circle', css: 'color:var(--c-ok)' },
        rose:    { icon: 'fa-circle-xmark', css: 'color:var(--c-alert)' },
        amber:   { icon: 'fa-triangle-exclamation', css: 'color:var(--c-warn)' },
        blue:    { icon: 'fa-circle-info', css: 'color:var(--c-accent)' },
        red:     { icon: 'fa-circle-xmark', css: 'color:var(--c-alert)' },
    };
    const meta = iconMap[color] || iconMap.emerald;
    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.innerHTML = `<i class="fa-solid ${meta.icon}" style="${meta.css}; font-size:13px; flex-shrink:0;"></i><span>${escHtml(msg)}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(8px)';
        toast.style.transition = 'opacity 0.3s, transform 0.3s';
        setTimeout(() => toast.remove(), 350);
    }, 3200);
}

// ── Periodic refresh ───────────────────────────────────────────────────────
async function refreshStats() {
    try {
        const res = await fetch(`${API}/api/stats`);
        const data = await res.json();
        const totalEl = document.getElementById('statTotalAlerts');
        if (totalEl && data.total_alerts !== undefined) totalEl.textContent = data.total_alerts;
        const activeEl = document.getElementById('statActiveThreats');
        if (activeEl && data.open_alerts !== undefined) activeEl.textContent = data.open_alerts;
    } catch {}
}
setInterval(refreshStats, 15000);
refreshStats();

setInterval(() => {
    const assistantTab = document.getElementById('tab-assistant');
    if (assistantTab && !assistantTab.classList.contains('hidden')) loadSyncStatus();
    const bcTab = document.getElementById('tab-blockchain');
    if (bcTab && !bcTab.classList.contains('hidden')) loadBlockchain();
}, 15000);

// ── Blockchain (Tab 7) ─────────────────────────────────────────────────────
async function loadBlockchain() {
    try {
        const res = await fetch(`${API}/api/blockchain/status`);
        const data = await res.json();
        document.getElementById('chainLength').textContent = data.length ?? '--';
        const intEl = document.getElementById('chainIntegrity');
        if (data.integrity) {
            intEl.textContent = 'Verified Clean';
            intEl.className = 'stat-value';
            intEl.style.color = 'var(--c-ok)';
        } else {
            intEl.textContent = 'Tamper Detected';
            intEl.className = 'stat-value alert';
        }
        document.getElementById('chainAlerts').textContent = (data.record_types || {}).alert ?? 0;
        document.getElementById('chainAudits').textContent = (data.record_types || {}).audit ?? 0;
        document.getElementById('chainLastHash').textContent = data.last_hash || '--';

        const ledgerRes = await fetch(`${API}/api/blockchain/ledger?n=30`);
        const ledgerData = await ledgerRes.json();
        renderBlocks(ledgerData.blocks || []);
    } catch (e) {
        document.getElementById('blockchainLedgerBody').innerHTML =
            `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--c-alert); font-family:\'JetBrains Mono\',monospace;">Error: ${escHtml(e.message)}</td></tr>`;
    }
}

function renderBlocks(blocks) {
    const tbody = document.getElementById('blockchainLedgerBody');
    if (!blocks.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">No blocks yet — commit some alerts first.</td></tr>';
        return;
    }
    const typeBadges = {
        genesis:  'badge-neutral',
        alert:    'badge-alert',
        evidence: 'badge-warn',
        audit:    'badge-ok',
    };
    tbody.innerHTML = blocks.map(b => {
        const cls = typeBadges[b.record_type] || 'badge-neutral';
        const powBadge = b.block_hash.startsWith('000')
            ? `<span style="color:var(--c-ok);" title="Valid Proof-of-Work">⛏️</span>`
            : `<span style="color:var(--c-alert);" title="Invalid Proof-of-Work">⚠️</span>`;
        return `<tr>
            <td style="color:var(--c-text-3); font-weight:700;">${b.index}</td>
            <td><span class="badge ${cls}">${b.record_type}</span></td>
            <td style="color:var(--c-text-2);">${escHtml(b.record_id)}</td>
            <td style="color:var(--c-text-4); font-size:10px;" title="${b.data_hash}">${b.data_hash.substring(0, 16)}…</td>
            <td style="font-size:10px;">
                ${powBadge} <span style="color:var(--c-ok);" title="${b.block_hash}">${b.block_hash.substring(0, 16)}…</span>
            </td>
            <td style="color:var(--c-text-3);">${b.nonce}</td>
            <td style="color:var(--c-text-4);">${formatTs(b.timestamp)}</td>
        </tr>`;
    }).join('');
}

async function verifyChain() {
    try {
        const res = await fetch(`${API}/api/blockchain/verify-chain`);
        const data = await res.json();
        showToast(data.message, data.valid ? 'emerald' : 'rose');
        loadBlockchain();
    } catch (e) {
        showToast(`Error: ${e.message}`, 'rose');
    }
}

async function verifyAlert() {
    const alertId = document.getElementById('verifyAlertId').value;
    if (!alertId) { showToast('Enter an alert ID', 'amber'); return; }
    const result = document.getElementById('verifyResult');
    result.classList.remove('hidden');
    result.innerHTML = '<div class="text-slate-400">Verifying…</div>';
    try {
        const res = await fetch(`${API}/api/blockchain/verify/${alertId}`);
        const data = await res.json();
        const ok = data.verified;
        result.className = `bg-ops-850 p-4 rounded-lg border font-mono text-xs space-y-2 ${ok ? 'border-emerald-700/50' : 'border-rose-700/50'}`;
        result.innerHTML = `
            <div class="text-base font-semibold ${ok ? 'text-emerald-400' : 'text-rose-400'}">${data.message}</div>
            <div class="grid grid-cols-2 gap-2 text-[11px]">
                <div><span class="text-gray-500">Alert ID:</span> <span class="text-gray-300">${data.alert_id}</span></div>
                <div><span class="text-gray-500">Block #:</span> <span class="text-gray-300">${data.block_index ?? 'N/A'}</span></div>
                <div class="col-span-2"><span class="text-gray-500">On-Chain Hash:</span> <span class="${ok ? 'text-emerald-400' : 'text-gray-400'} break-all">${data.on_chain_hash || '—'}</span></div>
                <div class="col-span-2"><span class="text-gray-500">Current Hash:</span> <span class="${ok ? 'text-emerald-400' : 'text-red-400'} break-all">${data.provided_hash || '—'}</span></div>
                ${data.evidence_verification ? `
                    <div class="col-span-2 pt-2 mt-1 border-t border-slate-700/60">
                        <span class="text-gray-400 font-semibold">Snapshot Evidence Verification:</span>
                        <div class="text-[10px] ${data.evidence_verification.verified ? 'text-emerald-400' : 'text-rose-400'} mt-0.5">
                            ${data.evidence_verification.verified ? '✅ Snapshot image matches blockchain fingerprint' : '🚨 Snapshot missing/deleted or modified'}
                        </div>
                    </div>` : ''}
                ${!ok && data.on_chain_hash ? '<div class="col-span-2 text-red-400 font-bold">⚠️ Integrity Mismatch — data or physical snapshot modified after blockchain commitment</div>' : ''}
            </div>`;
    } catch (e) {
        result.innerHTML = `<div class="text-red-400">Error: ${escHtml(e.message)}</div>`;
    }
}

async function simulateTamper() {
    let alertId = (document.getElementById('tamperAlertId').value || document.getElementById('verifyAlertId').value || '').trim();
    if (!alertId) {
        showToast('Please enter an Alert ID to simulate DB tampering', 'amber');
        return;
    }
    const statusEl = document.getElementById('tamperDemoStatus');
    if (statusEl) statusEl.textContent = 'Simulating insider DB alteration…';
    try {
        const res = await fetch(`${API}/api/blockchain/simulate-tamper/${alertId}`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Tamper simulation failed');
        if (statusEl) statusEl.textContent = '⚠️ DB record mutated!';
        showToast('⚠️ DB record tampered! Verifying to prove blockchain detection…', 'amber');
        document.getElementById('verifyAlertId').value = alertId;
        await verifyAlert();
        loadBlockchain();
    } catch (e) {
        if (statusEl) statusEl.textContent = `Error: ${e.message}`;
        showToast(`Tamper simulation error: ${e.message}`, 'rose');
    }
}

async function restoreTamper() {
    let alertId = (document.getElementById('tamperAlertId').value || document.getElementById('verifyAlertId').value || '').trim();
    if (!alertId) {
        showToast('Please enter an Alert ID to restore', 'amber');
        return;
    }
    const statusEl = document.getElementById('tamperDemoStatus');
    if (statusEl) statusEl.textContent = 'Restoring original record from backup…';
    try {
        const res = await fetch(`${API}/api/blockchain/restore-tamper/${alertId}`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Restore failed');
        if (statusEl) statusEl.textContent = '✅ Pristine state restored!';
        showToast('✅ Pristine record restored! Re-verifying ledger…', 'emerald');
        document.getElementById('verifyAlertId').value = alertId;
        await verifyAlert();
        loadBlockchain();
    } catch (e) {
        if (statusEl) statusEl.textContent = `Error: ${e.message}`;
        showToast(`Restore error: ${e.message}`, 'rose');
    }
}


async function commitAllAlerts() {
    try {
        const res = await fetch(`${API}/api/blockchain/commit-all`, { method: 'POST' });
        const data = await res.json();
        showToast(`✅ Committed ${data.committed} alerts | ${data.skipped_already_on_chain} already on chain`, 'emerald');
        setTimeout(loadBlockchain, 500);
    } catch (e) {
        showToast(`Error: ${e.message}`, 'red');
    }
}

async function resetBlockchain() {
    if (!confirm('Are you sure you want to reset the blockchain ledger back to Genesis block? This clears all existing blocks so you can re-mine cleanly.')) return;
    try {
        const res = await fetch(`${API}/api/blockchain/reset`, { method: 'POST' });
        const data = await res.json();
        showToast('✅ Blockchain ledger reset to Genesis Block', 'emerald');
        loadBlockchain();
    } catch (e) {
        showToast(`Reset error: ${e.message}`, 'rose');
    }
}


// ── String Escaping Utility ────────────────────────────────────────────────
function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ── Multi-Camera Network & Edge Deployment ──────────────────────────────────
let currentCameraId = 'cam_0';

async function switchCamera(camId) {
    currentCameraId = camId;
    document.querySelectorAll('.cam-btn, .cam-switch-btn, .camera-switch-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById('camBtn-' + camId);
    if (activeBtn) {
        activeBtn.classList.add('active');
    }

    try {
        const res = await fetch(`${API}/api/cameras/switch`, {
            method: 'POST',
            headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ camera_id: camId })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Switched active C2 optic to ${data.camera.name} (${data.camera.sector})`, 'emerald');
            const stream = document.getElementById('liveFeedImg') || document.getElementById('mainVideoStream');
            if (stream && stream.src && stream.src.includes('/api/video_feed')) {
                stream.src = `${API}/api/video_feed?_t=${Date.now()}`;
            }
            const label = document.getElementById('currentCameraLabel');
            if (label) label.textContent = `${data.camera.name} · ${data.camera.sector}`;
            const activeLabel = document.getElementById('activeCameraLabel');
            if (activeLabel) activeLabel.textContent = `${data.camera.name}`;
            const srcBadge = document.getElementById('currentSourceBadge');
            if (srcBadge) srcBadge.textContent = `CAM: ${camId.toUpperCase()} (${data.camera.sector})`;
            const zoneCam = document.getElementById('zoneCamera');
            if (zoneCam) zoneCam.value = camId;
            const baseCam = document.getElementById('baselineCamera');
            if (baseCam) baseCam.value = camId;

            // Sync sourceSelect dropdown according to camera video
            const sourceSel = document.getElementById('sourceSelect');
            if (sourceSel) {
                if (camId === 'cam_1' || camId === 'cam_3') {
                    sourceSel.value = 'sample_2';
                } else if (camId === 'cam_0' || camId === 'cam_2') {
                    sourceSel.value = 'sample';
                }
            }
        } else {
            showToast(`Camera switch failed: ${data.detail || 'Error'}`, 'rose');
        }
    } catch (e) {
        showToast(`Camera switch error: ${e.message}`, 'rose');
    }
}

// ── Mandatory Defense Authentication & RBAC Gate ────────────────────────────
let currentSessionUser = null;
let currentRole = 'COMMANDER';
let currentCallsign = 'COMMANDER-01';
let selectedRole = 'COMMANDER';
let sessionToken = sessionStorage.getItem('c2_session_token') || localStorage.getItem('c2_session_token') || '';

function getAuthHeaders(headers = {}) {
    const h = { ...headers };
    if (sessionToken) {
        h['Authorization'] = `Bearer ${sessionToken}`;
    }
    return h;
}

async function checkAuthSession() {
    sessionToken = sessionStorage.getItem('c2_session_token') || localStorage.getItem('c2_session_token') || '';
    if (!sessionToken) {
        lockDashboard();
        return;
    }
    try {
        const res = await fetch(`${API}/api/auth/me`, {
            headers: { 'Authorization': `Bearer ${sessionToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            unlockDashboard(data.user);
        } else {
            lockDashboard();
        }
    } catch (e) {
        console.warn('Authentication session check error:', e);
        lockDashboard();
    }
}

function lockDashboard() {
    const overlay = document.getElementById('loginGateOverlay');
    if (overlay) overlay.classList.remove('hidden');
    const img = document.getElementById('liveFeedImg');
    if (img) img.src = '';
    const errBox = document.getElementById('loginErrorAlert');
    if (errBox) errBox.classList.remove('visible');
}

function unlockDashboard(user) {
    currentSessionUser = user;
    currentRole = user.role || 'COMMANDER';
    currentCallsign = user.callsign || 'CDR. Vikram Singh';

    const overlay = document.getElementById('loginGateOverlay');
    if (overlay) overlay.classList.add('hidden');

    const callsignEl = document.getElementById('userCallsignBadge');
    if (callsignEl) callsignEl.textContent = currentCallsign;

    const stationEl = document.getElementById('userStationBadge');
    if (stationEl) stationEl.textContent = user.station || 'Northern Frontier C2 HQ';

    const roleBadge = document.getElementById('userRoleBadge');
    if (roleBadge) {
        roleBadge.textContent = currentRole;
        // Use design system badge classes
        roleBadge.className = '';
        roleBadge.id = 'userRoleBadge';
        roleBadge.style.cssText = '';
    }

    const auditCall = document.getElementById('auditCallsign');
    if (auditCall) auditCall.textContent = currentCallsign;
    const auditClr = document.getElementById('auditClearance');
    if (auditClr) auditClr.textContent = currentRole;

    // Mount real-time video feed
    const img = document.getElementById('liveFeedImg');
    if (img && (!img.src || img.src === window.location.href || !img.src.includes('/api/video_feed'))) {
        img.src = `${API}/api/video_feed?_t=${Date.now()}`;
    }

    // Connect WebSocket & start live HUD telemetry
    connectWS();
    refreshStats();
    loadAuditLogs();
    showToast(`Access Granted: ${currentCallsign} [${currentRole}]`, 'emerald');
}

async function handleLoginSubmit(e) {
    if (e) e.preventDefault();
    const uInput = document.getElementById('loginUsername');
    const pInput = document.getElementById('loginPassword');
    const errBox = document.getElementById('loginErrorAlert');
    const errMsg = document.getElementById('loginErrorMessage');
    const submitBtn = document.getElementById('loginSubmitBtn');

    const username = (uInput?.value || '').trim();
    const password = (pInput?.value || '').trim();

    if (!username || !password) {
        if (errBox && errMsg) {
            errMsg.textContent = 'Enter both callsign and security passkey.';
            errBox.classList.add('visible');
        }
        return;
    }

    if (errBox) errBox.classList.remove('visible');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Authenticating...';
    }

    try {
        const res = await fetch(`${API}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.token) {
            sessionToken = data.token;
            sessionStorage.setItem('c2_session_token', sessionToken);
            localStorage.setItem('c2_session_token', sessionToken);
            unlockDashboard(data.user);
        } else {
            if (errBox && errMsg) {
                errMsg.textContent = data.detail || 'Access Denied: Invalid credentials.';
                errBox.classList.add('visible');
            }
        }
    } catch (err) {
        if (errBox && errMsg) {
            errMsg.textContent = `Authentication error: ${err.message}`;
            errBox.classList.add('visible');
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Authenticate & Enter C2';
        }
    }
}

function quickLogin(role) {
    const uInput = document.getElementById('loginUsername');
    const pInput = document.getElementById('loginPassword');
    if (role === 'commander') {
        if (uInput) uInput.value = 'commander';
        if (pInput) pInput.value = 'cmd@border2024';
    } else if (role === 'operator') {
        if (uInput) uInput.value = 'operator';
        if (pInput) pInput.value = 'op@patrol2024';
    } else if (role === 'analyst') {
        if (uInput) uInput.value = 'analyst';
        if (pInput) pInput.value = 'audit@sih2024';
    }
    handleLoginSubmit();
}

function togglePasswordVisibility() {
    const pInput = document.getElementById('loginPassword');
    const icon = document.getElementById('pwEyeIcon');
    if (!pInput) return;
    if (pInput.type === 'password') {
        pInput.type = 'text';
        if (icon) icon.className = 'fa-solid fa-eye-slash';
    } else {
        pInput.type = 'password';
        if (icon) icon.className = 'fa-solid fa-eye';
    }
}

async function handleLogout() {
    try {
        if (sessionToken) {
            await fetch(`${API}/api/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionToken}`
                }
            }).catch(() => {});
        }
    } catch {}

    sessionToken = '';
    sessionStorage.removeItem('c2_session_token');
    localStorage.removeItem('c2_session_token');
    currentSessionUser = null;

    lockDashboard();
    showToast('Session securely terminated and recorded to audit ledger.', 'amber');
}

function openRoleModal() {
    const modal = document.getElementById('roleModal');
    if (modal) {
        modal.classList.remove('hidden');
        selectRole(currentRole);
        const callsignInput = document.getElementById('roleCallsignInput');
        if (callsignInput) callsignInput.value = currentCallsign;
    }
}

function closeRoleModal() {
    const modal = document.getElementById('roleModal');
    if (modal) modal.classList.add('hidden');
}

function selectRole(role) {
    selectedRole = role;
    ['COMMANDER', 'OPERATOR', 'ANALYST'].forEach(r => {
        const card = document.getElementById('roleCard-' + r);
        if (!card) return;
        const badge = card.querySelector('span');
        if (r === role) {
            card.classList.add('selected');
            if (badge) { badge.textContent = 'SELECTED'; }
        } else {
            card.classList.remove('selected');
            if (badge) { badge.textContent = 'SELECT'; }
        }
    });
}

async function commitRoleSwitch() {
    const callsignInput = document.getElementById('roleCallsignInput');
    const callsign = (callsignInput?.value || currentCallsign).trim();
    try {
        const res = await fetch(`${API}/api/auth/switch-role`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${sessionToken}`
            },
            body: JSON.stringify({ role: selectedRole, callsign: callsign })
        });
        const data = await res.json();
        if (res.ok) {
            currentRole = data.user.role;
            currentCallsign = data.user.callsign;
            sessionToken = data.token;
            sessionStorage.setItem('c2_session_token', sessionToken);
            localStorage.setItem('c2_session_token', sessionToken);

            const badge = document.getElementById('userRoleBadge');
            if (badge) {
                badge.textContent = currentRole;
                badge.className = '';
                badge.id = 'userRoleBadge';
            }
            const callsignBadge = document.getElementById('userCallsignBadge');
            if (callsignBadge) callsignBadge.textContent = currentCallsign;
            const stationEl = document.getElementById('userStationBadge');
            if (stationEl && data.user && data.user.station) stationEl.textContent = data.user.station;

            const auditCall = document.getElementById('auditCallsign');
            if (auditCall) auditCall.textContent = currentCallsign;
            const auditClr = document.getElementById('auditClearance');
            if (auditClr) auditClr.textContent = currentRole;

            showToast(`Clearance switched: ${currentRole} (${currentCallsign})`, 'emerald');
            closeRoleModal();
            loadAuditLogs();
        } else {
            showToast(`Switch failed: ${data.detail || 'Unauthorized'}`, 'rose');
        }
    } catch (e) {
        showToast(`Switch error: ${e.message}`, 'rose');
    }
}

// ── Historical Event Search & Forensic Investigation ────────────────────────
let currentDossierAlertId = null;

async function searchHistoricalIncidents() {
    const query = (document.getElementById('histSearchQuery')?.value || document.getElementById('invQuery')?.value || '').trim();
    const camera_id = document.getElementById('histCameraSelect')?.value || document.getElementById('invSector')?.value || '';
    const alert_type = document.getElementById('histThreatTypeSelect')?.value || document.getElementById('invThreatType')?.value || '';
    const status = document.getElementById('histStatusSelect')?.value || document.getElementById('invStatus')?.value || '';
    const plate_number = (document.getElementById('histPlateSearch')?.value || document.getElementById('invPlateQuery')?.value || '').trim();
    const min_risk = document.getElementById('histMinRiskSlider')?.value || document.getElementById('invMinRisk')?.value || '0';

    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (camera_id && camera_id !== 'all') params.append('camera_id', camera_id);
    if (alert_type && alert_type !== 'all') params.append('alert_type', alert_type);
    if (status && status !== 'all') params.append('status', status);
    if (plate_number) params.append('plate_number', plate_number);
    if (min_risk && min_risk !== '0') params.append('min_risk', min_risk);

    const tbody = document.getElementById('incidentsTableBody') || document.getElementById('investigationTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;"><i class="fa-solid fa-circle-notch fa-spin" style="margin-right:6px;"></i>Querying historical incidents...</td></tr>';

    try {
        const res = await fetch(`${API}/api/investigation/search?${params.toString()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const incidents = Array.isArray(data) ? data : (data.results || []);
        renderInvestigationTable(incidents);
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--c-alert); font-family:\'JetBrains Mono\',monospace;">Search error: ${escHtml(e.message)}</td></tr>`;
    }
}

function renderInvestigationTable(incidents) {
    const tbody = document.getElementById('incidentsTableBody') || document.getElementById('investigationTableBody');
    if (!tbody) return;
    if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:28px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">No historical incidents match the current criteria.</td></tr>';
        return;
    }
    tbody.innerHTML = incidents.map(inc => {
        const risk = Math.round(inc.risk_score || inc.risk_score_value || 0);
        const riskBadge = risk >= 80 ? 'badge-alert' :
                          risk >= 50 ? 'badge-warn' :
                          risk >= 25 ? 'badge-neutral' :
                          'badge-ok';
        
        const plateHtml = inc.plate_number ?
            `<span class="badge ${inc.is_watchlist_match ? 'badge-alert' : 'badge-neutral'}" style="font-weight:700;">${escHtml(inc.plate_number)}</span>` :
            '<span style="color:var(--c-text-4); font-size:11px;">—</span>';

        const st = (inc.status || 'open').toLowerCase();
        const statusBadge = st === 'confirmed' ?
            '<span class="badge badge-ok">CONFIRMED</span>' :
            (st === 'dismissed' ?
                '<span class="badge badge-neutral">DISMISSED</span>' :
                '<span class="badge badge-alert">OPEN</span>');

        const timeStr = inc.timestamp ? new Date(inc.timestamp).toLocaleString('en-IN', { hour12: false }) :
                        (inc.created_at ? new Date(inc.created_at).toLocaleString('en-IN', { hour12: false }) : '—');

        return `
        <tr>
            <td style="font-weight:700; color:var(--c-accent);">#${inc.id}</td>
            <td style="color:var(--c-text-3); white-space:nowrap;">${timeStr}</td>
            <td><span class="badge badge-neutral">${escHtml(inc.camera_id || 'cam_0')}</span></td>
            <td>
                <div style="font-weight:600; color:var(--c-text-1);">${escHtml(inc.alert_type || 'breach')}</div>
                ${inc.message ? `<div style="font-size:10px; color:var(--c-text-4); max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escHtml(inc.message)}">${escHtml(inc.message)}</div>` : ''}
            </td>
            <td>${plateHtml}</td>
            <td><span class="badge ${riskBadge}">${risk} / 100</span></td>
            <td>${statusBadge}</td>
            <td style="text-align:right; white-space:nowrap;">
                <div style="display:inline-flex; gap:5px; align-items:center;">
                    <button onclick="openInvestigationModal(${inc.id})" class="btn btn-sm">
                        <i class="fa-solid fa-file-shield"></i> Dossier
                    </button>
                    <a href="${API}/api/evidence/dossier/${inc.id}/html" target="_blank" class="btn btn-sm">
                        <i class="fa-solid fa-arrow-up-right-from-square"></i> Print
                    </a>
                </div>
            </td>
        </tr>`;
    }).join('');
}

function resetHistoricalFilters() {
    const q = document.getElementById('histSearchQuery'); if (q) q.value = '';
    const cam = document.getElementById('histCameraSelect'); if (cam) cam.value = 'all';
    const threat = document.getElementById('histThreatTypeSelect'); if (threat) threat.value = 'all';
    const status = document.getElementById('histStatusSelect'); if (status) status.value = 'all';
    const plate = document.getElementById('histPlateSearch'); if (plate) plate.value = '';
    const slider = document.getElementById('histMinRiskSlider'); if (slider) slider.value = '0';
    const label = document.getElementById('histRiskScoreLabel'); if (label) label.textContent = '0';
    searchHistoricalIncidents();
}

async function openInvestigationModal(alertId) {
    currentDossierAlertId = alertId;
    const modal = document.getElementById('investigationModal');
    if (!modal) return;
    modal.classList.remove('hidden');

    document.getElementById('invModalAlertId').textContent = `#${alertId}`;
    document.getElementById('invModalTimestamp').textContent = 'Loading forensic records...';
    document.getElementById('invModalReasoningList').innerHTML = '<li>Retrieving explainable threat factors...</li>';

    try {
        const res = await fetch(`${API}/api/evidence/dossier/${alertId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const dossier = await res.json();
        populateDossierModal(dossier);
    } catch (e) {
        showToast(`Error loading dossier: ${e.message}`, 'rose');
    }
}

function populateDossierModal(dossier) {
    document.getElementById('invModalAlertId').textContent = `#${dossier.alert_id}`;
    document.getElementById('invModalTimestamp').textContent = `Timestamp: ${new Date(dossier.timestamp).toLocaleString('en-IN', { hour12: false })}`;
    
    const sevEl = document.getElementById('invModalSeverity');
    const riskEl = document.getElementById('invModalRiskScore');
    const score = Math.round(dossier.risk_score || dossier.risk_score_value || 0);
    riskEl.textContent = `${score}.0 / 100`;

    const tier = dossier.explainability?.priority_tier || (score >= 80 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'GUARDED');
    sevEl.textContent = tier;
    sevEl.className = `stat-value ${tier === 'CRITICAL' ? 'alert' : ''}`;

    document.getElementById('invModalLocation').textContent = `${dossier.camera_id} (${dossier.sector || 'Zero-Line'})`;
    
    const sealEl = document.getElementById('invModalChainSeal');
    if (dossier.blockchain?.block_index !== undefined) {
        sealEl.textContent = `SEALED IN BLOCK #${dossier.blockchain.block_index}`;
        sealEl.style.color = 'var(--c-ok)';
    } else {
        sealEl.textContent = 'PENDING CHAIN BLOCK';
        sealEl.style.color = 'var(--c-warn)';
    }

    const imgEl = document.getElementById('invModalImg');
    if (dossier.snapshot_url) {
        imgEl.src = dossier.snapshot_url;
    } else {
        imgEl.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="250" viewBox="0 0 400 250"><rect fill="%2317191f" width="400" height="250"/><text fill="%236b7585" font-family="sans-serif" font-size="14" x="50%" y="50%" text-anchor="middle">No Sensor Frame Attached</text></svg>';
    }

    const plateTag = document.getElementById('invModalPlateTag');
    if (dossier.vehicle_plate) {
        plateTag.classList.remove('hidden');
        plateTag.innerHTML = `
            <div style="display:flex; align-items:center; justify-content:space-between;">
                <span>Detected Plate: <strong style="color:var(--c-text-1);">${escHtml(dossier.vehicle_plate.plate_number)}</strong> (${escHtml(dossier.vehicle_plate.vehicle_type || 'Vehicle')})</span>
                <span class="badge ${dossier.vehicle_plate.is_watchlist_match ? 'badge-alert' : 'badge-ok'}">
                    ${dossier.vehicle_plate.is_watchlist_match ? '🚨 WATCHLIST HIT' : 'CLEARED'}
                </span>
            </div>
            ${dossier.vehicle_plate.watchlist_reason ? `<div style="color:var(--c-warn); font-size:10px; margin-top:4px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:4px;"></i>${escHtml(dossier.vehicle_plate.watchlist_reason)}</div>` : ''}
        `;
    } else {
        plateTag.classList.add('hidden');
    }

    document.getElementById('invModalTrackId').textContent = dossier.telemetry?.track_id ? `#${dossier.telemetry.track_id}` : '#101';
    document.getElementById('invModalClass').textContent = dossier.alert_type || 'Intruder';
    document.getElementById('invModalViolations').textContent = dossier.telemetry?.intrusion ? 'Virtual Fence Intrusion' : (dossier.telemetry?.loitering ? 'Prolonged Presence (Loitering)' : 'Standard Observation');
    document.getElementById('invModalDwell').textContent = `${dossier.telemetry?.dwell_time ? dossier.telemetry.dwell_time.toFixed(1) : '14.2'} s`;

    const breakdown = dossier.explainability?.breakdown || {};
    document.getElementById('invModalRuleScore').textContent = `+${Math.round(breakdown.rule_score || score)} pts`;
    document.getElementById('invModalAnomalyScore').textContent = `+${Math.round(breakdown.baseline_component || 0)} pts`;
    document.getElementById('invModalFusionBonus').textContent = `+${Math.round(breakdown.fusion_bonus || 0)} pts`;
    document.getElementById('invModalCompositeScore').textContent = `${score}.0 / 100`;

    const rationale = dossier.explainability?.tactical_rationale || dossier.contributing_factors || [
        'Object confirmed via Multi-Object Tracking across consecutive frames.',
        'Boundary violation detected across geofenced perimeter.'
    ];
    const reasonList = document.getElementById('invModalReasoningList');
    reasonList.innerHTML = rationale.map(r => `<li>${escHtml(r)}</li>`).join('');

    document.getElementById('invModalShaHash').textContent = dossier.blockchain?.block_hash || dossier.snapshot_sha256 || 'SHA-256 Digest Pending Chain Commit';
}

function closeInvestigationModal() {
    const modal = document.getElementById('investigationModal');
    if (modal) modal.classList.add('hidden');
}

function printCurrentDossier() {
    if (currentDossierAlertId) {
        window.open(`${API}/api/evidence/dossier/${currentDossierAlertId}/html`, '_blank');
    }
}

function downloadJsonDossier() {
    if (currentDossierAlertId) {
        window.open(`${API}/api/evidence/dossier/${currentDossierAlertId}`, '_blank');
    }
}

// ── Automatic Number Plate Recognition (ANPR) & Watchlist ──────────────────
async function loadAnprData() {
    try {
        const [platesRes, watchlistRes] = await Promise.all([
            fetch(`${API}/api/anpr/plates`),
            fetch(`${API}/api/anpr/watchlist`)
        ]);
        if (platesRes.ok) {
            const rawPlates = await platesRes.json();
            const plates = Array.isArray(rawPlates) ? rawPlates : (rawPlates.plates || []);
            renderAnprLiveTable(plates);
        }
        if (watchlistRes.ok) {
            const rawWl = await watchlistRes.json();
            let watchlist = [];
            if (Array.isArray(rawWl)) {
                watchlist = rawWl;
            } else if (rawWl.watchlist) {
                if (Array.isArray(rawWl.watchlist)) {
                    watchlist = rawWl.watchlist;
                } else if (typeof rawWl.watchlist === 'object') {
                    watchlist = Object.entries(rawWl.watchlist).map(([plate, data]) => ({
                        plate_number: plate,
                        reason: data.reason || 'Flagged by intelligence',
                        threat_level: data.severity || data.threat_level || 'High',
                        flagged_by: data.agency || data.flagged_by || 'Tactical C2'
                    }));
                }
            }
            renderAnprWatchlistTable(watchlist);
        }
    } catch (e) {
        console.error('Failed to load ANPR data:', e);
    }
}

function renderAnprLiveTable(plates) {
    const tbody = document.getElementById('anprPlatesTableBody') || document.getElementById('anprLiveTableBody');
    if (!tbody) return;
    const countBadge = document.getElementById('anprPlateCountBadge');
    if (countBadge) countBadge.textContent = `${(plates || []).length} records`;
    if (!plates || plates.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">No vehicles recognized by optical engine yet.</td></tr>';
        return;
    }
    tbody.innerHTML = plates.map(p => {
        const isMatch = p.is_watchlist_match;
        const matchBadge = isMatch ?
            `<span class="badge badge-alert">🚨 WATCHLIST</span>` :
            `<span class="badge badge-ok">CLEARED</span>`;
        const timeStr = p.timestamp ? new Date(p.timestamp).toLocaleTimeString('en-IN', { hour12: false }) : 'Just now';
        return `
        <tr>
            <td style="font-weight:700; color:var(--c-accent);">${escHtml(p.plate_number)}</td>
            <td>${escHtml(p.vehicle_type || 'Vehicle')}</td>
            <td><span class="badge badge-neutral">${escHtml(p.camera_id || 'cam_0')}</span></td>
            <td>${matchBadge}</td>
            <td style="color:var(--c-text-3);">${timeStr}</td>
        </tr>`;
    }).join('');
}

function renderAnprWatchlistTable(watchlist) {
    const tbody = document.getElementById('anprWatchlistTableBody');
    if (!tbody) return;
    if (!watchlist || watchlist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">Threat watchlist empty.</td></tr>';
        return;
    }
    tbody.innerHTML = watchlist.map(w => {
        const threatCls = (w.threat_level === 'Critical' || w.threat_level === 'CRITICAL') ? 'badge-alert' : 'badge-warn';
        return `
        <tr>
            <td style="font-weight:700; color:var(--c-alert);">${escHtml(w.plate_number)}</td>
            <td style="color:var(--c-text-2);">${escHtml(w.reason || 'Flagged by intelligence')}</td>
            <td><span class="badge ${threatCls}">${escHtml(w.threat_level || 'High')}</span></td>
            <td style="color:var(--c-text-3);">${escHtml(w.flagged_by || 'Border Intelligence')}</td>
        </tr>`;
    }).join('');
}

async function lookupPlateIntelligence() {
    const input = document.getElementById('anprLookupInput') || document.getElementById('anprSearchPlate');
    const plate = (input?.value || '').trim();
    if (!plate) { showToast('Enter a license plate to lookup', 'amber'); return; }
    const resContainer = document.getElementById('anprLookupResult') || document.getElementById('plateIntelResult');
    if (resContainer) {
        resContainer.classList.remove('hidden');
        resContainer.innerHTML = '<span style="color:var(--c-text-3); font-family:\'JetBrains Mono\',monospace;"><i class="fa-solid fa-circle-notch fa-spin" style="margin-right:6px;"></i>Querying border intelligence database...</span>';
    }

    try {
        const res = await fetch(`${API}/api/anpr/lookup/${encodeURIComponent(plate)}`);
        const data = await res.json();
        if (data.found) {
            resContainer.innerHTML = `
                <div style="display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--c-border); padding-bottom:8px; margin-bottom:8px;">
                    <span style="font-size:13px; font-weight:700; color:var(--c-accent);">${escHtml(data.plate_number)}</span>
                    <span class="badge ${data.is_watchlist_match ? 'badge-alert' : 'badge-ok'}">
                        ${data.is_watchlist_match ? '🚨 THREAT WATCHLIST HIT' : 'CLEARED / NO HITS'}
                    </span>
                </div>
                <div style="display:flex; flex-direction:column; gap:4px; font-size:11px; font-family:'JetBrains Mono',monospace; color:var(--c-text-2);">
                    <div><span style="color:var(--c-text-4);">Sightings Recorded:</span> ${data.sightings_count || 1} occurrences</div>
                    <div><span style="color:var(--c-text-4);">Associated Vehicle:</span> ${escHtml(data.vehicle_type || 'Unknown')}</div>
                    ${data.watchlist_reason ? `<div style="color:var(--c-alert);"><span style="color:var(--c-text-4);">Intel Flag:</span> ${escHtml(data.watchlist_reason)}</div>` : ''}
                    ${data.flagged_by ? `<div><span style="color:var(--c-text-4);">Reporting Agency:</span> ${escHtml(data.flagged_by)}</div>` : ''}
                </div>
            `;
        } else {
            resContainer.innerHTML = `
                <div style="color:var(--c-warn); font-weight:600; margin-bottom:4px;">Plate Not in Local Database</div>
                <div style="color:var(--c-text-3); font-size:11px;">Plate <strong style="color:var(--c-text-1);">${escHtml(plate.toUpperCase())}</strong> has no historical surveillance logs and is not currently on the threat watchlist.</div>
            `;
        }
    } catch (e) {
        if (resContainer) resContainer.innerHTML = `<div style="color:var(--c-alert);">Lookup error: ${escHtml(e.message)}</div>`;
    }
}

function openWatchlistModal() {
    const modal = document.getElementById('watchlistModal');
    if (modal) modal.classList.remove('hidden');
}

function closeWatchlistModal() {
    const modal = document.getElementById('watchlistModal');
    if (modal) modal.classList.add('hidden');
}

async function submitWatchlistPlate() {
    const plate = (document.getElementById('wlPlateNumber')?.value || '').trim().toUpperCase();
    const vType = document.getElementById('wlVehicleType')?.value || 'Car';
    const reason = (document.getElementById('wlReason')?.value || '').trim();
    const threatLevel = document.getElementById('wlThreatLevel')?.value || 'High';
    const agency = (document.getElementById('wlAgency')?.value || 'Border Intelligence Branch').trim();

    if (!plate || !reason) {
        showToast('Please enter both plate number and intelligence reason', 'amber');
        return;
    }

    try {
        const res = await fetch(`${API}/api/anpr/watchlist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                plate_number: plate,
                vehicle_type: vType,
                reason: reason,
                severity: threatLevel,
                threat_level: threatLevel,
                agency: agency
            })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Plate ${plate} registered on active threat watchlist!`, 'emerald');
            closeWatchlistModal();
            loadAnprData();
        } else {
            showToast(`Failed: ${data.detail || 'Error'}`, 'rose');
        }
    } catch (e) {
        showToast(`Submission error: ${e.message}`, 'rose');
    }
}

// ── Immutable Audit Trail & RBAC Logs ───────────────────────────────────────
let allAuditLogs = [];

async function loadAuditLogs() {
    const tbody = document.getElementById('auditLogsTableBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;"><i class="fa-solid fa-circle-notch fa-spin" style="margin-right:6px;"></i>Loading audit records...</td></tr>';

    try {
        const res = await fetch(`${API}/api/audit-logs`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        allAuditLogs = Array.isArray(data) ? data : (data.logs || []);
        renderAuditLogsTable(allAuditLogs);
    } catch (e) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--c-alert); font-family:\'JetBrains Mono\',monospace;">Failed to load audit trail: ${escHtml(e.message)}</td></tr>`;
    }
}

function renderAuditLogsTable(logs) {
    const tbody = document.getElementById('auditLogsTableBody');
    if (!tbody) return;
    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--c-text-4); font-family:\'JetBrains Mono\',monospace;">No audit records logged yet.</td></tr>';
        return;
    }
    tbody.innerHTML = logs.map(l => {
        const timeStr = l.timestamp ? new Date(l.timestamp).toLocaleString('en-IN', { hour12: false }) : 'Just now';
        const roleCls = l.role === 'COMMANDER' ? 'badge-accent' :
                        l.role === 'OPERATOR' ? 'badge-warn' : 'badge-neutral';
        return `
        <tr>
            <td style="color:var(--c-text-3); white-space:nowrap;">${timeStr}</td>
            <td style="font-weight:600; color:var(--c-text-1);">${escHtml(l.user_callsign || 'SYSTEM')}</td>
            <td><span class="badge ${roleCls}">${escHtml(l.role || 'OPERATOR')}</span></td>
            <td style="font-weight:600; color:var(--c-ok);">${escHtml(l.action)}</td>
            <td style="color:var(--c-text-2);">${escHtml(l.resource || 'SYSTEM')}</td>
            <td style="color:var(--c-text-4); font-size:10px;">${escHtml(l.ip_address || '127.0.0.1')}</td>
            <td style="color:var(--c-text-3); font-size:11px; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escHtml(l.details || '')}">${escHtml(l.details || '—')}</td>
        </tr>`;
    }).join('');
}

function filterAuditLogs() {
    const q = (document.getElementById('auditFilterQuery')?.value || '').toLowerCase();
    if (!q) {
        renderAuditLogsTable(allAuditLogs);
        return;
    }
    const filtered = allAuditLogs.filter(l =>
        (l.user_callsign && l.user_callsign.toLowerCase().includes(q)) ||
        (l.action && l.action.toLowerCase().includes(q)) ||
        (l.resource && l.resource.toLowerCase().includes(q)) ||
        (l.details && l.details.toLowerCase().includes(q))
    );
    renderAuditLogsTable(filtered);
}

// ── Telemetry & Edge Polling ────────────────────────────────────────────────
async function refreshStats() {
    try {
        const [statsRes, edgeRes] = await Promise.all([
            fetch(`${API}/api/stats`),
            fetch(`${API}/api/edge/telemetry`)
        ]);

        if (statsRes.ok) {
            const data = await statsRes.json();
            
            const fpsEl = document.getElementById('fpsCounter');
            if (fpsEl && typeof data.fps === 'number') {
                fpsEl.textContent = `${data.fps.toFixed(1)} FPS`;
            }

            const activeEl = document.getElementById('statActiveThreats');
            if (activeEl && typeof data.active_threats === 'number') {
                activeEl.textContent = data.active_threats;
            }

            const totalEl = document.getElementById('statTotalAlerts');
            if (totalEl && typeof data.total_alerts === 'number') {
                totalEl.textContent = data.total_alerts;
            }

            const srcBadge = document.getElementById('currentSourceBadge');
            if (srcBadge && data.source) {
                const shortSrc = String(data.source).includes('getty') ? 'SRC: SAMPLE VIDEO' :
                                 String(data.source) === '0' ? 'SRC: WEBCAM (0)' : `SRC: ${data.source}`;
                srcBadge.textContent = shortSrc;
            }

            const badge = document.getElementById('threatBadge');
            const text = document.getElementById('threatStatusText');
            if (badge && text && typeof data.active_threats === 'number') {
                if (data.active_threats === 0) {
                    badge.className = 'px-3 py-1.5 rounded-md text-xs font-semibold tracking-wide uppercase border flex items-center gap-2 bg-emerald-950/40 text-emerald-400 border-emerald-800/40';
                    text.textContent = 'SECTOR CLEAR';
                }
            }
        }

        if (edgeRes.ok) {
            const edge = await edgeRes.json();
            const pill = document.getElementById('edgeComputePill');
            if (pill) {
                pill.textContent = `CPU: ${edge.cpu_percent.toFixed(0)}% | RAM: ${edge.ram_percent.toFixed(0)}%`;
            }
            const edgeNode = document.getElementById('auditEdgeNode');
            if (edgeNode) edgeNode.textContent = `${edge.device} · ${edge.os}`;
        }
    } catch {}
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    checkAuthSession();
    setInterval(() => {
        if (sessionToken) {
            refreshStats();
        }
    }, 1500);
});

