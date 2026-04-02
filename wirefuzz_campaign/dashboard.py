"""Web dashboard for wirefuzz campaign — zero external dependencies.

Runs a threaded HTTP server that serves a single-page app and JSON APIs.
The dashboard reads campaign_state.json on every request so it always
reflects the latest state from the campaign runner.
"""

import base64
import json
import os
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# HTML template (single page app with vanilla JS)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wirefuzz // campaign dashboard</title>
<style>
:root{--bg:#0a0e14;--card:#111820;--border:#1a2332;--text:#c9d1d9;--dim:#5a6a7a;
--green:#00ff88;--red:#ff2255;--yellow:#ffcc00;--blue:#00aaff;--cyan:#00ffcc;--orange:#ff8844;
--glow-cyan:0 0 10px rgba(0,255,204,0.3);--glow-red:0 0 10px rgba(255,34,85,0.3);--glow-green:0 0 10px rgba(0,255,136,0.3)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'SF Mono','Fira Code','Cascadia Code','JetBrains Mono',Consolas,monospace;
background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;
background-image:radial-gradient(ellipse at 50% 0%,rgba(0,255,204,0.03) 0%,transparent 60%)}
body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;
pointer-events:none;z-index:9999;
background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px)}
a{color:var(--blue);text-decoration:none}
.container{max-width:1600px;margin:0 auto;padding:16px}
h1{font-size:22px;color:var(--cyan);margin-bottom:4px;text-shadow:var(--glow-cyan);letter-spacing:2px}
.subtitle{color:var(--dim);font-size:12px;margin-bottom:16px;letter-spacing:0.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center;
transition:border-color 0.3s,box-shadow 0.3s}
.stat-card:hover{border-color:var(--cyan);box-shadow:var(--glow-cyan)}
.stat-card .value{font-size:26px;font-weight:bold;margin:4px 0}
.stat-card .label{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:1.5px}
.stat-card.crashes .value{color:var(--red);text-shadow:var(--glow-red)}
.stat-card.done .value{color:var(--green);text-shadow:var(--glow-green)}
.stat-card.running .value{color:var(--cyan);text-shadow:var(--glow-cyan)}
.stat-card.seeded .value{color:var(--yellow)}
.stat-card.progress .value{color:var(--blue)}
.section{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:14px}
.section h2{font-size:13px;color:var(--cyan);margin-bottom:12px;border-bottom:1px solid var(--border);
padding-bottom:8px;text-transform:uppercase;letter-spacing:1.5px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--dim);font-weight:normal;text-transform:uppercase;letter-spacing:0.5px;
padding:8px 10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--card);cursor:pointer;user-select:none}
th:hover{color:var(--cyan)}
th.sorted-asc::after{content:" \u25b2";color:var(--cyan)}
th.sorted-desc::after{content:" \u25bc";color:var(--cyan)}
td{padding:6px 10px;border-bottom:1px solid rgba(26,35,50,0.6)}
tr:hover td{background:rgba(0,255,204,0.03)}
.status{display:inline-block;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:0.5px}
.status.done{background:rgba(0,255,136,0.1);color:var(--green);border:1px solid rgba(0,255,136,0.2)}
.status.running{background:rgba(0,255,204,0.1);color:var(--cyan);border:1px solid rgba(0,255,204,0.3);animation:pulse 1.5s infinite}
.status.seeded{background:rgba(255,204,0,0.08);color:var(--yellow);border:1px solid rgba(255,204,0,0.2)}
.status.pending{background:rgba(90,106,122,0.1);color:var(--dim);border:1px solid rgba(90,106,122,0.2)}
.status.failed{background:rgba(255,34,85,0.1);color:var(--red);border:1px solid rgba(255,34,85,0.2)}
.status.skipped{background:rgba(90,106,122,0.05);color:var(--dim);border:1px solid rgba(90,106,122,0.1)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.progress-bar{width:100%;height:24px;background:var(--border);border-radius:4px;overflow:hidden;margin:8px 0;
border:1px solid rgba(0,255,204,0.1)}
.progress-fill{height:100%;border-radius:3px;transition:width 0.5s ease;display:flex;align-items:center;
justify-content:center;font-size:11px;font-weight:bold;color:#fff;letter-spacing:1px}
.config-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:4px 24px}
.config-item{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(26,35,50,0.4)}
.config-item .key{color:var(--dim);font-size:11px}
.config-item .val{color:var(--cyan);font-weight:bold;font-size:11px}
.filters{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filters input,.filters select{background:var(--bg);border:1px solid var(--border);color:var(--text);
padding:6px 10px;border-radius:4px;font-family:inherit;font-size:12px;min-height:36px}
.filters input:focus,.filters select:focus{outline:none;border-color:var(--cyan);box-shadow:var(--glow-cyan)}
.log-box{background:#060a0f;border:1px solid var(--border);border-radius:4px;padding:10px;max-height:400px;
overflow-y:auto;font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--dim)}
.crash-item{padding:10px;margin-bottom:6px;background:rgba(255,34,85,0.03);border:1px solid rgba(255,34,85,0.15);border-radius:4px}
.crash-item .encap{color:var(--red);font-weight:bold;text-shadow:var(--glow-red)}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;gap:12px}
.refresh-info{color:var(--dim);font-size:11px;white-space:nowrap}
.badge{display:inline-block;min-width:20px;text-align:center;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:bold}
.badge.red{background:rgba(255,34,85,0.15);color:var(--red)}
.badge.green{background:rgba(0,255,136,0.15);color:var(--green)}
.scan-bar{display:flex;height:20px;border-radius:4px;overflow:hidden;background:var(--border)}
.scan-segment{height:100%;min-width:2px;transition:width 0.3s}
.tooltip{position:relative}
.tooltip:hover::after{content:attr(data-tip);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);
background:#000;color:var(--cyan);padding:4px 10px;border-radius:4px;font-size:11px;white-space:nowrap;z-index:10;
border:1px solid var(--border)}
/* Mobile responsive */
@media(max-width:768px){
.container{padding:10px}
h1{font-size:16px}
.topbar{flex-direction:column}
.grid{grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}
.stat-card{padding:10px}
.stat-card .value{font-size:20px}
.stat-card .label{font-size:9px}
.section{padding:10px}
table{font-size:11px}
th,td{padding:4px 6px}
.filters{gap:6px}
.filters input,.filters select{padding:6px;font-size:11px;flex:1;min-width:100px}
.config-grid{grid-template-columns:1fr}
.log-box{max-height:250px;font-size:10px}
.progress-bar{height:20px}
}
@media(max-width:480px){
.grid{grid-template-columns:repeat(2,1fr)}
.stat-card .value{font-size:18px}
.section h2{font-size:12px}
table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
}
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div>
      <h1>// wirefuzz campaign</h1>
      <div class="subtitle" id="subtitle">loading...</div>
    </div>
    <div class="refresh-info">Auto-refresh: <select id="refreshInterval" onchange="setRefresh()">
      <option value="10">10s</option><option value="30">30s</option><option value="60">60s</option><option value="120" selected>120s</option><option value="0">off</option>
    </select> | Last: <span id="lastUpdate">-</span></div>
  </div>

  <!-- Progress bar -->
  <div class="progress-bar"><div class="progress-fill" id="progressBar" style="width:0%;background:var(--green)">0%</div></div>

  <!-- Stat cards -->
  <div class="grid" id="statCards"></div>

  <!-- Config -->
  <div class="section" id="configSection" style="display:none">
    <h2>Campaign Configuration</h2>
    <div class="config-grid" id="configGrid"></div>
  </div>

  <!-- Scan distribution -->
  <div class="section" id="scanSection" style="display:none">
    <h2>Encap Distribution (from scan)</h2>
    <div class="scan-bar" id="scanBar"></div>
    <div id="scanLegend" style="margin-top:8px;font-size:11px;color:var(--dim)"></div>
  </div>

  <!-- Encap table -->
  <div class="section">
    <h2>Encapsulation Types (<span id="encapCount">0</span>)</h2>
    <div class="filters">
      <input type="text" id="searchBox" placeholder="Search by name or ID..." oninput="renderTable()">
      <select id="statusFilter" onchange="renderTable()">
        <option value="">All statuses</option>
        <option value="running">Running</option>
        <option value="done">Done</option>
        <option value="failed">Failed</option>
        <option value="seeded">Seeded</option>
        <option value="pending">Pending</option>
        <option value="skipped">Skipped</option>
      </select>
      <select id="crashFilter" onchange="renderTable()">
        <option value="">All</option>
        <option value="crashes">With crashes only</option>
        <option value="seeds">With seeds only</option>
      </select>
    </div>
    <div style="max-height:600px;overflow-y:auto">
      <table id="encapTable">
        <thead><tr>
          <th data-col="encap_id" data-type="num">ID</th>
          <th data-col="encap_name">Name</th>
          <th data-col="status">Status</th>
          <th data-col="seed_count" data-type="num">Seeds</th>
          <th data-col="corpus_count" data-type="num">Corpus</th>
          <th data-col="crashes" data-type="num">Crashes</th>
          <th data-col="total_execs" data-type="num">Execs</th>
          <th data-col="coverage" data-type="num">Coverage</th>
          <th data-col="elapsed_secs" data-type="num">Elapsed</th>
          <th data-col="error">Error</th>
        </tr></thead>
        <tbody id="encapBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Crashes -->
  <div class="section" id="crashSection" style="display:none">
    <h2>Crashes (<span id="crashCount">0</span>)</h2>
    <div id="crashList"></div>
  </div>

  <!-- Log tail -->
  <div class="section">
    <h2>Campaign Log (last 200 lines)</h2>
    <div class="log-box" id="logBox">loading...</div>
  </div>
</div>

<script>
let state = null;
let logText = '';
let sortCol = 'encap_id';
let sortDir = 'asc';
let refreshTimer = null;

function setRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  const secs = parseInt(document.getElementById('refreshInterval').value);
  if (secs > 0) refreshTimer = setInterval(fetchAll, secs * 1000);
}

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.json();
}

async function fetchAll() {
  try {
    const [s, l] = await Promise.all([
      fetchJSON('/api/status'),
      fetchJSON('/api/log'),
    ]);
    if (s) { state = s; render(); }
    if (l) { logText = l.log; renderLog(); }
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
  } catch(e) { console.error(e); }
}

function render() {
  if (!state) return;
  renderSubtitle();
  renderProgress();
  renderCards();
  renderConfig();
  renderScan();
  renderTable();
  renderCrashes();
}

function renderSubtitle() {
  const s = state;
  document.getElementById('subtitle').textContent =
    `Wireshark ${s.ws_version} | ${s.workers} workers | ${s.duration}/encap | created ${(s.created||'').slice(0,19)}`;
}

function renderProgress() {
  const enc = Object.values(state.encaps || {});
  const total = enc.length || 1;
  const done = enc.filter(e => ['done','failed','skipped'].includes(e.status)).length;
  const pct = Math.round(100 * done / total);
  const bar = document.getElementById('progressBar');
  bar.style.width = pct + '%';
  bar.textContent = `${done}/${total} (${pct}%)`;
  const running = enc.find(e => e.status === 'running');
  if (running) bar.style.background = `linear-gradient(90deg, var(--green) ${pct}%, var(--cyan) ${pct}%)`;
  else bar.style.background = pct === 100 ? 'var(--green)' : 'var(--blue)';
}

function renderCards() {
  const enc = Object.values(state.encaps || {});
  const counts = {done:0, running:0, failed:0, seeded:0, pending:0, skipped:0};
  let totalCrashes = 0, totalExecs = 0, totalCorpus = 0;
  enc.forEach(e => {
    counts[e.status] = (counts[e.status]||0) + 1;
    totalCrashes += e.crashes || 0;
    totalExecs += e.total_execs || 0;
    totalCorpus += e.corpus_count || 0;
  });
  const running = enc.find(e => e.status === 'running');
  const cards = [
    {label:'Done', value:counts.done, cls:'done'},
    {label:'Running', value:running ? running.encap_name : (counts.running||'-'), cls:'running'},
    {label:'Seeded', value:counts.seeded, cls:'seeded'},
    {label:'Pending', value:counts.pending, cls:''},
    {label:'Failed', value:counts.failed, cls:'crashes'},
    {label:'Total Crashes', value:totalCrashes, cls:'crashes'},
    {label:'Total Execs', value:totalExecs.toLocaleString(), cls:'progress'},
    {label:'Total Corpus', value:totalCorpus.toLocaleString(), cls:''},
    {label:'Scanned Pcaps', value:(state.pcap_count||0).toLocaleString(), cls:''},
    {label:'Packets Scanned', value:(state.total_packets_scanned||0).toLocaleString(), cls:''},
  ];
  document.getElementById('statCards').innerHTML = cards.map(c =>
    `<div class="stat-card ${c.cls}"><div class="label">${c.label}</div><div class="value">${c.value}</div></div>`
  ).join('');
}

function renderConfig() {
  const s = state;
  const items = [
    ['Wireshark Version', s.ws_version],
    ['Workers', s.workers],
    ['Duration/Encap', s.duration],
    ['Max Input Length', s.max_len + ' bytes'],
    ['Timeout/Input', s.timeout_ms + ' ms'],
    ['RSS Limit', s.rss_limit_mb + ' MB'],
    ['Max Scan Packets', (s.max_scan_packets||0).toLocaleString()],
    ['Max Extract Packets', (s.max_extract_packets||0).toLocaleString()],
    ['PCAP Source', s.pcap_dir || '(none)'],
    ['Campaign Dir', s.campaign_dir],
  ];
  document.getElementById('configGrid').innerHTML = items.map(([k,v]) =>
    `<div class="config-item"><span class="key">${k}</span><span class="val">${v}</span></div>`
  ).join('');
  document.getElementById('configSection').style.display = '';
}

const COLORS = ['#58a6ff','#3fb950','#f85149','#d29922','#f0883e','#a371f7','#39d2c0','#db61a2','#79c0ff','#7ee787','#ffa657','#d2a8ff'];
function renderScan() {
  const scan = state.encap_scan || {};
  const entries = Object.entries(scan).sort((a,b) => b[1]-a[1]);
  if (!entries.length) return;
  document.getElementById('scanSection').style.display = '';
  const total = entries.reduce((s,e) => s+e[1], 0);
  let html = '', legend = '';
  entries.slice(0, 12).forEach(([id, count], i) => {
    const pct = (100*count/total).toFixed(1);
    const col = COLORS[i % COLORS.length];
    html += `<div class="scan-segment" style="width:${pct}%;background:${col}" title="WTAP ${id}: ${count} (${pct}%)"></div>`;
    legend += `<span style="color:${col}">\u25a0</span> ${id} (${pct}%) `;
  });
  if (entries.length > 12) legend += `... +${entries.length-12} more`;
  document.getElementById('scanBar').innerHTML = html;
  document.getElementById('scanLegend').innerHTML = legend;
}

function renderTable() {
  const enc = Object.values(state.encaps || {});
  const search = document.getElementById('searchBox').value.toLowerCase();
  const statusF = document.getElementById('statusFilter').value;
  const crashF = document.getElementById('crashFilter').value;

  let rows = enc.filter(e => {
    if (search && !e.encap_name.toLowerCase().includes(search) && !String(e.encap_id).includes(search)) return false;
    if (statusF && e.status !== statusF) return false;
    if (crashF === 'crashes' && !(e.crashes > 0)) return false;
    if (crashF === 'seeds' && !(e.seed_count > 0)) return false;
    return true;
  });

  rows.sort((a,b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (typeof va === 'number' && typeof vb === 'number') return sortDir === 'asc' ? va-vb : vb-va;
    va = String(va||''); vb = String(vb||'');
    return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
  });

  document.getElementById('encapCount').textContent = rows.length;

  // Update sort indicators
  document.querySelectorAll('#encapTable th').forEach(th => {
    th.classList.remove('sorted-asc','sorted-desc');
    if (th.dataset.col === sortCol) th.classList.add('sorted-' + sortDir);
  });

  document.getElementById('encapBody').innerHTML = rows.map(e => {
    const elapsed = e.elapsed_secs > 0 ? formatElapsed(e.elapsed_secs) : '-';
    const crashBadge = e.crashes > 0 ? `<span class="badge red">${e.crashes}</span>` : '-';
    const errText = e.error ? `<span title="${esc(e.error)}">${esc(e.error.slice(0,40))}...</span>` : '';
    return `<tr>
      <td>${e.encap_id}</td>
      <td><strong>${esc(e.encap_name)}</strong></td>
      <td><span class="status ${e.status}">${e.status}</span></td>
      <td>${e.seed_count > 0 ? e.seed_count.toLocaleString() : '-'}</td>
      <td>${e.corpus_count > 0 ? e.corpus_count.toLocaleString() : '-'}</td>
      <td>${crashBadge}</td>
      <td>${e.total_execs > 0 ? e.total_execs.toLocaleString() : '-'}</td>
      <td>${e.coverage > 0 ? e.coverage.toLocaleString() : '-'}</td>
      <td>${elapsed}</td>
      <td>${errText}</td>
    </tr>`;
  }).join('');
}

function renderCrashes() {
  const enc = Object.values(state.encaps || {}).filter(e => e.crashes > 0);
  enc.sort((a,b) => b.crashes - a.crashes);
  document.getElementById('crashCount').textContent = enc.reduce((s,e) => s+e.crashes, 0);
  if (!enc.length) { document.getElementById('crashSection').style.display = 'none'; return; }
  document.getElementById('crashSection').style.display = '';
  document.getElementById('crashList').innerHTML = enc.map(e =>
    `<div class="crash-item"><span class="encap">${esc(e.encap_name)} (WTAP ${e.encap_id})</span> — <span class="badge red">${e.crashes} crash(es)</span><br><span style="color:var(--dim);font-size:11px">${esc(e.run_dir)}</span></div>`
  ).join('');
}

function renderLog() {
  const box = document.getElementById('logBox');
  box.textContent = logText;
  box.scrollTop = box.scrollHeight;
}

function formatElapsed(secs) {
  if (secs < 60) return secs + 's';
  const m = Math.floor(secs/60), s = secs%60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m/60);
  return `${h}h ${m%60}m`;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s||''; return d.innerHTML; }

// Column sort
document.querySelectorAll('#encapTable th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortCol = col; sortDir = th.dataset.type === 'num' ? 'desc' : 'asc'; }
    renderTable();
  });
});

// Init
setRefresh();
fetchAll();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard HTML and JSON API endpoints."""

    campaign_dir: Path = None
    password: str = ""

    def log_message(self, fmt, *args):
        # Suppress default access log to keep terminal clean
        pass

    def _check_auth(self) -> bool:
        if not self.password:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self._send_auth_required()
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            _, pw = decoded.split(":", 1)
            if pw == self.password:
                return True
        except Exception:
            pass
        self._send_auth_required()
        return False

    def _send_auth_required(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="wirefuzz"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Authentication required")

    def _send_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _load_state(self) -> Optional[dict]:
        state_path = self.campaign_dir / "campaign_state.json"
        if not state_path.exists():
            return None
        try:
            return json.loads(state_path.read_text())
        except Exception:
            return None

    def do_GET(self):
        if not self._check_auth():
            return

        path = self.path.split("?")[0]

        if path == "/":
            self._send_html(DASHBOARD_HTML)

        elif path == "/api/status":
            state = self._load_state()
            if state:
                self._send_json(state)
            else:
                self._send_json({"error": "no state file found"})

        elif path == "/api/log":
            log_path = self.campaign_dir / "campaign.log"
            lines = []
            if log_path.exists():
                try:
                    text = log_path.read_text(errors="replace")
                    lines = text.splitlines()[-200:]
                except Exception:
                    pass
            self._send_json({"log": "\n".join(lines)})

        elif path.startswith("/api/encap/"):
            try:
                encap_id = path.split("/")[-1]
                state = self._load_state()
                if state and encap_id in state.get("encaps", {}):
                    self._send_json(state["encaps"][encap_id])
                else:
                    self._send_json({"error": "not found"})
            except Exception:
                self._send_json({"error": "invalid id"})

        elif path == "/api/crashes":
            state = self._load_state()
            crashes = []
            if state:
                for eid, ed in state.get("encaps", {}).items():
                    if ed.get("crashes", 0) > 0:
                        crashes.append(ed)
            crashes.sort(key=lambda x: -x.get("crashes", 0))
            self._send_json({"crashes": crashes, "total": sum(c.get("crashes", 0) for c in crashes)})

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not found")


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
def start_dashboard(
    campaign_dir: Path,
    port: int = 56789,
    password: str = "helloworld",
    host: str = "0.0.0.0",
) -> threading.Thread:
    """Start the dashboard HTTP server in a daemon thread.

    Returns the thread (already started). The server runs until the
    process exits.
    """
    # Configure handler class attributes
    handler = type("Handler", (DashboardHandler,), {
        "campaign_dir": campaign_dir,
        "password": password,
    })

    server = HTTPServer((host, port), handler)
    server.daemon_threads = True

    thread = threading.Thread(
        target=server.serve_forever,
        name="wirefuzz-dashboard",
        daemon=True,
    )
    thread.start()
    return thread
