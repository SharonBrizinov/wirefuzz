#!/usr/bin/env python3
"""wirefuzz_campaign.py — Automated full-encap fuzzing campaign.

Iterates over every WTAP encapsulation type (1-227), fuzzes each for a
configurable duration with configurable parallelism, and tracks progress
in a persistent state file so the campaign can be resumed after any
interruption.  Includes a built-in web dashboard for live monitoring.

Usage:
    python wirefuzz_campaign.py /path/to/pcaps -V master
    python wirefuzz_campaign.py /path/to/pcaps -V v4.6.4 --workers 60 --duration 60m
    python wirefuzz_campaign.py /path/to/pcaps --resume  # continue where we left off

Before fuzzing begins, all pcaps are scanned and a state file is written
that records which encap types have seed packets available.  Encap types
with matching seeds are fuzzed first, then the rest are fuzzed with an
empty (synthetic) corpus.
"""

import argparse
import base64
import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Rich console (optional graceful fallback)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ---------------------------------------------------------------------------
# wirefuzz imports
# ---------------------------------------------------------------------------
from wirefuzz.config import CONFIG
from wirefuzz.corpus import (
    find_pcap_files,
    probe_encaps,
    extract_by_encap,
    CorpusStats,
)
from wirefuzz.docker import build_image, check_docker, image_exists
from wirefuzz.encaps import ENCAP_REGISTRY, EncapType, get_encap
from wirefuzz.fuzzer import start_fuzz_session, FuzzSession

# ===========================================================================
# Dashboard — zero-dependency web UI (HTML SPA + JSON API)
# ===========================================================================
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

  <div class="progress-bar"><div class="progress-fill" id="progressBar" style="width:0%;background:var(--green)">0%</div></div>

  <div class="grid" id="statCards"></div>

  <div class="section" id="configSection" style="display:none">
    <h2>Campaign Configuration</h2>
    <div class="config-grid" id="configGrid"></div>
  </div>

  <div class="section" id="scanSection" style="display:none">
    <h2>Encap Distribution (from scan)</h2>
    <div class="scan-bar" id="scanBar"></div>
    <div id="scanLegend" style="margin-top:8px;font-size:11px;color:var(--dim)"></div>
  </div>

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
        <option value="crashes">With crashes</option>
        <option value="timeouts">With timeouts</option>
        <option value="ooms">With OOMs</option>
        <option value="any_issue">Any crash/TO/OOM</option>
        <option value="seeds">With seeds</option>
      </select>
    </div>
    <div style="max-height:600px;overflow-y:auto">
      <table id="encapTable">
        <thead><tr>
          <th data-col="encap_id" data-type="num">ID</th>
          <th data-col="encap_name">Name</th>
          <th data-col="status">Status</th>
          <th data-col="seed_count" data-type="num">Scan</th>
          <th data-col="seeds_extracted" data-type="num">Extracted</th>
          <th data-col="seeds_minimized" data-type="num">Minimized</th>
          <th data-col="corpus_count" data-type="num">Corpus</th>
          <th data-col="crashes" data-type="num">Crashes</th>
          <th data-col="timeouts" data-type="num">Timeout</th>
          <th data-col="ooms" data-type="num">OOM</th>
          <th data-col="total_execs" data-type="num">Execs</th>
          <th data-col="coverage" data-type="num">Cov</th>
          <th data-col="elapsed_secs" data-type="num">Elapsed</th>
        </tr></thead>
        <tbody id="encapBody"></tbody>
      </table>
    </div>
  </div>

  <div class="section" id="crashSection" style="display:none">
    <h2>Crashes (<span id="crashCount">0</span>)</h2>
    <div id="crashList"></div>
  </div>

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
  let totalCrashes = 0, totalTimeouts = 0, totalOoms = 0, totalExecs = 0, totalCorpus = 0;
  enc.forEach(e => {
    counts[e.status] = (counts[e.status]||0) + 1;
    totalCrashes += e.crashes || 0;
    totalTimeouts += e.timeouts || 0;
    totalOoms += e.ooms || 0;
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
    {label:'Crashes', value:totalCrashes, cls:'crashes'},
    {label:'Timeouts', value:totalTimeouts, cls:'crashes'},
    {label:'OOMs', value:totalOoms, cls:'crashes'},
    {label:'Total Execs', value:totalExecs.toLocaleString(), cls:'progress'},
    {label:'Total Corpus', value:totalCorpus.toLocaleString(), cls:''},
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
    if (crashF === 'timeouts' && !(e.timeouts > 0)) return false;
    if (crashF === 'ooms' && !(e.ooms > 0)) return false;
    if (crashF === 'any_issue' && !((e.crashes||0)+(e.timeouts||0)+(e.ooms||0) > 0)) return false;
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

  document.querySelectorAll('#encapTable th').forEach(th => {
    th.classList.remove('sorted-asc','sorted-desc');
    if (th.dataset.col === sortCol) th.classList.add('sorted-' + sortDir);
  });

  const now = Date.now();
  document.getElementById('encapBody').innerHTML = rows.map(e => {
    let elapsed = '-';
    if (e.status === 'running' && e.started_at) {
      const startMs = new Date(e.started_at).getTime();
      if (startMs > 0) elapsed = formatElapsed(Math.floor((now - startMs) / 1000));
    } else if (e.elapsed_secs > 0) {
      elapsed = formatElapsed(e.elapsed_secs);
    }
    const crashBadge = e.crashes > 0 ? `<span class="badge red">${e.crashes}</span>` : '-';
    const toBadge = e.timeouts > 0 ? `<span class="badge red">${e.timeouts}</span>` : '-';
    const oomBadge = e.ooms > 0 ? `<span class="badge red">${e.ooms}</span>` : '-';
    const n = v => v > 0 ? v.toLocaleString() : '-';
    return `<tr>
      <td>${e.encap_id}</td>
      <td><strong>${esc(e.encap_name)}</strong></td>
      <td><span class="status ${e.status}">${e.status}</span></td>
      <td>${n(e.seed_count)}</td>
      <td>${n(e.seeds_extracted)}</td>
      <td>${n(e.seeds_minimized)}</td>
      <td>${n(e.corpus_count)}</td>
      <td>${crashBadge}</td>
      <td>${toBadge}</td>
      <td>${oomBadge}</td>
      <td>${n(e.total_execs)}</td>
      <td>${n(e.coverage)}</td>
      <td>${elapsed}</td>
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

document.querySelectorAll('#encapTable th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    else { sortCol = col; sortDir = th.dataset.type === 'num' ? 'desc' : 'asc'; }
    renderTable();
  });
});

setRefresh();
fetchAll();
</script>
</body>
</html>"""


class _DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard HTML and JSON API endpoints."""

    campaign_dir: Path = None
    password: str = ""

    def log_message(self, fmt, *args):
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


def start_dashboard(
    campaign_dir: Path,
    port: int = 56789,
    password: str = "helloworld",
    host: str = "0.0.0.0",
) -> threading.Thread:
    """Start the dashboard HTTP server in a daemon thread."""
    handler = type("Handler", (_DashboardHandler,), {
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
STATE_FILENAME = "campaign_state.json"
DEFAULT_DURATION = "60m"
DEFAULT_WORKERS = 60
DEFAULT_OUTPUT = "wirefuzz_runs"
DEFAULT_MAX_SCAN_PACKETS = 350_000
DEFAULT_MAX_EXTRACT_PACKETS = 350_000
SCAN_PACKETS_PER_PCAP = 1000   # packets read per pcap during scan (categorization)

# Encap IDs to skip — they are meta-types, not real dissectors
SKIP_ENCAP_IDS = {-2, -1, 0}  # NONE, PER_PACKET, UNKNOWN

# WTAP encap range: 1-227 (228 real types). IDs beyond 227 don't exist in
# Wireshark's ENCAP_REGISTRY.  DLT numbers go higher (up to 303) but those
# map back to WTAP IDs within this range via dlt_to_wtap().


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
@dataclass
class EncapState:
    """Tracks the state of a single encap's fuzzing campaign."""
    encap_id: int
    encap_name: str
    status: str = "pending"  # pending | seeded | running | done | failed | skipped
    seed_count: int = 0          # from scan (categorization count)
    seeds_extracted: int = 0     # unique packets extracted from pcaps (pre-minimization)
    seeds_minimized: int = 0     # after libfuzzer -merge=1 minimization
    run_dir: str = ""
    crashes: int = 0
    timeouts: int = 0
    ooms: int = 0
    corpus_count: int = 0
    total_execs: int = 0
    coverage: int = 0
    exec_per_sec: int = 0
    peak_rss_mb: int = 0
    started_at: str = ""
    finished_at: str = ""
    elapsed_secs: int = 0
    error: str = ""


@dataclass
class CampaignState:
    """Persistent campaign state — serialised to JSON between runs."""
    campaign_dir: str = ""
    ws_version: str = "master"
    pcap_dir: str = ""
    workers: int = DEFAULT_WORKERS
    duration: str = DEFAULT_DURATION
    max_len: int = CONFIG.default_max_len
    timeout_ms: int = CONFIG.default_timeout_ms
    rss_limit_mb: int = CONFIG.default_rss_limit_mb
    max_scan_packets: int = DEFAULT_MAX_SCAN_PACKETS
    max_extract_packets: int = DEFAULT_MAX_EXTRACT_PACKETS
    created: str = ""
    updated: str = ""
    # Scan results: wtap_id -> packet count across all pcaps
    encap_scan: Dict[str, int] = field(default_factory=dict)
    # Scan results: wtap_id -> list of pcap file paths containing that encap
    encap_files: Dict[str, List[str]] = field(default_factory=dict)
    pcap_count: int = 0
    total_packets_scanned: int = 0
    # Per-encap state keyed by encap_id (as str for JSON compat)
    encaps: Dict[str, dict] = field(default_factory=dict)

    # ---- persistence helpers ----
    def save(self, path: Path):
        self.updated = datetime.now().isoformat()
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: Path) -> "CampaignState":
        raw = json.loads(path.read_text())
        return cls(**{k: v for k, v in raw.items()
                      if k in cls.__dataclass_fields__})

    def get_encap_state(self, encap_id: int) -> EncapState:
        key = str(encap_id)
        if key not in self.encaps:
            enc = ENCAP_REGISTRY.get(encap_id)
            name = enc.name if enc else f"UNKNOWN_{encap_id}"
            self.encaps[key] = asdict(EncapState(encap_id=encap_id, encap_name=name))
        d = self.encaps[key]
        return EncapState(**{k: v for k, v in d.items()
                            if k in EncapState.__dataclass_fields__})

    def set_encap_state(self, es: EncapState):
        self.encaps[str(es.encap_id)] = asdict(es)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
class CampaignLog:
    """Dual-output logger: Rich console + campaign log file."""

    def __init__(self, log_path: Path, console: Console):
        self.console = console
        self.log_path = log_path
        self._fh = open(log_path, "a", buffering=1)

    def info(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] {msg}\n")
        self.console.print(f"[cyan][{ts}][/cyan] {msg}")

    def ok(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] OK: {msg}\n")
        self.console.print(f"[green][{ts}] {msg}[/green]")

    def warn(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] WARN: {msg}\n")
        self.console.print(f"[yellow][{ts}] {msg}[/yellow]")

    def err(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._fh.write(f"[{ts}] ERROR: {msg}\n")
        self.console.print(f"[bold red][{ts}] {msg}[/bold red]")

    def close(self):
        self._fh.close()


# ---------------------------------------------------------------------------
# Scan phase — build encap distribution from pcaps
# ---------------------------------------------------------------------------
def scan_pcaps(
    pcap_dir: Path,
    state: CampaignState,
    log: CampaignLog,
) -> None:
    """Scan all pcaps, read up to N packets per file, record encap distribution."""
    pcap_files = find_pcap_files(pcap_dir)
    state.pcap_count = len(pcap_files)
    max_total = state.max_scan_packets
    log.info(f"Found {len(pcap_files)} pcap file(s) in {pcap_dir}")
    log.info(f"Max packets to scan: {max_total:,} "
             f"(up to {SCAN_PACKETS_PER_PCAP:,} per file)")

    if not pcap_files:
        log.warn("No pcap files found — all encaps will be fuzzed with synthetic seeds")
        return

    # Aggregate encap distribution and file mapping across all files
    distribution: Dict[int, int] = {}
    file_map: Dict[int, List[str]] = {}  # encap_id -> [file paths]
    total = 0

    for i, pf in enumerate(pcap_files, 1):
        if total >= max_total:
            log.info(f"  Reached {max_total:,} packet limit, stopping scan")
            break
        if i % 100 == 0 or i == len(pcap_files):
            log.info(f"  Scanned {i}/{len(pcap_files)} files ({total:,} packets so far)")
        remaining = max_total - total
        per_file_limit = min(SCAN_PACKETS_PER_PCAP, remaining)
        per_file = probe_encaps([pf], max_packets=per_file_limit)
        for encap_id, count in per_file.items():
            distribution[encap_id] = distribution.get(encap_id, 0) + count
            total += count
            # Track which files contain which encap types
            if encap_id not in file_map:
                file_map[encap_id] = []
            file_map[encap_id].append(str(pf))

    state.total_packets_scanned = total
    # Store as str keys for JSON
    state.encap_scan = {str(k): v for k, v in
                        sorted(distribution.items(), key=lambda x: -x[1])}
    state.encap_files = {str(k): v for k, v in file_map.items()}

    log.ok(f"Scan complete: {total:,} packets across {len(distribution)} encap types")

    # Mark encaps that have seeds
    for encap_id_str, count in state.encap_scan.items():
        encap_id = int(encap_id_str)
        if encap_id in SKIP_ENCAP_IDS:
            continue
        es = state.get_encap_state(encap_id)
        es.seed_count = count
        es.status = "seeded" if es.status == "pending" else es.status
        state.set_encap_state(es)


# ---------------------------------------------------------------------------
# Extract corpus for a single encap
# ---------------------------------------------------------------------------
def extract_corpus_for_encap(
    pcap_dir: Path,
    encap: EncapType,
    corpus_dir: Path,
    max_packets: int,
    log: CampaignLog,
    pcap_files: Optional[List[Path]] = None,
) -> int:
    """Extract matching packets from pcaps into corpus_dir.

    If pcap_files is given (from scan), only those files are read.
    Otherwise falls back to scanning the entire pcap_dir.
    Extracts up to max_packets unique packets. Returns actual count written.
    """
    if pcap_files is None:
        pcap_files = find_pcap_files(pcap_dir)
    if not pcap_files:
        return 0

    corpus_dir.mkdir(parents=True, exist_ok=True)
    stats = extract_by_encap(
        pcap_paths=pcap_files,
        target_encap=encap,
        output_dir=corpus_dir,
        console=Console(quiet=True),  # suppress progress bar
    )

    # Enforce max_packets: if we extracted more, trim the corpus
    written = stats.unique_packets
    if written > max_packets:
        files = sorted(corpus_dir.iterdir())
        for f in files[max_packets:]:
            f.unlink()
        written = max_packets
        log.info(f"  Trimmed corpus to {max_packets:,} packets (had {stats.unique_packets:,})")

    return written


# ---------------------------------------------------------------------------
# Post-run stats collection
# ---------------------------------------------------------------------------
def _collect_post_run_stats(run_dir: Path, es: EncapState):
    """Parse session log, run.json, and count crash/corpus files after a run."""
    import re as _re
    from wirefuzz.monitor import FuzzStats, parse_fuzzer_line

    # Read run.json for minimization stats
    run_json = run_dir / "run.json"
    if run_json.exists():
        try:
            meta = json.loads(run_json.read_text())
            es.seeds_extracted = meta.get("samples_before_min", 0)
            es.seeds_minimized = meta.get("samples_after_min", 0)
        except Exception:
            pass

    # Count crash files by type (crash-*, timeout-*, oom-*)
    crashes_dir = run_dir / "crashes"
    if crashes_dir.exists():
        for f in crashes_dir.iterdir():
            if not f.is_file():
                continue
            name = f.name.lower()
            if name.startswith("crash-"):
                es.crashes += 1
            elif name.startswith("timeout-"):
                es.timeouts += 1
            elif name.startswith("oom-"):
                es.ooms += 1
            elif name.startswith("slow-unit-"):
                es.timeouts += 1
            elif name.startswith("leak-"):
                es.crashes += 1
            else:
                es.crashes += 1

    corpus_dir = run_dir / "corpus"
    if corpus_dir.exists():
        es.corpus_count = sum(1 for f in corpus_dir.iterdir() if f.is_file())

    # Parse log for execution stats
    log_file = run_dir / "logs" / "session.log"
    if log_file.exists():
        stats = FuzzStats()
        try:
            for line in log_file.read_text().splitlines():
                parse_fuzzer_line(line, stats)
            es.total_execs = stats.total_execs
            es.coverage = stats.coverage
            es.exec_per_sec = stats.exec_per_sec
            es.peak_rss_mb = stats.peak_rss_mb
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Fuzz one encap
# ---------------------------------------------------------------------------
def fuzz_encap(
    encap: EncapType,
    state: CampaignState,
    campaign_dir: Path,
    pcap_dir: Optional[Path],
    log: CampaignLog,
    console: Console,
) -> EncapState:
    """Run a single fuzz session for one encap type. Updates state in-place."""
    es = state.get_encap_state(encap.id)
    es.status = "running"
    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)

    # Prepare corpus directory
    corpus_dir = campaign_dir / "corpus_staging" / f"encap_{encap.id}"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Extract seeds if we have pcaps and this encap has known seeds
    seed_count = 0
    if pcap_dir and es.seed_count > 0:
        # Use file list from scan to avoid re-scanning the entire pcap directory
        known_files = state.encap_files.get(str(encap.id))
        if known_files:
            relevant_pcaps = [Path(f) for f in known_files if Path(f).exists()]
            log.info(f"  Extracting seeds for {encap.name} "
                     f"({es.seed_count} packets in scan, {len(relevant_pcaps)} file(s))...")
        else:
            relevant_pcaps = None
            log.info(f"  Extracting seeds for {encap.name} ({es.seed_count} packets in scan)...")
        seed_count = extract_corpus_for_encap(
            pcap_dir, encap, corpus_dir, state.max_extract_packets, log,
            pcap_files=relevant_pcaps)
        es.seeds_extracted = seed_count
        log.info(f"  Extracted {seed_count} unique seed(s)")

    # Always ensure at least one minimal seed
    if not any(corpus_dir.iterdir()):
        (corpus_dir / "seed_minimal").write_bytes(b"\x00" * 4)
        seed_count = 1
        es.seeds_extracted = 1

    # Persist extraction stats immediately so the dashboard can show them
    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)

    output_base = Path(state.campaign_dir) / "runs"
    output_base.mkdir(parents=True, exist_ok=True)

    # Set started_at right before the actual fuzz session (not including extraction time)
    es.started_at = datetime.now().isoformat()
    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)

    try:
        session = start_fuzz_session(
            version=state.ws_version,
            encap=encap,
            corpus_dir=corpus_dir,
            output_base=output_base,
            workers=state.workers,
            max_len=state.max_len,
            timeout_ms=state.timeout_ms,
            rss_limit_mb=state.rss_limit_mb,
            duration=state.duration,
            pcap_source=pcap_dir,
            samples_before_min=seed_count,
            verbose=False,
            console=console,
        )

        es.run_dir = str(session.run_dir)
        es.status = "done"

        # Gather post-run stats by parsing the session log
        _collect_post_run_stats(session.run_dir, es)

    except KeyboardInterrupt:
        es.status = "done"  # Mark as done on Ctrl+C (duration ran)
        es.finished_at = datetime.now().isoformat()
        state.set_encap_state(es)
        state.save(campaign_dir / STATE_FILENAME)
        raise
    except Exception as exc:
        es.status = "failed"
        es.error = str(exc)[:500]
        log.err(f"  Failed: {exc}")

    es.finished_at = datetime.now().isoformat()
    if es.started_at:
        try:
            dt_start = datetime.fromisoformat(es.started_at)
            dt_end = datetime.fromisoformat(es.finished_at)
            es.elapsed_secs = int((dt_end - dt_start).total_seconds())
        except Exception:
            pass

    state.set_encap_state(es)
    state.save(campaign_dir / STATE_FILENAME)
    return es


# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------
def print_progress(state: CampaignState, console: Console):
    """Print a rich table summarising campaign progress."""
    table = Table(title="Campaign Progress", show_lines=False, expand=False)
    table.add_column("Status", style="bold", width=10)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Details", width=60)

    counts = {"pending": 0, "seeded": 0, "running": 0,
              "done": 0, "failed": 0, "skipped": 0}
    total_crashes = 0
    crashed_encaps = []

    for _, ed in state.encaps.items():
        s = ed.get("status", "pending")
        counts[s] = counts.get(s, 0) + 1
        cr = ed.get("crashes", 0)
        if cr > 0:
            total_crashes += cr
            crashed_encaps.append(f"{ed.get('encap_name', '?')} ({cr})")

    total = sum(counts.values())
    # Also count encaps not yet in state
    max_id = max((e.id for e in ENCAP_REGISTRY.values() if e.id not in SKIP_ENCAP_IDS), default=0)
    not_started = 0
    for eid in range(0, max_id + 1):
        if eid in SKIP_ENCAP_IDS:
            continue
        if eid not in ENCAP_REGISTRY:
            continue
        if str(eid) not in state.encaps:
            not_started += 1

    counts["pending"] += not_started
    total += not_started

    done = counts["done"] + counts["failed"] + counts["skipped"]

    table.add_row("[green]Done[/green]", str(counts["done"]), "")
    table.add_row("[red]Failed[/red]", str(counts["failed"]), "")
    table.add_row("[yellow]Seeded[/yellow]", str(counts["seeded"]),
                  "Have pcap seeds, waiting to fuzz")
    table.add_row("[dim]Pending[/dim]", str(counts["pending"]),
                  "No seeds, will fuzz with synthetic corpus")
    table.add_row("[cyan]Skipped[/cyan]", str(counts["skipped"]), "")
    table.add_row("", "", "")
    table.add_row("[bold]Total[/bold]", str(total),
                  f"{done}/{total} complete ({100*done//max(total,1)}%)")

    if total_crashes:
        table.add_row("[bold red]Crashes[/bold red]",
                      str(total_crashes),
                      ", ".join(crashed_encaps[:10]))

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Build the ordered fuzzing queue
# ---------------------------------------------------------------------------
def build_fuzz_queue(
    state: CampaignState,
    encap_range: Optional[Tuple[int, int]] = None,
) -> List[int]:
    """Return list of encap IDs to fuzz in sequential order (1-227).

    Skips encaps that are already done/failed/skipped/running.
    If encap_range is given, only IDs within [lo, hi] inclusive are considered.
    """
    queue = []

    max_id = max((e.id for e in ENCAP_REGISTRY.values()), default=0)
    lo = encap_range[0] if encap_range else 0
    hi = encap_range[1] if encap_range else max_id

    for encap_id in range(lo, hi + 1):
        if encap_id in SKIP_ENCAP_IDS:
            continue
        if encap_id not in ENCAP_REGISTRY:
            continue

        es = state.get_encap_state(encap_id)
        if es.status in ("done", "failed", "skipped", "running"):
            continue

        queue.append(encap_id)

    return queue


# ---------------------------------------------------------------------------
# Main campaign loop
# ---------------------------------------------------------------------------
def run_campaign(args: argparse.Namespace):
    console = Console()

    campaign_dir = Path(args.output).resolve()
    campaign_dir.mkdir(parents=True, exist_ok=True)
    state_path = campaign_dir / STATE_FILENAME

    log = CampaignLog(campaign_dir / "campaign.log", console)

    # ---- Load or create state ----
    if args.resume and state_path.exists():
        log.info(f"Resuming campaign from {state_path}")
        state = CampaignState.load(state_path)
        # Allow CLI overrides on resume
        if args.workers:
            state.workers = args.workers
        if args.duration:
            state.duration = args.duration
        if args.ws_version:
            state.ws_version = args.ws_version
    else:
        if not args.pcap_dir:
            log.err("--pcap-dir is required for a new campaign (or use --resume)")
            sys.exit(1)
        if not args.ws_version:
            log.err("--version is required for a new campaign")
            sys.exit(1)

        state = CampaignState(
            campaign_dir=str(campaign_dir),
            ws_version=args.ws_version,
            pcap_dir=str(Path(args.pcap_dir).resolve()) if args.pcap_dir else "",
            workers=args.workers or DEFAULT_WORKERS,
            duration=args.duration or DEFAULT_DURATION,
            max_len=args.max_len,
            timeout_ms=args.timeout_ms,
            rss_limit_mb=args.rss_limit_mb,
            max_scan_packets=args.max_scan_packets,
            max_extract_packets=args.max_extract_packets,
            created=datetime.now().isoformat(),
        )

    # ---- Header + full config log ----
    console.print()
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold]  wirefuzz campaign — automated full-encap fuzzing[/bold]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print()

    config_lines = [
        ("Wireshark version",  state.ws_version),
        ("Workers per encap",  str(state.workers)),
        ("Duration per encap", state.duration),
        ("Max input length",   f"{state.max_len} bytes"),
        ("Timeout per input",  f"{state.timeout_ms} ms"),
        ("RSS limit",          f"{state.rss_limit_mb} MB"),
        ("Scan packets/pcap",  f"{SCAN_PACKETS_PER_PCAP:,}"),
        ("Max scan packets",   f"{state.max_scan_packets:,} total"),
        ("Max extract packets", f"{state.max_extract_packets:,} per encap"),
        ("Campaign dir",       str(campaign_dir)),
        ("PCAP source",        state.pcap_dir or "(none)"),
        ("Encap range",        args.encap_range or "all (1-227)"),
        ("Resume mode",        "yes" if args.resume else "no"),
        ("Dashboard",          f"http://0.0.0.0:{args.dashboard_port}/" if not args.no_dashboard else "disabled"),
    ]
    for label, value in config_lines:
        padded = f"{label + ':':.<24s}"
        console.print(f"  {padded} {value}")
        log.info(f"  {padded} {value}")

    console.print()

    # ---- Start dashboard ----
    if not args.no_dashboard:
        dash_port = args.dashboard_port
        dash_pw = args.dashboard_password
        try:
            start_dashboard(campaign_dir, port=dash_port, password=dash_pw)
            log.ok(f"Dashboard running at http://0.0.0.0:{dash_port}/ (password: {'***' if dash_pw else 'none'})")
        except Exception as e:
            log.warn(f"Failed to start dashboard: {e}")

    # ---- Docker check ----
    log.info("Checking Docker...")
    try:
        check_docker()
    except Exception as e:
        log.err(f"Docker not available: {e}")
        sys.exit(1)

    # ---- Ensure image is built ----
    if not image_exists(state.ws_version):
        log.info(f"Building Docker image for Wireshark {state.ws_version}...")
        build_image(state.ws_version, console=console)
    else:
        log.ok(f"Docker image exists: {CONFIG.image_tag(state.ws_version)}")

    # ---- Scan phase (only if not yet done) ----
    pcap_dir = Path(state.pcap_dir) if state.pcap_dir else None

    if not state.encap_scan and pcap_dir:
        log.info("=== Phase 1: Scanning pcaps ===")
        scan_pcaps(pcap_dir, state, log)
        state.save(state_path)

        # Show scan results
        console.print()
        scan_table = Table(title="Encap Distribution (from scan)", show_lines=False)
        scan_table.add_column("WTAP ID", justify="right")
        scan_table.add_column("Name")
        scan_table.add_column("Packets", justify="right")
        for eid_str, count in list(state.encap_scan.items())[:30]:
            enc = ENCAP_REGISTRY.get(int(eid_str))
            name = enc.name if enc else f"UNKNOWN_{eid_str}"
            scan_table.add_row(eid_str, name, f"{count:,}")
        if len(state.encap_scan) > 30:
            scan_table.add_row("...", f"({len(state.encap_scan) - 30} more)", "")
        console.print(scan_table)
        console.print()
    elif state.encap_scan:
        n_seeded = sum(1 for v in state.encap_scan.values() if v > 0)
        log.info(f"Scan already done: {state.total_packets_scanned} packets, "
                 f"{n_seeded} encap types with seeds")

    # ---- Initialize all encap states ----
    max_id = max((e.id for e in ENCAP_REGISTRY.values()), default=0)
    for encap_id in range(0, max_id + 1):
        if encap_id in SKIP_ENCAP_IDS:
            continue
        if encap_id not in ENCAP_REGISTRY:
            continue
        # Ensure state entry exists
        _ = state.get_encap_state(encap_id)
    state.save(state_path)

    # ---- Parse encap range ----
    encap_range = None
    if args.encap_range:
        parts = args.encap_range.split("-")
        encap_range = (int(parts[0]), int(parts[1]))
        log.info(f"Encap range filter: {encap_range[0]}-{encap_range[1]}")

    # ---- Build queue ----
    queue = build_fuzz_queue(state, encap_range=encap_range)
    total_todo = len(queue)
    if encap_range:
        total_encaps = sum(1 for eid in range(encap_range[0], encap_range[1] + 1)
                           if eid not in SKIP_ENCAP_IDS and eid in ENCAP_REGISTRY)
    else:
        total_encaps = sum(1 for eid in range(0, max_id + 1)
                           if eid not in SKIP_ENCAP_IDS and eid in ENCAP_REGISTRY)
    already_done = total_encaps - total_todo

    log.info(f"=== Phase 2: Fuzzing {total_todo} encaps "
             f"({already_done} already done, {total_encaps} total) ===")

    print_progress(state, console)

    # ---- Fuzz loop ----
    interrupted = False
    for idx, encap_id in enumerate(queue, 1):
        encap = ENCAP_REGISTRY.get(encap_id)
        if not encap:
            continue

        es = state.get_encap_state(encap_id)

        console.print()
        console.print("[bold cyan]" + "-" * 60 + "[/bold cyan]")
        log.info(f"[{already_done + idx}/{total_encaps}] "
                 f"Fuzzing: {encap.name} (WTAP {encap.id}) — {encap.full_name}")
        if es.seed_count > 0:
            log.info(f"  Seeds available: {es.seed_count} packets from pcaps")
        else:
            log.info(f"  No seeds — using synthetic minimal corpus")
        console.print("[bold cyan]" + "-" * 60 + "[/bold cyan]")

        try:
            result = fuzz_encap(
                encap=encap,
                state=state,
                campaign_dir=campaign_dir,
                pcap_dir=pcap_dir,
                log=log,
                console=console,
            )

            if result.crashes > 0:
                log.ok(f"  CRASHES FOUND: {result.crashes} crash file(s) "
                       f"in {result.run_dir}")
            else:
                log.ok(f"  Done: corpus={result.corpus_count}, "
                       f"elapsed={result.elapsed_secs}s")

        except KeyboardInterrupt:
            log.warn("Campaign interrupted by user (Ctrl+C)")
            log.info("Progress saved. Resume with --resume")
            interrupted = True
            break
        except Exception as exc:
            log.err(f"  Unexpected error: {exc}")
            # Mark as failed and continue
            es = state.get_encap_state(encap_id)
            es.status = "failed"
            es.error = str(exc)[:500]
            es.finished_at = datetime.now().isoformat()
            state.set_encap_state(es)
            state.save(state_path)
            continue

    # ---- Final summary ----
    console.print()
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    if interrupted:
        console.print("[bold yellow]  Campaign paused — resume with --resume[/bold yellow]")
    else:
        console.print("[bold green]  Campaign complete![/bold green]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")

    print_progress(state, console)

    # Summary of crashes
    all_crashes = []
    for _, ed in state.encaps.items():
        if ed.get("crashes", 0) > 0:
            all_crashes.append(ed)

    if all_crashes:
        console.print("[bold red]Encap types with crashes:[/bold red]")
        crash_table = Table(show_lines=False)
        crash_table.add_column("Encap", style="bold")
        crash_table.add_column("WTAP ID", justify="right")
        crash_table.add_column("Crashes", justify="right", style="red")
        crash_table.add_column("Run Directory")
        for ed in sorted(all_crashes, key=lambda x: -x.get("crashes", 0)):
            crash_table.add_row(
                ed.get("encap_name", "?"),
                str(ed.get("encap_id", "?")),
                str(ed.get("crashes", 0)),
                ed.get("run_dir", ""),
            )
        console.print(crash_table)
        console.print()
    else:
        console.print("[dim]No crashes found across any encap type.[/dim]")
        console.print()

    log.info(f"State saved to: {state_path}")
    log.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="wirefuzz campaign — fuzz every encap type systematically",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # New campaign — scan pcaps, then fuzz all encaps
  python wirefuzz_campaign.py /data/pcaps -V master -w 60 -d 60m -o campaign_run

  # Resume after interruption
  python wirefuzz_campaign.py --resume -o campaign_run

  # Custom settings
  python wirefuzz_campaign.py /data/pcaps -V v4.6.4 -w 32 -d 2h --max-len 32768
""",
    )

    parser.add_argument(
        "pcap_dir", nargs="?", default=None,
        help="Directory with pcap/pcapng files (scanned recursively)",
    )
    parser.add_argument(
        "-V", "--version", dest="ws_version", default=None,
        help="Wireshark version to fuzz (tag, branch, or commit hash)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=None,
        help=f"Number of libfuzzer fork workers per encap (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "-d", "--duration", default=None,
        help=f"Duration per encap, e.g. '60m', '2h', '3600s' (default: {DEFAULT_DURATION})",
    )
    parser.add_argument(
        "-o", "--output", default="wirefuzz_campaign",
        help="Campaign output directory (default: wirefuzz_campaign)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume a previous campaign from its state file",
    )
    parser.add_argument(
        "--max-len", type=int, default=CONFIG.default_max_len,
        help=f"Max input length in bytes (default: {CONFIG.default_max_len})",
    )
    parser.add_argument(
        "--timeout-ms", type=int, default=CONFIG.default_timeout_ms,
        help=f"Per-input timeout in ms (default: {CONFIG.default_timeout_ms})",
    )
    parser.add_argument(
        "--rss-limit-mb", type=int, default=CONFIG.default_rss_limit_mb,
        help=f"RSS limit per worker in MB (default: {CONFIG.default_rss_limit_mb})",
    )
    parser.add_argument(
        "--max-scan-packets", type=int, default=DEFAULT_MAX_SCAN_PACKETS,
        help=f"Max total packets to read during pcap scan/categorization phase (default: {DEFAULT_MAX_SCAN_PACKETS:,})",
    )
    parser.add_argument(
        "--max-extract-packets", type=int, default=DEFAULT_MAX_EXTRACT_PACKETS,
        help=f"Max packets to extract per encap for seed corpus (default: {DEFAULT_MAX_EXTRACT_PACKETS:,})",
    )
    parser.add_argument(
        "--encap-range", default=None,
        help="Encap ID range to fuzz, e.g. '0-50' or '100-227' (default: all)",
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Disable the web dashboard",
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=56789,
        help="Dashboard HTTP port (default: 56789)",
    )
    parser.add_argument(
        "--dashboard-password", default="helloworld",
        help="Dashboard password (default: helloworld)",
    )

    args = parser.parse_args()

    # Validate
    if not args.resume and not args.pcap_dir:
        parser.error("pcap_dir is required for a new campaign (or use --resume)")
    if not args.resume and not args.ws_version:
        parser.error("-V/--version is required for a new campaign")

    run_campaign(args)


if __name__ == "__main__":
    main()
