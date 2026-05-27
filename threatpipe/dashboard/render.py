"""Single-file HTML dashboard served by the API server.

The dashboard is shipped inline so the API server stays self-contained
- no static directory, no asset pipeline. It uses ``fetch`` against
the same origin for live data and renders the provenance graph with
the upstream Cytoscape.js CDN build. The HTML is rendered through a
tiny templating step so we can stamp in the package version and a
generated nonce for the inline ``script`` tag.

Operators who want to host their own assets can simply route ``GET /``
to a static file server instead.
"""

from __future__ import annotations

import secrets

from ..version import __version__


_DASHBOARD_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>threatpipe console</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg: #0b1020;
    --panel: #131a30;
    --panel-2: #1a2342;
    --text: #d8def0;
    --muted: #8893b3;
    --border: #233055;
    --accent: #4a8df0;
    --sev-low: #7d8aa6;
    --sev-medium: #f2c744;
    --sev-high: #e8631a;
    --sev-critical: #c8262c;
    --good: #4ac68f;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); }
  header { display: flex; align-items: center; justify-content: space-between;
           padding: 12px 20px; border-bottom: 1px solid var(--border);
           background: linear-gradient(180deg, var(--panel-2), var(--panel)); }
  header h1 { margin: 0; font-size: 16px; letter-spacing: 0.4px; }
  header .tag { color: var(--muted); font-size: 12px; margin-left: 12px; }
  nav { display: flex; gap: 4px; padding: 8px 16px; background: var(--panel);
        border-bottom: 1px solid var(--border); }
  nav button { background: transparent; color: var(--muted); border: 1px solid transparent;
               padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  nav button.active { color: var(--text); border-color: var(--border); background: var(--panel-2); }
  nav button:hover { color: var(--text); }
  main { padding: 16px 20px; }
  .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
          padding: 14px 16px; }
  .card h2 { font-size: 11px; margin: 0 0 6px 0; color: var(--muted); letter-spacing: 0.6px;
             text-transform: uppercase; }
  .metric { font-size: 28px; font-weight: 600; }
  .metric .sub { font-size: 12px; color: var(--muted); margin-left: 8px; font-weight: 400; }
  .row { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 6px;
         font-size: 13px; }
  .row + .row { border-top: 1px solid rgba(255,255,255,0.04); }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px;
         font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .sev-low      { background: rgba(125,138,166,0.20); color: var(--sev-low); }
  .sev-medium   { background: rgba(242,199,68,0.20); color: var(--sev-medium); }
  .sev-high     { background: rgba(232,99,26,0.20);  color: var(--sev-high); }
  .sev-critical { background: rgba(200,38,44,0.30);  color: #ff6b6b; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; }
  pre { background: var(--bg); padding: 10px; border-radius: 6px; overflow: auto;
        font-size: 12px; border: 1px solid var(--border); }
  input, select, textarea { background: var(--panel-2); color: var(--text);
                            border: 1px solid var(--border); border-radius: 6px;
                            padding: 6px 8px; font-size: 13px; font-family: inherit; }
  button.primary { background: var(--accent); color: white; border: 0; padding: 8px 14px;
                   border-radius: 6px; cursor: pointer; font-size: 13px; }
  #graph { width: 100%; height: 420px; background: var(--panel); border-radius: 10px;
           border: 1px solid var(--border); }
  .view { display: none; }
  .view.active { display: block; }
  .muted { color: var(--muted); }
  .pill { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px;
          background: rgba(74,141,240,0.15); color: var(--accent); margin-right: 4px; }
  .attck-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; }
  .attck-cell { background: var(--panel-2); border-radius: 4px; padding: 6px 4px;
                 font-size: 10px; min-height: 32px; }
  .attck-tactic { font-size: 10px; color: var(--muted); margin-bottom: 4px;
                  text-transform: uppercase; letter-spacing: 0.5px; }
  .attck-cell.covered { background: rgba(74,198,143,0.18); color: #88e1b2; }
</style>
</head>
<body>
<header>
  <div>
    <h1>threatpipe console</h1>
    <span class="tag" id="version">v__VERSION__</span>
  </div>
  <div class="muted" id="last-update"></div>
</header>
<nav>
  <button class="tab active" data-view="overview">Overview</button>
  <button class="tab" data-view="incidents">Incidents</button>
  <button class="tab" data-view="detections">Detections</button>
  <button class="tab" data-view="graph">Graph</button>
  <button class="tab" data-view="hunt">Hunt</button>
  <button class="tab" data-view="attck">ATT&amp;CK</button>
  <button class="tab" data-view="response">Response</button>
</nav>
<main>

  <section class="view active" id="overview">
    <div class="grid" id="metric-cards"></div>
    <div class="grid" style="margin-top: 12px;">
      <div class="card">
        <h2>Severity mix</h2>
        <div id="sev-mix"></div>
      </div>
      <div class="card">
        <h2>Detectors</h2>
        <div id="det-mix"></div>
      </div>
      <div class="card">
        <h2>System</h2>
        <div id="sys-info" class="muted"></div>
      </div>
    </div>
  </section>

  <section class="view" id="incidents">
    <div class="card">
      <h2>Open incidents</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Score</th><th>Status</th><th>Hosts</th><th>Title</th></tr></thead>
        <tbody id="incidents-rows"></tbody>
      </table>
    </div>
  </section>

  <section class="view" id="detections">
    <div class="card">
      <h2>Recent detections</h2>
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Score</th><th>Detector</th><th>Host</th><th>Reason</th></tr></thead>
        <tbody id="detections-rows"></tbody>
      </table>
    </div>
  </section>

  <section class="view" id="graph">
    <div class="card">
      <h2>Provenance graph</h2>
      <div id="graph"></div>
      <div class="muted" id="graph-stats" style="margin-top: 8px;"></div>
    </div>
  </section>

  <section class="view" id="hunt">
    <div class="card">
      <h2>Hunt</h2>
      <textarea id="hunt-query" rows="3" style="width: 100%;"
        placeholder='severity == "high" AND event.dst_port IN (4444, 1337)'></textarea>
      <div style="margin-top: 8px; display: flex; gap: 8px; align-items: center;">
        <select id="hunt-target">
          <option value="detections">detections</option>
          <option value="incidents">incidents</option>
          <option value="events">events</option>
        </select>
        <button class="primary" id="hunt-run">Run</button>
        <span class="muted" id="hunt-summary"></span>
      </div>
      <pre id="hunt-result" style="margin-top: 12px;"></pre>
    </div>
  </section>

  <section class="view" id="attck">
    <div class="card">
      <h2>ATT&amp;CK coverage</h2>
      <div class="muted" id="attck-summary"></div>
      <div class="attck-grid" id="attck-grid" style="margin-top: 12px;"></div>
    </div>
  </section>

  <section class="view" id="response">
    <div class="card">
      <h2>Playbooks</h2>
      <table>
        <thead><tr><th>ID</th><th>Trigger</th><th>Min sev</th><th>Steps</th><th>Enabled</th></tr></thead>
        <tbody id="playbook-rows"></tbody>
      </table>
    </div>
    <div class="card" style="margin-top: 12px;">
      <h2>Audit log</h2>
      <table>
        <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Playbook</th><th>Detail</th></tr></thead>
        <tbody id="audit-rows"></tbody>
      </table>
    </div>
  </section>

</main>

<script src="https://unpkg.com/cytoscape@3.26.0/dist/cytoscape.min.js"
        crossorigin="anonymous" nonce="__NONCE__"></script>
<script nonce="__NONCE__">
(function () {
  const NONCE_OK = true;
  const $ = (id) => document.getElementById(id);
  const ESC = (s) => String(s ?? '').replace(/[&<>"']/g,
    (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmtTime = (epoch) => {
    const d = new Date(epoch * 1000);
    return d.toLocaleString();
  };

  // tab routing -----------------------------------------------
  document.querySelectorAll('nav button.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('nav button.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      $(btn.dataset.view).classList.add('active');
      if (btn.dataset.view === 'graph') refreshGraph();
      if (btn.dataset.view === 'incidents') refreshIncidents();
      if (btn.dataset.view === 'detections') refreshDetections();
      if (btn.dataset.view === 'attck') refreshAttck();
      if (btn.dataset.view === 'response') { refreshPlaybooks(); refreshAudit(); }
    });
  });

  async function api(path, opts) {
    const resp = await fetch(path, opts || {});
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  // overview --------------------------------------------------
  async function refreshOverview() {
    try {
      const s = await api('/status');
      const cards = [
        { label: 'Events', value: s.events_in },
        { label: 'Detections', value: s.detections_out },
        { label: 'Queue', value: s.queue_depth, sub: `(dropped ${s.queue_dropped})` },
        { label: 'Uptime', value: Math.round(s.uptime_s) + 's' },
      ];
      $('metric-cards').innerHTML = cards.map(c => `
        <div class="card">
          <h2>${ESC(c.label)}</h2>
          <div class="metric">${ESC(c.value)} <span class="sub">${ESC(c.sub || '')}</span></div>
        </div>`).join('');
      const sev = s.by_severity || {};
      $('sev-mix').innerHTML = ['low','medium','high','critical'].map(k => `
        <div class="row"><span class="sev sev-${k}">${k}</span>
        <span class="muted" style="margin-left:auto;">${sev[k] || 0}</span></div>`).join('');
      const det = s.by_detector || {};
      $('det-mix').innerHTML = Object.keys(det).length
        ? Object.entries(det).map(([k, v]) => `<div class="row">${ESC(k)}
          <span class="muted" style="margin-left:auto;">${v}</span></div>`).join('')
        : '<div class="muted">no detections yet</div>';
      $('sys-info').textContent = `running: ${s.running ? 'yes' : 'no'} - last event: ${s.last_event_ts ? fmtTime(s.last_event_ts) : 'n/a'}`;
      $('last-update').textContent = 'updated ' + new Date().toLocaleTimeString();
    } catch (e) { console.warn(e); }
  }

  async function refreshIncidents() {
    try {
      const r = await api('/incidents');
      const rows = (r.items || []).map(i => `
        <tr>
          <td><code>${ESC(i.incident_id)}</code></td>
          <td><span class="sev sev-${i.severity}">${i.severity}</span></td>
          <td>${i.score.toFixed(2)}</td>
          <td>${ESC(i.status)}</td>
          <td>${i.affected_hosts.map(h => `<span class="pill">${ESC(h)}</span>`).join('')}</td>
          <td>${ESC(i.title)}</td>
        </tr>`).join('');
      $('incidents-rows').innerHTML = rows || '<tr><td colspan="6" class="muted">no incidents</td></tr>';
    } catch (e) { $('incidents-rows').innerHTML = `<tr><td colspan="6" class="muted">${ESC(e.message)}</td></tr>`; }
  }

  async function refreshDetections() {
    try {
      const r = await api('/detections?limit=100');
      const rows = (r.items || []).slice().reverse().map(d => `
        <tr>
          <td>${ESC(d.event.timestamp_iso || '')}</td>
          <td><span class="sev sev-${d.severity}">${d.severity}</span></td>
          <td>${(d.score || 0).toFixed(2)}</td>
          <td>${ESC(d.detector)}</td>
          <td>${ESC(d.event.host || '-')}</td>
          <td>${ESC((d.reasons || [])[0] || '')}</td>
        </tr>`).join('');
      $('detections-rows').innerHTML = rows || '<tr><td colspan="6" class="muted">no detections</td></tr>';
    } catch (e) { console.warn(e); }
  }

  async function refreshGraph() {
    try {
      const stats = await api('/graph/stats');
      $('graph-stats').textContent = stats.enabled
        ? `nodes ${stats.nodes} - edges ${stats.edges}`
        : 'graph layer disabled';
      if (!stats.enabled) return;
      const layer = await api('/graph/export');
      if (window.__cy) window.__cy.destroy();
      window.__cy = cytoscape({
        container: $('graph'),
        elements: layer.elements || [],
        style: [
          { selector: 'node', style: {
              'label': 'data(label)', 'color': '#d8def0', 'font-size': 10,
              'background-color': '#5a8fbb', 'width': 24, 'height': 24, 'text-valign': 'bottom',
          }},
          { selector: 'node[type = "process"]', style: { 'background-color': '#e0a458' } },
          { selector: 'node[type = "file"]',    style: { 'background-color': '#48bb78' } },
          { selector: 'node[type = "socket"]',  style: { 'background-color': '#e74c3c' } },
          { selector: 'node[type = "user"]',    style: { 'background-color': '#9b59b6' } },
          { selector: 'edge', style: {
              'line-color': '#3a4670', 'target-arrow-color': '#3a4670',
              'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
              'width': 1.2, 'font-size': 8, 'color': '#8893b3',
              'label': 'data(type)',
          }},
        ],
        layout: { name: 'cose', animate: false, nodeRepulsion: 5000 },
      });
    } catch (e) { console.warn(e); }
  }

  async function refreshAttck() {
    try {
      const cov = await api('/attck/coverage');
      const tactics = Object.entries(cov.summary.by_tactic);
      $('attck-summary').textContent =
        `${cov.summary.techniques_covered} / ${cov.summary.techniques_total} techniques covered`;
      const entries = new Map();
      (cov.entries || []).forEach(e => entries.set(e.technique_id, e));
      const grid = $('attck-grid');
      grid.innerHTML = '';
      tactics.forEach(([tac, info]) => {
        const wrap = document.createElement('div');
        wrap.innerHTML = `<div class="attck-tactic">${ESC(tac)} (${info.covered}/${info.total})</div>`;
        cov.entries.filter(e => e.tactics.includes(tac))
          .slice(0, 12)
          .forEach(e => {
            const cell = document.createElement('div');
            cell.className = 'attck-cell covered';
            cell.title = `${e.technique_id}  ${e.rule_count} rules`;
            cell.innerHTML = `<div>${ESC(e.technique_id)}</div><div class="muted">${ESC(e.name.slice(0, 28))}</div>`;
            wrap.appendChild(cell);
          });
        grid.appendChild(wrap);
      });
    } catch (e) { console.warn(e); }
  }

  async function refreshPlaybooks() {
    try {
      const r = await api('/response/playbooks');
      const rows = (r.items || []).map(p => `
        <tr><td><code>${ESC(p.playbook_id)}</code></td>
            <td>${ESC(p.trigger)}</td>
            <td>${ESC(p.min_severity || '-')}</td>
            <td>${p.steps.length}</td>
            <td>${p.enabled ? '<span class="sev sev-low">enabled</span>' : '<span class="muted">disabled</span>'}</td></tr>`).join('');
      $('playbook-rows').innerHTML = rows || '<tr><td colspan="5" class="muted">no playbooks</td></tr>';
    } catch (e) { console.warn(e); }
  }

  async function refreshAudit() {
    try {
      const r = await api('/response/audit?limit=50');
      const rows = (r.items || []).map(a => `
        <tr><td>${ESC(a.timestamp_iso)}</td>
            <td>${ESC(a.action)}</td>
            <td>${ESC(a.status)}</td>
            <td><code>${ESC(a.playbook_id || '')}</code></td>
            <td>${ESC(a.detail)}</td></tr>`).join('');
      $('audit-rows').innerHTML = rows || '<tr><td colspan="5" class="muted">no audit entries</td></tr>';
    } catch (e) { console.warn(e); }
  }

  // hunt console ----------------------------------------------
  $('hunt-run').addEventListener('click', async () => {
    try {
      const body = { query: $('hunt-query').value, target: $('hunt-target').value, limit: 50 };
      const r = await fetch('/hunt/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const payload = await r.json();
      $('hunt-summary').textContent = r.ok
        ? `${payload.match_count}/${payload.scanned} in ${payload.duration_ms}ms`
        : `error: ${payload.error || ''}`;
      $('hunt-result').textContent = JSON.stringify(payload.matches || payload, null, 2);
    } catch (e) {
      $('hunt-summary').textContent = 'error: ' + e.message;
    }
  });

  setInterval(refreshOverview, 5000);
  refreshOverview();
})();
</script>
</body>
</html>
"""


def render_dashboard() -> str:
    """Return a fresh dashboard HTML page.

    A new nonce is generated per request so that operators who place a
    proxy in front (which usually injects a strict Content-Security-Policy)
    can mirror the value into the response header without having to
    rewrite the dashboard payload.
    """
    nonce = secrets.token_urlsafe(16)
    return _DASHBOARD_TEMPLATE.replace("__VERSION__", __version__).replace("__NONCE__", nonce)


DASHBOARD_HTML = _DASHBOARD_TEMPLATE
