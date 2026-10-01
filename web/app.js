/**
 * AegisScan v3.1 — Frontend Logic
 * Minimal pro dashboard: sidebar navigation, SSE streaming, topology graph,
 * vulnerability display, and all intelligence module interactions.
 */

'use strict';

// ============================================================================
// Global State
// ============================================================================

let currentData = null;
let isScanning = false;
let activeEventSource = null;
let currentSevFilter = 'ALL';
let allVulnerabilities = [];

// Topology state
let topoNodes = [];
let topoEdges = [];
let topoScale = 1;
let topoOffsetX = 0;
let topoOffsetY = 0;
let topoDragging = null;
let topoPanning = false;
let topoPanStart = { x: 0, y: 0 };
let topoAnimFrame = null;

// ============================================================================
// Init
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initScanForm();
  initVulnFilters();
  initExport();
  initIntelButtons();
  initTopologyCanvas();

  // Restore saved target
  const saved = sessionStorage.getItem('aegis_target');
  if (saved) document.getElementById('targetInput').value = saved;
});

// ============================================================================
// Sidebar Navigation
// ============================================================================

function initSidebar() {
  const navItems = document.querySelectorAll('.nav-item[data-page]');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      navItems.forEach(n => n.classList.remove('active'));
      item.classList.add('active');
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
      const page = document.getElementById(item.dataset.page);
      if (page) page.classList.add('active');
    });
  });
}

function navigateTo(pageId) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const page = document.getElementById(pageId);
  if (page) page.classList.add('active');
  const nav = document.querySelector(`.nav-item[data-page="${pageId}"]`);
  if (nav) nav.classList.add('active');
}

// ============================================================================
// Scan Form
// ============================================================================

function initScanForm() {
  const profileSel = document.getElementById('profileSelect');
  const customWrap = document.getElementById('customPortsWrap');
  const threadsRange = document.getElementById('threadsRange');
  const workersVal = document.getElementById('workersVal');
  const form = document.getElementById('scanForm');
  const clearLog = document.getElementById('btnClearLog');

  profileSel.addEventListener('change', () => {
    customWrap.style.display = profileSel.value === 'custom' ? 'flex' : 'none';
    if (profileSel.value === 'custom') document.getElementById('customPortsInput').focus();
  });

  threadsRange.addEventListener('input', () => {
    workersVal.textContent = threadsRange.value;
  });

  form.addEventListener('submit', e => {
    e.preventDefault();
    if (!isScanning) startScan();
  });

  clearLog.addEventListener('click', () => {
    document.getElementById('terminalBody').innerHTML =
      '<div class="log-line info">[LOG] Cleared.</div>';
  });
}

// ============================================================================
// Scan Orchestration
// ============================================================================

async function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  const profile = document.getElementById('profileSelect').value;
  const customPorts = document.getElementById('customPortsInput')?.value.trim() || '';
  const threads = parseInt(document.getElementById('threadsRange').value, 10);

  if (!target) {
    showToast('Enter a target hostname or IP address.', 'error');
    return;
  }

  sessionStorage.setItem('aegis_target', target);
  isScanning = true;

  // UI state
  const btn = document.getElementById('btnScan');
  const btnText = document.getElementById('btnScanText');
  btn.disabled = true;
  btnText.textContent = 'Scanning…';
  setSidebarStatus('scanning', 'Scanning…');
  setProgress(5);
  showProgressMsg('Initializing scan engine…');

  if (activeEventSource) { activeEventSource.close(); activeEventSource = null; }

  // Reset display
  resetDisplayData();
  navigateTo('pageOverview');

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, profile, custom_ports: customPorts, threads })
    });

    if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
    const { scan_id } = await resp.json();

    // SSE streaming
    const sse = new EventSource(`/api/stream?scan_id=${scan_id}`);
    activeEventSource = sse;

    sse.onmessage = ev => {
      try {
        const event = JSON.parse(ev.data);
        handleScanEvent(event);
      } catch {}
    };

    sse.onerror = () => {
      sse.close();
      scanComplete();
    };

  } catch (err) {
    showToast(`Scan failed: ${err.message}`, 'error');
    scanComplete();
    logLine(`[ERROR] ${err.message}`, 'error');
  }
}

function handleScanEvent(ev) {
  if (ev.type === 'port_found') {
    logLine(`[PORT] ${ev.port}/tcp  ${ev.service}  ${ev.version || ''}  (${ev.latency_ms}ms)`, 'port');
    setProgress(5 + ev.progress * 0.5);
    showProgressMsg(`Scanning ports… ${Math.round(ev.progress)}%`);
  } else if (ev.type === 'scan_progress') {
    setProgress(5 + ev.progress * 0.5);
    showProgressMsg(`Probing ports… ${Math.round(ev.progress)}%`);
  } else if (ev.type === 'status') {
    logLine(`[STATUS] ${ev.message}`, 'status');
    showProgressMsg(ev.message);
  } else if (ev.type === 'complete') {
    logLine(`[COMPLETE] ${ev.message}`, 'ok');
    populateAllData(ev.data);
    scanComplete();
  } else if (ev.type === 'error') {
    logLine(`[ERROR] ${ev.message}`, 'error');
    showToast(ev.message, 'error');
    scanComplete();
  }
}

function scanComplete() {
  isScanning = false;
  activeEventSource = null;
  const btn = document.getElementById('btnScan');
  const btnText = document.getElementById('btnScanText');
  btn.disabled = false;
  btnText.textContent = 'Run Scan';
  setSidebarStatus('idle', 'Ready');
  setProgress(100);
  setTimeout(() => { setProgress(0); hideProgressMsg(); }, 1500);
  if (currentData) {
    document.getElementById('exportWrapper').style.display = '';
  }
}

// ============================================================================
// Populate All Data
// ============================================================================

function populateAllData(data) {
  currentData = data;
  allVulnerabilities = data.vulnerabilities || [];

  populateOverview(data);
  populatePorts(data.open_ports || []);
  populateVulnerabilities(allVulnerabilities);
  populateSSL(data.ssl_audit);
  populateWeb(data.web_audit);
  populateDNS(data.dns_audit);
  populatePlaybooks(data.remediations || []);
  buildTopologyGraph(data);

  showToast(`Scan complete — ${allVulnerabilities.length} findings`, 'success');
}

// ============================================================================
// Overview
// ============================================================================

function populateOverview(data) {
  const r = data.risk_summary;
  const m = data.metadata;

  document.getElementById('riskScore').textContent = r.cvss_average.toFixed(1);
  document.getElementById('totalFindings').textContent = r.total_findings;
  document.getElementById('openPortsCount').textContent = m.open_ports_count;
  document.getElementById('scanDuration').textContent = `${m.scan_duration_seconds}s`;
  document.getElementById('scanTimestamp').textContent = m.timestamp;
  document.getElementById('teleTarget').textContent = m.target;
  document.getElementById('teleIP').textContent = m.resolved_ip;
  document.getElementById('teleEngine').textContent = m.engine_version;
  document.getElementById('cvssAvgLabel').textContent = `CVSS avg: ${r.cvss_average.toFixed(1)}`;

  document.getElementById('sevCritical').textContent = r.critical;
  document.getElementById('sevHigh').textContent = r.high;
  document.getElementById('sevMedium').textContent = r.medium;
  document.getElementById('sevLow').textContent = r.low;

  // Risk badge
  const badge = document.getElementById('riskBadge');
  const label = document.getElementById('riskLabel');
  const risk = r.overall_risk.toLowerCase();
  badge.className = `risk-badge ${risk}`;
  label.textContent = r.overall_risk.toUpperCase();

  // Badges
  updateNavBadge('badgePorts', m.open_ports_count);
  updateNavBadge('badgeVulns', r.total_findings);

  // Hide empty placeholder
  document.getElementById('overviewEmpty').style.display = 'none';
}

function updateNavBadge(id, count) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = count;
  el.classList.toggle('has-data', count > 0);
}

// ============================================================================
// Ports Table
// ============================================================================

const PORT_RISK_NOTES = {
  21: '⚠ FTP — cleartext credential transmission',
  23: '🔴 Telnet — completely unencrypted remote access',
  80: '⚠ HTTP — no TLS encryption',
  110: '⚠ POP3 — cleartext',
  143: '⚠ IMAP — cleartext',
  3389: '⚠ RDP exposed — brute-force risk',
  5900: '⚠ VNC exposed',
  6379: '🔴 Redis exposed — no auth by default',
  27017: '🔴 MongoDB exposed — no auth by default',
  1433: '⚠ MSSQL exposed',
  3306: '⚠ MySQL exposed',
  5432: '⚠ PostgreSQL exposed',
};

function populatePorts(ports) {
  const tbody = document.getElementById('portsTableBody');
  document.getElementById('portsCount').textContent = `${ports.length} ports`;
  updateNavBadge('badgePorts', ports.length);

  if (!ports.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">No open ports discovered</div></td></tr>`;
    return;
  }

  tbody.innerHTML = ports.map(p => {
    const note = PORT_RISK_NOTES[p.port] || '';
    const latency = p.latency_ms ? `${p.latency_ms}ms` : '—';
    const banner = p.banner ? escHtml(p.banner.slice(0, 80)) : '—';
    const version = p.version && p.version !== 'Unknown' ? escHtml(p.version) : '—';
    return `
      <tr>
        <td class="mono"><strong>${p.port}</strong></td>
        <td><span class="badge badge-open">● open</span></td>
        <td>${escHtml(p.service)}</td>
        <td class="mono" style="font-size:11.5px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${version}</td>
        <td class="mono">${latency}</td>
        <td style="font-size:12px;color:var(--text-3);">${note || '—'}</td>
      </tr>`;
  }).join('');
}

// ============================================================================
// Vulnerabilities
// ============================================================================

function initVulnFilters() {
  const search = document.getElementById('vulnSearch');
  const pills = document.querySelectorAll('.filter-pills .pill');

  search.addEventListener('input', filterVulns);
  pills.forEach(p => {
    p.addEventListener('click', () => {
      pills.forEach(pp => pp.classList.remove('active'));
      p.classList.add('active');
      currentSevFilter = p.dataset.sev;
      filterVulns();
    });
  });
}

function filterVulns() {
  const q = (document.getElementById('vulnSearch').value || '').toLowerCase();
  const filtered = allVulnerabilities.filter(v => {
    const matchSev = currentSevFilter === 'ALL' || v.severity === currentSevFilter;
    const matchQ = !q || v.title.toLowerCase().includes(q) ||
      (v.description || '').toLowerCase().includes(q) ||
      (v.severity || '').toLowerCase().includes(q);
    return matchSev && matchQ;
  });
  renderVulnList(filtered);
}

function populateVulnerabilities(vulns) {
  updateNavBadge('badgeVulns', vulns.length);
  renderVulnList(vulns);
}

function renderVulnList(vulns) {
  const list = document.getElementById('vulnList');
  if (!vulns.length) {
    list.innerHTML = `<div class="empty-state" style="padding:40px;">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>
      No vulnerabilities match filters</div>`;
    return;
  }

  list.innerHTML = vulns.map((v, i) => `
    <div class="vuln-item" id="vuln-${i}" onclick="toggleVuln(${i})">
      <div class="vuln-row-top">
        <div class="vuln-title">${escHtml(v.title)}</div>
        <div class="vuln-meta">
          <span class="cvss-score">${v.cvss_score?.toFixed(1) || '—'}</span>
          <span class="sev-badge ${escHtml(v.severity || 'None')}">${escHtml(v.severity || 'None')}</span>
        </div>
      </div>
      <div class="vuln-desc">${escHtml((v.description || '').slice(0, 160))}${(v.description||'').length > 160 ? '…' : ''}</div>
      <div class="vuln-body">
        <div class="vuln-rec" style="margin-bottom:6px;">💡 ${escHtml(v.recommendation || '')}</div>
        ${v.vector_string ? `<div class="vuln-vector">CVSS Vector: ${escHtml(v.vector_string)}</div>` : ''}
        ${v.cve_id ? `<div class="vuln-vector">CVE: ${escHtml(v.cve_id)}</div>` : ''}
      </div>
    </div>`).join('');
}

function toggleVuln(i) {
  document.getElementById(`vuln-${i}`)?.classList.toggle('expanded');
}

// ============================================================================
// SSL / TLS
// ============================================================================

function populateSSL(ssl) {
  const el = document.getElementById('sslContent');
  if (!ssl || !ssl.enabled) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No TLS data available for this target (port 443/8443 not open or no TLS).</div>`;
    return;
  }

  const ciphers = (ssl.supported_ciphers || []).map(c => {
    const cls = (c.includes('NULL') || c.includes('EXPORT') || c.includes('RC4')) ? 'tag-bad' : 'tag-ok';
    return `<span class="tag ${cls}">${escHtml(c)}</span>`;
  }).join('');

  const protocols = (ssl.protocols || []).map(p => {
    const cls = (p.includes('1.0') || p.includes('1.1') || p.includes('SSLv')) ? 'tag-warn' : 'tag-ok';
    return `<span class="tag ${cls}">${escHtml(p)}</span>`;
  }).join('');

  const cert = ssl.certificate || {};

  el.innerHTML = `
    <div class="ssl-grid" style="padding:16px;">
      <div>
        <div class="card-header" style="padding:0 0 10px;border-bottom:1px solid var(--border-1);margin-bottom:10px;">
          <div class="card-title">Certificate Details</div>
        </div>
        ${infoRow('Subject', cert.subject || '—')}
        ${infoRow('Issuer', cert.issuer || '—')}
        ${infoRow('Not Before', cert.not_before || '—')}
        ${infoRow('Not After', cert.not_after || '—')}
        ${infoRow('Days Remaining', cert.days_remaining != null ? `${cert.days_remaining}d` : '—')}
        ${infoRow('Self-Signed', cert.is_self_signed ? '⚠ Yes' : '✓ No')}
        ${infoRow('Wildcard', cert.is_wildcard ? 'Yes' : 'No')}
      </div>
      <div>
        <div class="card-header" style="padding:0 0 10px;border-bottom:1px solid var(--border-1);margin-bottom:10px;">
          <div class="card-title">Protocols & Ciphers</div>
        </div>
        <div style="margin-bottom:12px;">
          <div class="metric-label" style="margin-bottom:6px;">TLS Protocols</div>
          <div class="tag-list">${protocols || '<span class="tag tag-info">None detected</span>'}</div>
        </div>
        <div>
          <div class="metric-label" style="margin-bottom:6px;">Cipher Suites</div>
          <div class="tag-list">${ciphers || '<span class="tag tag-info">None detected</span>'}</div>
        </div>
        ${ssl.heartbleed ? '<div style="margin-top:12px;"><span class="sev-badge Critical">HEARTBLEED VULNERABLE</span></div>' : ''}
        ${ssl.poodle ? '<div style="margin-top:6px;"><span class="sev-badge High">POODLE VULNERABLE</span></div>' : ''}
      </div>
    </div>`;
}

// ============================================================================
// Web Audit
// ============================================================================

function populateWeb(web) {
  const el = document.getElementById('webAuditContent');
  if (!web || !web.is_web) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No web application found on scanned ports.</div>`;
    return;
  }

  const headers = (web.missing_headers || []);
  const foundHeaders = (web.present_headers || []);
  const paths = (web.sensitive_paths || []);
  const redirects = web.redirects_to_https;

  el.innerHTML = `
    <div>
      <div class="web-check-item">
        ${checkIcon(redirects)} 
        <div>
          <div class="check-title">HTTPS Redirect</div>
          <div class="check-desc">${redirects ? 'HTTP traffic redirected to HTTPS' : 'HTTP does NOT redirect to HTTPS'}</div>
        </div>
      </div>
      ${foundHeaders.map(h => `
        <div class="web-check-item">
          ${checkIcon(true)}
          <div>
            <div class="check-title">${escHtml(h)}</div>
            <div class="check-desc">Security header present</div>
          </div>
        </div>`).join('')}
      ${headers.map(h => `
        <div class="web-check-item">
          ${checkIcon(false)}
          <div>
            <div class="check-title">${escHtml(h)}</div>
            <div class="check-desc">Missing security header — adds attack surface</div>
          </div>
        </div>`).join('')}
      ${paths.map(p => `
        <div class="web-check-item">
          <div class="check-icon warn">⚠</div>
          <div>
            <div class="check-title">Sensitive path exposed: <span class="mono">${escHtml(p.path)}</span></div>
            <div class="check-desc">Status ${p.status} — ${escHtml(p.title || 'Potentially sensitive endpoint')}</div>
          </div>
        </div>`).join('')}
    </div>`;
}

// ============================================================================
// DNS
// ============================================================================

function populateDNS(dns) {
  const el = document.getElementById('dnsContent');
  if (!dns) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No DNS data available.</div>`;
    return;
  }

  function spfRow(spf) {
    if (!spf) return '';
    return `
      <div class="info-row">
        <span class="info-label">SPF</span>
        <span class="info-value">${spf.is_secure ? '✓ Secure' : '✗ Missing or weak'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">SPF Record</span>
        <span class="info-value" style="max-width:400px;word-break:break-all;">${escHtml(spf.record || '—')}</span>
      </div>`;
  }

  function dmarcRow(dmarc) {
    if (!dmarc) return '';
    return `
      <div class="info-row">
        <span class="info-label">DMARC</span>
        <span class="info-value">${dmarc.is_secure ? '✓ Secure' : '✗ Missing or weak'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">DMARC Policy</span>
        <span class="info-value">${escHtml(dmarc.policy || '—')}</span>
      </div>`;
  }

  const records = dns.records || {};
  const recordTypes = Object.keys(records);

  el.innerHTML = `
    <div style="padding:16px;">
      <div style="margin-bottom:20px;">
        ${spfRow(dns.spf)}
        ${dmarcRow(dns.dmarc)}
        ${dns.is_ip ? '<div class="info-row"><span class="info-label">Note</span><span class="info-value">Target is an IP — DNS spoofing analysis limited</span></div>' : ''}
      </div>
      ${recordTypes.length ? `
        <div class="card-title" style="margin-bottom:12px;">DNS Records</div>
        ${recordTypes.map(type => {
          const vals = records[type];
          if (!vals || !vals.length) return '';
          return vals.map(v => `<div class="dns-record"><span class="dns-type">${type}</span>${escHtml(v)}</div>`).join('');
        }).join('')}` : ''}
    </div>`;
}

// ============================================================================
// Playbooks
// ============================================================================

function populatePlaybooks(playbooks) {
  const el = document.getElementById('playbooksContent');
  if (!playbooks.length) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No remediation playbooks generated.</div>`;
    return;
  }

  el.innerHTML = playbooks.map(pb => `
    <div class="playbook-item">
      <div class="playbook-title">${escHtml(pb.title || 'Hardening Recommendation')}</div>
      ${pb.description ? `<p style="font-size:12.5px;color:var(--text-3);margin-bottom:10px;">${escHtml(pb.description)}</p>` : ''}
      ${pb.code ? `<div class="code-block">${escHtml(pb.code)}</div>` : ''}
      ${pb.steps ? pb.steps.map(s => `<div class="code-block" style="margin-top:6px;">${escHtml(s)}</div>`).join('') : ''}
    </div>`).join('');
}

// ============================================================================
// Intelligence Module Buttons
// ============================================================================

function initIntelButtons() {
  document.getElementById('btnRunHeaders').addEventListener('click', () => runIntelModule('headers'));
  document.getElementById('btnRunGeo').addEventListener('click', () => runIntelModule('geo'));
  document.getElementById('btnRunTech').addEventListener('click', () => runIntelModule('tech'));
  document.getElementById('btnRunSubdomains').addEventListener('click', () => runIntelModule('subdomains'));
  document.getElementById('btnRunCerts').addEventListener('click', () => runIntelModule('certs'));
}

async function runIntelModule(module) {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) {
    showToast('Enter a target in the scanbar first.', 'error');
    return;
  }

  const btnId = {
    headers: 'btnRunHeaders', geo: 'btnRunGeo', tech: 'btnRunTech',
    subdomains: 'btnRunSubdomains', certs: 'btnRunCerts'
  }[module];

  const btn = document.getElementById(btnId);
  const origContent = btn.innerHTML;
  btn.classList.add('running');
  btn.innerHTML = `<svg class="spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Running…`;
  btn.disabled = true;

  try {
    const resp = await fetch(`/api/intel?target=${encodeURIComponent(target)}&module=${module}`);
    if (!resp.ok) throw new Error(`Server error ${resp.status}`);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);

    switch (module) {
      case 'headers':    renderHeaderGrade(data); break;
      case 'geo':        renderGeo(data); break;
      case 'tech':       renderTech(data); break;
      case 'subdomains': renderSubdomains(data); break;
      case 'certs':      renderCerts(data); break;
    }
    showToast(`${module} analysis complete`, 'success');
  } catch (err) {
    showToast(`Error: ${err.message}`, 'error');
  } finally {
    btn.innerHTML = origContent;
    btn.classList.remove('running');
    btn.disabled = false;
  }
}

// ============================================================================
// Header Grader Render
// ============================================================================

function renderHeaderGrade(data) {
  const el = document.getElementById('headersContent');
  if (data.error) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">⚠ ${escHtml(data.error)}</div>`;
    return;
  }

  const grade = data.grade;
  const score = data.score;
  const gradeClass = grade.replace('+', 'plus');
  const pct = score;

  let scoreColor = '#22c55e';
  if (score < 35) scoreColor = '#ef4444';
  else if (score < 50) scoreColor = '#f97316';
  else if (score < 65) scoreColor = '#eab308';
  else if (score < 80) scoreColor = '#84cc16';

  const infoLeaks = data.info_leaks || [];
  const found = data.headers_found || [];
  const missing = data.headers_missing || [];

  el.innerHTML = `
    <div class="grade-display">
      <div class="grade-letter ${gradeClass}">${grade}</div>
      <div class="grade-info">
        <div class="grade-title">Security Header Score: ${score}/100</div>
        <div class="grade-sub">Graded ${found.length} present, ${missing.length} missing — ${data.url}</div>
        <div class="grade-score-bar">
          <div class="grade-score-fill" style="width:${pct}%;background:${scoreColor};"></div>
        </div>
      </div>
      ${infoLeaks.length ? `<div>
        ${infoLeaks.map(l => `<div class="risk-flag">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Info leak: <span class="mono">${escHtml(l.header)}: ${escHtml(l.value.slice(0, 40))}</span>
        </div>`).join('')}
      </div>` : ''}
    </div>
    ${found.map(h => `
      <div class="header-row">
        <div class="header-check ok">✓</div>
        <div class="header-name">${escHtml(h.label)}</div>
        <div class="header-desc">${escHtml(h.description)}</div>
        <div class="header-pts">+${h.weight}pts</div>
      </div>`).join('')}
    ${missing.map(h => `
      <div class="header-row">
        <div class="header-check bad">✕</div>
        <div class="header-name" style="color:var(--red);">${escHtml(h.label)}</div>
        <div class="header-desc">${escHtml(h.description)}</div>
        <div class="header-pts" style="color:var(--red);">-${h.weight}pts</div>
      </div>`).join('')}`;
}

// ============================================================================
// Geo / WHOIS Render
// ============================================================================

function renderGeo(data) {
  const el = document.getElementById('geoContent');
  if (data.error) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">⚠ ${escHtml(data.error)}</div>`;
    return;
  }

  const geo = data.geo || {};
  const rdap = data.rdap || {};
  const abuse = data.abuse || {};

  const flagEmoji = geo.country_code ? countryFlag(geo.country_code) : '🌐';

  el.innerHTML = `
    <div class="geo-grid" style="padding:16px;gap:20px;">
      <div>
        <div class="flag">${flagEmoji}</div>
        <div class="geo-primary">${escHtml(geo.city || '')}${geo.city && geo.country ? ', ' : ''}${escHtml(geo.country || 'Unknown location')}</div>
        <div class="geo-sub">${escHtml(geo.region || '')} · ${escHtml(geo.timezone || '')}</div>

        ${(abuse.risk_flags || []).map(f => `<div class="risk-flag">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/></svg>
          ${escHtml(f)}</div>`).join('')}

        <div style="margin-top:14px;">
          ${infoRow('IP', data.ip || '—')}
          ${infoRow('ISP', geo.isp || '—')}
          ${infoRow('Organization', geo.org || '—')}
          ${infoRow('ASN', geo.asn || '—')}
          ${infoRow('Reverse DNS', geo.reverse_dns || '—')}
          ${infoRow('Lat / Lon', geo.latitude != null ? `${geo.latitude}, ${geo.longitude}` : '—')}
          ${infoRow('Mobile Network', geo.is_mobile ? 'Yes' : 'No')}
          ${infoRow('Proxy / VPN', geo.is_proxy ? '⚠ Yes' : 'No')}
          ${infoRow('Hosting / DC', geo.is_hosting ? 'Yes' : 'No')}
        </div>
      </div>

      <div>
        <div class="card-title" style="margin-bottom:12px;">RDAP Registration</div>
        ${infoRow('Name', rdap.name || '—')}
        ${infoRow('Handle', rdap.handle || '—')}
        ${infoRow('Type', rdap.type || '—')}
        ${infoRow('Range Start', rdap.start_address || '—')}
        ${infoRow('Range End', rdap.end_address || '—')}
        ${infoRow('Country', rdap.country || '—')}
        ${infoRow('Abuse Email', rdap.abuse_email || '—')}
        ${rdap.rdap_link ? `<div class="info-row">
          <span class="info-label">RDAP Source</span>
          <a href="${escHtml(rdap.rdap_link)}" target="_blank" style="color:var(--accent);font-size:11.5px;">View Raw ↗</a>
        </div>` : ''}
      </div>
    </div>`;
}

// Country flag emoji helper
function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  const offset = 0x1F1E6;
  return String.fromCodePoint(...code.toUpperCase().split('').map(c => c.charCodeAt(0) - 65 + offset));
}

// ============================================================================
// Tech Fingerprint Render
// ============================================================================

const TECH_ICONS = {
  'Nginx': '🟢', 'Apache': '🔴', 'LiteSpeed': '⚡', 'Microsoft IIS': '🪟',
  'Caddy': '🔷', 'OpenResty': '🟢', 'PHP': '🐘', 'ASP.NET': '🪟',
  'Express.js': '🚂', 'Next.js': '▲', 'Cloudflare': '🟠', 'AWS CloudFront': '🟡',
  'Azure CDN': '🔵', 'Sucuri WAF': '🛡', 'DataDome': '🤖', 'WordPress': '📝',
  'Drupal': '💧', 'Joomla': '🔴', 'Shopify': '🛍', 'Wix': '🌐', 'Ghost': '👻',
};

const CAT_COLORS = {
  'Web Server': 'var(--green)', 'CDN/WAF': 'var(--orange)', 'CDN': 'var(--yellow)',
  'WAF': 'var(--red)', 'Framework': 'var(--accent)', 'Language': 'var(--purple)',
  'CMS': 'var(--green)', 'E-Commerce': 'var(--orange)', 'Website Builder': 'var(--text-3)',
  'Bot Protection': 'var(--red)',
};

function renderTech(data) {
  const el = document.getElementById('techContent');
  if (data.error) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">⚠ ${escHtml(data.error)}</div>`;
    return;
  }

  const techs = data.technologies || [];

  const summary = [];
  if (data.server) summary.push(`Server: <span class="mono">${escHtml(data.server)}</span>`);
  if (data.waf_detected) summary.push(`WAF: <strong>${escHtml(data.waf_detected)}</strong>`);
  if (data.cdn_detected) summary.push(`CDN: <strong>${escHtml(data.cdn_detected)}</strong>`);

  if (!techs.length) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No technologies detected — target may block fingerprinting.</div>`;
    return;
  }

  el.innerHTML = `
    ${summary.length ? `<div style="padding:12px 16px;border-bottom:1px solid var(--border-1);font-size:12.5px;color:var(--text-3);">${summary.join(' · ')}</div>` : ''}
    <div class="tech-grid">
      ${techs.map(t => `
        <div class="tech-chip">
          <div class="tech-chip-icon">${TECH_ICONS[t.name] || '🔧'}</div>
          <div>
            <div class="tech-name">${escHtml(t.name)}</div>
            <div class="tech-cat" style="color:${CAT_COLORS[t.category] || 'var(--text-3)'};">${escHtml(t.category)}</div>
          </div>
        </div>`).join('')}
    </div>`;
}

// ============================================================================
// Subdomains Render
// ============================================================================

let allSubdomains = [];

function renderSubdomains(data) {
  const empty = document.getElementById('subdomainsEmpty');
  const toolbar = document.getElementById('subdomainsToolbar');
  const table = document.getElementById('subdomainsTable');
  const tbody = document.getElementById('subdomainsTableBody');
  const badge = document.getElementById('badgeSubdomains');

  if (data.error) {
    empty.innerHTML = `<div class="empty-state" style="padding:40px;">⚠ ${escHtml(data.error)}</div>`;
    return;
  }

  allSubdomains = data.subdomains || [];
  badge.textContent = allSubdomains.length;
  badge.classList.add('has-data');

  if (!allSubdomains.length) {
    empty.innerHTML = `<div class="empty-state" style="padding:40px;">No subdomains found in certificate transparency logs for <strong>${escHtml(data.domain)}</strong>.</div>`;
    return;
  }

  document.getElementById('subdomainCount').textContent = `${allSubdomains.length} subdomains from crt.sh`;
  toolbar.style.display = '';
  table.style.display = '';
  empty.style.display = 'none';

  renderSubdomainRows(allSubdomains);

  document.getElementById('subdomainSearch').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    renderSubdomainRows(allSubdomains.filter(s => s.subdomain.includes(q)));
  });
}

function renderSubdomainRows(subs) {
  const tbody = document.getElementById('subdomainsTableBody');
  tbody.innerHTML = subs.map(s => `
    <tr>
      <td class="mono" style="font-size:12.5px;">${escHtml(s.subdomain)}</td>
      <td style="font-size:12px;color:var(--text-3);">${escHtml(s.issuer.slice(0, 60))}</td>
      <td class="mono" style="font-size:12px;color:var(--text-3);">${s.not_before?.slice(0,10) || '—'}</td>
      <td class="mono" style="font-size:12px;color:var(--text-3);">${s.not_after?.slice(0,10) || '—'}</td>
    </tr>`).join('');
}

// ============================================================================
// Certificate Transparency Render
// ============================================================================

function renderCerts(data) {
  const el = document.getElementById('certsContent');
  if (data.error) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">⚠ ${escHtml(data.error)}</div>`;
    return;
  }

  const certs = data.certificates || [];
  if (!certs.length) {
    el.innerHTML = `<div class="empty-state" style="padding:40px;">No certificates found for <strong>${escHtml(data.domain)}</strong>.</div>`;
    return;
  }

  el.innerHTML = `
    <div style="padding:10px 16px;border-bottom:1px solid var(--border-1);font-size:12px;color:var(--text-3);">
      Showing ${certs.length} most recent certificates (of ${data.total} total) — source: crt.sh
    </div>
    ${certs.map(c => {
      const daysLeft = c.days_remaining;
      let expiryClass = '';
      let expiryLabel = c.not_after?.slice(0, 10) || '—';
      if (c.is_expired) { expiryClass = 'expired'; expiryLabel += ' (expired)'; }
      else if (daysLeft != null && daysLeft < 30) { expiryClass = 'expiring-soon'; expiryLabel += ` (${daysLeft}d left)`; }

      return `
        <div class="cert-item">
          <div class="cert-row-top">
            <div class="cert-cn">${escHtml(c.common_name || c.name_value?.split('\n')[0] || '—')}</div>
            <div class="cert-expiry ${expiryClass}">${expiryLabel}</div>
          </div>
          <div class="cert-issuer">${escHtml(c.issuer?.slice(0, 100) || '—')}</div>
          ${c.name_value && c.name_value !== c.common_name ? `<div class="cert-issuer mono" style="font-size:11px;margin-top:2px;">${escHtml(c.name_value.split('\n').slice(0, 3).join(', '))}</div>` : ''}
        </div>`;
    }).join('')}`;
}

// ============================================================================
// Topology Canvas
// ============================================================================

function initTopologyCanvas() {
  const canvas = document.getElementById('topologyCanvas');
  if (!canvas) return;

  canvas.addEventListener('mousedown', e => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - topoOffsetX) / topoScale;
    const my = (e.clientY - rect.top - topoOffsetY) / topoScale;
    const node = topoNodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.r + 4);
    if (node) { topoDragging = node; }
    else { topoPanning = true; topoPanStart = { x: e.clientX - topoOffsetX, y: e.clientY - topoOffsetY }; }
  });

  canvas.addEventListener('mousemove', e => {
    if (topoDragging) {
      const rect = canvas.getBoundingClientRect();
      topoDragging.x = (e.clientX - rect.left - topoOffsetX) / topoScale;
      topoDragging.y = (e.clientY - rect.top - topoOffsetY) / topoScale;
      drawTopology();
    } else if (topoPanning) {
      topoOffsetX = e.clientX - topoPanStart.x;
      topoOffsetY = e.clientY - topoPanStart.y;
      drawTopology();
    }
  });

  canvas.addEventListener('mouseup', () => { topoDragging = null; topoPanning = false; });
  canvas.addEventListener('mouseleave', () => { topoDragging = null; topoPanning = false; });

  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    topoScale = Math.min(4, Math.max(0.3, topoScale * factor));
    drawTopology();
  }, { passive: false });

  document.getElementById('btnResetGraph')?.addEventListener('click', () => {
    topoScale = 1; topoOffsetX = 0; topoOffsetY = 0;
    if (topoNodes.length) layoutTopology(topoNodes[0]?.label);
    drawTopology();
  });
}

function buildTopologyGraph(data) {
  const canvas = document.getElementById('topologyCanvas');
  if (!canvas) return;

  topoNodes = [];
  topoEdges = [];
  const w = canvas.parentElement.clientWidth;
  const h = canvas.parentElement.clientHeight;
  canvas.width = w; canvas.height = h;

  const cx = w / 2, cy = h / 2;

  // Target node
  const target = { id: 'target', label: data.metadata.target, type: 'target', x: cx, y: cy, r: 22 };
  topoNodes.push(target);

  const ports = data.open_ports || [];
  const vulns = data.vulnerabilities || [];

  // Port nodes
  ports.forEach((p, i) => {
    const angle = (i / ports.length) * Math.PI * 2 - Math.PI / 2;
    const dist = 130;
    const node = {
      id: `port-${p.port}`,
      label: `${p.port}`,
      sublabel: p.service.split(' ')[0],
      type: 'port',
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      r: 16
    };
    topoNodes.push(node);
    topoEdges.push({ from: 'target', to: node.id });
  });

  // Vuln nodes (attach to relevant port node)
  const highVulns = vulns.filter(v => ['Critical', 'High'].includes(v.severity)).slice(0, 8);
  highVulns.forEach((v, i) => {
    const portMatch = ports.find(p => v.title.includes(String(p.port)));
    const parentId = portMatch ? `port-${portMatch.port}` : 'target';
    const parent = topoNodes.find(n => n.id === parentId);
    if (!parent) return;
    const angle = (i / highVulns.length) * Math.PI * 2 + 0.3;
    const node = {
      id: `vuln-${i}`,
      label: v.severity,
      sublabel: v.cvss_score?.toFixed(1) || '',
      type: 'vuln',
      x: parent.x + Math.cos(angle) * 70,
      y: parent.y + Math.sin(angle) * 70,
      r: 12
    };
    topoNodes.push(node);
    topoEdges.push({ from: parentId, to: node.id });
  });

  topoScale = 1; topoOffsetX = 0; topoOffsetY = 0;
  drawTopology();
}

function drawTopology() {
  const canvas = document.getElementById('topologyCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.save();
  ctx.translate(topoOffsetX, topoOffsetY);
  ctx.scale(topoScale, topoScale);

  const getNode = id => topoNodes.find(n => n.id === id);

  // Draw edges
  topoEdges.forEach(e => {
    const a = getNode(e.from), b = getNode(e.to);
    if (!a || !b) return;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.strokeStyle = '#2a2a2a';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  });

  // Draw nodes
  topoNodes.forEach(n => {
    const colors = {
      target: { fill: '#1d4ed8', stroke: '#3b82f6', text: '#fff' },
      port:   { fill: '#14532d', stroke: '#22c55e', text: '#86efac' },
      vuln:   { fill: '#7f1d1d', stroke: '#ef4444', text: '#fca5a5' },
    };
    const c = colors[n.type] || colors.port;

    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = c.fill;
    ctx.fill();
    ctx.strokeStyle = c.stroke;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.fillStyle = c.text;
    ctx.font = `bold ${n.r < 14 ? 9 : 11}px Inter`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(n.label, n.x, n.y - (n.sublabel ? 4 : 0));

    if (n.sublabel) {
      ctx.font = `9px Inter`;
      ctx.fillStyle = c.text + 'aa';
      ctx.fillText(n.sublabel, n.x, n.y + 7);
    }
  });

  ctx.restore();
}

// ============================================================================
// Export
// ============================================================================

function initExport() {
  const btn = document.getElementById('btnExportToggle');
  const menu = document.getElementById('exportMenu');
  if (!btn || !menu) return;

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('open');
  });

  document.addEventListener('click', () => menu.classList.remove('open'));
}

function exportReport(format) {
  window.location.href = `/api/export?format=${format}`;
  document.getElementById('exportMenu').classList.remove('open');
}

// ============================================================================
// Helpers
// ============================================================================

function infoRow(label, value) {
  return `<div class="info-row">
    <span class="info-label">${escHtml(String(label))}</span>
    <span class="info-value">${escHtml(String(value))}</span>
  </div>`;
}

function checkIcon(pass) {
  if (pass) {
    return `<div class="check-icon pass">
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
    </div>`;
  }
  return `<div class="check-icon fail">
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
  </div>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function logLine(msg, cls = 'info') {
  const tb = document.getElementById('terminalBody');
  if (!tb) return;
  const d = document.createElement('div');
  d.className = `log-line ${cls}`;
  d.textContent = msg;
  tb.appendChild(d);
  tb.scrollTop = tb.scrollHeight;
}

function setProgress(pct) {
  const fill = document.getElementById('progressFill');
  if (fill) {
    fill.classList.remove('indeterminate');
    fill.style.width = `${pct}%`;
  }
}

function showProgressMsg(msg) {
  const el = document.getElementById('progressMsg');
  if (el) { el.textContent = msg; el.classList.add('visible'); }
}

function hideProgressMsg() {
  const el = document.getElementById('progressMsg');
  if (el) el.classList.remove('visible');
}

function setSidebarStatus(state, label) {
  const dot = document.getElementById('sidebarDot');
  const txt = document.getElementById('sidebarStatus');
  if (dot) dot.className = `status-dot${state === 'scanning' ? ' scanning' : state === 'error' ? ' error' : ''}`;
  if (txt) txt.textContent = label;
}

function resetDisplayData() {
  currentData = null;
  allVulnerabilities = [];
  document.getElementById('riskScore').textContent = '—';
  document.getElementById('totalFindings').textContent = '0';
  document.getElementById('openPortsCount').textContent = '0';
  document.getElementById('scanDuration').textContent = '—';
  document.getElementById('scanTimestamp').textContent = 'running…';
  document.getElementById('teleTarget').textContent = document.getElementById('targetInput').value.trim();
  document.getElementById('teleIP').textContent = '—';
  ['sevCritical', 'sevHigh', 'sevMedium', 'sevLow'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  document.getElementById('overviewEmpty').style.display = '';
  document.getElementById('vulnList').innerHTML = `<div class="empty-state" style="padding:40px;">Scan in progress…</div>`;
  document.getElementById('portsTableBody').innerHTML = `<tr><td colspan="6"><div class="empty-state">Scanning…</div></td></tr>`;
  updateNavBadge('badgePorts', 0);
  updateNavBadge('badgeVulns', 0);
  document.getElementById('exportWrapper').style.display = 'none';
}

function showToast(msg, type = 'info') {
  const area = document.getElementById('toastArea');
  if (!area) return;
  const icons = {
    success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    info:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    warn:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#eab308" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>',
  };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<div class="toast-icon">${icons[type] || icons.info}</div><span>${escHtml(msg)}</span>`;
  area.appendChild(toast);
  setTimeout(() => toast.remove(), 4500);
}
