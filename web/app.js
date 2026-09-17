/**
 * AegisScan: Tactical Cyber Operations Console Logic
 * Coordinates SSE real-time streaming, HTML5 Canvas Network Topology Graph,
 * dynamic tabs, CVSS gauge animation, and data export.
 */

// Global State
let currentAssessmentData = null;
let isScanning = false;
let activeEventSource = null;
let currentSeverityFilter = 'ALL';

// ==========================================================================
// Initialization & Event Listeners
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
  initFormControls();
  initTabs();
  initTopologyCanvas();
  initExportMenu();
});

function initFormControls() {
  const profileSelect = document.getElementById('profileSelect');
  const customPortsWrapper = document.getElementById('customPortsWrapper');
  const threadsRange = document.getElementById('threadsRange');
  const threadsValue = document.getElementById('threadsValue');
  const scanForm = document.getElementById('scanForm');
  const btnClearTerminal = document.getElementById('btnClearTerminal');
  const vulnFilterInput = document.getElementById('vulnFilterInput');
  const severityFilterPills = document.getElementById('severityFilterPills');

  profileSelect.addEventListener('change', (e) => {
    if (e.target.value === 'custom') {
      customPortsWrapper.style.display = 'flex';
      document.getElementById('customPortsInput').focus();
    } else {
      customPortsWrapper.style.display = 'none';
    }
  });

  threadsRange.addEventListener('input', (e) => {
    threadsValue.textContent = e.target.value;
  });

  scanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (isScanning) return;
    startScan();
  });

  btnClearTerminal.addEventListener('click', () => {
    document.getElementById('terminalBody').innerHTML = '';
  });

  vulnFilterInput.addEventListener('input', () => {
    filterVulnerabilities();
  });

  severityFilterPills.addEventListener('click', (e) => {
    const btn = e.target.closest('.pill-btn');
    if (!btn) return;
    severityFilterPills.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentSeverityFilter = btn.dataset.sev;
    filterVulnerabilities();
  });
}

function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const contentId = btn.dataset.tab;
      const targetContent = document.getElementById(contentId);
      if (targetContent) targetContent.classList.add('active');
    });
  });
}

// ==========================================================================
// Scan Orchestration & Real-Time SSE
// ==========================================================================
async function startScan() {
  const target = document.getElementById('targetInput').value.trim();
  const profile = document.getElementById('profileSelect').value;
  const customPorts = document.getElementById('customPortsInput').value.trim();
  const threads = parseInt(document.getElementById('threadsRange').value, 10);

  if (!target) {
    showToast('Please specify a target IP or domain');
    return;
  }

  isScanning = true;
  document.body.classList.add('is-scanning');
  document.getElementById('systemPulse').className = 'pulse-dot scanning';
  document.getElementById('systemStatusText').textContent = 'RECON IN PROGRESS';
  document.getElementById('btnLaunchText').textContent = 'AUDITING...';
  document.getElementById('btnLaunchScan').disabled = true;

  // Show progress bar
  const progressContainer = document.getElementById('progressBarContainer');
  const progressFill = document.getElementById('progressBarFill');
  const progressStatus = document.getElementById('progressStatusText');
  const progressPercent = document.getElementById('progressPercentageText');
  progressContainer.style.display = 'block';
  progressFill.style.width = '5%';
  progressPercent.textContent = '5%';
  progressStatus.textContent = `Resolving ${target}...`;

  // Reset Topology Graph
  resetTopology(target);

  // Clear or note in terminal
  appendTerminalLog(`[RECON] Initializing multi-vector scan against target: ${target}`, 'info');

  try {
    const payload = {
      target: target,
      profile: profile,
      custom_ports: customPorts,
      threads: threads
    };

    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const initial = await response.json();
    if (!initial.scan_id) {
      throw new Error(initial.error || 'Failed to initialize scan');
    }

    const scanId = initial.scan_id;
    listenToScanStream(scanId);

  } catch (err) {
    appendTerminalLog(`[ERROR] Scan initiation failed: ${err.message}`, 'crit');
    endScan();
    showToast(`Scan failed: ${err.message}`);
  }
}

function listenToScanStream(scanId) {
  if (activeEventSource) {
    activeEventSource.close();
  }

  const eventSource = new EventSource(`/api/stream?scan_id=${scanId}`);
  activeEventSource = eventSource;

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleStreamEvent(data);
    } catch (e) {
      console.error('Error parsing SSE event', e);
    }
  };

  eventSource.onerror = () => {
    eventSource.close();
    if (isScanning) {
      endScan();
    }
  };
}

function handleStreamEvent(data) {
  const progressFill = document.getElementById('progressBarFill');
  const progressStatus = document.getElementById('progressStatusText');
  const progressPercent = document.getElementById('progressPercentageText');

  if (data.type === 'status') {
    progressStatus.textContent = data.message;
    appendTerminalLog(`[STATUS] ${data.message}`, 'info');
  } else if (data.type === 'port_found') {
    appendTerminalLog(`[FOUND] Open port detected: ${data.port}/TCP (${data.service}) - ${data.latency_ms}ms`, 'found');
    addPortNodeToTopology(data.port, data.service, data.version);
    if (data.progress) {
      progressFill.style.width = `${data.progress}%`;
      progressPercent.textContent = `${data.progress}%`;
    }
  } else if (data.type === 'scan_progress') {
    progressFill.style.width = `${data.progress}%`;
    progressPercent.textContent = `${data.progress}%`;
  } else if (data.type === 'complete') {
    progressFill.style.width = '100%';
    progressPercent.textContent = '100%';
    progressStatus.textContent = 'Assessment finalized.';
    appendTerminalLog(`[SUCCESS] ${data.message}`, 'found');

    if (activeEventSource) {
      activeEventSource.close();
      activeEventSource = null;
    }

    currentAssessmentData = data.data;
    renderAssessmentResults(currentAssessmentData);
    endScan();
    showToast('Cybersecurity assessment completed successfully');
  } else if (data.type === 'error') {
    appendTerminalLog(`[ERROR] ${data.message}`, 'crit');
    endScan();
    showToast(data.message);
  }
}

function endScan() {
  isScanning = false;
  document.body.classList.remove('is-scanning');
  document.getElementById('systemPulse').className = 'pulse-dot idle';
  document.getElementById('systemStatusText').textContent = 'AUDIT COMPLETE';
  document.getElementById('btnLaunchText').textContent = 'EXECUTE AUDIT';
  document.getElementById('btnLaunchScan').disabled = false;
  document.getElementById('btnExportMenu').style.display = 'inline-flex';
}

function appendTerminalLog(message, level = 'info') {
  const terminal = document.getElementById('terminalBody');
  const timestamp = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = `log-line ${level}`;
  line.textContent = `[${timestamp}] ${message}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// ==========================================================================
// Dashboard Data Rendering
// ==========================================================================
function renderAssessmentResults(data) {
  if (!data) return;

  const { metadata, risk_summary, open_ports, vulnerabilities, ssl_audit, web_audit, dns_audit, remediations } = data;

  // 1. Telemetry Top Row
  document.getElementById('telemetryIp').textContent = `${metadata.target} (${metadata.resolved_ip})`;
  document.getElementById('telemetryOpenPorts').textContent = open_ports.length;
  document.getElementById('telemetryDuration').textContent = `${metadata.scan_duration_seconds}s`;

  // 2. Risk Gauge & Severity Counts
  const avgCvss = risk_summary.cvss_average;
  const overallRisk = risk_summary.overall_risk;
  document.getElementById('gaugeScore').textContent = avgCvss.toFixed(1);
  document.getElementById('gaugeTier').textContent = overallRisk.toUpperCase();

  document.getElementById('countCritical').textContent = risk_summary.critical;
  document.getElementById('countHigh').textContent = risk_summary.high;
  document.getElementById('countMedium').textContent = risk_summary.medium;

  // Animate Gauge Meter (Circumference = 2 * PI * 68 ~= 427.26)
  const maxDash = 427.26;
  const fillOffset = maxDash - (avgCvss / 10.0) * maxDash;
  const meter = document.getElementById('gaugeMeter');
  meter.style.strokeDashoffset = fillOffset;

  if (overallRisk === 'Critical') {
    meter.style.stroke = 'var(--rose-crit)';
    document.getElementById('gaugeTier').style.color = 'var(--rose-crit)';
  } else if (overallRisk === 'High') {
    meter.style.stroke = 'var(--amber-warn)';
    document.getElementById('gaugeTier').style.color = 'var(--amber-warn)';
  } else if (overallRisk === 'Medium') {
    meter.style.stroke = 'var(--indigo-accent)';
    document.getElementById('gaugeTier').style.color = 'var(--indigo-accent)';
  } else {
    meter.style.stroke = 'var(--emerald-safe)';
    document.getElementById('gaugeTier').style.color = 'var(--emerald-safe)';
  }

  // 3. Tab Badge Counts
  document.getElementById('tabCountPorts').textContent = open_ports.length;
  document.getElementById('tabCountVulns').textContent = vulnerabilities.length;

  // 4. Populate Open Ports Table
  renderPortsTable(open_ports);

  // 5. Populate Web Audit Tab
  renderWebAudit(web_audit);

  // 6. Populate SSL/TLS Tab
  renderCryptoAudit(ssl_audit);

  // 7. Populate DNS Tab
  renderDnsAudit(dns_audit);

  // 8. Populate Vulnerabilities Tab
  renderVulnerabilities(vulnerabilities);

  // 9. Populate Remediation Playbooks
  renderPlaybooks(remediations);

  // 10. Update Topology with Vulnerability satellites
  populateTopologyVulnerabilities(vulnerabilities);
}

function renderPortsTable(ports) {
  const tbody = document.getElementById('portsTableBody');
  if (!ports || ports.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No open ports discovered.</td></tr>';
    return;
  }

  tbody.innerHTML = ports.map(p => `
    <tr>
      <td class="mono" style="font-weight: 700; color: var(--cyan-glow);">${p.port}/TCP</td>
      <td><span class="badge-open">OPEN</span></td>
      <td><strong>${escapeHtml(p.service)}</strong></td>
      <td class="mono">${escapeHtml(p.version)}</td>
      <td class="mono" style="color: var(--emerald-safe);">${p.latency_ms} ms</td>
      <td class="mono" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(p.banner || 'N/A')}</td>
    </tr>
  `).join('');
}

function renderWebAudit(web) {
  const container = document.getElementById('webAuditContainer');
  if (!web || !web.is_web) {
    container.innerHTML = '<div class="empty-state">No active HTTP/HTTPS web application detected on this target.</div>';
    return;
  }

  const presentHtml = web.present_headers.length > 0
    ? web.present_headers.map(h => `
        <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px; margin-bottom: 6px;">
          <span class="mono" style="color: var(--emerald-safe); font-weight: 700;">&#10003; ${escapeHtml(h.name)}</span>
          <span class="mono" style="font-size: 11px; color: var(--text-muted);">${escapeHtml(h.value.substring(0, 45))}...</span>
        </div>
      `).join('')
    : '<div style="color: var(--rose-crit); font-size: 12px;">No recommended OWASP defensive headers present.</div>';

  const missingHtml = web.missing_headers.length > 0
    ? web.missing_headers.map(h => `
        <div style="padding: 8px 12px; background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 4px; margin-bottom: 6px; color: var(--rose-crit); font-size: 12px;">
          &#10007; Missing <strong>${escapeHtml(h)}</strong>
        </div>
      `).join('')
    : '<div style="color: var(--emerald-safe); font-size: 12px;">All essential security headers configured!</div>';

  const pathsHtml = web.sensitive_paths.length > 0
    ? `
      <div style="margin-top: 20px;">
        <h4 style="font-size: 12px; letter-spacing: 0.08em; color: var(--rose-crit); text-transform: uppercase; margin-bottom: 8px;">Exposed Sensitive Endpoints</h4>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          ${web.sensitive_paths.map(p => `
            <div style="background: var(--bg-card); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--rose-crit);">
              <div style="display: flex; justify-content: space-between;">
                <span class="mono" style="color: #fff; font-weight: 700;">${escapeHtml(p.path)}</span>
                <span class="badge-open" style="background: var(--rose-dim); color: var(--rose-crit);">HTTP ${p.status} EXPOSED</span>
              </div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${escapeHtml(p.name)} &bull; ${escapeHtml(p.preview)}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `
    : '';

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div>
        <h3 style="font-size: 14px; color: #fff;">Web Target: <span class="mono" style="color: var(--cyan-glow);">${escapeHtml(web.url)}</span></h3>
        <div style="font-size: 11px; color: var(--text-muted);">HTTP Status: ${web.status_code} &bull; Server: ${escapeHtml(web.server_banner || 'Hidden')}</div>
      </div>
      <div>
        ${web.powered_by ? `<span class="version-tag" style="background: var(--amber-dim); color: var(--amber-warn); border-color: var(--amber-warn);">Powered by: ${escapeHtml(web.powered_by)}</span>` : ''}
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
      <div>
        <h4 style="font-size: 11px; letter-spacing: 0.08em; color: var(--emerald-safe); text-transform: uppercase; margin-bottom: 10px;">Enforced Defensive Headers (${web.present_headers.length})</h4>
        ${presentHtml}
      </div>
      <div>
        <h4 style="font-size: 11px; letter-spacing: 0.08em; color: var(--rose-crit); text-transform: uppercase; margin-bottom: 10px;">Missing Defensive Headers (${web.missing_headers.length})</h4>
        ${missingHtml}
      </div>
    </div>

    ${pathsHtml}
  `;
}

function renderCryptoAudit(crypto) {
  const container = document.getElementById('cryptoAuditContainer');
  if (!crypto || !crypto.enabled) {
    container.innerHTML = '<div class="empty-state">Target does not have an active SSL/TLS listener on probed ports.</div>';
    return;
  }

  const cert = crypto.certificate || {};

  container.innerHTML = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;">
      
      <!-- Certificate Details -->
      <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 18px;">
        <h4 style="font-size: 11px; letter-spacing: 0.08em; color: var(--cyan-glow); text-transform: uppercase; margin-bottom: 12px;">X.509 Certificate Chain</h4>
        <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12.5px;">
          <div><span style="color: var(--text-muted);">Common Name:</span> <strong style="color: #fff;">${escapeHtml(cert.common_name || 'N/A')}</strong></div>
          <div><span style="color: var(--text-muted);">Issuer:</span> ${escapeHtml(cert.issuer_common_name || 'N/A')} (${escapeHtml(cert.issuer_organization || 'N/A')})</div>
          <div><span style="color: var(--text-muted);">Valid From:</span> ${escapeHtml(cert.valid_from || 'N/A')}</div>
          <div><span style="color: var(--text-muted);">Expires:</span> <strong style="color: ${crypto.days_until_expiration < 14 ? 'var(--rose-crit)' : 'var(--emerald-safe)'}">${escapeHtml(cert.valid_to || 'N/A')}</strong> (${crypto.days_until_expiration} days remaining)</div>
          <div><span style="color: var(--text-muted);">Self-Signed:</span> ${crypto.is_self_signed ? '<span style="color: var(--rose-crit); font-weight: 700;">YES (Insecure)</span>' : '<span style="color: var(--emerald-safe);">NO (CA Verified)</span>'}</div>
        </div>
      </div>

      <!-- Cipher & Protocol -->
      <div style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 18px;">
        <h4 style="font-size: 11px; letter-spacing: 0.08em; color: var(--cyan-glow); text-transform: uppercase; margin-bottom: 12px;">Protocol & Cipher Suite</h4>
        <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12.5px;">
          <div><span style="color: var(--text-muted);">Negotiated Protocol:</span> <strong class="mono" style="color: #fff;">${escapeHtml(crypto.protocol_version || 'N/A')}</strong></div>
          <div><span style="color: var(--text-muted);">Cipher Suite:</span> <span class="mono" style="color: #38bdf8;">${escapeHtml(crypto.cipher_suite || 'N/A')}</span></div>
          <div><span style="color: var(--text-muted);">Key Encryption Strength:</span> <strong style="color: ${crypto.cipher_bits < 128 ? 'var(--rose-crit)' : 'var(--emerald-safe)'};">${crypto.cipher_bits} bits</strong></div>
          <div><span style="color: var(--text-muted);">Perfect Forward Secrecy (PFS):</span> ${crypto.has_pfs ? '<span style="color: var(--emerald-safe); font-weight: 700;">Enabled (ECDHE/DHE)</span>' : '<span style="color: var(--amber-warn);">Disabled</span>'}</div>
        </div>
      </div>

    </div>
  `;
}

function renderDnsAudit(dns) {
  const container = document.getElementById('dnsAuditContainer');
  if (!dns) {
    container.innerHTML = '<div class="empty-state">DNS audit not available.</div>';
    return;
  }

  if (dns.is_ip) {
    container.innerHTML = `
      <div style="background: var(--bg-card); padding: 18px; border-radius: 8px; border: 1px solid var(--border-subtle);">
        <h4 style="font-size: 12px; color: var(--cyan-glow); margin-bottom: 8px;">Direct IP Target</h4>
        <p style="color: var(--text-muted); font-size: 12.5px;">Target is a numerical IP address (${escapeHtml(dns.target_host)}). Reverse DNS PTR: <strong>${escapeHtml(dns.reverse_dns || 'None')}</strong>. SPF and DMARC checks are domain-specific and apply when querying hostnames.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 18px;">
      
      <!-- SPF Box -->
      <div style="background: var(--bg-card); padding: 18px; border-radius: 8px; border: 1px solid var(--border-subtle); border-left: 4px solid ${dns.spf.is_secure ? 'var(--emerald-safe)' : 'var(--rose-crit)'};">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <h4 style="font-size: 12px; font-weight: 700; color: #fff;">SENDER POLICY FRAMEWORK (SPF)</h4>
          <span class="vuln-badge ${dns.spf.is_secure ? 'low' : 'critical'}">${escapeHtml(dns.spf.mechanism)}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin: 8px 0;">${escapeHtml(dns.spf.details)}</div>
        ${dns.spf.record ? `<pre class="code-box" style="padding: 8px 10px; font-size: 11px;">${escapeHtml(dns.spf.record)}</pre>` : ''}
      </div>

      <!-- DMARC Box -->
      <div style="background: var(--bg-card); padding: 18px; border-radius: 8px; border: 1px solid var(--border-subtle); border-left: 4px solid ${dns.dmarc.is_secure ? 'var(--emerald-safe)' : 'var(--rose-crit)'};">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <h4 style="font-size: 12px; font-weight: 700; color: #fff;">DMARC SPOOFING DEFENSE (_dmarc)</h4>
          <span class="vuln-badge ${dns.dmarc.is_secure ? 'low' : 'critical'}">${escapeHtml(dns.dmarc.policy)}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); margin: 8px 0;">${escapeHtml(dns.dmarc.details)}</div>
        ${dns.dmarc.record ? `<pre class="code-box" style="padding: 8px 10px; font-size: 11px;">${escapeHtml(dns.dmarc.record)}</pre>` : ''}
      </div>

    </div>

    <!-- Resolved DNS Records -->
    <div style="background: var(--bg-card); padding: 14px 18px; border-radius: 8px; border: 1px solid var(--border-subtle);">
      <h4 style="font-size: 11px; letter-spacing: 0.08em; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Resolved DNS Infrastructure Records</h4>
      <div style="font-size: 12px; display: flex; flex-direction: column; gap: 4px;" class="mono">
        <div><span style="color: var(--cyan-glow);">A Records:</span> ${dns.a_records.join(', ') || 'None'}</div>
        <div><span style="color: var(--cyan-glow);">MX (Mail Servers):</span> ${dns.mx_records.join(', ') || 'None'}</div>
      </div>
    </div>
  `;
}

function renderVulnerabilities(vulnerabilities) {
  const container = document.getElementById('vulnCardsList');
  if (!vulnerabilities || vulnerabilities.length === 0) {
    container.innerHTML = '<div class="empty-state" style="color: var(--emerald-safe);">&#10003; Zero security vulnerabilities identified. Target satisfies security baselines.</div>';
    return;
  }

  filterVulnerabilities();
}

function filterVulnerabilities() {
  if (!currentAssessmentData) return;
  const vulnerabilities = currentAssessmentData.vulnerabilities || [];
  const keyword = document.getElementById('vulnFilterInput').value.toLowerCase();
  const container = document.getElementById('vulnCardsList');

  const filtered = vulnerabilities.filter(v => {
    const matchesSev = (currentSeverityFilter === 'ALL') || (v.severity.toLowerCase() === currentSeverityFilter.toLowerCase());
    const matchesKey = !keyword || (
      v.title.toLowerCase().includes(keyword) ||
      v.description.toLowerCase().includes(keyword) ||
      (v.vector_string && v.vector_string.toLowerCase().includes(keyword))
    );
    return matchesSev && matchesKey;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">No vulnerabilities match the selected filter criteria.</div>';
    return;
  }

  container.innerHTML = filtered.map(v => {
    const sevClass = v.severity.toLowerCase();
    return `
      <div class="vuln-card ${sevClass}">
        <div class="vuln-header">
          <div class="vuln-title">${escapeHtml(v.title)}</div>
          <div class="vuln-badge ${sevClass}">${escapeHtml(v.severity)} &bull; CVSS ${v.cvss_score}</div>
        </div>
        <div class="vuln-meta-row">
          <span>VECTOR: <strong>${escapeHtml(v.vector_string || 'CVSS:3.1/AV:N/...')}</strong></span>
        </div>
        <div class="vuln-desc">${escapeHtml(v.description)}</div>
        <div class="vuln-fix-box">
          <strong>Remediation:</strong> ${escapeHtml(v.recommendation)}
        </div>
      </div>
    `;
  }).join('');
}

function renderPlaybooks(remediations) {
  const container = document.getElementById('playbooksContainer');
  if (!remediations || remediations.length === 0) {
    container.innerHTML = '<div class="empty-state" style="color: var(--emerald-safe);">&#10003; No remediation actions required. System configurations adhere to security benchmarks.</div>';
    return;
  }

  container.innerHTML = remediations.map((rem, idx) => `
    <div class="playbook-block">
      <div class="playbook-header">
        <div class="playbook-title">&gt; ${escapeHtml(rem.title)}</div>
      </div>
      ${rem.nginx ? `
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">NGINX CONFIGURATION:</div>
        <div class="code-container">
          <pre class="code-box" id="code-nginx-${idx}">${escapeHtml(rem.nginx)}</pre>
          <button class="btn btn-xs btn-copy" onclick="copyCode('code-nginx-${idx}')">Copy Nginx</button>
        </div>
      ` : ''}
      ${rem.apache ? `
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 10px;">APACHE DIRECTIVES:</div>
        <div class="code-container">
          <pre class="code-box" id="code-apache-${idx}">${escapeHtml(rem.apache)}</pre>
          <button class="btn btn-xs btn-copy" onclick="copyCode('code-apache-${idx}')">Copy Apache</button>
        </div>
      ` : ''}
      ${rem.iptables ? `
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 10px;">LINUX FIREWALL (IPTABLES):</div>
        <div class="code-container">
          <pre class="code-box" id="code-iptables-${idx}">${escapeHtml(rem.iptables)}</pre>
          <button class="btn btn-xs btn-copy" onclick="copyCode('code-iptables-${idx}')">Copy Rules</button>
        </div>
      ` : ''}
      ${rem.dns_records ? `
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 10px;">DNS RESOURCE RECORDS:</div>
        <div class="code-container">
          <pre class="code-box" id="code-dns-${idx}">${escapeHtml(rem.dns_records)}</pre>
          <button class="btn btn-xs btn-copy" onclick="copyCode('code-dns-${idx}')">Copy Records</button>
        </div>
      ` : ''}
    </div>
  `).join('');
}

// ==========================================================================
// Interactive Attack Surface Network Topology Graph (HTML5 Canvas)
// ==========================================================================
let canvas, ctx, width, height;
let nodes = [];
let links = [];
let hoveredNode = null;
let draggedNode = null;
let radarAngle = 0;

function initTopologyCanvas() {
  canvas = document.getElementById('topologyCanvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');

  function resize() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    width = canvas.width;
    height = canvas.height;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  window.addEventListener('resize', resize);
  resize();

  // Mouse drag & hover listeners
  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    if (draggedNode) {
      draggedNode.x = mx;
      draggedNode.y = my;
      return;
    }

    hoveredNode = null;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = mx - n.x;
      const dy = my - n.y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
        hoveredNode = n;
        canvas.style.cursor = 'pointer';
        return;
      }
    }
    canvas.style.cursor = 'default';
  });

  canvas.addEventListener('mousedown', () => {
    if (hoveredNode) {
      draggedNode = hoveredNode;
    }
  });

  window.addEventListener('mouseup', () => {
    draggedNode = null;
  });

  document.getElementById('btnResetTopology').addEventListener('click', () => {
    const target = document.getElementById('targetInput').value.trim() || 'Target';
    resetTopology(target);
    if (currentAssessmentData) {
      currentAssessmentData.open_ports.forEach(p => addPortNodeToTopology(p.port, p.service, p.version));
      populateTopologyVulnerabilities(currentAssessmentData.vulnerabilities);
    }
  });

  requestAnimationFrame(topologyLoop);
}

function resetTopology(targetName) {
  const rect = canvas.getBoundingClientRect();
  const cx = rect.width / 2;
  const cy = rect.height / 2;

  nodes = [
    {
      id: 'target',
      label: targetName,
      type: 'target',
      x: cx,
      y: cy,
      vx: 0,
      vy: 0,
      radius: 20,
      color: '#00f0ff'
    }
  ];
  links = [];
}

function addPortNodeToTopology(port, service, version) {
  if (nodes.find(n => n.id === `port-${port}`)) return;

  const rect = canvas.getBoundingClientRect();
  const cx = rect.width / 2;
  const cy = rect.height / 2;
  const angle = Math.random() * Math.PI * 2;
  const dist = 100 + Math.random() * 50;

  const portNode = {
    id: `port-${port}`,
    port: port,
    label: `${port}/TCP`,
    sub: service,
    type: 'port',
    x: cx + Math.cos(angle) * dist,
    y: cy + Math.sin(angle) * dist,
    vx: (Math.random() - 0.5) * 2,
    vy: (Math.random() - 0.5) * 2,
    radius: 13,
    color: '#10b981'
  };

  nodes.push(portNode);
  links.push({ source: 'target', target: portNode.id });
}

function populateTopologyVulnerabilities(vulns) {
  if (!vulns) return;

  vulns.forEach((v, idx) => {
    const vid = `vuln-${idx}`;
    if (nodes.find(n => n.id === vid)) return;

    // Attach to matching port if found, or target
    let attachTo = 'target';
    for (let n of nodes) {
      if (n.type === 'port' && v.title.includes(String(n.port))) {
        attachTo = n.id;
        break;
      }
    }

    const parent = nodes.find(n => n.id === attachTo) || nodes[0];
    const angle = Math.random() * Math.PI * 2;
    const dist = 40 + Math.random() * 30;

    const vColor = v.severity === 'Critical' ? '#ef4444' : (v.severity === 'High' ? '#f59e0b' : '#6366f1');

    const vNode = {
      id: vid,
      label: `CVSS ${v.cvss_score}`,
      sub: v.severity,
      title: v.title,
      type: 'vuln',
      x: parent.x + Math.cos(angle) * dist,
      y: parent.y + Math.sin(angle) * dist,
      vx: 0,
      vy: 0,
      radius: 8,
      color: vColor
    };

    nodes.push(vNode);
    links.push({ source: attachTo, target: vid });
  });
}

function topologyLoop() {
  const rect = canvas.getBoundingClientRect();
  const cWidth = rect.width;
  const cHeight = rect.height;

  ctx.clearRect(0, 0, cWidth, cHeight);

  // 1. Draw radar sweep background
  radarAngle += 0.015;
  const centerNode = nodes[0];
  if (centerNode) {
    ctx.save();
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.08)';
    ctx.lineWidth = 1;
    [60, 120, 180, 240].forEach(r => {
      ctx.beginPath();
      ctx.arc(centerNode.x, centerNode.y, r, 0, Math.PI * 2);
      ctx.stroke();
    });

    if (isScanning) {
      ctx.beginPath();
      ctx.moveTo(centerNode.x, centerNode.y);
      ctx.arc(centerNode.x, centerNode.y, 240, radarAngle, radarAngle + 0.35);
      ctx.fillStyle = 'rgba(0, 240, 255, 0.05)';
      ctx.fill();
    }
    ctx.restore();
  }

  // 2. Physics simulation (Spring-Damping)
  for (let i = 1; i < nodes.length; i++) {
    const node = nodes[i];
    if (node === draggedNode) continue;

    // Repulsion between nodes
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue;
      const other = nodes[j];
      const dx = node.x - other.x;
      const dy = node.y - other.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      if (dist < 80) {
        const force = (80 - dist) / 80;
        node.vx += (dx / dist) * force * 0.5;
        node.vy += (dy / dist) * force * 0.5;
      }
    }
  }

  // Spring links
  links.forEach(l => {
    const source = nodes.find(n => n.id === l.source);
    const target = nodes.find(n => n.id === l.target);
    if (!source || !target) return;

    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const targetDist = target.type === 'vuln' ? 50 : 130;
    const force = (dist - targetDist) * 0.02;

    if (target !== draggedNode) {
      target.vx -= (dx / dist) * force;
      target.vy -= (dy / dist) * force;
    }
  });

  // Apply velocities & damping
  nodes.forEach(n => {
    if (n.type === 'target') return;
    if (n === draggedNode) return;
    n.vx *= 0.85;
    n.vy *= 0.85;
    n.x += n.vx;
    n.y += n.vy;

    // Bounds check
    n.x = Math.max(20, Math.min(cWidth - 20, n.x));
    n.y = Math.max(20, Math.min(cHeight - 20, n.y));
  });

  // 3. Draw Links
  links.forEach(l => {
    const source = nodes.find(n => n.id === l.source);
    const target = nodes.find(n => n.id === l.target);
    if (!source || !target) return;

    ctx.beginPath();
    ctx.moveTo(source.x, source.y);
    ctx.lineTo(target.x, target.y);
    ctx.strokeStyle = target.type === 'vuln' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(0, 240, 255, 0.25)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  });

  // 4. Draw Nodes
  nodes.forEach(n => {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    ctx.fillStyle = n.color;
    ctx.fill();

    ctx.strokeStyle = '#070b14';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Node labels
    ctx.font = n.type === 'target' ? 'bold 11px Plus Jakarta Sans' : '10px JetBrains Mono';
    ctx.fillStyle = '#f3f6fc';
    ctx.textAlign = 'center';
    ctx.fillText(n.label, n.x, n.y + n.radius + 14);

    if (n.sub) {
      ctx.font = '9px Plus Jakarta Sans';
      ctx.fillStyle = '#8899b5';
      ctx.fillText(n.sub, n.x, n.y + n.radius + 25);
    }
  });

  // 5. Draw Tooltip for Hovered Node
  if (hoveredNode) {
    ctx.save();
    ctx.font = '11px Plus Jakarta Sans';
    const text = hoveredNode.title || `${hoveredNode.label} (${hoveredNode.sub || ''})`;
    const textWidth = ctx.measureText(text).width;
    const tipX = Math.min(cWidth - textWidth - 24, Math.max(12, hoveredNode.x - textWidth / 2));
    const tipY = Math.max(16, hoveredNode.y - hoveredNode.radius - 28);

    ctx.fillStyle = 'rgba(13, 20, 36, 0.95)';
    ctx.strokeStyle = hoveredNode.color;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(tipX - 8, tipY - 14, textWidth + 16, 24, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#fff';
    ctx.textAlign = 'left';
    ctx.fillText(text, tipX, tipY + 2);
    ctx.restore();
  }

  requestAnimationFrame(topologyLoop);
}

// ==========================================================================
// Exports & Utilities
// ==========================================================================
function initExportMenu() {
  const btnExport = document.getElementById('btnExportMenu');
  btnExport.addEventListener('click', () => {
    if (!currentAssessmentData) {
      showToast('No assessment data to export');
      return;
    }

    const options = [
      { label: 'Download HTML Report', format: 'html' },
      { label: 'Export JSON Data', format: 'json' },
      { label: 'Export CSV Format', format: 'csv' },
      { label: 'Print / PDF Report', format: 'print' }
    ];

    const action = prompt("Select export format:\n1. HTML Executive Report\n2. JSON\n3. CSV\n4. Print / PDF", "1");
    if (action === "1") {
      triggerFileDownload('/api/export?format=html', `${currentAssessmentData.metadata.target}_report.html`);
    } else if (action === "2") {
      triggerFileDownload('/api/export?format=json', `${currentAssessmentData.metadata.target}_results.json`);
    } else if (action === "3") {
      triggerFileDownload('/api/export?format=csv', `${currentAssessmentData.metadata.target}_ports.csv`);
    } else if (action === "4") {
      window.print();
    }
  });
}

function triggerFileDownload(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function copyCode(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    showToast('Remediation code copied to clipboard');
  }).catch(() => {
    showToast('Failed to copy code');
  });
}

function showToast(message) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => container.removeChild(toast), 300);
  }, 3000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
