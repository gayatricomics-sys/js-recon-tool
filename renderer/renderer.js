const webview = document.getElementById('webview');
const urlInput = document.getElementById('url-input');
const sessionLabel = document.getElementById('session-label');
const authCheckbox = document.getElementById('auth-checkbox');
const authTarget = document.getElementById('auth-target');

const countFiles = document.getElementById('count-files');
const countEndpoints = document.getElementById('count-endpoints');
const countSecrets = document.getElementById('count-secrets');
const countDomXss = document.getElementById('count-domxss');

const jsFilesList = document.getElementById('jsfiles-list');
const jsFilesDetail = document.getElementById('jsfiles-detail');
const endpointsBody = document.querySelector('#endpoints-table tbody');
const secretsBody = document.querySelector('#secrets-table tbody');
const domXssBody = document.querySelector('#domxss-table tbody');

const filesByHash = new Map();
let currentHostname = null;

function normalizeUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return trimmed;
  return 'https://' + trimmed;
}

function navigateTo(raw) {
  const url = normalizeUrl(raw);
  if (!url) return;
  webview.loadURL(url);
}

document.getElementById('btn-back').addEventListener('click', () => webview.canGoBack() && webview.goBack());
document.getElementById('btn-forward').addEventListener('click', () => webview.canGoForward() && webview.goForward());
document.getElementById('btn-reload').addEventListener('click', () => webview.reload());
document.getElementById('btn-go').addEventListener('click', () => navigateTo(urlInput.value));
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') navigateTo(urlInput.value);
});

webview.addEventListener('dom-ready', () => {
  const id = webview.getWebContentsId();
  window.recon.webviewReady(id);
});

function updateNavState() {
  urlInput.value = webview.getURL();
  try {
    currentHostname = new URL(webview.getURL()).hostname;
  } catch (_) {
    currentHostname = null;
  }
  authTarget.textContent = currentHostname ? `(applies to: ${currentHostname})` : '';
  if (authCheckbox.checked) {
    window.recon.setAuthorized(true, currentHostname);
  }
}

webview.addEventListener('did-navigate', updateNavState);
webview.addEventListener('did-navigate-in-page', updateNavState);

document.getElementById('btn-start-session').addEventListener('click', async () => {
  const url = webview.getURL();
  if (!url || url === 'about:blank') {
    alert('Navigate to a target URL first, then start the session.');
    return;
  }
  const res = await window.recon.startSession(url);
  if (res.ok) {
    sessionLabel.textContent = `Session: ${res.sessionId}`;
    filesByHash.clear();
    jsFilesList.innerHTML = '';
    jsFilesDetail.textContent = 'Select a captured JS file to view its explanation and source.';
    endpointsBody.innerHTML = '';
    secretsBody.innerHTML = '';
    domXssBody.innerHTML = '';
    refreshCounts({ fileCount: 0, endpointCount: 0, secretCount: 0, domXssCount: 0 });
    authCheckbox.checked = false;
  }
});

authCheckbox.addEventListener('change', () => {
  window.recon.setAuthorized(authCheckbox.checked, currentHostname);
});

function refreshCounts(summary) {
  countFiles.textContent = summary.fileCount;
  countEndpoints.textContent = summary.endpointCount;
  countSecrets.textContent = summary.secretCount;
  countDomXss.textContent = summary.domXssCount;
}

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
  });
});

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

function addEndpointRow(e) {
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>${escapeHtml(e.context)}</td>
    <td>${escapeHtml(e.urlStructure.kind)}</td>
    <td>${escapeHtml(e.urlStructure.host || '-')}</td>
    <td><code>${escapeHtml(e.urlStructure.pathname || e.raw)}</code></td>
    <td>${escapeHtml(e.sourceFile)}</td>
    <td>${e.line != null ? e.line : '-'}</td>`;
  endpointsBody.appendChild(tr);
}

function addSecretRow(s) {
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>${escapeHtml(s.type)}</td>
    <td><code>${escapeHtml(s.redacted)}</code></td>
    <td>${s.length}</td>
    <td>${s.entropy}</td>
    <td>${escapeHtml(s.reason)}</td>
    <td>${escapeHtml(s.sourceFile)}</td>
    <td>${s.line != null ? s.line : '-'}</td>`;
  secretsBody.appendChild(tr);
}

function addDomXssRow(f) {
  const tr = document.createElement('tr');
  const rowId = 'xss-' + Math.random().toString(36).slice(2);
  tr.innerHTML = `
    <td><span class="badge badge-${f.severity}">${escapeHtml(f.severity)}</span></td>
    <td>${escapeHtml(f.sinkType)}</td>
    <td>${escapeHtml(f.target)}</td>
    <td>${f.taintedBySource ? 'Yes (heuristic)' : 'Not confirmed'}</td>
    <td>${escapeHtml(f.sourceFile)}</td>
    <td>${f.line != null ? f.line : '-'}</td>
    <td><pre>${escapeHtml(f.snippet)}</pre></td>
    <td>
      <button class="action-btn" data-role="gen">Generate PoC</button>
      <button class="action-btn" data-role="fire" disabled>Fire in tab</button>
      <div class="poc-output" style="font-size:11px;margin-top:4px;"></div>
    </td>`;
  domXssBody.appendChild(tr);

  const genBtn = tr.querySelector('[data-role="gen"]');
  const fireBtn = tr.querySelector('[data-role="fire"]');
  const output = tr.querySelector('.poc-output');
  let payloadRecord = null;

  genBtn.addEventListener('click', async () => {
    payloadRecord = await window.recon.generatePayload(f);
    output.innerHTML = `<div>Marker: <code>${escapeHtml(payloadRecord.marker)}</code></div><pre>${escapeHtml(payloadRecord.payload)}</pre>`;
    fireBtn.disabled = !authCheckbox.checked || payloadRecord.payloadKind === 'navigate';
  });

  fireBtn.addEventListener('click', async () => {
    if (!payloadRecord) return;
    const res = await window.recon.firePayload({
      webContentsId: webview.getWebContentsId(),
      currentUrl: webview.getURL(),
      payloadRecord
    });
    output.innerHTML += `<div>${res.ok ? 'Fired. Watch for the marker alert/console warning in the Browser tab.' : 'Error: ' + escapeHtml(res.error)}</div>`;
  });
}

window.recon.onJsFileAnalyzed((data) => {
  const item = document.createElement('div');
  item.className = 'file-item';
  item.textContent = `${data.meta.url} (${data.meta.size} bytes)`;
  item.addEventListener('click', () => {
    document.querySelectorAll('.file-item').forEach((el) => el.classList.remove('selected'));
    item.classList.add('selected');
    showFileDetail(data);
  });
  jsFilesList.appendChild(item);
  filesByHash.set(data.meta.hash, data);

  data.endpoints.forEach(addEndpointRow);
  data.secrets.forEach(addSecretRow);
  data.domXss.forEach(addDomXssRow);

  window.recon.getSessionSummary().then((summary) => summary && refreshCounts(summary));
});

window.recon.onRequestSeen((endpointRecord) => {
  addEndpointRow(endpointRecord);
});

window.recon.onCaptureError((msg) => {
  console.warn('Capture error:', msg);
});

function showFileDetail(data) {
  jsFilesDetail.innerHTML = `
    <h3>${escapeHtml(data.meta.url)}</h3>
    <p><strong>Size:</strong> ${data.meta.size} bytes &nbsp; <strong>Frameworks:</strong> ${escapeHtml((data.frameworks || []).join(', ') || 'none detected')}</p>
    <p>${escapeHtml(data.narrative)}</p>
    <h4>Endpoints found in this file (${data.endpoints.length})</h4>
    <ul>${data.endpoints.map((e) => `<li><code>${escapeHtml(e.urlStructure.full)}</code> <span style="color:#718096">(${escapeHtml(e.context)})</span></li>`).join('') || '<li>None</li>'}</ul>
    <h4>Secret candidates in this file (${data.secrets.length})</h4>
    <ul>${data.secrets.map((s) => `<li>${escapeHtml(s.type)}: <code>${escapeHtml(s.redacted)}</code></li>`).join('') || '<li>None</li>'}</ul>
    <h4>DOM XSS sinks in this file (${data.domXss.length})</h4>
    <ul>${data.domXss.map((x) => `<li><span class="badge badge-${x.severity}">${escapeHtml(x.severity)}</span> ${escapeHtml(x.sinkType)} at line ${x.line}</li>`).join('') || '<li>None</li>'}</ul>
    <h4>Source ${data.truncated ? '(truncated preview)' : ''}</h4>
    <pre>${escapeHtml(data.contentPreview)}</pre>
  `;
}

document.getElementById('btn-generate-report').addEventListener('click', async () => {
  const status = document.getElementById('report-status');
  status.textContent = 'Generating...';
  const res = await window.recon.generateReport();
  if (!res.ok) {
    status.textContent = 'Error: ' + res.error;
    return;
  }
  document.getElementById('report-frame').srcdoc = res.html;
  document.getElementById('btn-export-pdf').disabled = false;
  document.getElementById('btn-export-pdf').dataset.html = '';
  window.__lastReportHtml = res.html;
  status.textContent = `Report saved to ${res.reportPath}`;
});

document.getElementById('btn-export-pdf').addEventListener('click', async () => {
  const status = document.getElementById('report-status');
  if (!window.__lastReportHtml) return;
  status.textContent = 'Exporting PDF...';
  const res = await window.recon.exportPdf(window.__lastReportHtml);
  status.textContent = res.ok ? `PDF saved to ${res.pdfPath}` : 'Error: ' + res.error;
  if (res.ok) window.recon.openInFolder(res.pdfPath);
});
