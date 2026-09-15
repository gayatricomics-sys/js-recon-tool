function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function severityBadge(sev) {
  const colors = { HIGH: '#c0152f', MEDIUM: '#c07515', LOW: '#4a5568', INFO: '#2b6cb0' };
  const c = colors[sev] || '#4a5568';
  return `<span style="background:${c};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">${escapeHtml(sev)}</span>`;
}

function countBySeverity(domXss) {
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of domXss) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

function buildReportHtml(index, explanations) {
  const sevCounts = countBySeverity(index.domXss);
  const generatedAt = new Date().toISOString();

  const endpointRows = index.endpoints.map((e) => `
    <tr>
      <td>${escapeHtml(e.context)}</td>
      <td>${escapeHtml(e.urlStructure.kind)}</td>
      <td>${escapeHtml(e.urlStructure.host || '-')}</td>
      <td><code>${escapeHtml(e.urlStructure.pathname || e.raw)}</code></td>
      <td>${escapeHtml(e.sourceFile)}</td>
      <td>${e.line != null ? e.line : '-'}</td>
    </tr>`).join('\n');

  const secretRows = index.secrets.map((s) => `
    <tr>
      <td>${escapeHtml(s.type)}</td>
      <td><code>${escapeHtml(s.redacted)}</code></td>
      <td>${s.length}</td>
      <td>${s.entropy}</td>
      <td>${escapeHtml(s.reason)}</td>
      <td>${escapeHtml(s.sourceFile)}</td>
      <td>${s.line != null ? s.line : '-'}</td>
    </tr>`).join('\n');

  const xssRows = index.domXss.map((f) => `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td>${escapeHtml(f.sinkType)}</td>
      <td>${escapeHtml(f.target)}</td>
      <td>${f.taintedBySource ? 'Yes (heuristic)' : 'Not confirmed'}</td>
      <td>${escapeHtml(f.sourceFile)}</td>
      <td>${f.line != null ? f.line : '-'}</td>
      <td><pre style="white-space:pre-wrap;margin:0;font-size:11px;">${escapeHtml(f.snippet)}</pre></td>
    </tr>`).join('\n');

  const fileExplanationBlocks = (explanations || []).map((e) => `
    <div class="file-block">
      <h4>${escapeHtml(e.url)}</h4>
      <p class="meta">${e.lineCount} lines &middot; frameworks: ${escapeHtml(e.frameworks.join(', ') || 'none detected')}</p>
      <p>${escapeHtml(e.narrative)}</p>
    </div>`).join('\n');

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>JS Recon Security Testing Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 40px; color: #1a202c; line-height: 1.5; }
  h1 { font-size: 26px; border-bottom: 3px solid #1a202c; padding-bottom: 8px; }
  h2 { font-size: 20px; margin-top: 36px; border-bottom: 1px solid #cbd5e0; padding-bottom: 4px; }
  h3 { font-size: 16px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  th, td { border: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f7fafc; }
  code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; }
  .summary-grid { display: flex; gap: 16px; margin-top: 16px; flex-wrap: wrap; }
  .summary-card { border: 1px solid #cbd5e0; border-radius: 8px; padding: 14px 18px; min-width: 140px; }
  .summary-card .num { font-size: 28px; font-weight: 700; }
  .summary-card .label { font-size: 12px; color: #4a5568; text-transform: uppercase; }
  .file-block { border-top: 1px solid #e2e8f0; padding: 10px 0; }
  .meta { color: #718096; font-size: 12px; }
  .disclaimer { background: #fffbea; border: 1px solid #f0d878; padding: 12px 16px; border-radius: 6px; font-size: 13px; margin-top: 16px; }
  footer { margin-top: 48px; font-size: 11px; color: #a0aec0; }
</style>
</head>
<body>
  <h1>Executive JS Recon Security Testing Report</h1>
  <p><strong>Target:</strong> ${escapeHtml(index.target)}<br>
  <strong>Session started:</strong> ${escapeHtml(index.startedAt)}<br>
  <strong>Report generated:</strong> ${escapeHtml(generatedAt)}</p>

  <div class="disclaimer">
    This report documents a JavaScript reconnaissance and static DOM XSS review performed against the target above.
    It is intended solely for use against systems the tester owns or is explicitly authorized to assess.
    Findings are the result of automated static analysis and heuristics and require manual verification before being treated as confirmed vulnerabilities.
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="num">${index.files.length}</div><div class="label">JS Files Captured</div></div>
    <div class="summary-card"><div class="num">${index.endpoints.length}</div><div class="label">Endpoints Discovered</div></div>
    <div class="summary-card"><div class="num">${index.secrets.length}</div><div class="label">Secret Candidates</div></div>
    <div class="summary-card"><div class="num">${index.domXss.length}</div><div class="label">DOM XSS Sinks</div></div>
    <div class="summary-card"><div class="num">${sevCounts.HIGH}</div><div class="label">High Severity</div></div>
  </div>

  <h2>Methodology</h2>
  <p>
    JavaScript resources were captured passively via Chrome DevTools Protocol network interception while browsing the target
    application interactively (including authenticated and OTP-gated flows) inside an isolated Electron browsing session.
    Each captured file was parsed into an abstract syntax tree (AST) and analyzed for: (1) string and template literals that
    resolve to structurally valid absolute or relative URLs, cross-referenced against HTTP call sites (fetch/XHR/axios);
    (2) known credential/secret prefixes, PEM blocks, JWT structure, sensitively-named variables/properties, and high-entropy
    strings; (3) DOM XSS sink patterns (innerHTML/outerHTML assignment, document.write, insertAdjacentHTML, eval, Function
    constructor, string-based setTimeout/setInterval, location assignment) with a best-effort heuristic taint check against
    known client-controllable sources (location.search/hash, document.referrer, window.name, postMessage, storage APIs).
  </p>

  <h2>Discovered Endpoints (${index.endpoints.length})</h2>
  <table>
    <thead><tr><th>Context</th><th>Kind</th><th>Host</th><th>Path</th><th>Source File</th><th>Line</th></tr></thead>
    <tbody>${endpointRows || '<tr><td colspan="6">None found</td></tr>'}</tbody>
  </table>

  <h2>Secret / Sensitive Data Candidates (${index.secrets.length})</h2>
  <table>
    <thead><tr><th>Type</th><th>Redacted Value</th><th>Length</th><th>Entropy</th><th>Reason</th><th>Source File</th><th>Line</th></tr></thead>
    <tbody>${secretRows || '<tr><td colspan="7">None found</td></tr>'}</tbody>
  </table>

  <h2>DOM XSS Static Findings (${index.domXss.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Sink</th><th>Target</th><th>Source-Tainted</th><th>Source File</th><th>Line</th><th>Snippet</th></tr></thead>
    <tbody>${xssRows || '<tr><td colspan="7">None found</td></tr>'}</tbody>
  </table>

  <h2>JavaScript File Explanations</h2>
  ${fileExplanationBlocks || '<p>No files analyzed.</p>'}

  <h2>Proof-of-Concept Payloads</h2>
  <p>Plain-text, non-obfuscated PoC payloads generated for confirmed sinks are stored under
  <code>captures/${escapeHtml(index.__sessionId || '')}/payloads/</code> in the project folder. Each payload embeds a
  unique marker string for unambiguous manual confirmation and requires explicit manual or in-app authorized action to fire.</p>

  <footer>Generated by js-recon-tool. For authorized security testing use only.</footer>
</body>
</html>`;
}

module.exports = { buildReportHtml };
