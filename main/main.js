const { app, BrowserWindow, ipcMain, webContents: webContentsModule, shell } = require('electron');
const path = require('path');
const fs = require('fs');

const { NetworkCapture } = require('../src/capture/networkCapture');
const { extractEndpoints, classifyUrl } = require('../src/analysis/endpointExtractor');
const { scanForSecrets } = require('../src/analysis/secretScanner');
const { analyzeDomXss } = require('../src/analysis/domXssAnalyzer');
const { explainFile } = require('../src/analysis/jsExplainer');
const { generatePayloadForFinding } = require('../src/report/payloadGenerator');
const { buildReportHtml } = require('../src/report/reportGenerator');
const { ProjectStore } = require('../src/store/projectStore');

let mainWindow = null;
let capture = null;
const store = new ProjectStore();
const explanationsByUrl = new Map();
const seenFileHashes = new Set();

const authState = { authorized: false, hostname: null };

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
      sandbox: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

function sinkKindOf(sinkType) {
  if (['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'write', 'writeln', 'setHTML'].includes(sinkType)) return 'html';
  if (sinkType === 'location.assign' || sinkType === 'location.replace') return 'navigate';
  return 'js';
}

function analyzeAndStore(fileMeta, content) {
  const meta = store.saveJsFile(fileMeta.url, content);
  if (seenFileHashes.has(meta.hash)) return null;
  seenFileHashes.add(meta.hash);

  const { endpoints } = extractEndpoints(content, fileMeta);
  const { secrets } = scanForSecrets(content, fileMeta);
  const { findings: domXss } = analyzeDomXss(content, fileMeta);
  const explanation = explainFile(content, fileMeta);

  store.recordFindings({ endpoints, secrets, domXss });
  explanationsByUrl.set(fileMeta.url, {
    url: fileMeta.url,
    lineCount: explanation.lineCount,
    frameworks: explanation.frameworks,
    narrative: explanation.narrative
  });

  const MAX_PREVIEW = 20000;
  const preview = content.length > MAX_PREVIEW ? content.slice(0, MAX_PREVIEW) : content;

  return {
    meta,
    endpoints,
    secrets,
    domXss,
    narrative: explanation.narrative,
    frameworks: explanation.frameworks,
    contentPreview: preview,
    truncated: content.length > MAX_PREVIEW
  };
}

function attachCaptureToWebContents(wc) {
  if (capture) capture.detach();

  capture = new NetworkCapture(wc, {
    onJsFile: (fileMeta, content) => {
      try {
        const result = analyzeAndStore(fileMeta, content);
        if (result && mainWindow) {
          mainWindow.webContents.send('capture:js-file-analyzed', result);
        }
      } catch (err) {
        if (mainWindow) mainWindow.webContents.send('capture:error', String(err && err.message || err));
      }
    },
    onRequest: (req) => {
      const classified = classifyUrl(req.url);
      if (classified) {
        const endpointRecord = {
          raw: req.url,
          urlStructure: classified,
          line: null,
          context: `network-request:${req.method}`,
          sourceFile: '(live network traffic)'
        };
        store.recordFindings({ endpoints: [endpointRecord] });
        if (mainWindow) mainWindow.webContents.send('capture:request-seen', endpointRecord);
      }
    },
    onError: (err) => {
      if (mainWindow) mainWindow.webContents.send('capture:error', String(err && err.message || err));
    }
  });

  capture.attach();
}

ipcMain.handle('webview:ready', (_event, webContentsId) => {
  const wc = webContentsModule.fromId(webContentsId);
  if (!wc) return { ok: false, error: 'webContents not found' };
  attachCaptureToWebContents(wc);
  return { ok: true };
});

ipcMain.handle('session:start', (_event, targetUrl) => {
  seenFileHashes.clear();
  explanationsByUrl.clear();
  authState.authorized = false;
  authState.hostname = null;
  const sessionId = store.startSession(targetUrl);
  return { ok: true, sessionId, summary: store.getSessionSummary() };
});

ipcMain.handle('session:summary', () => {
  return store.hasSession() ? store.getSessionSummary() : null;
});

ipcMain.handle('session:findings', () => {
  return store.hasSession() ? store.getIndex() : null;
});

ipcMain.handle('auth:set', (_event, { authorized, hostname }) => {
  authState.authorized = !!authorized;
  authState.hostname = hostname || null;
  return authState;
});

ipcMain.handle('payload:generate', (_event, finding) => {
  const record = generatePayloadForFinding(finding);
  record.payloadKind = sinkKindOf(finding.sinkType);
  store.savePayload(record);
  return record;
});

ipcMain.handle('payload:fire', async (_event, { webContentsId, currentUrl, payloadRecord }) => {
  if (!authState.authorized) {
    return { ok: false, error: 'Authorization checkbox is not enabled. Enable it before firing any payload.' };
  }
  let currentHost = null;
  try {
    currentHost = new URL(currentUrl).hostname;
  } catch (_) {}

  if (!currentHost || currentHost !== authState.hostname) {
    return { ok: false, error: `Authorized hostname (${authState.hostname}) does not match the current tab (${currentHost}). Refusing to fire.` };
  }

  const wc = webContentsModule.fromId(webContentsId);
  if (!wc) return { ok: false, error: 'webContents not found' };

  let expression;
  if (payloadRecord.payloadKind === 'html') {
    expression = `document.body.insertAdjacentHTML('beforeend', ${JSON.stringify(payloadRecord.payload)});'JSRECON_INJECTED'`;
  } else if (payloadRecord.payloadKind === 'navigate') {
    return { ok: false, error: 'Navigation-based payloads must be fired manually by entering them in the address bar; auto-fire is disabled for this sink type.' };
  } else {
    expression = `(function(){ try { return String(eval(${JSON.stringify(payloadRecord.payload)})); } catch(e) { return 'error: ' + e.message; } })()`;
  }

  try {
    const result = await wc.debugger.sendCommand('Runtime.evaluate', { expression, returnByValue: true });
    return { ok: true, result: result && result.result ? result.result.value : null };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err) };
  }
});

ipcMain.handle('report:generate', () => {
  if (!store.hasSession()) return { ok: false, error: 'No active session' };
  const index = store.getIndex();
  index.__sessionId = store.sessionId;
  const explanations = [...explanationsByUrl.values()];
  const html = buildReportHtml(index, explanations);
  const reportPath = path.join(store.sessionDir, 'report.html');
  fs.writeFileSync(reportPath, html, 'utf8');
  return { ok: true, html, reportPath };
});

ipcMain.handle('report:export-pdf', async (_event, html) => {
  if (!store.hasSession()) return { ok: false, error: 'No active session' };
  const pdfWindow = new BrowserWindow({ show: false, webPreferences: { offscreen: true } });
  const tmpHtmlPath = path.join(store.sessionDir, 'report.html');
  fs.writeFileSync(tmpHtmlPath, html, 'utf8');
  await pdfWindow.loadFile(tmpHtmlPath);
  const pdfBuffer = await pdfWindow.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
  const pdfPath = path.join(store.sessionDir, 'report.pdf');
  fs.writeFileSync(pdfPath, pdfBuffer);
  pdfWindow.destroy();
  return { ok: true, pdfPath };
});

ipcMain.handle('shell:open-path', (_event, targetPath) => {
  shell.showItemInFolder(targetPath);
  return { ok: true };
});

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
