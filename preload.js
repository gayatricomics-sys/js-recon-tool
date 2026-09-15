const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('recon', {
  webviewReady: (webContentsId) => ipcRenderer.invoke('webview:ready', webContentsId),
  startSession: (targetUrl) => ipcRenderer.invoke('session:start', targetUrl),
  getSessionSummary: () => ipcRenderer.invoke('session:summary'),
  getFindings: () => ipcRenderer.invoke('session:findings'),
  setAuthorized: (authorized, hostname) => ipcRenderer.invoke('auth:set', { authorized, hostname }),
  generatePayload: (finding) => ipcRenderer.invoke('payload:generate', finding),
  firePayload: (args) => ipcRenderer.invoke('payload:fire', args),
  generateReport: () => ipcRenderer.invoke('report:generate'),
  exportPdf: (html) => ipcRenderer.invoke('report:export-pdf', html),
  openInFolder: (targetPath) => ipcRenderer.invoke('shell:open-path', targetPath),

  onJsFileAnalyzed: (cb) => ipcRenderer.on('capture:js-file-analyzed', (_e, data) => cb(data)),
  onRequestSeen: (cb) => ipcRenderer.on('capture:request-seen', (_e, data) => cb(data)),
  onCaptureError: (cb) => ipcRenderer.on('capture:error', (_e, msg) => cb(msg))
});
