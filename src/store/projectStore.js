const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CAPTURES_ROOT = path.join(__dirname, '..', '..', 'captures');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function sanitizeHost(hostname) {
  return (hostname || 'unknown-host').replace(/[^a-zA-Z0-9.-]/g, '_');
}

class ProjectStore {
  constructor() {
    ensureDir(CAPTURES_ROOT);
    this.sessionId = null;
    this.sessionDir = null;
    this.filesDir = null;
    this.payloadsDir = null;
    this.index = { target: null, startedAt: null, files: [], endpoints: [], secrets: [], domXss: [], payloads: [] };
  }

  startSession(targetUrl) {
    let hostname = 'unknown-host';
    try {
      hostname = new URL(targetUrl).hostname;
    } catch (_) {}

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    this.sessionId = `${sanitizeHost(hostname)}_${timestamp}`;
    this.sessionDir = path.join(CAPTURES_ROOT, this.sessionId);
    this.filesDir = path.join(this.sessionDir, 'js-files');
    this.payloadsDir = path.join(this.sessionDir, 'payloads');

    ensureDir(this.sessionDir);
    ensureDir(this.filesDir);
    ensureDir(this.payloadsDir);

    this.index = { target: targetUrl, startedAt: new Date().toISOString(), files: [], endpoints: [], secrets: [], domXss: [], payloads: [] };
    this._flushIndex();
    return this.sessionId;
  }

  _flushIndex() {
    if (!this.sessionDir) return;
    fs.writeFileSync(path.join(this.sessionDir, 'index.json'), JSON.stringify(this.index, null, 2), 'utf8');
  }

  hasSession() {
    return !!this.sessionDir;
  }

  saveJsFile(url, content) {
    if (!this.sessionDir) throw new Error('No active session');
    const hash = crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
    const safeName = hash + '.js';
    const filePath = path.join(this.filesDir, safeName);
    fs.writeFileSync(filePath, content, 'utf8');

    const meta = {
      url,
      hash,
      storedAs: path.relative(this.sessionDir, filePath),
      size: Buffer.byteLength(content, 'utf8'),
      capturedAt: new Date().toISOString()
    };

    const existing = this.index.files.find((f) => f.hash === hash);
    if (!existing) {
      this.index.files.push(meta);
      this._flushIndex();
    }
    return meta;
  }

  recordFindings({ endpoints, secrets, domXss }) {
    if (endpoints) this.index.endpoints.push(...endpoints);
    if (secrets) this.index.secrets.push(...secrets);
    if (domXss) this.index.domXss.push(...domXss);
    this._flushIndex();
  }

  savePayload(payloadRecord) {
    if (!this.sessionDir) throw new Error('No active session');
    const filename = `poc-${payloadRecord.marker}.json`;
    fs.writeFileSync(path.join(this.payloadsDir, filename), JSON.stringify(payloadRecord, null, 2), 'utf8');
    this.index.payloads.push({ marker: payloadRecord.marker, file: filename, sinkType: payloadRecord.findingRef.sinkType });
    this._flushIndex();
  }

  getSessionSummary() {
    return {
      sessionId: this.sessionId,
      sessionDir: this.sessionDir,
      target: this.index.target,
      startedAt: this.index.startedAt,
      fileCount: this.index.files.length,
      endpointCount: this.index.endpoints.length,
      secretCount: this.index.secrets.length,
      domXssCount: this.index.domXss.length
    };
  }

  getIndex() {
    return this.index;
  }
}

module.exports = { ProjectStore, CAPTURES_ROOT };
