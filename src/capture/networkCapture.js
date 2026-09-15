const JS_MIME_HINTS = ['javascript', 'ecmascript', 'x-javascript', 'jscript'];

function isJsResponse(response, resourceType) {
  if (resourceType === 'Script') return true;
  const mime = (response && response.mimeType || '').toLowerCase();
  return JS_MIME_HINTS.some((hint) => mime.includes(hint));
}

class NetworkCapture {
  constructor(webContents, { onJsFile, onRequest, onError }) {
    this.webContents = webContents;
    this.onJsFile = onJsFile || (() => {});
    this.onRequest = onRequest || (() => {});
    this.onError = onError || (() => {});
    this.pending = new Map();
    this.attached = false;
  }

  attach() {
    if (this.attached) return;
    const dbg = this.webContents.debugger;
    try {
      dbg.attach('1.3');
    } catch (err) {
      this.onError(err);
      return;
    }
    this.attached = true;

    dbg.sendCommand('Network.enable').catch((err) => this.onError(err));

    this._messageHandler = (_event, method, params) => this._handleMessage(method, params);
    dbg.on('message', this._messageHandler);

    this._detachHandler = () => {
      this.attached = false;
    };
    dbg.on('detach', this._detachHandler);
  }

  detach() {
    if (!this.attached) return;
    try {
      this.webContents.debugger.detach();
    } catch (_) {}
    this.attached = false;
  }

  _handleMessage(method, params) {
    if (method === 'Network.requestWillBeSent') {
      this.pending.set(params.requestId, {
        url: params.request.url,
        method: params.request.method,
        resourceType: params.type
      });
      this.onRequest({
        url: params.request.url,
        method: params.request.method,
        resourceType: params.type
      });
      return;
    }

    if (method === 'Network.responseReceived') {
      const entry = this.pending.get(params.requestId);
      if (entry) {
        entry.mimeType = params.response.mimeType;
        entry.status = params.response.status;
      }
      return;
    }

    if (method === 'Network.loadingFinished') {
      const entry = this.pending.get(params.requestId);
      if (!entry) return;
      if (!isJsResponse({ mimeType: entry.mimeType }, entry.resourceType)) {
        this.pending.delete(params.requestId);
        return;
      }
      this._fetchBody(params.requestId, entry);
    }
  }

  _fetchBody(requestId, entry) {
    this.webContents.debugger
      .sendCommand('Network.getResponseBody', { requestId })
      .then((result) => {
        const content = result.base64Encoded
          ? Buffer.from(result.body, 'base64').toString('utf8')
          : result.body;
        this.onJsFile({ url: entry.url, method: entry.method }, content);
      })
      .catch((err) => this.onError(err))
      .finally(() => this.pending.delete(requestId));
  }
}

module.exports = { NetworkCapture };
