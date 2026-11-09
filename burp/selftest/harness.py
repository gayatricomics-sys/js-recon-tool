# -*- coding: utf-8 -*-
import sys, time, traceback
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
from java.net import URL
from java.lang import String as JString
import js_recon_burp as M

class Info(object):
    def __init__(s, headers): s.h = headers
    def getHeaders(s): return s.h
    def getMethod(s): return "GET"
    def getBodyOffset(s): return 0
class Helpers(object):
    def analyzeRequest(s, msg): return Info(msg.reqh)
    def analyzeResponse(s, resp): return Info(resp.h)
    def getHeaderValue(s, headers, name):
        for h in headers:
            if h.lower().startswith(name.lower()+":"): return h.split(":",1)[1].strip()
        return None
    def bytesToString(s, b): return unicode(b.body)  # Jython converts Burp java.lang.String to unicode
class Resp(object):
    def __init__(s, body, h): s.body, s.h = body, h
    def __nonzero__(s): return True
class Msg(object):
    def __init__(s, url, body, ctype):
        s.url = URL(url); s.reqh = ["GET / HTTP/1.1", "Accept: */*", "Content-Type: application/x-www-form-urlencoded"]; s.resp = Resp(body, ["HTTP/1.1 200 OK", "Content-Type: "+ctype])
    def getUrl(s): return s.url
    def getResponse(s): return s.resp
    def getRequest(s): return "x"
class CB(object):
    def getHelpers(s): return Helpers()
    def setExtensionName(s, n): pass
    def registerExtensionStateListener(s, l): pass
    def addSuiteTab(s, t): pass
    def registerHttpListener(s, l): pass
    def registerContextMenuFactory(s, l): pass
    def isInScope(s, u): return True
    def printOutput(s, m): print(m)

def step(name, fn):
    try:
        r = fn(); print("[OK]   %s %s" % (name, "" if r is None else r))
    except Exception:
        print("[FAIL] %s\n%s" % (name, traceback.format_exc().strip().splitlines()[-1]))

ext = M.BurpExtender()
step("load extension", lambda: ext.registerExtenderCallbacks(CB()))
fx = open(sys.argv[3]).read()
step("passive capture app.js (application/javascript)", lambda: ext.processHttpMessage(4, False, Msg("https://t.test/app.js", fx, "application/javascript")))
step("files captured", lambda: len(ext._store))
step("JS without .js in URL (/bundle?v=1)", lambda: (ext.processHttpMessage(4, False, Msg("https://t.test/bundle?v=1", "var a=location.hash;x.innerHTML=a;", "text/javascript")), len(ext._store))[1])
step(".json response wrongly treated as JS", lambda: (ext.processHttpMessage(4, False, Msg("https://t.test/data.json", '{"a":"/api/x"}', "application/json")), len(ext._store))[1])
from javax.swing import SwingUtilities as _SU
from java.lang import Runnable as _R
class _N(_R):
    def run(s): pass
def flush(): _SU.invokeAndWait(_N())
def render(model):
    flush()
    for r in range(model.getRowCount()):
        for c in range(model.getColumnCount()): model.getValueAt(r, c)
    return "%d rows" % model.getRowCount()
step("render Files table", lambda: render(ext._files_model))
step("render Endpoints table", lambda: render(ext._endpoint_model))
step("render XSS table", lambda: render(ext._xss_model))
def sel():
    flush()
    ext._files_table.setRowSelectionInterval(0,0); return ext._file_detail.getText()[:30]
step("select file -> detail pane", sel)
uni = u"var msg='Bienvenue à l’app — 日本';\nvar q=location.search; document.getElementById('x').innerHTML = q + msg;\n"
step("JS with non-ASCII text", lambda: (ext.processHttpMessage(4, False, Msg("https://t.test/i18n.js", uni, "application/javascript")), len(ext._store))[1])
step("render XSS table after unicode", lambda: render(ext._xss_model))
step("HTML export", lambda: ext._write_html_report(sys.argv[4]+"/r.html"))
# minified bundle perf / FP
body = ";".join(["var a%d=document.getElementById('n%d')" % (i,i) for i in range(3000)]) + ";var h=location.hash;" + ";".join(["e%d.innerHTML='<b>static</b>'" % i for i in range(300)])
t=time.time()
step("minified 1-line bundle (%dKB)" % (len(body)//1024), lambda: ext._analyze_and_store(Msg("https://t.test/min.js", body, "application/javascript"), "https://t.test/min.js"))
print("       took %.1fs" % (time.time()-t))
it = ext._by_url.get("https://t.test/min.js")
if it: print("       static innerHTML flagged HIGH: %d of %d" % (len([x for x in it["xss"] if x["severity"]=="HIGH"]), len(it["xss"])))
step("JWT false positive on hostnames", lambda: [s["type"] for s in M.scan_secrets("var h='assets.cloudfront.netlify';x=this.something.anotherthing;")])

import threading as T
def burst():
    ths=[T.Thread(target=lambda i=i: ext.processHttpMessage(4, False, Msg("https://t.test/c%d.js"%i, "var q%d=location.hash;el.innerHTML=q%d;fetch('/api/c%d')"%(i,i,i), "application/javascript"))) for i in range(40)]
    [t.start() for t in ths]; [t.join() for t in ths]
    from javax.swing import SwingUtilities
    from java.lang import Runnable
    class N(Runnable):
        def run(s): pass
    SwingUtilities.invokeAndWait(N())
    return "store=%d files_rows=%d" % (len(ext._store), ext._files_model.getRowCount())
step("40 concurrent proxy threads", burst)
step("render all tables after burst", lambda: [render(m) for m in (ext._files_model, ext._endpoint_model, ext._secret_model, ext._xss_model)])
step("CSV export (unicode)", lambda: ext._write_csv(sys.argv[4]+"/r.csv"))
step("PoC for every sink type", lambda: len([M.payload_for_finding({"sinkType": k}) for k in ["innerHTML","location-assign","jquery-html","srcdoc","message-listener","eval"]]))
step("authz gate blocks wrong host", lambda: (ext._authz_check.setSelected(True), ext._authz_host_field.setText("other.test"), ext._on_authz_changed(None), ext._generate_and_copy({"host":u"t.test","url":u"x"}, {"sinkType":"eval"}), ext._log_area.getText().strip().splitlines()[-1])[-1])
step("host filter re-apply", lambda: (ext._host_filter.setText("nomatch"), ext._refresh_tables(), ext._endpoint_model.getRowCount())[-1])
step("clear", lambda: (ext._on_clear(None), len(ext._store), ext._xss_model.getRowCount())[1:])
for f in sys.argv[5:]:
    src = unicode(open(f).read(), "utf-8", "replace"); t=time.time()
    r = M.analyze_js_source(src, {"url": f})
    print("[REAL] %-28s %5dKB %4.1fs  E:%d S:%d X:%d (HIGH %d)" % (f.split("/")[-1], len(src)//1024, time.time()-t, len(r["endpoints"]), len(r["secrets"]), len(r["xss"]), len([x for x in r["xss"] if x["severity"]=="HIGH"])))
