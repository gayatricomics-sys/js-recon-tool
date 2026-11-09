# -*- coding: utf-8 -*-
import sys, time, traceback
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2])
from java.net import URL
from java.lang import String as JString
import js_recon_burp as M

# STRICT mock of the Burp Extender API: only methods that exist on the real
# interfaces (IExtensionHelpers, IRequestInfo, IResponseInfo,
# IHttpRequestResponse). Anything else raises AttributeError, like in Burp.
from java.lang import String as _JS
from java.util import ArrayList as _AL
def _jlist(items):
    l = _AL()
    for i in items: l.add(_JS(i))
    return l
class RequestInfo(object):  # IRequestInfo
    def __init__(s, msg): s._m = msg
    def getMethod(s): return "GET"
    def getUrl(s): return s._m._url
    def getHeaders(s): return _jlist(s._m._reqh)
    def getParameters(s): return _AL()
    def getBodyOffset(s): return 0
    def getContentType(s): return 0
class ResponseInfo(object):  # IResponseInfo
    def __init__(s, raw):
        text = _JS(raw, "ISO-8859-1"); i = text.indexOf("\r\n\r\n")
        s._h = [h for h in unicode(text.substring(0, i)).split("\r\n")]; s._off = i + 4
    def getHeaders(s): return _jlist(s._h)
    def getBodyOffset(s): return s._off
    def getStatusCode(s): return 200
    def getCookies(s): return _AL()
    def getStatedMimeType(s): return ""
    def getInferredMimeType(s): return ""
class Helpers(object):  # IExtensionHelpers (subset actually used)
    def analyzeRequest(s, msg): return RequestInfo(msg)
    def analyzeResponse(s, raw): return ResponseInfo(raw)
    def bytesToString(s, raw): return unicode(_JS(raw, "ISO-8859-1"))
    def stringToBytes(s, text): return _JS(text).getBytes("ISO-8859-1")
class Msg(object):  # IHttpRequestResponse -- note: NO getUrl()
    def __init__(s, url, body, ctype):
        s._url = URL(url); s._reqh = ["GET / HTTP/1.1", "Accept: */*"]
        raw = u"HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n" % ctype + (body if isinstance(body, unicode) else body.decode("utf-8"))
        s._resp = _JS(raw).getBytes("UTF-8")
    def getResponse(s): return s._resp
    def getRequest(s): return _JS("GET / HTTP/1.1\r\n\r\n").getBytes("UTF-8")
    def getHttpService(s): return None
    def getComment(s): return None
    def getHighlight(s): return None
LOGGED = []
SCOPE = set([u"t.test"])  # hosts added to Burp Target scope
class CB(object):
    def getHelpers(s): return Helpers()
    def setExtensionName(s, n): pass
    def registerExtensionStateListener(s, l): pass
    def addSuiteTab(s, t): pass
    def registerHttpListener(s, l): pass
    def registerContextMenuFactory(s, l): pass
    def isInScope(s, u): return unicode(u.getHost()) in SCOPE
    def printOutput(s, m):
        LOGGED.append(unicode(m)); print(m)

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
step("minified 1-line bundle (%dKB)" % (len(body)//1024), lambda: ext._analyze_and_store(Msg("https://t.test/min.js", body, "application/javascript"), u"https://t.test/min.js", URL("https://t.test/min.js")))
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
step("scope: in-scope host authorized", lambda: ext._is_authorized({"url": u"https://t.test/a.js", "host": u"t.test"}))
step("scope: out-of-scope host blocked", lambda: (ext._generate_and_copy({"url": u"https://evil.test/a.js", "host": u"evil.test"}, {"sinkType": "eval"}), flush(), ext._status.getText()[:40])[-1])
step("scope: out-of-scope JS not captured (In-scope only default)", lambda: (ext.processHttpMessage(4, False, Msg("https://other.test/x.js", "eval(location.hash)", "application/javascript")), any(i["host"] == u"other.test" for i in ext._store.values()))[-1])
step("diag: out-of-scope JS logs a skip reason", lambda: (ext.processHttpMessage(4, False, Msg("https://cdn.evil.test/a.js", "var x=1", "application/javascript")), any("out of Burp scope" in l for l in LOGGED))[-1])
step("diag: counters increment", lambda: (ext._seen_responses > 0 and ext._seen_js > 0))
# PoC export: capture an in-scope vulnerable file, export, verify exact payload present
def poc_export():
    ext._on_clear(None); flush()
    vuln = "var q=location.hash; el.innerHTML=q; eval(location.search);"
    ext.processHttpMessage(4, False, Msg("https://t.test/vuln.js", vuln, "application/javascript")); flush()
    recs, skipped = ext._collect_pocs()
    import os
    hp = sys.argv[4]+"/pocs.html"; mp = sys.argv[4]+"/pocs.md"
    ext._write_poc_html(hp, recs, skipped); ext._write_poc_md(mp, recs, skipped)
    html = open(hp).read(); md = open(mp).read()
    # exact payload for innerHTML must appear verbatim in both
    import cgi as _cgi
    mk_ok = all(("JSRECON-" in r["payload"] and _cgi.escape(r["payload"], True) in html) for r in recs)
    md_ok = all(r["payload"] in md for r in recs)
    steps_ok = all(len(r["steps"])>=3 for r in recs)
    return "recs=%d html_payload=%s md_payload=%s steps=%s html_bytes=%d" % (len(recs), mk_ok, md_ok, steps_ok, len(html))
step("Export PoCs: exact payloads in HTML+MD", poc_export)
def poc_scope():
    ext._on_clear(None); flush()
    ext.processHttpMessage(4, False, Msg("https://outofscope.test/v.js", "el.innerHTML=location.hash;", "application/javascript")); flush()
    # In-scope only default drops capture, but even if captured, export must skip out-of-scope
    recs, skipped = ext._collect_pocs()
    return "recs=%d (expect 0 for out-of-scope)" % len(recs)
step("Export PoCs: out-of-scope excluded", poc_scope)
step("build_test_url hash", lambda: M.build_test_url("https://t.test/p", "location.hash", "<x>")[0])
step("build_test_url search encodes", lambda: ("xss=" in M.build_test_url("https://t.test/p?a=1", "location.search", "<x>")[0]) and ("%3C" in M.build_test_url("https://t.test/p", "location.search", "<x>")[0]))
step("build_test_url non-url source -> None", lambda: M.build_test_url("https://t.test/p", ".data", "<x>")[0] is None)
step("stable marker deterministic", lambda: (M._stable_marker({"sinkType":"innerHTML","line":2,"snippet":"el.innerHTML=q;"}) == M._stable_marker({"sinkType":"innerHTML","line":2,"snippet":"el.innerHTML=q;"})))
def shot_export():
    ext._on_clear(None); flush()
    ext.processHttpMessage(4, False, Msg("https://t.test/s.js", "var q=location.hash; el.innerHTML=q;", "application/javascript")); flush()
    # attach a fake screenshot to the first finding's stable marker
    recs, _ = ext._collect_pocs()
    mk = recs[0]["marker"]
    from java.util import Base64
    from java.lang import String as JS
    fake = JS("PNGDATA").getBytes("UTF-8")
    ext._shots[mk] = {"b64": Base64.getEncoder().encodeToString(fake), "bytes": fake, "mime":"image/png"}
    hp = sys.argv[4]+"/pocs_shot.html"; mp = sys.argv[4]+"/pocs_shot.md"
    recs, skipped = ext._collect_pocs()
    ext._write_poc_html(hp, recs, skipped); ext._write_poc_md(mp, recs, skipped)
    html=open(hp).read(); md=open(mp).read()
    import os
    html_ok = ("data:image/png;base64," in html) and ("How to execute" in html)
    md_ok = (("poc-%s.png"%mk) in md) and os.path.exists(sys.argv[4]+"/poc-%s.png"%mk) and ("How to execute" in md)
    return "html_shot+guide=%s md_pngref+guide=%s" % (html_ok, md_ok)
step("Screenshot embeds in HTML + PNG file for MD + guide", shot_export)
def find(term):
    flush(); ext._search_field.setText(term); ext._on_search(None)
    return (ext._files_table.getRowCount(), ext._endpoint_table.getRowCount(), ext._secret_table.getRowCount(), ext._xss_table.getRowCount(), ext._status.getText()[:30])
step("Find 'c7.js' filters tables", lambda: find("c7.js"))
step("Find highlights hit in file detail", lambda: ext._file_detail.getSelectedText())
step("Find empty clears filter", lambda: find(""))
step("host filter re-apply", lambda: (ext._host_filter.setText("nomatch"), ext._refresh_tables(), ext._endpoint_model.getRowCount())[-1])
step("clear", lambda: (ext._on_clear(None), len(ext._store), ext._xss_model.getRowCount())[1:])
for f in sys.argv[5:]:
    src = unicode(open(f).read(), "utf-8", "replace"); t=time.time()
    r = M.analyze_js_source(src, {"url": f})
    print("[REAL] %-28s %5dKB %4.1fs  E:%d S:%d X:%d (HIGH %d)" % (f.split("/")[-1], len(src)//1024, time.time()-t, len(r["endpoints"]), len(r["secrets"]), len(r["xss"]), len([x for x in r["xss"] if x["severity"]=="HIGH"])))

class Invocation(object):  # IContextMenuInvocation
    def __init__(s, msgs): s._m = msgs
    def getSelectedMessages(s): return s._m
    def getInvocationContext(s): return 0
def send_to():
    items = ext.createMenuItems(Invocation([Msg("https://t.test/ctx.js", "var z=location.hash;eval(z);", "text/plain")]))
    items[0].doClick(); flush()
    return "%d store, ctx.js analyzed=%s" % (len(ext._store), any(i["url"].endswith("ctx.js") for i in ext._store.values()))
step("right-click Send to JS Recon", send_to)
bad = [l for l in LOGGED if ("error" in l.lower() and "logged" not in l.lower()) or "has no attribute" in l.lower()]
print(("[FAIL] extension logged %d error(s):\n  " % len(bad) + "\n  ".join(bad[:10])) if bad else "[OK]   no errors in extension log")
