# -*- coding: utf-8 -*-
# Detection assertions for the tokenizer engine. Exits non-zero on any failure.
import sys
sys.path.insert(0, sys.argv[1])   # plugin dir
sys.path.insert(0, sys.argv[2])   # mock burp
import js_recon_burp as M

def xss(s):
    b = M.beautify(unicode(s))
    return sorted("%s:%s" % (f["sinkType"], f["severity"]) for f in M.analyze_dom_xss(b))
def sec(s):
    return sorted(f["type"] for f in M.scan_secrets(M.beautify(unicode(s))))
def ep(s):
    return sorted(f["raw"] for f in M.extract_endpoints(M.beautify(unicode(s))))
def fn(s):
    return sorted(f["name"] for f in M.extract_functions(M.beautify(unicode(s))))

CASES = [
    ("XSS location.href=hash", xss("location.href = location.hash.slice(1);"), ["href-assign:HIGH"]),
    ("XSS window.location=q", xss("var q=new URLSearchParams(location.search).get('r'); window.location=q;"), ["location-assign:HIGH"]),
    ("XSS window.location.replace(tainted)", xss("var u=location.hash; window.location.replace(u);"), ["location.replace:HIGH"]),
    ("XSS jQuery .html(tainted)", xss("$('#a').html(location.hash);"), ["jquery-html:HIGH"]),
    ("XSS jQuery .html(static) none", xss("$('#a').html('<b>hi</b>');"), []),
    ("XSS $(tainted)", xss("$(location.hash);"), ["jquery-selector:HIGH"]),
    ("XSS el['innerHTML']", xss("el['innerHTML'] = location.hash;"), ["innerHTML:HIGH"]),
    ("XSS Function() no new", xss("Function(location.hash)();"), ["Function-constructor:HIGH"]),
    ("XSS setTimeout(tainted var)", xss("var c=location.hash; setTimeout(c, 10);"), ["setTimeout-string-arg:HIGH"]),
    ("XSS setTimeout(fn) none", xss("var c=location.hash; setTimeout(function(){go(c)}, 10);"), []),
    ("XSS srcdoc", xss("f.srcdoc = location.hash;"), ["srcdoc:HIGH"]),
    ("XSS iframe.src tainted", xss("ifr.src = location.hash;"), ["src-assign:HIGH"]),
    ("XSS $el var taint", xss("var $el = location.hash; x.innerHTML=$el;"), ["innerHTML:HIGH"]),
    ("XSS eval static MEDIUM", xss("eval('1+1');"), ["eval:MEDIUM"]),
    ("XSS innerHTML static LOW", xss("el.innerHTML='<b>x</b>';"), ["innerHTML:LOW"]),
    ("FP stream.write none", xss("stream.write(buf);"), []),
    ("FP == not taint-assign", xss("var h=location.hash; if (z == h) {}; y.innerHTML=z;"), ["innerHTML:LOW"]),
    ("TOK regex literal not division", xss("var re=/innerHTML=/; el.innerHTML=location.hash;"), ["innerHTML:HIGH"]),
    ("TOK sink inside string none", xss("var s='el.innerHTML = location.hash';"), []),
    ("TOK sink inside comment none", xss("// el.innerHTML = location.hash\nvar a=1;"), []),
    ("TOK division not regex", xss("var a=b/c; var d=e/f; x.innerHTML=location.hash;"), ["innerHTML:HIGH"]),
    ("SEC sk- css none", sec("var c='sk-skeleton-loader-wrapper';"), []),
    ("SEC jwt real", sec("var t='eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdZGVmZ2hpamtsbW5vcA';"), ["JWT"]),
    ("SEC hostname not jwt", sec("x = a.b.c.d.e.foo.bar.baz;"), []),
    ("SEC secret only in comment none", sec("// password = 'hunter2abc'\nvar q=1;"), []),
    ("EP template", ep("fetch(`/api/v1/users/${id}/profile`);"), ["/api/v1/users/{param}/profile"]),
    ("EP noise filtered", ep("var a='text/html', b='application/json', c='dd/mm/yyyy', d='/api/v2/orders';"), ["/api/v2/orders"]),
    ("EP url in comment none", ep("// see https://old.example.com/api/x\nvar z=1;"), []),
    ("FN sensitive", fn("function loginUser(){}; function harmless(){}; var decryptToken=function(){};"), ["decryptToken", "loginUser"]),
]

fails = 0
for name, got, exp in CASES:
    ok = got == sorted(exp)
    if not ok:
        fails += 1
    print("%-5s %-38s %s%s" % ("[OK]" if ok else "[FAIL]", name, got,
                               "" if ok else "  expected %s" % sorted(exp)))

# Special-case: postMessage handler whose event.data reaches innerHTML -> both
pm = xss("window.addEventListener('message', function(ev){ d.innerHTML = ev.data; });")
ok = ("innerHTML:HIGH" in pm) and any(x.startswith("message-listener:") for x in pm)
fails += 0 if ok else 1
print("%-5s %-38s %s" % ("[OK]" if ok else "[FAIL]", "XSS postMessage data->sink", pm))

print("\nDETECTION ASSERTIONS: %s (%d failing)" % ("ALL PASS" if fails == 0 else "FAILED", fails))
sys.exit(1 if fails else 0)
