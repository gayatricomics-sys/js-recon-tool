# -*- coding: utf-8 -*-
"""
JS Recon - Burp Suite Extension (Jython)
Port of the JS Recon Tool's passive JavaScript reconnaissance engine to Burp.

Install: Extender -> Add -> Extension type "Python" -> select this file.
Requires Jython 2.7 (Burp's bundled Jython if configured in Extender options).

Features
  * Passive capture + analysis of JavaScript responses seen through Proxy
  * Right-click "Send to JS Recon" from Proxy / HTTP history / Repeater / Intruder
  * JS Files tab: narrative explanation, framework signatures, source preview
  * Endpoints tab: URL/path candidates from string/template literals
  * Secrets tab: redacted known-prefix, JWT, PEM, sensitive-name, entropy hits
  * DOM XSS tab: static sink findings with best-effort taint heuristics
  * PoC payload generation per DOM-XSS finding (copy to clipboard)
  * Scope / host filtering, text search, CSV + HTML export, live log
  * Burp Target scope is the authorization: PoCs only for in-scope hosts

This extension is passive and does not attack or modify traffic.
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IExtensionStateListener
from burp import IParameter

from java.awt import BorderLayout, Dimension, Font, Color, GridBagLayout, GridBagConstraints, Insets, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener
from javax.swing import (JPanel, JLabel, JTextField, JButton, JCheckBox, JComboBox,
                         JTable, JTextArea, JScrollPane, JTabbedPane, JSplitPane,
                         SwingConstants, ListSelectionModel, SwingUtilities, BorderFactory,
                         JMenuBar, JMenu, JMenuItem, JOptionPane, JPasswordField)
from javax.swing import RowFilter
from javax.swing.table import AbstractTableModel, TableRowSorter
from javax.swing.event import ListSelectionListener
from java.lang import Runnable, Thread, System, String as JString, Long
from java.util import ArrayList
from java.net import URL
from java.io import File, PrintWriter, BufferedWriter, FileWriter
from java.text import SimpleDateFormat
from java.util import Date
from java.util.concurrent import ConcurrentHashMap
from java.util.regex import Pattern, Matcher

import base64
import cgi
import codecs
import json
import math
import threading
import os
import re
import time


VERSION = "1.2.0"
AUTHZ_FILENAME = ".js_recon_authorization"


# ---------------------------------------------------------------------------
# Analysis engine (regex-based port; no external dependencies)
# ---------------------------------------------------------------------------

HTTP_CALL_RE = re.compile(
    r"""(?:fetch|axios|\bget|\bpost|\bput|\bpatch|\bdelete|\bhead|\bopen|\brequest)
        \s*\(\s*(['"`])([^'"`]{1,600}?)\1""",
    re.VERBOSE | re.IGNORECASE,
)

STRING_URL_RE = re.compile(
    r"""['"`]
        (
            (?:(?:https?:)?//)[^\s'"`<>]{3,600}
            | /(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%/]{1,600})
            | (?:[A-Za-z0-9][A-Za-z0-9\-_.]*/){1,6}[A-Za-z0-9][A-Za-z0-9\-._]*?
              (?:\?[^'"`\s]{0,400})?
        )
    ['"`]""",
    re.VERBOSE,
)

TEMPLATE_URL_RE = re.compile(
    r"""[`]
        (
            (?:(?:https?:)?//)[^`]{3,600}
            | /[^`]{1,600}
        )
    [`]""",
    re.VERBOSE,
)

SENSITIVE_NAME_RE = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|authorization|auth[_-]?token|
        access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id|credential|bearer)""",
    re.VERBOSE,
)

ASSIGN_VALUE_RE = re.compile(
    r"""(?i)(?:\b(?:api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|
        access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id|credential|bearer)
        \b\s*[:=]\s*)['"]([^'"]{6,512})['"]""",
    re.VERBOSE,
)

TAINT_SOURCE_TOKENS = [
    "location.search", "location.hash", "location.href", "location.pathname",
    "event.data", "evt.data", "msg.data", "message.data",
    "document.referrer", "document.url", "document.documenturi",
    "window.name", "urlsearchparams", "postmessage", "localstorage",
    "sessionstorage", "document.cookie",
]

KNOWN_PREFIX_RULES = [
    ("AWS Access Key ID", ("AKIA", "ASIA"), 20, 20),
    ("Google API Key", ("AIza",), 39, 39),
    ("GitHub Token", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), 20, 255),
    ("Slack Token", ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"), 20, 200),
    ("Stripe Key", ("sk_live_", "pk_live_", "rk_live_"), 15, 200),
    ("Stripe Test Key", ("sk_test_", "rk_test_"), 15, 200),
    ("Anthropic API Key", ("sk-ant-",), 20, 200),
    ("OpenAI API Key", ("sk-",), 20, 200),
]

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

FRAMEWORK_SIGNATURES = [
    ("React", ["React.createElement", "react-dom", "_jsx", "__REACT_DEVTOOLS"]),
    ("Vue", ["Vue.component", "createApp", "__VUE__", "vue-router"]),
    ("Angular", ["angular.module", "ng-app", "@angular/core"]),
    ("jQuery", ["jQuery.fn.jquery", "jQuery(", "$.ajax"]),
    ("Webpack bundle", ["__webpack_require__", "webpackJsonp"]),
    ("Next.js", ["__NEXT_DATA__", "next/router"]),
]


def entropy(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log(p, 2)
    return result


# Relative "a/b" strings that are almost never endpoints: MIME types, date
# formats, fractions/ratios.
NOISE_SEGMENT_RE = re.compile(
    r"^(?:(?:application|text|image|audio|video|font|multipart|model|message)/[\w.+\-*]+"
    r"|[dmyhsDMYHS]{1,4}/[dmyhsDMYHS]{1,4}(?:/[dmyhsDMYHS]{1,4})?"
    r"|\d+/\d+)$")


def classify_candidate(candidate):
    candidate = candidate.strip()
    if not candidate or len(candidate) > 2000:
        return None
    if "\n" in candidate or "\t" in candidate or " " in candidate:
        return None
    if "://" in candidate:
        # NOTE: Jython/Python 2.7 sre rejects "([^?#]*)?" ("nothing to repeat"),
        # which previously crashed analysis of every file containing a full URL.
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/{2}([^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$", candidate)
        if m:
            return {"kind": "absolute", "protocol": m.group(1), "host": m.group(2),
                    "pathname": m.group(3) or "", "query": m.group(4) or "", "full": candidate}
        return None
    if candidate.startswith("/") and not candidate.startswith("//"):
        return {"kind": "relative-path", "protocol": None, "host": None,
                "pathname": candidate.split("?")[0], "query": "", "full": candidate}
    parts = candidate.split("/")
    if NOISE_SEGMENT_RE.match(candidate):
        return None
    if len(parts) >= 2 and not candidate.startswith((".", "#", "\\")):
        return {"kind": "relative-segment", "protocol": None, "host": None,
                "pathname": candidate, "query": "", "full": candidate}
    return None


def parametrize_template(template):
    return re.sub(r"\$\{[^}]*\}", "{param}", template)


def looks_like_path_or_url(candidate):
    if not candidate:
        return False
    if "/" not in candidate and not candidate.lower().startswith("http"):
        return False
    if re.match(r"^\d+(\.\d+)?$", candidate):
        return False
    return True


def extract_endpoints(source):
    findings = []
    seen = set()

    def record(candidate, line, context):
        classified = classify_candidate(candidate)
        if not classified:
            return
        key = classified["full"]
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "raw": candidate,
            "kind": classified["kind"],
            "host": classified.get("host") or "",
            "path": classified.get("pathname") or "",
            "query": classified.get("query") or "",
            "line": line,
        })

    # Template literals first, so `${...}` paths survive.
    for m in TEMPLATE_URL_RE.finditer(source):
        pattern = parametrize_template(m.group(1))
        record(pattern, line_number_of_index(source, m.start(1)), "template-literal")

    # HTTP call arguments.
    for m in HTTP_CALL_RE.finditer(source):
        candidate = parametrize_template(m.group(2))
        record(candidate, line_number_of_index(source, m.start(2)), "http-call")

    # Generic string literals that look like paths/URLs.
    for m in STRING_URL_RE.finditer(source):
        candidate = parametrize_template(m.group(1))
        record(candidate, line_number_of_index(source, m.start(1)), "string-literal")

    return findings


def line_number_of_index(source, index):
    if index is None or index < 0:
        return 1
    return source.count("\n", 0, min(index, len(source))) + 1


def redact_value(value):
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * max(4, len(value) - 8) + value[-4:]


def base64_like(value):
    if not value:
        return False
    for ch in value:
        if ch not in BASE64_CHARS:
            return False
    return True


def detect_jwt(value):
    parts = value.split(".")
    if len(parts) != 3:
        return None
    if any(len(p) < 4 or not base64_like(p) for p in parts):
        return None
    # Require a real JWT header ({"alg":..} / {"typ":..}) so dotted
    # hostnames and property chains are not reported as tokens.
    try:
        head = str(parts[0]).replace("-", "+").replace("_", "/")
        head += "=" * (-len(head) % 4)
        header = json.loads(base64.b64decode(head))
        if isinstance(header, dict) and ("alg" in header or "typ" in header):
            return "JWT"
    except Exception:
        return None
    return None


def detect_pem(value):
    if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        return "PEM Private Key"
    if "-----BEGIN CERTIFICATE-----" in value:
        return "X.509 Certificate"
    return None


def scan_secrets(source):
    findings = []
    seen = set()

    def record(label, value, line, reason):
        key = label + "|" + value
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "type": label,
            "redacted": redact_value(value),
            "length": len(value),
            "entropy": round(entropy(value), 2),
            "line": line,
            "reason": reason,
        })

    # Known prefixes
    for label, prefixes, min_len, max_len in KNOWN_PREFIX_RULES:
        for prefix in prefixes:
            tail_min = max(0, min_len - len(prefix))
            tail_max = max(tail_min, max_len - len(prefix))
            pattern = re.escape(prefix) + r"[A-Za-z0-9_\-]{%d,%d}" % (tail_min, tail_max)
            for m in re.finditer(pattern, source):
                value = m.group(0)
                if label == "OpenAI API Key":
                    if value.startswith("sk-ant-"):
                        continue
                    # "sk-" alone matches CSS classes (sk-skeleton-...); real
                    # keys are long, contain digits and mixed case.
                    if not (re.search(r"\d", value) and re.search(r"[A-Z]", value)
                            and re.search(r"[a-z]", value) and entropy(value) >= 3.8):
                        continue
                # Keys embedded mid-word (e.g. "EURASIA...") are not keys.
                if m.start() > 0 and re.match(r"[A-Za-z0-9_]", source[m.start() - 1]):
                    continue
                record(label, value, line_number_of_index(source, m.start()), "known-prefix")

    # PEM / JWT
    for m in re.finditer(r"-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----", source):
        label = detect_pem(m.group(0))
        if label:
            record(label, m.group(0), line_number_of_index(source, m.start()), "pem-block")

    for m in re.finditer(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", source):
        value = m.group(0)
        label = detect_jwt(value)
        if label:
            record(label, value, line_number_of_index(source, m.start()), "jwt-structure")

    # Sensitive-name assignments / properties.
    for m in ASSIGN_VALUE_RE.finditer(source):
        value = m.group(1)
        record("Sensitive-Named Value", value, line_number_of_index(source, m.start()), "sensitive-name")

    # High-entropy literals (best-effort, strings only).
    for m in re.finditer(r"""['"]([^'"\s]{24,4096})['"]""", source):
        value = m.group(1)
        if not base64_like(value):
            continue
        if value == value.upper() and re.search(r"[A-Z]", value):
            continue
        e = entropy(value)
        if e >= 4.2:
            record("High-Entropy String", value, line_number_of_index(source, m.start()), "entropy")

    return findings


def contains_taint(fragment):
    lowered = fragment.lower()
    return any(token in lowered for token in TAINT_SOURCE_TOKENS)


def _var_ref_re(name):
    # \b does not work for identifiers containing "$" (e.g. $el), so use
    # explicit identifier-boundary lookarounds.
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")


def _statement_window(source, start, limit=400, stop_at_close=False):
    """Text from `start` to the end of the current expression/statement:
    stops at ; , or newline at nesting depth 0 (or at the closing paren of a
    call when stop_at_close). Keeps minified one-line bundles from treating
    the rest of the whole file as the sink argument."""
    depth = 0
    end = start
    n = min(len(source), start + limit)
    quote = None
    while end < n:
        ch = source[end]
        if quote:
            if ch == "\\":
                end += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch in ";,\n":
            break
        end += 1
    return source[start:end]


def _is_commented(source, index):
    line_start = source.rfind("\n", 0, index) + 1
    prefix = source[line_start:index].lstrip()
    return prefix.startswith("//") or prefix.startswith("*") or prefix.startswith("/*")


XSS_PROPERTY_SINK_RE = re.compile(
    r"(?:\.\s*(innerHTML|outerHTML|srcdoc)|\[\s*['\"](innerHTML|outerHTML|srcdoc)['\"]\s*\])\s*=(?![=>])")
XSS_LOCATION_ASSIGN_RE = re.compile(
    r"(?<![\w$.])(?:(?:window|document|self|top|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=(?![=>])")
XSS_CALL_SINKS = [
    (re.compile(r"\.\s*insertAdjacentHTML\s*\("), "insertAdjacentHTML", False),
    (re.compile(r"\bdocument\s*\.\s*write\s*\("), "write", False),
    (re.compile(r"\bdocument\s*\.\s*writeln\s*\("), "writeln", False),
    (re.compile(r"(?<![\w$.])eval\s*\("), "eval", False),
    (re.compile(r"\bnew\s+Function\s*\("), "Function-constructor", False),
    (re.compile(r"(?<![\w$.])(?<!new )(?<!new\t)Function\s*\("), "Function-constructor", False),
    (re.compile(r"\blocation\s*\.\s*assign\s*\("), "location.assign", False),
    (re.compile(r"\blocation\s*\.\s*replace\s*\("), "location.replace", False),
    # jQuery HTML sinks are extremely common with static strings; only report
    # them when the argument looks attacker-controlled.
    (re.compile(r"\.\s*(?:html|append|prepend|after|before|replaceWith|wrap|wrapAll)\s*\("), "jquery-html", True),
    (re.compile(r"(?<![\w$.])(?:\$|jQuery)\s*\("), "jquery-selector", True),
]
XSS_TIMER_RE = re.compile(r"\b(setTimeout|setInterval)\s*\(")
XSS_MESSAGE_LISTENER_RE = re.compile(r"""addEventListener\s*\(\s*['"]message['"]|\bonmessage\s*=(?!=)""")
TAINT_ASSIGN_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]{1,600})")


def analyze_dom_xss(source):
    findings = []

    # Collect tainted variable names, bounded fixed point.
    assignments = []
    for m in TAINT_ASSIGN_RE.finditer(source):
        name = m.group(1)
        value = _statement_window(source, m.start(2), 600)
        if re.match(r"^(?:function|class|new\s+Function\b)", value):
            continue
        assignments.append((name, value))

    tainted_vars = set()
    var_res = {}
    for _ in range(6):
        changed = False
        for name, value in assignments:
            if name in tainted_vars:
                continue
            if contains_taint(value) or any(var_res[v].search(value) for v in tainted_vars):
                tainted_vars.add(name)
                var_res[name] = _var_ref_re(name)
                changed = True
        if not changed:
            break

    def is_tainted(text):
        return contains_taint(text) or any(var_res[v].search(text) for v in tainted_vars)

    def add(sink, target, index, argtext, tainted, severity=None):
        if severity is None:
            if tainted:
                severity = "HIGH"
            elif sink in ("eval", "Function-constructor"):
                severity = "MEDIUM"
            else:
                severity = "LOW"
        line_no = line_number_of_index(source, index)
        snippet = source[max(0, index - 60):index + 240].replace("\n", " ").strip()
        findings.append({
            "sinkType": sink,
            "target": target,
            "line": line_no,
            "index": index,
            "snippet": snippet[:300],
            "argument": argtext[:300],
            "taintedBySource": bool(tainted),
            "severity": severity,
        })

    for m in XSS_PROPERTY_SINK_RE.finditer(source):
        if _is_commented(source, m.start()):
            continue
        prop = m.group(1) or m.group(2)
        right = _statement_window(source, m.end())
        add(prop, prop, m.start(), right, is_tainted(right))

    for m in XSS_LOCATION_ASSIGN_RE.finditer(source):
        if _is_commented(source, m.start()):
            continue
        right = _statement_window(source, m.end())
        tainted = is_tainted(right)
        add("location-assign", "location", m.start(), right, tainted,
            "HIGH" if tainted else "INFO")

    for regex, sink, only_if_tainted in XSS_CALL_SINKS:
        for m in regex.finditer(source):
            if _is_commented(source, m.start()):
                continue
            arg = _statement_window(source, m.end(), 400, stop_at_close=True)
            tainted = is_tainted(arg)
            if only_if_tainted and not tainted:
                continue
            add(sink, sink, m.start(), arg, tainted)

    for m in XSS_TIMER_RE.finditer(source):
        if _is_commented(source, m.start()):
            continue
        # The window stops at the first depth-0 comma, i.e. it is the first
        # argument only.
        first = _statement_window(source, m.end(), 400).strip()
        sink = m.group(1) + "-string-arg"
        if first[:1] in ("'", '"', "`"):
            add(sink, m.group(1), m.start(), first, is_tainted(first), "MEDIUM")
        elif not re.match(r"(?:async\s+)?(?:function\b|\(?[\w$,\s]*\)?\s*=>)", first) and is_tainted(first):
            add(sink, m.group(1), m.start(), first, True, "HIGH")

    for m in XSS_MESSAGE_LISTENER_RE.finditer(source):
        if _is_commented(source, m.start()):
            continue
        body = source[m.start():m.start() + 1500]
        has_origin_check = re.search(r"\.origin\b", body) is not None
        # Find the handler's event parameter (function(ev){..} / ev => ..) and
        # check whether ev.data reaches an HTML/JS sink inside the handler.
        pm = re.search(r"function\s*[\w$]*\s*\(\s*([\w$]+)|\(?\s*([\w$]+)\s*\)?\s*=>", body)
        param = (pm.group(1) or pm.group(2)) if pm else None
        data_to_sink = False
        if param:
            data_re = re.escape(param) + r"\s*\.\s*data\b"
            data_to_sink = re.search(
                r"(?:innerHTML|outerHTML|srcdoc|insertAdjacentHTML|document\.write|eval|Function|\.html|location)"
                r"[^;]{0,200}" + data_re, body) is not None
        if data_to_sink:
            severity = "MEDIUM" if has_origin_check else "HIGH"
        else:
            severity = "LOW" if has_origin_check else "MEDIUM"
        add("message-listener", "postMessage handler", m.start(), body[:300], data_to_sink, severity)

    # Deduplicate by (sink, position) -- NOT by line, so every sink in a
    # minified single-line bundle is reported.
    deduped = []
    seen = set()
    for f in sorted(findings, key=lambda x: x["index"]):
        key = (f["sinkType"], f["index"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def detect_frameworks(source):
    detected = []
    for name, tokens in FRAMEWORK_SIGNATURES:
        for token in tokens:
            if token in source:
                detected.append(name)
                break
    return detected


def build_summary(source, meta, endpoints, secrets, xss):
    lines = source.count("\n") + 1
    frameworks = detect_frameworks(source)
    url = meta.get("url", "This file")
    sentences = []
    sentences.append("%s is a JavaScript resource of %d lines." % (url, lines))
    if frameworks:
        sentences.append("It appears to use: %s." % ", ".join(frameworks))
    else:
        sentences.append("No recognized frontend framework signature was detected; it may be a plain script, utility bundle, or custom code.")
    if endpoints:
        sentences.append("Static analysis found %d candidate URL/endpoint string(s) referenced in this file." % len(endpoints))
    if secrets:
        sentences.append("WARNING: %d string(s) matched secret/credential heuristics and should be manually verified." % len(secrets))
    if xss:
        high = len([f for f in xss if f.get("severity") == "HIGH"])
        sentences.append("%d potential DOM XSS sink(s) were identified, of which %d appear tainted by a client-controllable source and are flagged HIGH severity." % (len(xss), high))
    else:
        sentences.append("No DOM XSS sink patterns were identified by static analysis in this file.")
    return " ".join(sentences)


def analyze_js_source(source, meta):
    endpoints = extract_endpoints(source)
    secrets = scan_secrets(source)
    xss = analyze_dom_xss(source)
    frameworks = detect_frameworks(source)
    summary = build_summary(source, meta, endpoints, secrets, xss)
    return {
        "endpoints": endpoints,
        "secrets": secrets,
        "xss": xss,
        "frameworks": frameworks,
        "summary": summary,
        "lineCount": lines_of(source),
        # The Files table and detail pane read item["lines"]; it was missing,
        # which raised KeyError on every repaint of the JS Files tab.
        "lines": lines_of(source),
    }


def lines_of(source):
    return source.count("\n") + 1


def payload_for_finding(finding):
    sink = finding.get("sinkType", "")
    marker = "JSRECON-%d" % int(time.time() * 1000)
    templates = {
        "innerHTML": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "outerHTML": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "insertAdjacentHTML": '<svg onload="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "write": "<script>console.warn('%s');alert('%s')<\/script>" % (marker, marker),
        "writeln": "<script>console.warn('%s');alert('%s')<\/script>" % (marker, marker),
        "eval": "alert('%s')" % marker,
        "Function-constructor": "alert('%s')" % marker,
        "setTimeout-string-arg": "alert('%s')" % marker,
        "setInterval-string-arg": "alert('%s')" % marker,
        "location.assign": "javascript:alert('%s')" % marker,
        "location.replace": "javascript:alert('%s')" % marker,
        "location-assign": "javascript:alert('%s')" % marker,
        "srcdoc": '<script>console.warn(\'%s\');alert(\'%s\')<\/script>' % (marker, marker),
        "jquery-html": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "jquery-selector": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "message-listener": "postMessage('<img src=x onerror=alert(\\'%s\\')>', '*')  // send from an attacker-controlled window/iframe" % marker,
    }
    payload = templates.get(sink, '<img src=x onerror="alert(\'%s\')">' % marker)
    return marker, payload


# ---------------------------------------------------------------------------
# Table models
# ---------------------------------------------------------------------------

MAX_SOURCE_CHARS = 8 * 1024 * 1024


class _RunnableFn(Runnable):
    def __init__(self, fn):
        self._fn = fn

    def run(self):
        try:
            self._fn()
        except Exception:
            pass


def _u(value):
    """Unicode-safe text conversion (Jython str() fails on non-ASCII)."""
    if value is None:
        return u""
    if isinstance(value, unicode):
        return value
    try:
        return unicode(value)
    except UnicodeDecodeError:
        return str(value).decode("utf-8", "replace")


def header_value(headers, name):
    """Value of the first header called `name` (case-insensitive), or u"".
    Burp's IExtensionHelpers has no getHeaderValue(), so parse it here."""
    prefix = name.lower() + u":"
    for raw in headers or []:
        line = _u(raw)
        if line.lower().startswith(prefix):
            return line.split(u":", 1)[1].strip()
    return u""


def _esc(value):
    return cgi.escape(_u(value), quote=True)


def _csv_cell(value):
    text = _u(value).replace("\r", " ").replace("\n", " ")
    if any(c in text for c in ',"'):
        text = u'"' + text.replace(u'"', u'""') + u'"'
    return text


class _PyRowFilter(RowFilter):
    """Table filter for Find. With `fn`, keeps model rows where fn(row) is
    true; otherwise keeps rows where any cell contains `term` (lowercase)."""
    def __init__(self, fn=None, term=None):
        self._fn = fn
        self._term = term

    def include(self, entry):
        try:
            if self._fn is not None:
                return bool(self._fn(entry.getIdentifier()))
            for i in range(entry.getValueCount()):
                if self._term in _u(entry.getStringValue(i)).lower():
                    return True
            return False
        except Exception:
            return True


class FilesTableModel(AbstractTableModel):
    columns = ["#", "URL", "Lines", "Endpoints", "Secrets", "DOM XSS", "Frameworks"]

    def __init__(self):
        self.rows = ArrayList()

    def getRowCount(self):
        return self.rows.size()

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, index):
        return self.columns[index]

    def getValueAt(self, row, col):
        item = self.rows.get(row)
        if col == 0:
            return Long(item["id"])
        if col == 1:
            return item["url"]
        if col == 2:
            return item["lines"]
        if col == 3:
            return len(item["endpoints"])
        if col == 4:
            return len(item["secrets"])
        if col == 5:
            return len(item["xss"])
        if col == 6:
            return ", ".join(item["frameworks"])
        return ""

    def getColumnClass(self, c):
        return Long if c == 0 else JString

    def isCellEditable(self, row, col):
        return False

    def addRow(self, item):
        self.rows.add(item)
        self.fireTableRowsInserted(self.rows.size() - 1, self.rows.size() - 1)

    def clearRows(self):
        count = self.rows.size()
        self.rows.clear()
        if count:
            self.fireTableDataChanged()


class SimpleTableModel(AbstractTableModel):
    def __init__(self, columns):
        self.columns = columns
        self.rows = ArrayList()

    def getRowCount(self):
        return self.rows.size()

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, index):
        return self.columns[index]

    def getValueAt(self, row, col):
        item = self.rows.get(row)
        value = item.get(self.columns[col], "")
        if isinstance(value, (int, float, long, bool)):
            return value
        return JString(_u(value))

    def getColumnClass(self, c):
        return JString

    def isCellEditable(self, row, col):
        return False

    def addRow(self, item):
        self.rows.add(item)
        self.fireTableRowsInserted(self.rows.size() - 1, self.rows.size() - 1)

    def clearRows(self):
        count = self.rows.size()
        self.rows.clear()
        if count:
            self.fireTableDataChanged()


# ---------------------------------------------------------------------------
# Burp extension
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Recon")
        callbacks.registerExtensionStateListener(self)

        self._store = {}  # id -> item
        self._next_id = 1
        self._lock = threading.RLock()
        self._host_cache = set()

        self._build_ui()
        callbacks.addSuiteTab(self)

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self._log("JS Recon %s loaded." % VERSION)

    # -- ITab ---------------------------------------------------------------
    def getTabCaption(self):
        return "JS Recon"

    def getUiComponent(self):
        return self._root

    # -- Extension lifecycle -------------------------------------------------
    def extensionUnloaded(self):
        self._log("JS Recon unloaded.")

    # -- HTTP listener -------------------------------------------------------
    def processHttpMessage(self, tool_flag, message_is_request, message):
        if message_is_request:
            return
        try:
            self._handle_response(message)
        except Exception as e:
            self._log("Passive analysis error: %s" % e)

    def _handle_response(self, message):
        if not self._auto_capture.isSelected():
            return
        response = message.getResponse()
        if not response:
            return
        # Content-Type must come from the RESPONSE headers (the old code read
        # the request headers, so JS was only detected by URL extension).
        info = self._helpers.analyzeResponse(response)
        content_type = header_value(info.getHeaders(), "Content-Type").lower()
        java_url = self._url_of(message)
        if java_url is None:
            return
        url = unicode(java_url)
        is_js_type = any(t in content_type for t in ("javascript", "ecmascript", "jscript"))
        if not is_js_type:
            # Burp's own MIME sniffing ("script") catches JS served as text/plain etc.
            try:
                mimes = (_u(info.getStatedMimeType()) + u" " + _u(info.getInferredMimeType())).lower()
                is_js_type = "script" in mimes
            except Exception:
                pass
        if not is_js_type and not self._looks_like_js_url(java_url):
            return
        if self._scope_only.isSelected() and not self._callbacks.isInScope(java_url):
            return
        allowed = _u(self._host_filter.getText()).strip().lower()
        if allowed and allowed not in _u(java_url.getHost()).lower():
            return
        self._analyze_and_store(message, url, java_url)

    def _url_of(self, message):
        """java.net.URL for a message. IHttpRequestResponse has no getUrl() in
        the Burp Extender API; the supported way is analyzeRequest(msg).getUrl()."""
        try:
            return self._helpers.analyzeRequest(message).getUrl()
        except Exception:
            return None

    def _looks_like_js_url(self, java_url):
        # Match on the path extension only, so .json / .jsp / ?x=.js are not
        # mistaken for JavaScript.
        path = unicode(java_url.getPath() or "").lower()
        return path.endswith(".js") or path.endswith(".mjs") or path.endswith(".cjs")

    # -- Context menu --------------------------------------------------------
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        menu = JMenuItem("Send to JS Recon", actionPerformed=lambda evt: self._send_to_recon(messages))
        return [menu]

    def _send_to_recon(self, messages):
        for message in messages:
            if message and message.getResponse():
                try:
                    java_url = self._url_of(message)
                    if java_url is None:
                        self._log("Send-to-Recon: could not determine URL for a selected item.")
                        continue
                    self._analyze_and_store(message, unicode(java_url), java_url)
                except Exception as e:
                    self._log("Send-to-Recon error: %s" % e)

    # -- Analysis ------------------------------------------------------------
    def _analyze_and_store(self, message, url, java_url):
        response = message.getResponse()
        try:
            # Analyze only the body, not the HTTP status line + headers.
            body_offset = self._helpers.analyzeResponse(response).getBodyOffset()
            source = unicode(self._helpers.bytesToString(response)[body_offset:])
        except Exception:
            source = u""
        if not source.strip():
            return
        if len(source) > MAX_SOURCE_CHARS:
            self._log("Skipped %s: %d chars exceeds %d limit." % (url, len(source), MAX_SOURCE_CHARS))
            return

        source_hash = hash(source)
        with self._lock:
            existing = self._by_url.get(url)
            if existing is not None and existing.get("sourceHash") == source_hash:
                return

        # Heavy analysis runs outside the lock (Burp calls us from many threads).
        item = {
            "url": url,
            "host": _u(java_url.getHost()),
            "method": self._helpers.analyzeRequest(message).getMethod() if message.getRequest() else "",
            "ts": int(time.time() * 1000),
            "source": source,
            "sourceHash": source_hash,
        }
        item.update(analyze_js_source(source, item))

        with self._lock:
            existing = self._by_url.get(url)
            if existing is not None and existing.get("sourceHash") == source_hash:
                return
            item["id"] = self._next_id
            self._next_id += 1
            self._store[item["id"]] = item
            self._by_url[url] = item

        self._log("Analyzed %s (E:%d S:%d X:%d)" % (
            url, len(item["endpoints"]), len(item["secrets"]), len(item["xss"])))
        # Swing models must only be touched on the Event Dispatch Thread.
        self._on_edt(lambda: (self._append_item_rows(item), self._update_stats()))

    def _on_edt(self, fn):
        if SwingUtilities.isEventDispatchThread():
            fn()
        else:
            SwingUtilities.invokeLater(_RunnableFn(fn))

    # -- UI ------------------------------------------------------------------
    def _build_ui(self):
        self._root = JPanel(BorderLayout())
        self._root.setBackground(Color(0xF5, 0xF5, 0xF7))
        self._by_url = {}
        self._host_filter_cache = set()

        # Authorization banner: Burp's Target scope IS the authorization. Hosts
        # you add to Target -> Scope are treated as authorized automatically;
        # there is no separate host box or checkbox to fill in.
        banner = JPanel(GridBagLayout())
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(4, 8, 4, 8),
            BorderFactory.createTitledBorder("Authorization = Burp Target scope")))
        banner.setBackground(Color(0xFF, 0xF6, 0xE5))
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(2, 2, 2, 6)
        self._authz_status = JLabel(
            "Hosts in Burp's Target scope are treated as authorized targets. "
            "PoC payloads are only generated for in-scope URLs; out-of-scope hosts stay passive.")
        banner.add(self._authz_status, gbc)

        # Toolbar
        toolbar = JPanel()
        self._auto_capture = JCheckBox("Passive capture", True)
        # Default ON: only the target(s) you added to Burp scope are captured.
        self._scope_only = JCheckBox("In-scope only", True)
        self._scope_only.setToolTipText("Capture only URLs in Burp's Target scope. Untick to capture all JavaScript seen by the proxy.")
        self._host_filter = JTextField(14)
        # Press Enter in the host filter to re-apply it to existing findings.
        self._host_filter.addActionListener(lambda evt: self._refresh_tables())
        self._search_field = JTextField(18)
        self._search_field.setToolTipText("Text to find in URLs, source, endpoints, secrets and DOM XSS rows. Press Enter or Find; empty + Find shows all.")
        self._search_field.addActionListener(self._on_search)  # Enter runs Find
        search_btn2 = JButton("Find", actionPerformed=self._on_search)
        clear_btn = JButton("Clear", actionPerformed=self._on_clear)
        export_csv_btn = JButton("Export CSV", actionPerformed=self._on_export_csv)
        export_html_btn = JButton("Export HTML", actionPerformed=self._on_export_html)
        copy_btn = JButton("Copy PoC", actionPerformed=self._on_copy_poc)
        gen_all_btn = JButton("Generate all PoCs", actionPerformed=self._on_generate_all_pocs)
        toolbar.add(self._auto_capture)
        toolbar.add(self._scope_only)
        toolbar.add(JLabel("Host filter"))
        toolbar.add(self._host_filter)
        toolbar.add(JLabel("Search"))
        toolbar.add(self._search_field)
        toolbar.add(search_btn2)
        toolbar.add(clear_btn)
        toolbar.add(export_csv_btn)
        toolbar.add(export_html_btn)
        toolbar.add(copy_btn)
        toolbar.add(gen_all_btn)

        self._status = JLabel("Ready")
        statusbar = JPanel(BorderLayout())
        statusbar.add(self._status, BorderLayout.WEST)

        top = JPanel(BorderLayout())
        top.add(toolbar, BorderLayout.NORTH)
        top.add(banner, BorderLayout.CENTER)

        # Main tabbed pane
        self._tabs = JTabbedPane()

        # Files tab
        self._files_model = FilesTableModel()
        self._files_table = JTable(self._files_model)
        self._files_sorter = TableRowSorter(self._files_model)
        self._files_table.setRowSorter(self._files_sorter)
        self._files_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._files_table.getSelectionModel().addListSelectionListener(self._on_file_selected)
        files_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        files_left = JScrollPane(self._files_table)
        self._file_detail = JTextArea()
        self._file_detail.setEditable(False)
        self._file_detail.setLineWrap(True)
        self._file_detail.setWrapStyleWord(True)
        files_right = JScrollPane(self._file_detail)
        files_split.setLeftComponent(files_left)
        files_split.setRightComponent(files_right)
        files_split.setDividerLocation(400)
        self._tabs.addTab("JS Files", files_split)

        # Endpoints tab
        self._endpoint_model = SimpleTableModel(["URL", "Kind", "Host", "Path", "Query", "Line", "Source File"])
        self._endpoint_table = JTable(self._endpoint_model)
        self._endpoint_sorter = TableRowSorter(self._endpoint_model)
        self._endpoint_table.setRowSorter(self._endpoint_sorter)
        self._endpoint_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._tabs.addTab("Endpoints", JScrollPane(self._endpoint_table))

        # Secrets tab
        self._secret_model = SimpleTableModel(["Type", "Redacted", "Length", "Entropy", "Line", "Reason", "Source File"])
        self._secret_table = JTable(self._secret_model)
        self._secret_sorter = TableRowSorter(self._secret_model)
        self._secret_table.setRowSorter(self._secret_sorter)
        self._secret_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._tabs.addTab("Secrets", JScrollPane(self._secret_table))

        # DOM XSS tab
        self._xss_model = SimpleTableModel(["Severity", "Sink", "Target", "Line", "Tainted", "Snippet", "Source File"])
        self._xss_table = JTable(self._xss_model)
        self._xss_sorter = TableRowSorter(self._xss_model)
        self._xss_table.setRowSorter(self._xss_sorter)
        self._xss_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._tabs.addTab("DOM XSS", JScrollPane(self._xss_table))

        # Log tab
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._tabs.addTab("Log", JScrollPane(self._log_area))

        center = JPanel(BorderLayout())
        center.add(top, BorderLayout.NORTH)
        center.add(self._tabs, BorderLayout.CENTER)
        self._root.add(center, BorderLayout.CENTER)
        self._root.add(statusbar, BorderLayout.SOUTH)
        self._root.setPreferredSize(Dimension(1100, 700))

        self._endpoint_by_row = []
        self._secret_by_row = []
        self._xss_by_row = []
        self._xss_findings = []

    def _is_authorized(self, item):
        """A file's host is authorized when its URL is in Burp's Target scope."""
        try:
            return bool(self._callbacks.isInScope(URL(item["url"])))
        except Exception:
            return False

    def _notify(self, msg):
        """Message the user can see right away (status bar) and in the Log tab."""
        self._log(msg)
        self._status.setText(_u(msg))

    def _blocked(self, item):
        msg = (u"Blocked: %s is not in Burp's Target scope. Add it under Target -> Scope "
               u"(right-click the host -> Add to scope) to generate PoCs." % item["host"])
        self._log(msg)
        self._status.setText(msg)

    def _on_file_selected(self, evt):
        row = self._files_table.getSelectedRow()
        if row >= 0:
            model_row = self._files_table.convertRowIndexToModel(row)
            item = self._files_model.rows.get(model_row)
            if item is None:
                return
            self._file_detail.setText(self._file_summary_text(item))
            self._file_detail.setCaretPosition(0)

    def _file_summary_text(self, item):
        lines = []
        lines.append("URL: %s" % item["url"])
        lines.append("Host: %s" % item["host"])
        lines.append("Lines: %d" % item["lines"])
        lines.append("Frameworks: %s" % (", ".join(item["frameworks"]) if item["frameworks"] else "none"))
        lines.append("")
        lines.append("Summary:")
        lines.append("  %s" % item["summary"])
        lines.append("")
        lines.append("Endpoints: %d" % len(item["endpoints"]))
        for e in item["endpoints"][:30]:
            lines.append("  L%s  %s" % (e["line"], e["raw"]))
        lines.append("")
        lines.append("Secrets: %d" % len(item["secrets"]))
        for s in item["secrets"][:30]:
            lines.append("  L%s  %s  (%s)" % (s["line"], s["redacted"], s["type"]))
        lines.append("")
        lines.append("DOM XSS findings: %d" % len(item["xss"]))
        for x in item["xss"][:30]:
            lines.append("  L%s  %s  %s" % (x["line"], x["severity"], x["sinkType"]))
        lines.append("")
        lines.append("Source preview (first 500 lines):")
        preview = item["source"].split("\n")[:500]
        lines.extend(preview)
        return "\n".join(lines)

    def _refresh_tables(self):
        """Full rebuild (used after Clear). New captures use _append_item_rows
        so the UI does not re-render every row on each response."""
        self._files_model.clearRows()
        self._endpoint_model.clearRows()
        self._secret_model.clearRows()
        self._xss_model.clearRows()
        self._endpoint_by_row = []
        self._secret_by_row = []
        self._xss_by_row = []
        self._xss_findings = []
        with self._lock:
            items = sorted(self._store.values(), key=lambda i: i["id"])
        for item in items:
            self._append_item_rows(item)
        self._update_stats()

    def _append_item_rows(self, item):
        self._files_model.addRow(item)
        host_filter = _u(self._host_filter.getText()).strip().lower()
        if host_filter and host_filter not in item["host"].lower():
            return
        for e in item["endpoints"]:
            self._endpoint_by_row.append(item)
            self._endpoint_model.addRow({
                "URL": e["raw"],
                "Kind": e["kind"],
                "Host": e["host"],
                "Path": e["path"],
                "Query": e["query"],
                "Line": e["line"],
                "Source File": item["url"],
            })
        for s in item["secrets"]:
            self._secret_by_row.append(item)
            self._secret_model.addRow({
                "Type": s["type"],
                "Redacted": s["redacted"],
                "Length": s["length"],
                "Entropy": s["entropy"],
                "Line": s["line"],
                "Reason": s["reason"],
                "Source File": item["url"],
            })
        for x in item["xss"]:
            self._xss_by_row.append(item)
            self._xss_findings.append(x)
            self._xss_model.addRow({
                "Severity": x["severity"],
                "Sink": x["sinkType"],
                "Target": x["target"],
                "Line": x["line"],
                "Tainted": "yes" if x["taintedBySource"] else "no",
                "Snippet": x["snippet"],
                "Source File": item["url"],
            })

    def _update_stats(self):
        with self._lock:
            items = list(self._store.values())
        files = len(items)
        endpoints = sum(len(i["endpoints"]) for i in items)
        secrets = sum(len(i["secrets"]) for i in items)
        xss = sum(len(i["xss"]) for i in items)
        self._status.setText("Files: %d | Endpoints: %d | Secrets: %d | DOM XSS: %d" % (
            files, endpoints, secrets, xss))

    # -- Actions -------------------------------------------------------------
    def _on_clear(self, evt):
        with self._lock:
            self._store.clear()
            self._by_url.clear()
        self._refresh_tables()
        self._log("Cleared all captured JS files and findings.")

    def _on_search(self, evt):
        """Find: filters every table to matching rows (previously it only
        wrote to the Log tab, so it looked like nothing happened). An empty
        search box + Find clears the filter."""
        term = _u(self._search_field.getText()).strip().lower()
        sorters = (self._files_sorter, self._endpoint_sorter, self._secret_sorter, self._xss_sorter)
        if not term:
            for sorter in sorters:
                sorter.setRowFilter(None)
            self._status.setText("Find cleared - showing all rows.")
            self._update_stats()
            return

        files_rows = self._files_model.rows

        def file_matches(model_row):
            item = files_rows.get(model_row)
            return (term in item["url"].lower() or term in item["summary"].lower()
                    or term in item["source"].lower())

        self._files_sorter.setRowFilter(_PyRowFilter(file_matches))
        for sorter in sorters[1:]:
            sorter.setRowFilter(_PyRowFilter(None, term))

        counts = (self._files_table.getRowCount(), self._endpoint_table.getRowCount(),
                  self._secret_table.getRowCount(), self._xss_table.getRowCount())
        msg = (u"Find '%s': %d file(s), %d endpoint(s), %d secret(s), %d DOM XSS row(s) match. "
               u"Empty the box and click Find to show all." % ((term,) + counts))
        self._status.setText(msg)
        self._log(msg)

        if counts[0]:
            # Open the first matching file and highlight the first hit in its source.
            self._files_table.setRowSelectionInterval(0, 0)
            text = _u(self._file_detail.getText())
            pos = text.lower().find(term)
            if pos >= 0:
                self._file_detail.requestFocusInWindow()
                self._file_detail.select(pos, pos + len(term))
        # If the visible tab has no hits, switch to the first tab that has some.
        tab_counts = {0: counts[0], 1: counts[1], 2: counts[2], 3: counts[3]}
        current = self._tabs.getSelectedIndex()
        if tab_counts.get(current, 1) == 0:
            for idx in (0, 1, 2, 3):
                if tab_counts[idx]:
                    self._tabs.setSelectedIndex(idx)
                    break
        if not any(counts):
            try:
                JOptionPane.showMessageDialog(self._root, u"No matches for '%s'." % term,
                                              "JS Recon - Find", JOptionPane.INFORMATION_MESSAGE)
            except Exception:
                pass  # headless (self-test); the status bar already says 0 matches

    def _on_export_csv(self, evt):
        chooser = None
        try:
            from javax.swing import JFileChooser
            chooser = JFileChooser()
            chooser.setSelectedFile(File("js_recon_export.csv"))
            if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
                return
            target = chooser.getSelectedFile()
        except Exception as e:
            self._log("Export dialog error: %s" % e)
            return
        try:
            self._write_csv(_u(target.getAbsolutePath()))
            self._log("Exported CSV to %s" % target.getAbsolutePath())
            self._status.setText("CSV exported to %s" % target.getAbsolutePath())
        except Exception as e:
            self._log("CSV export error: %s" % e)

    def _on_export_html(self, evt):
        try:
            from javax.swing import JFileChooser
            chooser = JFileChooser()
            chooser.setSelectedFile(File("js_recon_report.html"))
            if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
                return
            target = chooser.getSelectedFile()
        except Exception as e:
            self._log("Export dialog error: %s" % e)
            return
        try:
            self._write_html_report(str(target.getAbsolutePath()))
            self._log("Exported HTML report to %s" % target.getAbsolutePath())
            self._status.setText("HTML report exported to %s" % target.getAbsolutePath())
        except Exception as e:
            self._log("HTML export error: %s" % e)

    def _snapshot(self):
        with self._lock:
            return sorted(self._store.values(), key=lambda i: i["id"])

    def _write_csv(self, path):
        with codecs.open(path, "w", "utf-8") as f:
            f.write(u"﻿kind,source_file,line,type,value,severity,detail\r\n")
            for item in self._snapshot():
                for e in item["endpoints"]:
                    row = ["endpoint", item["url"], e["line"], e["kind"], e["raw"], "", e["host"]]
                    f.write(u",".join(_csv_cell(c) for c in row) + u"\r\n")
                for s in item["secrets"]:
                    row = ["secret", item["url"], s["line"], s["type"], s["redacted"], "",
                           "entropy=%s %s" % (s["entropy"], s["reason"])]
                    f.write(u",".join(_csv_cell(c) for c in row) + u"\r\n")
                for x in item["xss"]:
                    row = ["domxss", item["url"], x["line"], x["sinkType"], x["snippet"], x["severity"],
                           "tainted" if x["taintedBySource"] else "not-tainted"]
                    f.write(u",".join(_csv_cell(c) for c in row) + u"\r\n")

    def _write_html_report(self, path):
        # Every value comes from the target's JavaScript, so it is HTML-escaped
        # (otherwise a hostile JS file could inject script into the report).
        rows = []
        for item in self._snapshot():
            rows.append(u"<h3>%s</h3>" % _esc(item["url"]))
            rows.append(u"<p><b>Summary:</b> %s</p>" % _esc(item["summary"]))
            if item["endpoints"]:
                rows.append(u"<p><b>Endpoints</b></p><ul>")
                for e in item["endpoints"]:
                    rows.append(u"<li>L%d <code>%s</code> <i>(%s)</i></li>" % (e["line"], _esc(e["raw"]), _esc(e["kind"])))
                rows.append(u"</ul>")
            if item["secrets"]:
                rows.append(u"<p><b>Secrets</b></p><ul>")
                for s in item["secrets"]:
                    rows.append(u"<li>L%d <code>%s</code> <i>(%s)</i></li>" % (s["line"], _esc(s["redacted"]), _esc(s["type"])))
                rows.append(u"</ul>")
            if item["xss"]:
                rows.append(u"<p><b>DOM XSS</b></p><ul>")
                for x in item["xss"]:
                    rows.append(u"<li>L%d <b>%s</b> <code>%s</code> <i>%s</i><pre>%s</pre></li>" % (
                        x["line"], _esc(x["severity"]), _esc(x["sinkType"]),
                        "tainted" if x["taintedBySource"] else "not tainted", _esc(x["snippet"])))
                rows.append(u"</ul>")
        html = u"<html><head><meta charset='utf-8'><title>JS Recon Report</title></head><body>"
        html += u"<h1>JS Recon Report</h1><p>Generated by JS Recon Burp extension.</p>"
        html += u"".join(rows)
        html += u"</body></html>"
        with codecs.open(path, "w", "utf-8") as f:
            f.write(html)

    def _selected_item(self):
        row = self._files_table.getSelectedRow()
        if row < 0:
            return None
        model_row = self._files_table.convertRowIndexToModel(row)
        return self._files_model.rows.get(model_row)

    def _on_copy_poc(self, evt):
        row = self._xss_table.getSelectedRow()
        if row < 0:
            self._notify("Copy PoC: select a finding in the DOM XSS table.")
            return
        idx = self._xss_table.convertRowIndexToModel(row)
        if idx >= len(self._xss_findings):
            self._notify("Copy PoC: selection is out of range.")
            return
        # Use the file the finding came from (previously this used whatever
        # was selected in the JS Files tab, so the authorization host check
        # could be made against the wrong host).
        item = self._xss_by_row[idx]
        finding = self._xss_findings[idx]
        self._generate_and_copy(item, finding)

    def _generate_and_copy(self, item, finding):
        if not self._is_authorized(item):
            self._blocked(item)
            return
        marker, payload = payload_for_finding(finding)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(payload), None)
        msg = u"PoC copied to clipboard for %s (marker %s)." % (item["url"], marker)
        self._log(msg)
        self._status.setText(msg)

    def _on_generate_all_pocs(self, evt):
        item = self._selected_item()
        if not item:
            self._notify("Generate all PoCs: select a JS file first.")
            return
        if not self._is_authorized(item):
            self._blocked(item)
            return
        lines = []
        for idx, x in enumerate(item["xss"]):
            marker, payload = payload_for_finding(x)
            lines.append("Finding %d: %s (line %d)\nMarker: %s\nPayload: %s\n" % (
                idx + 1, x["sinkType"], x["line"], marker, payload))
        text = "\n".join(lines)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
        self._log("Generated and copied %d PoCs for %s." % (len(item["xss"]), item["url"]))

    # -- Logging -------------------------------------------------------------
    def _log(self, message):
        text = _u(message)
        try:
            self._callbacks.printOutput(u"[JS Recon] " + text)
        except Exception:
            pass

        def append():
            if getattr(self, "_log_area", None) is not None:
                self._log_area.append(text + u"\n")
                self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        try:
            self._on_edt(append)
        except Exception:
            pass
