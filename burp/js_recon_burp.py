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
  * Authorization gate before generating active PoC payloads

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
from javax.swing.table import AbstractTableModel, TableRowSorter
from javax.swing.event import ListSelectionListener
from java.lang import Runnable, Thread, System, String as JString, Long
from java.util import ArrayList
from java.io import File, PrintWriter, BufferedWriter, FileWriter
from java.text import SimpleDateFormat
from java.util import Date
from java.util.concurrent import ConcurrentHashMap
from java.util.regex import Pattern, Matcher

import json
import math
import os
import re
import time


VERSION = "1.0.0"
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


def classify_candidate(candidate):
    candidate = candidate.strip()
    if not candidate or len(candidate) > 2000:
        return None
    if "\n" in candidate or "\t" in candidate or " " in candidate:
        return None
    if "://" in candidate:
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/{2}([^/?#]+)([^?#]*)?(\?[^#]*)?(#.*)?$", candidate)
        if m:
            return {"kind": "absolute", "protocol": m.group(1), "host": m.group(2),
                    "pathname": m.group(3) or "", "query": m.group(4) or "", "full": candidate}
        return None
    if candidate.startswith("/") and not candidate.startswith("//"):
        return {"kind": "relative-path", "protocol": None, "host": None,
                "pathname": candidate.split("?")[0], "query": "", "full": candidate}
    parts = candidate.split("/")
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
    return "JWT"


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
                if label == "OpenAI API Key" and value.startswith("sk-ant-"):
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


def analyze_dom_xss(source):
    findings = []
    lines = source.split("\n")
    tainted_vars = set()

    # Collect tainted variable names, bounded fixed point.
    assignments = []
    for m in re.finditer(r"(?:\bvar\b|\blet\b|\bconst\b)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,600})", source):
        name = m.group(1)
        value = m.group(2)
        if re.match(r"^(?:function|class|new\s+Function\b)", value):
            continue
        assignments.append((name, value))

    for _ in range(6):
        changed = False
        for name, value in assignments:
            if name in tainted_vars:
                continue
            if contains_taint(value):
                tainted_vars.add(name)
                changed = True
            else:
                for other in tainted_vars:
                    if re.search(r"\b" + re.escape(other) + r"\b", value):
                        tainted_vars.add(name)
                        changed = True
                        break
        if not changed:
            break

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        # property sinks: innerHTML / outerHTML
        for m in re.finditer(r"\.(innerHTML|outerHTML)\s*=", line):
            prop = m.group(1)
            right = line[m.end():]
            tainted = contains_taint(right) or any(
                re.search(r"\b" + re.escape(v) + r"\b", right) for v in tainted_vars
            )
            findings.append({
                "sinkType": prop,
                "target": line.strip()[:120],
                "line": line_no,
                "snippet": stripped[:300],
                "taintedBySource": tainted,
                "severity": "HIGH" if tainted else "LOW",
            })

        # call sinks
        for prop, label in [("insertAdjacentHTML", "insertAdjacentHTML"), ("document.write", "write"),
                            ("document.writeln", "writeln"), ("eval", "eval")]:
            for m in re.finditer(re.escape(prop) + r"\s*\(", line):
                idx = m.end()
                depth = 1
                end = idx
                while end < len(line) and depth > 0:
                    ch = line[end]
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                    end += 1
                argtext = line[idx:end - 1] if depth == 0 else line[idx:min(end, idx + 400)]
                tainted = contains_taint(argtext) or any(
                    re.search(r"\b" + re.escape(v) + r"\b", argtext) for v in tainted_vars
                )
                severity = "HIGH" if tainted else ("MEDIUM" if label == "eval" else "LOW")
                findings.append({
                    "sinkType": label,
                    "target": prop,
                    "line": line_no,
                    "snippet": stripped[:300],
                    "taintedBySource": tainted,
                    "severity": severity,
                })

        # new Function(...) and setTimeout/setInterval string args
        for m in re.finditer(r"\bnew\s+Function\s*\(", line):
            argtext = line[m.end():min(len(line), m.end() + 300)]
            tainted = contains_taint(argtext) or any(
                re.search(r"\b" + re.escape(v) + r"\b", argtext) for v in tainted_vars
            )
            findings.append({
                "sinkType": "Function-constructor",
                "target": "new Function()",
                "line": line_no,
                "snippet": stripped[:300],
                "taintedBySource": tainted,
                "severity": "HIGH" if tainted else "MEDIUM",
            })

        for m in re.finditer(r"\b(setTimeout|setInterval)\s*\(\s*['\"]", line):
            findings.append({
                "sinkType": m.group(1) + "-string-arg",
                "target": m.group(1),
                "line": line_no,
                "snippet": stripped[:300],
                "taintedBySource": contains_taint(line),
                "severity": "MEDIUM",
            })

        for m in re.finditer(r"\blocation\s*\.\s*(assign|replace)\s*\(", line):
            argtext = line[m.end():min(len(line), m.end() + 300)]
            tainted = contains_taint(argtext) or any(
                re.search(r"\b" + re.escape(v) + r"\b", argtext) for v in tainted_vars
            )
            findings.append({
                "sinkType": "location." + m.group(1),
                "target": "location",
                "line": line_no,
                "snippet": stripped[:300],
                "taintedBySource": tainted,
                "severity": "HIGH" if tainted else "LOW",
            })

    # deduplicate by (sink, line, snippet)
    deduped = []
    seen = set()
    for f in findings:
        key = (f["sinkType"], f["line"], f["snippet"])
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
    }
    payload = templates.get(sink, '<img src=x onerror="alert(\'%s\')">' % marker)
    return marker, payload


# ---------------------------------------------------------------------------
# Table models
# ---------------------------------------------------------------------------

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
        return JString(str(value))

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
        self._lock = Thread.currentThread()
        self._host_cache = set()
        self._authz_host = None
        self._authz_checked = False

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
        info = self._helpers.analyzeRequest(message)
        headers = info.getHeaders()
        content_type = self._helpers.getHeaderValue(headers, "Content-Type") or ""
        url = str(message.getUrl())
        if "javascript" not in content_type.lower() and not self._looks_like_js_url(url):
            return
        if self._scope_only.isSelected() and not self._callbacks.isInScope(message.getUrl()):
            return
        if self._host_filter.getText().strip():
            allowed = str(self._host_filter.getText().strip()).lower()
            host = str(message.getUrl().getHost()).lower()
            if allowed not in host:
                return
        self._analyze_and_store(message, url)

    def _looks_like_js_url(self, url):
        return ".js" in url.lower() or ".mjs" in url.lower()

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
                    self._analyze_and_store(message, str(message.getUrl()))
                except Exception as e:
                    self._log("Send-to-Recon error: %s" % e)

    # -- Analysis ------------------------------------------------------------
    def _analyze_and_store(self, message, url):
        response = message.getResponse()
        bytes_data = response
        source = None
        try:
            source = self._helpers.bytesToString(bytes_data)
        except:
            source = ""
        if source is None or not source.strip():
            return

        # Avoid reanalyzing identical large source blobs.
        existing = self._by_url.get(url)
        if existing is not None and existing.get("sourceHash") == hash(source):
            return

        item = {
            "id": self._next_id,
            "url": url,
            "host": str(message.getUrl().getHost()),
            "method": self._helpers.analyzeRequest(message).getMethod() if message.getRequest() else "",
            "ts": int(time.time() * 1000),
            "source": source,
            "sourceHash": hash(source),
        }
        result = analyze_js_source(source, item)
        item.update(result)

        self._next_id += 1
        self._store[item["id"]] = item
        self._by_url[url] = item
        self._log("Analyzed %s (E:%d S:%d X:%d)" % (
            url, len(item["endpoints"]), len(item["secrets"]), len(item["xss"])))
        self._refresh_tables()
        self._update_stats()

    # -- UI ------------------------------------------------------------------
    def _build_ui(self):
        self._root = JPanel(BorderLayout())
        self._root.setBackground(Color(0xF5, 0xF5, 0xF7))
        self._by_url = {}
        self._host_filter_cache = set()

        # Authorization banner
        banner = JPanel(GridBagLayout())
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(4, 8, 4, 8),
            BorderFactory.createTitledBorder("Authorization gate")))
        banner.setBackground(Color(0xFF, 0xF6, 0xE5))
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(2, 2, 2, 6)
        banner.add(JLabel("Host"), gbc)
        gbc.gridx = 1
        self._authz_host_field = JTextField(20)
        banner.add(self._authz_host_field, gbc)
        gbc.gridx = 2
        self._authz_check = JCheckBox("I am authorized to actively test this host")
        self._authz_check.addActionListener(self._on_authz_changed)
        banner.add(self._authz_check, gbc)
        gbc.gridx = 3
        self._authz_status = JLabel("Inactive (passive-only mode)")
        banner.add(self._authz_status, gbc)
        self._root.add(banner, BorderLayout.NORTH)

        # Toolbar
        toolbar = JPanel()
        self._auto_capture = JCheckBox("Passive capture", True)
        self._scope_only = JCheckBox("In-scope only", False)
        self._host_filter = JTextField(14)
        search_btn = JButton("Search", actionPerformed=self._on_search)
        self._search_field = JTextField(18)
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
        self._files_table.setRowSorter(TableRowSorter(self._files_model))
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
        self._endpoint_table.setRowSorter(TableRowSorter(self._endpoint_model))
        self._endpoint_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._tabs.addTab("Endpoints", JScrollPane(self._endpoint_table))

        # Secrets tab
        self._secret_model = SimpleTableModel(["Type", "Redacted", "Length", "Entropy", "Line", "Reason", "Source File"])
        self._secret_table = JTable(self._secret_model)
        self._secret_table.setRowSorter(TableRowSorter(self._secret_model))
        self._secret_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._tabs.addTab("Secrets", JScrollPane(self._secret_table))

        # DOM XSS tab
        self._xss_model = SimpleTableModel(["Severity", "Sink", "Target", "Line", "Tainted", "Snippet", "Source File"])
        self._xss_table = JTable(self._xss_model)
        self._xss_table.setRowSorter(TableRowSorter(self._xss_model))
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

    def _on_authz_changed(self, evt):
        host = str(self._authz_host_field.getText()).strip().lower()
        if self._authz_check.isSelected() and host:
            self._authz_host = host
            self._authz_status.setText("Authorization armed for: %s" % host)
            self._status.setText("Active-test payloads are authorized for %s." % host)
        else:
            self._authz_host = None
            self._authz_status.setText("Inactive (passive-only mode)")
            self._status.setText("Active-test payloads are disabled.")

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
        self._files_model.clearRows()
        self._endpoint_model.clearRows()
        self._secret_model.clearRows()
        self._xss_model.clearRows()
        self._endpoint_by_row = []
        self._secret_by_row = []
        self._xss_by_row = []
        self._xss_findings = []

        for item in sorted(self._store.values(), key=lambda i: i["id"]):
            self._files_model.addRow(item)
            host_filter = str(self._host_filter.getText()).strip().lower()
            if host_filter and host_filter not in item["host"].lower():
                continue
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
        self._update_stats()

    def _update_stats(self):
        files = len(self._store)
        endpoints = sum(len(i["endpoints"]) for i in self._store.values())
        secrets = sum(len(i["secrets"]) for i in self._store.values())
        xss = sum(len(i["xss"]) for i in self._store.values())
        self._status.setText("Files: %d | Endpoints: %d | Secrets: %d | DOM XSS: %d" % (
            files, endpoints, secrets, xss))

    # -- Actions -------------------------------------------------------------
    def _on_clear(self, evt):
        self._store.clear()
        self._by_url.clear()
        self._files_model.clearRows()
        self._endpoint_model.clearRows()
        self._secret_model.clearRows()
        self._xss_model.clearRows()
        self._endpoint_by_row = []
        self._secret_by_row = []
        self._xss_by_row = []
        self._log("Cleared all captured JS files and findings.")
        self._update_stats()

    def _on_search(self, evt):
        term = str(self._search_field.getText()).strip().lower()
        if not term:
            self._log("Search: enter a term.")
            return
        matched_files = []
        for item in self._store.values():
            hay = " ".join([
                item["url"],
                item["summary"],
                " ".join(e["raw"] for e in item["endpoints"]),
                " ".join(s["redacted"] for s in item["secrets"]),
                " ".join(x["snippet"] for x in item["xss"]),
                item["source"],
            ]).lower()
            if term in hay:
                matched_files.append(item["url"])
        self._log("Search '%s': %d file(s) matched." % (term, len(matched_files)))
        for url in matched_files[:100]:
            self._log("  %s" % url)

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
            with open(str(target.getAbsolutePath()), "w") as f:
                f.write("kind,url,field,value,extra\n")
                for item in self._store.values():
                    base = "%s" % item["url"]
                    for e in item["endpoints"]:
                        f.write("endpoint,%s,%s,%s,%s\n" % (base, e["kind"], e["raw"], e["line"]))
                    for s in item["secrets"]:
                        f.write("secret,%s,%s,%s,%s,%s\n" % (base, s["type"], s["redacted"], s["entropy"], s["line"]))
                    for x in item["xss"]:
                        f.write("domxss,%s,%s,%s,%s,%s,%s\n" % (
                            base, x["sinkType"], x["severity"], x["line"],
                            "tainted" if x["taintedBySource"] else "not-tainted", x["snippet"].replace("\n", " ")))
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

    def _write_html_report(self, path):
        rows = []
        for item in sorted(self._store.values(), key=lambda i: i["id"]):
            rows.append("<h3>%s</h3>" % item["url"])
            rows.append("<p><b>Summary:</b> %s</p>" % item["summary"])
            if item["endpoints"]:
                rows.append("<p><b>Endpoints</b></p><ul>")
                for e in item["endpoints"]:
                    rows.append("<li>L%d <code>%s</code> <i>(%s)</i></li>" % (e["line"], e["raw"], e["kind"]))
                rows.append("</ul>")
            if item["secrets"]:
                rows.append("<p><b>Secrets</b></p><ul>")
                for s in item["secrets"]:
                    rows.append("<li>L%d <code>%s</code> <i>(%s)</i></li>" % (s["line"], s["redacted"], s["type"]))
                rows.append("</ul>")
            if item["xss"]:
                rows.append("<p><b>DOM XSS</b></p><ul>")
                for x in item["xss"]:
                    rows.append("<li>L%d <b>%s</b> <code>%s</code> <i>%s</i></li>" % (
                        x["line"], x["severity"], x["sinkType"],
                        "tainted" if x["taintedBySource"] else "not tainted"))
                rows.append("</ul>")
        html = "<html><head><meta charset='utf-8'><title>JS Recon Report</title></head><body>"
        html += "<h1>JS Recon Report</h1><p>Generated by JS Recon Burp extension.</p>"
        html += "".join(rows)
        html += "</body></html>"
        with open(path, "w") as f:
            f.write(html)

    def _selected_item(self):
        row = self._files_table.getSelectedRow()
        if row < 0:
            return None
        model_row = self._files_table.convertRowIndexToModel(row)
        return self._files_model.rows.get(model_row)

    def _on_copy_poc(self, evt):
        item = self._selected_item()
        if not item or not item["xss"]:
            self._log("Copy PoC: select a JS file with DOM XSS findings.")
            return
        row = self._xss_table.getSelectedRow()
        if row < 0:
            self._log("Copy PoC: select a finding in the DOM XSS table.")
            return
        idx = self._xss_table.convertRowIndexToModel(row)
        if idx >= len(self._xss_findings):
            self._log("Copy PoC: selection is out of range.")
            return
        finding = self._xss_findings[idx]
        self._generate_and_copy(item, finding)

    def _generate_and_copy(self, item, finding):
        if not self._authz_check.isSelected() or self._authz_host != item["host"].lower():
            self._log("Blocked: authorization checkbox not set for %s." % item["host"])
            self._status.setText("Authorization required for %s to generate active PoC." % item["host"])
            return
        marker, payload = payload_for_finding(finding)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(payload), None)
        self._log("PoC copied to clipboard for %s (marker %s)." % (item["url"], marker))

    def _on_generate_all_pocs(self, evt):
        item = self._selected_item()
        if not item:
            self._log("Generate all PoCs: select a JS file first.")
            return
        if not self._authz_check.isSelected() or self._authz_host != item["host"].lower():
            self._log("Blocked: authorization checkbox not set for %s." % item["host"])
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
        try:
            self._callbacks.printOutput("[JS Recon] " + str(message))
            if hasattr(self, "_log_area") and self._log_area is not None:
                self._log_area.append("%s\n" % message)
                self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        except Exception:
            pass
