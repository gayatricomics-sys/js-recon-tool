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
  * DOM XSS tab: token-based sink findings (innerHTML/outerHTML/srcdoc,
    document.write, insertAdjacentHTML, eval, Function, setTimeout string arg,
    jQuery html/$(), location & src/href assignment, postMessage handlers)
  * Sensitive functions surfaced per file; JS is beautified before analysis
  * PoC payload generation per DOM-XSS finding (copy to clipboard)
  * Scope / host filtering, text search, CSV + HTML export, live log
  * Burp Target scope is the authorization: PoCs only for in-scope hosts

Analysis engine (v1.3.0): JavaScript is beautified, then lexed into tokens
(strings, template literals, comments, regex literals, numbers, names,
punctuators). Endpoint / secret / DOM-XSS / sensitive-function detection run
over the token stream -- no regex is run over raw source, so matches never
land inside string bodies or comments. DOM XSS is the primary focus.

This extension is passive and does not attack or modify traffic.
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IExtensionStateListener
from burp import IParameter

from java.awt import BorderLayout, Dimension, Font, Color, GridBagLayout, GridBagConstraints, Insets, Toolkit, GridLayout
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


VERSION = "1.5.0"
AUTHZ_FILENAME = ".js_recon_authorization"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def entropy(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    result = 0.0
    for c in counts.values():
        p = c / total
        result -= p * math.log(p, 2)
    return result


def redact_value(value):
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * max(4, len(value) - 8) + value[-4:]


def lines_of(source):
    return source.count("\n") + 1


def line_number_of_index(source, index):
    if index is None or index < 0:
        return 1
    return source.count("\n", 0, min(index, len(source))) + 1


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_ID_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
_DIGITS = set("0123456789")
_ID_PART = _ID_START | _DIGITS
_WS = set(" \t\r\f\v\xa0")

# Multi-char punctuators, longest first so ">>>=" wins over ">>>".
_MULTI_PUNCT = [
    ">>>=", "===", "!==", "**=", "<<=", ">>=", ">>>", "...",
    "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "=>", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
]

# Keywords after which a "/" begins a regex literal, not division.
_REGEX_KEYWORDS = set([
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "do", "else", "throw", "case", "yield", "await", "default",
])
# Names after which "/" is division (a value precedes it).
_VALUE_KEYWORDS = set(["this", "super", "true", "false", "null"])


class Tok(object):
    __slots__ = ("type", "value", "start", "line", "raw")

    def __init__(self, type_, value, start, line, raw=None):
        self.type = type_
        self.value = value          # decoded text (for strings: no quotes)
        self.start = start
        self.line = line
        self.raw = raw if raw is not None else value  # verbatim source slice


def _regex_allowed(prev):
    if prev is None:
        return True
    if prev.type in ("number", "string", "template", "regex"):
        return False
    if prev.type == "name":
        if prev.value in _VALUE_KEYWORDS:
            return False
        if prev.value in _REGEX_KEYWORDS:
            return True
        return False  # plain identifier -> value -> division
    if prev.type == "punct":
        return prev.value not in (")", "]", "}")
    return True


def tokenize(src):
    tokens = []
    i = 0
    n = len(src)
    line = 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in _WS:
            i += 1
            continue

        # Comments
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i + 2
            while j < n and src[j] != "\n":
                j += 1
            tokens.append(Tok("comment", src[i:j], i, line))
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = i + 2
            while j + 1 < n and not (src[j] == "*" and src[j + 1] == "/"):
                if src[j] == "\n":
                    line += 1
                j += 1
            j = min(n, j + 2)
            tokens.append(Tok("comment", src[i:j], i, line))
            i = j
            continue

        # String literals
        if c == '"' or c == "'":
            j = i + 1
            buf = []
            while j < n:
                d = src[j]
                if d == "\\":
                    if j + 1 < n:
                        buf.append(src[j + 1])
                        j += 2
                        continue
                    j += 1
                    continue
                if d == c:
                    j += 1
                    break
                if d == "\n":
                    break  # unterminated; stop at EOL
                buf.append(d)
                j += 1
            t = Tok("string", "".join(buf), i, line, raw=src[i:j])
            tokens.append(t)
            i = j
            continue

        # Template literals (handle ${ } nesting on brace depth)
        if c == "`":
            j = i + 1
            depth = 0
            while j < n:
                d = src[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "\n":
                    line += 1
                    j += 1
                    continue
                if depth == 0 and d == "`":
                    j += 1
                    break
                if d == "$" and j + 1 < n and src[j + 1] == "{":
                    depth += 1
                    j += 2
                    continue
                if depth > 0 and d == "{":
                    depth += 1
                elif depth > 0 and d == "}":
                    depth -= 1
                j += 1
            tokens.append(Tok("template", src[i:j], i, line))
            i = j
            continue

        # Regex literal vs division
        if c == "/" and _regex_allowed(tokens[-1] if tokens else None):
            j = i + 1
            in_class = False
            ok = True
            while j < n:
                d = src[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "\n":
                    ok = False
                    break
                if d == "[":
                    in_class = True
                elif d == "]":
                    in_class = False
                elif d == "/" and not in_class:
                    j += 1
                    break
                j += 1
            if ok and j <= n:
                while j < n and (src[j] in _ID_PART):
                    j += 1
                tokens.append(Tok("regex", src[i:j], i, line))
                i = j
                continue
            # else fall through to punctuator

        # Numbers
        if c in _DIGITS or (c == "." and i + 1 < n and src[i + 1] in _DIGITS):
            j = i + 1
            while j < n and (src[j] in _ID_PART or src[j] == "."):
                # allow exponent sign
                if src[j] in "eE" and j + 1 < n and src[j + 1] in "+-":
                    j += 2
                    continue
                j += 1
            tokens.append(Tok("number", src[i:j], i, line))
            i = j
            continue

        # Identifiers / keywords (allow unicode)
        if c in _ID_START or ord(c) > 127:
            j = i + 1
            while j < n and (src[j] in _ID_PART or ord(src[j]) > 127):
                j += 1
            tokens.append(Tok("name", src[i:j], i, line))
            i = j
            continue

        # Punctuators
        matched = None
        for p in _MULTI_PUNCT:
            if src.startswith(p, i):
                matched = p
                break
        if matched:
            tokens.append(Tok("punct", matched, i, line))
            i += len(matched)
        else:
            tokens.append(Tok("punct", c, i, line))
            i += 1
    return tokens


def significant(tokens):
    return [t for t in tokens if t.type != "comment"]


# ---------------------------------------------------------------------------
# Beautifier (token-driven; for readable source preview + snippets)
# ---------------------------------------------------------------------------

_KW_SPACE_AFTER = set([
    "return", "var", "let", "const", "function", "if", "else", "for", "while",
    "do", "switch", "case", "new", "typeof", "instanceof", "in", "of", "throw",
    "delete", "void", "yield", "await", "default", "class", "extends",
])
_WORD_TYPES = set(["name", "number", "string", "template", "regex"])


def beautify(src, max_chars=2000000):
    if len(src) > max_chars:
        return src
    tokens = tokenize(src)
    if not tokens:
        return src
    out = []
    indent = 0
    paren = 0
    at_line_start = True

    def nl():
        out.append("\n")

    def pad():
        out.append("  " * max(0, indent))

    prev = None
    for idx, t in enumerate(tokens):
        if t.type == "comment":
            if not at_line_start:
                nl()
            pad()
            out.append(t.value)
            nl()
            at_line_start = True
            prev = t
            continue

        # Emit the verbatim source for anything whose decoded value differs
        # from how it must appear in code (strings lose their quotes).
        v = t.raw if t.type == "string" else t.value
        if t.type == "punct":
            if v == "{":
                if prev is not None and not at_line_start:
                    out.append(" ")
                out.append("{")
                indent += 1
                nl()
                pad()
                at_line_start = True
                prev = t
                continue
            if v == "}":
                if not at_line_start:
                    nl()
                indent -= 1
                pad()
                out.append("}")
                at_line_start = False
                prev = t
                continue
            if v == ";":
                out.append(";")
                if paren == 0:
                    nl()
                    pad()
                    at_line_start = True
                else:
                    out.append(" ")
                    at_line_start = False
                prev = t
                continue
            if v == "(":
                paren += 1
            elif v == ")":
                paren = max(0, paren - 1)
            elif v == ",":
                out.append(",")
                out.append(" ")
                at_line_start = False
                prev = t
                continue

        # Start a fresh line after a block close before the next statement.
        if not at_line_start and prev is not None and prev.type == "punct" and prev.value == "}" \
                and not (t.type == "punct" and v in (")", "]", "}", ";", ",", ".", "(")):
            nl()
            pad()
            at_line_start = True

        # Spacing before this token
        if not at_line_start and prev is not None:
            need = False
            pv = prev.value
            if prev.type in _WORD_TYPES and t.type in _WORD_TYPES:
                need = True
            if prev.type == "name" and pv in _KW_SPACE_AFTER:
                need = True
            if prev.type == "punct" and pv in ("=", "=>", "==", "===", "!=",
                                               "!==", "<", ">", "<=", ">=", "&&",
                                               "||", "+", "-", "*", "/", "%", "?",
                                               ":", "|", "&", "+=", "-=", "=="):
                need = True
            if t.type == "punct" and v in ("=", "=>", "==", "===", "!=", "!==",
                                           "<=", ">=", "&&", "||", "?", ":"):
                need = True
            if need:
                out.append(" ")
        out.append(v)
        at_line_start = False
        prev = t
    return "".join(out)


# ---------------------------------------------------------------------------
# Member-chain + slice helpers over tokens
# ---------------------------------------------------------------------------

def chain_backward(sig, idx):
    """Dotted chain ending at sig[idx] (a name), reading left over .name and
    ['string']. Returns (chain_list, start_index)."""
    parts = [sig[idx].value]
    j = idx - 1
    start = idx
    while j >= 1:
        if sig[j].type == "punct" and sig[j].value in (".", "?."):
            if sig[j - 1].type == "name":
                parts.append(sig[j - 1].value)
                start = j - 1
                j -= 2
                continue
        if sig[j].type == "punct" and sig[j].value == "]":
            # skip ['...'] -> find matching [
            depth = 1
            k = j - 1
            inner = None
            while k >= 0 and depth:
                if sig[k].value == "]":
                    depth += 1
                elif sig[k].value == "[":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if k >= 1 and sig[k - 1].type in ("name",) and j - 1 == k + 1 and sig[k + 1].type == "string":
                parts.append(sig[k + 1].value)
                start = k - 1
                parts.append(sig[k - 1].value)
                j = k - 2
                continue
            break
        break
    parts.reverse()
    return parts, start


def chain_forward(sig, idx):
    """Dotted chain starting at sig[idx] (a name), reading right over .name."""
    parts = [sig[idx].value]
    j = idx + 1
    end = idx
    while j + 1 < len(sig):
        if sig[j].type == "punct" and sig[j].value in (".", "?.") and sig[j + 1].type == "name":
            parts.append(sig[j + 1].value)
            end = j + 1
            j += 2
            continue
        break
    return parts, end


def statement_slice(sig, start, stop_depth_open=0):
    """Tokens from sig[start] until end of the current expression/statement:
    a depth-0 ';' or ',' , or a ')'/']'/'}' that closes a level we did not
    open. Used for RHS of assignments and call arguments."""
    depth = stop_depth_open
    out = []
    j = start
    while j < len(sig):
        t = sig[j]
        if t.type == "punct":
            if t.value in ("(", "[", "{"):
                depth += 1
            elif t.value in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and t.value in (";", ","):
                break
        out.append(t)
        j += 1
    return out, j


def slice_text(tokens):
    return " ".join(t.value for t in tokens)


# ---------------------------------------------------------------------------
# Endpoint extraction
# ---------------------------------------------------------------------------

HTTP_CALL_NAMES = set([
    "fetch", "axios", "ajax", "get", "post", "put", "patch", "delete", "head",
    "open", "request", "sendBeacon", "load",
])

_URL_SHAPE = re.compile(r"^[A-Za-z0-9_@./:%+\-~!$&'()*,;=?#\[\]{}]+$")
_NOISE = re.compile(
    r"^(?:(?:application|text|image|audio|video|font|multipart|model|message)/[\w.+\-*]+"
    r"|[dmyhsDMYHS]{1,4}/[dmyhsDMYHS]{1,4}(?:/[dmyhsDMYHS]{1,4})?"
    r"|\d+/\d+)$")


def parametrize_template(raw):
    """`...${x}...` (raw incl backticks) -> text with ${...} => {param}."""
    s = raw
    if s.startswith("`"):
        s = s[1:]
    if s.endswith("`"):
        s = s[:-1]
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            out.append(s[i + 1])
            i += 2
            continue
        if s[i] == "$" and i + 1 < n and s[i + 1] == "{":
            depth = 1
            i += 2
            while i < n and depth:
                if s[i] == "{":
                    depth += 1
                elif s[i] == "}":
                    depth -= 1
                i += 1
            out.append("{param}")
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _operand_text(t):
    if t.type == "string":
        return t.value, True
    if t.type == "template":
        return parametrize_template(t.value), True
    return "{param}", False


def classify_candidate(candidate):
    candidate = candidate.strip()
    if not candidate or len(candidate) > 2000:
        return None
    if "\n" in candidate or "\t" in candidate or " " in candidate:
        return None
    if _NOISE.match(candidate):
        return None
    if "://" in candidate:
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):/{2}([^/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$", candidate)
        if m:
            return {"kind": "absolute", "protocol": m.group(1), "host": m.group(2),
                    "pathname": m.group(3) or "", "query": m.group(4) or "", "full": candidate}
        return None
    if candidate.startswith("//") and len(candidate) > 2:
        return {"kind": "protocol-relative", "protocol": None, "host": candidate[2:].split("/")[0],
                "pathname": "/" + "/".join(candidate[2:].split("/")[1:]), "query": "", "full": candidate}
    if candidate.startswith("/"):
        return {"kind": "relative-path", "protocol": None, "host": None,
                "pathname": candidate.split("?")[0], "query": "", "full": candidate}
    parts = candidate.split("/")
    if len(parts) >= 2 and not candidate.startswith((".", "#", "\\")):
        return {"kind": "relative-segment", "protocol": None, "host": None,
                "pathname": candidate, "query": "", "full": candidate}
    return None


def _fold_concat(sig, idx):
    """If sig[idx] (string/template) is part of a '+' chain, fold the whole
    chain into one URL pattern. Returns (text, had_string, end_index)."""
    # expand left to the chain start
    start = idx
    while start - 2 >= 0 and sig[start - 1].type == "punct" and sig[start - 1].value == "+" \
            and sig[start - 2].type in ("string", "template", "name", "number"):
        # only keep simple operands on the left
        start -= 2
    # collect operands left..right joined by '+'
    text = []
    had_string = False
    j = start
    end = idx
    while j < len(sig):
        t = sig[j]
        if t.type in ("string", "template"):
            frag, is_str = _operand_text(t)
            text.append(frag)
            had_string = had_string or is_str
            end = j
        elif t.type in ("name", "number"):
            # member chain operand -> {param}
            _, e = chain_forward(sig, j) if t.type == "name" else ([], j)
            text.append("{param}")
            j = e
            end = j
        else:
            break
        # expect '+' to continue
        if j + 1 < len(sig) and sig[j + 1].type == "punct" and sig[j + 1].value == "+":
            j += 2
            continue
        break
    return "".join(text), had_string, end


def extract_endpoints(source, tokens=None):
    sig = significant(tokens if tokens is not None else tokenize(source))
    findings = []
    seen = set()

    def record(candidate, line, context):
        classified = classify_candidate(candidate)
        if not classified:
            return
        key = context + "|" + classified["full"]
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

    consumed = set()
    for i, t in enumerate(sig):
        if i in consumed:
            continue
        # HTTP call: name(  ...
        if t.type == "name" and t.value in HTTP_CALL_NAMES:
            if i + 1 < len(sig) and sig[i + 1].type == "punct" and sig[i + 1].value == "(":
                k = i + 2
                if k < len(sig) and sig[k].type in ("string", "template"):
                    text, _, end = _fold_concat(sig, k)
                    for x in range(k, end + 1):
                        consumed.add(x)
                    record(text, sig[k].line, "http-call:" + t.value)
                    continue
        if t.type in ("string", "template"):
            text, had_string, end = _fold_concat(sig, i)
            for x in range(i, end + 1):
                consumed.add(x)
            if had_string:
                ctx = "concat" if end > i else ("template-literal" if t.type == "template" else "string-literal")
                record(text, t.line, ctx)
    return findings


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------

SENSITIVE_NAME_HINTS = [
    "apikey", "api_key", "secret", "token", "password", "passwd", "pwd",
    "authorization", "auth_token", "authtoken", "accesskey", "access_key",
    "privatekey", "private_key", "clientsecret", "client_secret", "sessionid",
    "session_id", "credential", "bearer",
]

KNOWN_PREFIX_RULES = [
    ("AWS Access Key ID", ("AKIA", "ASIA"), 20, 20),
    ("Google API Key", ("AIza",), 39, 39),
    ("GitHub Token", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), 20, 255),
    ("Slack Token", ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"), 20, 200),
    ("Stripe Key", ("sk_live_", "pk_live_", "rk_live_"), 15, 200),
    ("Stripe Test Key", ("sk_test_", "rk_test_", "pk_test_"), 15, 200),
    ("Anthropic API Key", ("sk-ant-",), 20, 200),
    ("OpenAI API Key", ("sk-",), 20, 200),
]

_BASE64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def base64_like(value):
    if not value:
        return False
    for ch in value:
        if ch not in _BASE64:
            return False
    return True


def _b64decode(seg):
    import base64
    s = str(seg).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def detect_jwt(value):
    parts = value.split(".")
    if len(parts) != 3:
        return None
    if any(len(p) < 4 or not base64_like(p) for p in parts):
        return None
    try:
        import json
        header = json.loads(_b64decode(parts[0]))
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


def _name_sensitive(name):
    if not name:
        return None
    low = name.lower()
    for hint in SENSITIVE_NAME_HINTS:
        if hint in low:
            return hint
    return None


def _known_prefix(value):
    for label, prefixes, lo, hi in KNOWN_PREFIX_RULES:
        for p in prefixes:
            if value.startswith(p) and lo <= len(value) <= hi:
                if label == "OpenAI API Key":
                    if value.startswith("sk-ant-"):
                        continue
                    if not (re.search(r"\d", value) and re.search(r"[A-Z]", value)
                            and re.search(r"[a-z]", value) and entropy(value) >= 3.8):
                        continue
                return label
    return None


def scan_secrets(source, tokens=None):
    sig = significant(tokens if tokens is not None else tokenize(source))
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

    for i, t in enumerate(sig):
        # Sensitive-named assignment / property: name (= | :) "string"
        if t.type == "name":
            hint = _name_sensitive(t.value)
            if hint and i + 2 < len(sig):
                op = sig[i + 1]
                val = sig[i + 2]
                if op.type == "punct" and op.value in ("=", ":") and val.type == "string" and len(val.value) >= 6:
                    record("Sensitive-Named Value", val.value, val.line, "name:" + t.value)
        if t.type != "string":
            continue
        v = t.value
        if len(v) < 8:
            continue
        known = _known_prefix(v)
        if known:
            record(known, v, t.line, "known-prefix")
            continue
        pem = detect_pem(v)
        if pem:
            record(pem, v, t.line, "pem-block")
            continue
        jwt = detect_jwt(v)
        if jwt:
            record(jwt, v, t.line, "jwt-structure")
            continue
        if 24 <= len(v) <= 4096 and " " not in v and base64_like(v):
            if not (v == v.upper() and re.search(r"[A-Z]", v)):
                e = entropy(v)
                if e >= 4.2:
                    record("High-Entropy String", v, t.line, "entropy:%.2f" % e)
    return findings


# ---------------------------------------------------------------------------
# DOM XSS
# ---------------------------------------------------------------------------

SOURCE_TOKENS = [
    "location.search", "location.hash", "location.href", "location.pathname",
    "location.search", "document.referrer", "document.url", "document.documenturi",
    "window.name", "urlsearchparams", "localstorage", "sessionstorage",
    "document.cookie", "location",
]
HTML_PROP_SINKS = set(["innerHTML", "outerHTML", "srcdoc"])
URL_PROP_SINKS = set(["src", "href", "action", "formaction", "data"])
JQUERY_HTML = set(["html", "append", "prepend", "after", "before", "replaceWith", "wrap", "wrapAll"])


# Canonical source -> (human name, replication step). Order matters: most
# specific first so "location.search" wins over bare "location".
SOURCE_META = [
    ("location.hash", "URL fragment (location.hash)",
     "Append the payload to the page URL fragment:  <TARGET-URL>#PAYLOAD"),
    ("location.search", "URL query string (location.search)",
     "Add the payload as the query value this code reads:  <TARGET-URL>?PARAM=PAYLOAD"),
    ("urlsearchparams", "URL query string (URLSearchParams)",
     "Add the payload as the query value this code reads:  <TARGET-URL>?PARAM=PAYLOAD"),
    ("location.pathname", "URL path (location.pathname)",
     "Craft a target URL whose path contains the payload, then load it."),
    ("location.href", "URL (location.href)",
     "Craft a target URL containing the payload, then load it."),
    ("document.url", "URL (document.URL)",
     "Craft a target URL containing the payload, then load it."),
    ("document.documenturi", "URL (document.documentURI)",
     "Craft a target URL containing the payload, then load it."),
    ("document.referrer", "Referer header (document.referrer)",
     "Link to the target from a page you control whose URL contains the payload; the victim arrives with that Referer."),
    ("window.name", "window.name",
     "From an attacker page set window.name to the payload, then navigate that window to the target."),
    ("document.cookie", "Cookie (document.cookie)",
     "Set the cookie this code reads to the payload (requires an attacker-settable cookie)."),
    ("localstorage", "localStorage",
     "Seed the localStorage key this code reads with the payload."),
    ("sessionstorage", "sessionStorage",
     "Seed the sessionStorage key this code reads with the payload."),
    (".data", "postMessage data (event.data)",
     "From an attacker-controlled page or iframe, postMessage the payload to the target window."),
    ("location", "URL (location)",
     "Craft a target URL containing the payload, then load it."),
]
_GENERIC_SOURCE = ("the input that reaches this sink",
                   "Place the payload into the user-controllable input (parameter, field, storage, or message) that reaches this sink.")


def _norm(tokens_slice):
    return slice_text(tokens_slice).lower().replace(" ", "")


def _first_source(text):
    """Canonical source key present in normalized text, or None."""
    for key, _name, _step in SOURCE_META:
        if key == "location":
            import re as _re
            if _re.search(r"(?<![a-z0-9_$.])location(?![a-z0-9_$])", text):
                return key
        elif key in text:
            return key
    return None


def _chain_has_source(tokens_slice):
    return _first_source(_norm(tokens_slice)) is not None


def _collect_tainted(sig):
    """(tainted var names, var -> canonical source key). Bounded fixed point."""
    assigns = []  # (name, value_tokens)
    for i, t in enumerate(sig):
        if t.type == "name" and i + 1 < len(sig) and sig[i + 1].type == "punct" and sig[i + 1].value == "=" \
                and not (i + 1 < len(sig) and sig[i + 1].value in ("==", "===")):
            prev = sig[i - 1] if i > 0 else None
            if prev is not None and prev.type == "punct" and prev.value in (".", "?."):
                continue  # member assignment, handled as sink
            val, _ = statement_slice(sig, i + 2)
            assigns.append((t.value, val))
        elif t.type == "name" and t.value in ("var", "let", "const") and i + 3 < len(sig) \
                and sig[i + 1].type == "name" and sig[i + 2].type == "punct" and sig[i + 2].value == "=":
            val, _ = statement_slice(sig, i + 3)
            assigns.append((sig[i + 1].value, val))

    tainted = {}  # name -> source key
    for _ in range(6):
        changed = False
        for name, val in assigns:
            if name in tainted:
                continue
            src = _first_source(_norm(val))
            if src:
                tainted[name] = src
                changed = True
                continue
            for v in val:
                if v.type == "name" and v.value in tainted:
                    tainted[name] = tainted[v.value]
                    changed = True
                    break
        if not changed:
            break
    return set(tainted.keys()), tainted


def _slice_source_key(tokens_slice, var_source):
    """Canonical source feeding this slice: a direct source, a tainted var's
    source, or '.data'. None if not tainted."""
    direct = _first_source(_norm(tokens_slice))
    if direct:
        return direct
    for t in tokens_slice:
        if t.type == "name" and t.value in var_source:
            return var_source[t.value]
    if ".data" in _norm(tokens_slice):
        return ".data"
    return None


def _slice_tainted(tokens_slice, var_source):
    return _slice_source_key(tokens_slice, var_source) is not None


def analyze_dom_xss(source, tokens=None):
    sig = significant(tokens if tokens is not None else tokenize(source))
    findings = []
    seen = set()
    tainted_set, var_source = _collect_tainted(sig)
    src_lines = source.split("\n")

    def real_line(line):
        if line and 1 <= line <= len(src_lines):
            return src_lines[line - 1].strip()[:300]
        return ""

    def add(sink, target, line, start_idx, arg_tokens, is_tainted, severity=None):
        if severity is None:
            if is_tainted:
                severity = "HIGH"
            elif sink in ("eval", "Function-constructor"):
                severity = "MEDIUM"
            else:
                severity = "LOW"
        key = (sink, line, start_idx)
        if key in seen:
            return
        seen.add(key)
        snippet = real_line(line) or slice_text(sig[max(0, start_idx - 2):start_idx + 10])[:300]
        src_key = _slice_source_key(arg_tokens, var_source) if is_tainted else None
        findings.append({
            "sinkType": sink,
            "target": target,
            "line": line,
            "snippet": snippet,
            "taintedBySource": bool(is_tainted),
            "sourceKey": src_key,
            "severity": severity,
        })

    n = len(sig)
    for i in range(n):
        t = sig[i]

        # Property sinks: .innerHTML = / ['innerHTML'] = / .src = ...
        if t.type == "punct" and t.value == "=" and i + 1 < n:
            # left side: previous token is a name (prop) or a string in [ ]
            prop = None
            obj_end = i - 1
            if i >= 1 and sig[i - 1].type == "name":
                prop = sig[i - 1].value
                obj_end = i - 1
            elif i >= 2 and sig[i - 1].type == "punct" and sig[i - 1].value == "]" and sig[i - 2].type == "string":
                prop = sig[i - 2].value
            if prop:
                chain = None
                if i >= 2 and sig[i - 2].type == "punct" and sig[i - 2].value in (".", "?."):
                    parts, _ = chain_backward(sig, obj_end)
                    chain = ".".join(parts)
                if prop in HTML_PROP_SINKS:
                    rhs, _ = statement_slice(sig, i + 1)
                    add(prop, chain or prop, t.line, i + 1, rhs, _slice_tainted(rhs, var_source))
                    continue
                if prop in URL_PROP_SINKS and chain:
                    rhs, _ = statement_slice(sig, i + 1)
                    tt = _slice_tainted(rhs, var_source)
                    # javascript: URLs or tainted navigations
                    if tt:
                        add(prop + "-assign", chain, t.line, i + 1, rhs, True, "HIGH")
                    continue
                # location = ... / window.location = ...
                if (prop == "location" or (chain and chain.lower().endswith("location"))):
                    rhs, _ = statement_slice(sig, i + 1)
                    tt = _slice_tainted(rhs, var_source)
                    add("location-assign", chain or "location", t.line, i + 1, rhs, tt,
                        "HIGH" if tt else "INFO")
                    continue

        if t.type != "name":
            continue
        nxt = sig[i + 1] if i + 1 < n else None
        is_call = nxt is not None and nxt.type == "punct" and nxt.value == "("
        dotted = i >= 1 and sig[i - 1].type == "punct" and sig[i - 1].value in (".", "?.")

        if is_call:
            args, _ = statement_slice(sig, i + 2)
            tt = _slice_tainted(args, var_source)

            if t.value == "eval" and not dotted:
                add("eval", "eval()", t.line, i, args, tt)
                continue
            if t.value in ("setTimeout", "setInterval") and args:
                first_depth0 = []
                depth = 0
                for a in args:
                    if a.type == "punct" and a.value in ("(", "[", "{"):
                        depth += 1
                    elif a.type == "punct" and a.value in (")", "]", "}"):
                        depth -= 1
                    elif a.type == "punct" and a.value == "," and depth == 0:
                        break
                    first_depth0.append(a)
                if first_depth0 and first_depth0[0].type == "string":
                    add(t.value + "-string-arg", t.value, t.line, i, first_depth0,
                        _slice_tainted(first_depth0, var_source), "MEDIUM")
                elif first_depth0 and first_depth0[0].type not in ("name",) and _slice_tainted(first_depth0, var_source):
                    add(t.value + "-string-arg", t.value, t.line, i, first_depth0, True, "HIGH")
                elif first_depth0 and first_depth0[0].type == "name" and first_depth0[0].value in tainted_set \
                        and not (len(first_depth0) > 1 and first_depth0[1].value in ("=>",)):
                    add(t.value + "-string-arg", t.value, t.line, i, first_depth0, True, "HIGH")
                continue
            if t.value == "Function":
                is_new = i >= 1 and sig[i - 1].type == "name" and sig[i - 1].value == "new"
                if is_new or not dotted:
                    add("Function-constructor", "new Function()", t.line, i, args, tt)
                    continue
            if dotted and t.value in ("write", "writeln"):
                parts, _ = chain_backward(sig, i - 2) if i >= 2 else ([], i)
                chain = ".".join(parts).lower()
                # Only document.write / doc.write -- not stream.write, res.write.
                if "document" in chain or chain in ("doc", "d"):
                    add(t.value, ".".join(parts) or t.value, t.line, i, args, tt)
                continue
            if dotted and t.value in ("insertAdjacentHTML", "setHTML"):
                add(t.value, t.value, t.line, i, args, tt)
                continue
            if dotted and t.value in JQUERY_HTML and tt:
                add("jquery-html", t.value, t.line, i, args, True, "HIGH")
                continue
            if t.value in ("$", "jQuery") and not dotted and tt:
                add("jquery-selector", t.value, t.line, i, args, True, "HIGH")
                continue
            if dotted and t.value in ("assign", "replace"):
                parts, _ = chain_backward(sig, i - 2) if i >= 2 else ([], i)
                if ".".join(parts).lower().endswith("location"):
                    add("location." + t.value, "location", t.line, i, args, tt,
                        "HIGH" if tt else "LOW")
                    continue
            if t.value == "addEventListener" and args and args[0].type == "string" and args[0].value == "message":
                body, _ = statement_slice(sig, i + 2)
                _add_message_listener(add, sig, i, body)
                continue
        else:
            # onmessage = handler
            if t.value == "onmessage" and nxt is not None and nxt.type == "punct" and nxt.value == "=":
                body, _ = statement_slice(sig, i + 2)
                _add_message_listener(add, sig, i, body)
                continue

    findings.sort(key=lambda f: (f["line"], f["sinkType"]))
    return findings


def _add_message_listener(add, sig, i, body_tokens):
    low = slice_text(body_tokens).lower()
    has_origin = ".origin" in low.replace(" ", "")
    # find event param name: function(ev) or (ev)=> or ev=>
    param = None
    for k, t in enumerate(body_tokens):
        if t.type == "name" and t.value == "function":
            # function ( PARAM
            for m in range(k + 1, min(k + 4, len(body_tokens))):
                if body_tokens[m].type == "name":
                    param = body_tokens[m].value
                    break
            break
    if param is None:
        # arrow: NAME =>  or ( NAME ) =>
        for k, t in enumerate(body_tokens):
            if t.type == "punct" and t.value == "=>":
                # look back for a name
                j = k - 1
                while j >= 0 and body_tokens[j].type == "punct" and body_tokens[j].value in (")",):
                    j -= 1
                if j >= 0 and body_tokens[j].type == "name":
                    param = body_tokens[j].value
                break
    data_to_sink = False
    if param:
        txt = slice_text(body_tokens).replace(" ", "")
        if (param + ".data") in txt and any(s in txt for s in (
                "innerHTML", "outerHTML", "srcdoc", "insertAdjacentHTML",
                "document.write", "eval(", "Function(", ".html(", "location")):
            data_to_sink = True
    if data_to_sink:
        sev = "MEDIUM" if has_origin else "HIGH"
    else:
        sev = "LOW" if has_origin else "MEDIUM"
    add("message-listener", "postMessage handler", sig[i].line, i, body_tokens, data_to_sink, sev)


# ---------------------------------------------------------------------------
# Sensitive functions (information gathering)
# ---------------------------------------------------------------------------

SENSITIVE_FUNC_HINTS = [
    "auth", "login", "logout", "token", "password", "passwd", "secret", "cred",
    "admin", "pay", "payment", "checkout", "card", "crypt", "encrypt", "decrypt",
    "sign", "session", "csrf", "nonce", "debug", "eval", "exec", "upload",
    "download", "redirect", "sanitiz", "escape", "render", "template", "key",
    "jwt", "oauth", "sso", "permission", "role", "privileg",
]


def extract_functions(source, tokens=None):
    sig = significant(tokens if tokens is not None else tokenize(source))
    found = []
    seen = set()

    def add(name, line):
        hint = None
        low = name.lower()
        for h in SENSITIVE_FUNC_HINTS:
            if h in low:
                hint = h
                break
        if not hint:
            return
        key = name + "|" + str(line)
        if key in seen:
            return
        seen.add(key)
        found.append({"name": name, "line": line, "why": "name~" + hint})

    n = len(sig)
    for i in range(n):
        t = sig[i]
        if t.type == "name" and t.value == "function" and i + 1 < n and sig[i + 1].type == "name":
            add(sig[i + 1].value, sig[i + 1].line)
        # NAME = function / NAME = ( ... ) =>  / NAME : function
        if t.type == "name" and i + 1 < n and sig[i + 1].type == "punct" and sig[i + 1].value in ("=", ":"):
            if i + 2 < n and sig[i + 2].type == "name" and sig[i + 2].value == "function":
                add(t.value, t.line)
            else:
                # arrow within a few tokens
                for k in range(i + 2, min(i + 8, n)):
                    if sig[k].type == "punct" and sig[k].value == "=>":
                        add(t.value, t.line)
                        break
                    if sig[k].type == "punct" and sig[k].value in (";", ",", "{"):
                        break
    return found


# ---------------------------------------------------------------------------
# Frameworks + summary + top-level
# ---------------------------------------------------------------------------

FRAMEWORK_SIGNATURES = [
    ("React", ["React.createElement", "react-dom", "_jsx", "__REACT_DEVTOOLS"]),
    ("Vue", ["Vue.component", "createApp", "__VUE__", "vue-router"]),
    ("Angular", ["angular.module", "ng-app", "@angular/core"]),
    ("jQuery", ["jQuery.fn.jquery", "jQuery(", "$.ajax"]),
    ("Webpack bundle", ["__webpack_require__", "webpackJsonp"]),
    ("Next.js", ["__NEXT_DATA__", "next/router"]),
]


def detect_frameworks(source):
    detected = []
    for name, tokens_ in FRAMEWORK_SIGNATURES:
        for tk in tokens_:
            if tk in source:
                detected.append(name)
                break
    return detected


def build_summary(source, meta, endpoints, secrets, xss, functions):
    lines = source.count("\n") + 1
    frameworks = detect_frameworks(source)
    url = meta.get("url", "This file")
    out = ["%s is a JavaScript resource of %d lines (beautified)." % (url, lines)]
    if frameworks:
        out.append("It appears to use: %s." % ", ".join(frameworks))
    else:
        out.append("No recognized frontend framework signature was detected.")
    if endpoints:
        out.append("Found %d candidate URL/endpoint(s)." % len(endpoints))
    if functions:
        out.append("Flagged %d sensitive-looking function(s) for review." % len(functions))
    if secrets:
        out.append("WARNING: %d string(s) matched secret/credential heuristics; verify manually." % len(secrets))
    if xss:
        high = len([f for f in xss if f.get("severity") == "HIGH"])
        out.append("%d DOM XSS sink(s) identified, %d flagged HIGH (tainted by a client-controllable source)." % (len(xss), high))
    else:
        out.append("No DOM XSS sink patterns identified by static analysis.")
    return " ".join(out)


def analyze_js_source(source, meta):
    beautified = beautify(source)
    tokens = tokenize(beautified)
    endpoints = extract_endpoints(beautified, tokens)
    secrets = scan_secrets(beautified, tokens)
    xss = analyze_dom_xss(beautified, tokens)
    functions = extract_functions(beautified, tokens)
    frameworks = detect_frameworks(beautified)
    summary = build_summary(beautified, meta, endpoints, secrets, xss, functions)
    return {
        "endpoints": endpoints,
        "secrets": secrets,
        "xss": xss,
        "functions": functions,
        "frameworks": frameworks,
        "summary": summary,
        "lineCount": lines_of(beautified),
        "lines": lines_of(beautified),
        "source": beautified,
    }


def _stable_marker(finding):
    """Deterministic per-finding marker so Copy PoC, Fire, Screenshot and
    Export all reference the same value and can be correlated."""
    import hashlib
    basis = u"%s|%s|%s" % (finding.get("sinkType", ""), finding.get("line", ""),
                           finding.get("snippet", ""))
    return "JSRECON-" + hashlib.md5(basis.encode("utf-8")).hexdigest()[:10]


def payload_for_finding(finding):
    sink = finding.get("sinkType", "")
    marker = _stable_marker(finding)
    templates = {
        "innerHTML": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "outerHTML": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "srcdoc": '<script>console.warn(\'%s\');alert(\'%s\')<\/script>' % (marker, marker),
        "insertAdjacentHTML": '<svg onload="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "setHTML": '<img src=x onerror="alert(\'%s\')">' % marker,
        "write": "<script>console.warn('%s');alert('%s')<\/script>" % (marker, marker),
        "writeln": "<script>console.warn('%s');alert('%s')<\/script>" % (marker, marker),
        "eval": "alert('%s')" % marker,
        "Function-constructor": "alert('%s')" % marker,
        "setTimeout-string-arg": "alert('%s')" % marker,
        "setInterval-string-arg": "alert('%s')" % marker,
        "location.assign": "javascript:alert('%s')" % marker,
        "location.replace": "javascript:alert('%s')" % marker,
        "location-assign": "javascript:alert('%s')" % marker,
        "src-assign": "javascript:alert('%s')" % marker,
        "href-assign": "javascript:alert('%s')" % marker,
        "jquery-html": '<img src=x onerror="console.warn(\'%s\');alert(\'%s\')">' % (marker, marker),
        "jquery-selector": '<img src=x onerror="alert(\'%s\')">' % marker,
        "message-listener": "postMessage('<img src=x onerror=alert(\\'%s\\')>', '*')" % marker,
    }
    payload = templates.get(sink, '<img src=x onerror="alert(\'%s\')">' % marker)
    return marker, payload


# Sources that can be driven straight from a URL (so firing can be automated).
_URL_SOURCE_KEYS = set(["location.hash", "location.search", "urlsearchparams",
                        "location.pathname", "location.href", "document.url",
                        "document.documenturi", "location"])


def _url_encode(value):
    try:
        from java.net import URLEncoder
        return _u(URLEncoder.encode(value, "UTF-8")).replace("+", "%20")
    except Exception:
        out = []
        for ch in value:
            if ch.isalnum() or ch in "-_.~":
                out.append(ch)
            else:
                for b in ch.encode("utf-8"):
                    out.append("%%%02X" % (ord(b) if isinstance(b, str) else b))
        return "".join(out)


def build_test_url(page_url, source_key, payload):
    """Best-effort live test URL that drives a URL-based source with the
    payload. Returns (url, note) or (None, reason) for sources that need a
    manual trigger (postMessage/cookie/storage/referrer/window.name)."""
    page_url = (page_url or "").strip()
    if not page_url:
        return None, "Set the target page URL (the page that loads the vulnerable script)."
    if source_key not in _URL_SOURCE_KEYS:
        return None, "This source (%s) cannot be driven from a URL; use the manual trigger steps." % source_key
    base = page_url.split("#")[0]
    if source_key == "location.hash":
        return base + "#" + payload, "Payload placed in the URL fragment (after #)."
    if source_key in ("location.search", "urlsearchparams"):
        sep = "&" if "?" in base else "?"
        return base + sep + "xss=" + _url_encode(payload), \
            "Payload placed in query parameter 'xss' (URL-encoded); rename it to the parameter this code reads."
    # pathname / href / url / bare location: fragment is the safest generic carrier.
    return base + "#" + payload, "Payload placed in the URL fragment as a best-effort carrier; adjust if the code reads the path."


EXECUTION_GUIDE = [
    "Confirm the sink and source in the vulnerable line below.",
    "Build the test input: put the payload into the client-controllable source "
    "(URL fragment/query, postMessage, storage, cookie, etc.) as described per finding.",
    "Open the target page in a browser with the payload in place (the extension's "
    "'Fire in browser' does this for URL-based sources).",
    "Trigger the code path that reaches the sink (load, click, route change, or send "
    "the postMessage), if it is not reached on page load.",
    "Observe the result: a JavaScript alert box and a console warning, both showing "
    "the unique marker, confirm execution.",
    "Capture a screenshot of the alert for the report (the extension can attach it).",
]


# Which execution context the payload lands in, for replication wording.
_HTML_SINKS = set(["innerHTML", "outerHTML", "srcdoc", "insertAdjacentHTML",
                   "setHTML", "write", "writeln", "jquery-html", "jquery-selector",
                   "message-listener"])
_JS_SINKS = set(["eval", "Function-constructor", "setTimeout-string-arg",
                 "setInterval-string-arg"])
_NAV_SINKS = set(["location.assign", "location.replace", "location-assign",
                  "src-assign", "href-assign"])


def _source_from_snippet(snippet):
    """Best-effort guess of the client-controllable source feeding a sink,
    from the finding snippet, so replication steps can be concrete."""
    s = (snippet or "").lower().replace(" ", "")
    if "location.hash" in s:
        return ("URL fragment (location.hash)",
                "Append the payload to the page URL fragment:  <TARGET-URL>#<payload>")
    if "location.search" in s or "urlsearchparams" in s:
        return ("URL query string (location.search)",
                "Add the payload as the query-parameter value this code reads:  <TARGET-URL>?<param>=<payload>")
    if "location.pathname" in s or "location.href" in s or "document.url" in s or "documenturi" in s:
        return ("URL (location.href / pathname)",
                "Craft a target URL whose path/href contains the payload, then load it.")
    if "document.referrer" in s:
        return ("Referer header (document.referrer)",
                "Place a link to the target on a page you control whose URL contains the payload; the victim arrives with that Referer.")
    if "window.name" in s:
        return ("window.name",
                "From an attacker page set window.name to the payload, then navigate that window/tab to the target.")
    if ".data" in s or "postmessage" in s:
        return ("postMessage data (event.data)",
                "From an attacker-controlled page or iframe, postMessage the payload to the target window/iframe.")
    if "document.cookie" in s:
        return ("Cookie (document.cookie)",
                "Set the cookie this code reads to the payload (requires an attacker-settable cookie).")
    if "localstorage" in s or "sessionstorage" in s:
        return ("Web storage (local/sessionStorage)",
                "Seed the storage key this code reads with the payload (e.g. via another injection or a shared subdomain).")
    return ("the input that reaches this sink",
            "Place the payload into the user-controllable input (parameter, field, storage, or message) that reaches this sink.")


def poc_details(finding, source_file=None, host=None):
    """Full PoC record for one DOM XSS finding: exact payload + how to replicate."""
    marker, payload = payload_for_finding(finding)
    sink = finding.get("sinkType", "")
    if sink in _JS_SINKS:
        context = "JavaScript (the payload is executed as script, not HTML)"
    elif sink in _NAV_SINKS:
        context = "Navigation (javascript: URL executed when the sink navigates)"
    else:
        context = "HTML (the payload is parsed into the DOM)"
    key = finding.get("sourceKey")
    meta = None
    if key:
        for k, name, step in SOURCE_META:
            if k == key:
                meta = (name, step)
                break
    if meta is None:
        meta = _source_from_snippet(finding.get("snippet", ""))
    source_name, place_step = meta
    steps = [
        "Confirm the sink is reachable: %s at %s line %s." % (
            sink, source_file or finding.get("sourceFile") or "the file", finding.get("line")),
        place_step.replace("PAYLOAD", payload).replace("<payload>", payload),
        "Load / trigger the page so the sink runs.",
        "Success = an alert box and a console warning showing the marker %s." % marker,
    ]
    return {
        "marker": marker,
        "payload": payload,
        "sink": sink,
        "target": finding.get("target", ""),
        "severity": finding.get("severity", ""),
        "tainted": bool(finding.get("taintedBySource")),
        "context": context,
        "source": source_name,
        "line": finding.get("line"),
        "snippet": finding.get("snippet", ""),
        "sourceFile": source_file,
        "host": host,
        "steps": steps,
    }


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
        # Capture diagnostics (surfaced in the Log tab).
        self._seen_responses = 0
        self._seen_js = 0
        self._skip_scope = 0
        self._skip_filter = 0
        # marker -> {"b64": <png base64>, "bytes": <java byte[]>} screenshot proof
        self._shots = {}

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
        self._seen_responses += 1
        if self._seen_responses == 1:
            self._log("Passive capture is receiving traffic (first HTTP response seen).")
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
            self._heartbeat()
            return
        # This IS a JavaScript response. From here, log why it is or isn't kept
        # so an empty JS Recon tab is never a silent mystery.
        self._seen_js += 1
        if self._seen_js == 1:
            self._log("First JavaScript response seen: %s" % url)
        if self._scope_only.isSelected() and not self._callbacks.isInScope(java_url):
            self._skip_scope += 1
            if self._skip_scope <= 20 or self._skip_scope % 50 == 0:
                self._log("Skipped (out of Burp scope): %s  -- add its host to Target > Scope, "
                          "or untick 'In-scope only' to capture all JS." % url)
            self._heartbeat()
            return
        allowed = _u(self._host_filter.getText()).strip().lower()
        if allowed and allowed not in _u(java_url.getHost()).lower():
            self._skip_filter += 1
            if self._skip_filter <= 5:
                self._log("Skipped (host filter '%s'): %s" % (allowed, url))
            self._heartbeat()
            return
        self._analyze_and_store(message, url, java_url)

    def _heartbeat(self):
        # Periodic one-liner so the user can tell traffic is flowing and see
        # why nothing was captured, without spamming the log.
        if self._seen_responses % 100 != 0:
            return
        self._log("Traffic seen: %d responses, %d JavaScript, %d analyzed, "
                  "%d skipped out-of-scope, %d skipped by host filter." % (
                      self._seen_responses, self._seen_js, len(self._store),
                      self._skip_scope, self._skip_filter))

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

        self._log("Analyzed %s (E:%d S:%d X:%d F:%d)" % (
            url, len(item["endpoints"]), len(item["secrets"]), len(item["xss"]),
            len(item.get("functions", []))))
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
        export_pocs_btn = JButton("Export PoCs", actionPerformed=self._on_export_pocs)
        export_pocs_btn.setToolTipText("Write every in-scope DOM XSS PoC (exact payload + replication steps) to an HTML and Markdown report.")
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
        toolbar.add(export_pocs_btn)

        # Second row: active DOM XSS verification (scope-gated, user-initiated).
        toolbar2 = JPanel()
        toolbar2.add(JLabel("Target page URL"))
        self._page_url_field = JTextField(26)
        self._page_url_field.setToolTipText("The page that LOADS the vulnerable script (not the .js URL). Prefilled from the selected finding's host; edit as needed.")
        toolbar2.add(self._page_url_field)
        fire_btn = JButton("Fire in browser", actionPerformed=self._on_fire_in_browser)
        fire_btn.setToolTipText("Build the test URL for the selected DOM XSS finding and open it in your default browser (in-scope hosts only). Active test -- confirms before opening.")
        shot_btn = JButton("Capture screenshot", actionPerformed=self._on_capture_screenshot)
        shot_btn.setToolTipText("Capture the current screen (showing the alert) and attach it to the selected finding for the PoC report.")
        attach_btn = JButton("Attach screenshot file", actionPerformed=self._on_attach_screenshot)
        attach_btn.setToolTipText("Attach an existing image file as the screenshot proof for the selected finding.")
        toolbar2.add(fire_btn)
        toolbar2.add(shot_btn)
        toolbar2.add(attach_btn)

        self._status = JLabel("Ready")
        statusbar = JPanel(BorderLayout())
        statusbar.add(self._status, BorderLayout.WEST)

        toolbars = JPanel(GridLayout(2, 1))
        toolbars.add(toolbar)
        toolbars.add(toolbar2)
        top = JPanel(BorderLayout())
        top.add(toolbars, BorderLayout.NORTH)
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
        for x in item["xss"][:40]:
            tag = "tainted" if x.get("taintedBySource") else "not-tainted"
            lines.append("  L%s  %-6s %-22s %s" % (x["line"], x["severity"], x["sinkType"], tag))
        lines.append("")
        funcs = item.get("functions", [])
        lines.append("Sensitive functions: %d" % len(funcs))
        for fdef in funcs[:40]:
            lines.append("  L%s  %s  (%s)" % (fdef["line"], fdef["name"], fdef["why"]))
        lines.append("")
        lines.append("Source preview (first 500 lines, beautified):")
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

    # -- PoC export ----------------------------------------------------------
    def _collect_pocs(self):
        """PoC records for every DOM XSS finding on an in-scope (authorized)
        host. Returns (records, skipped_out_of_scope_count)."""
        records = []
        skipped = 0
        for item in self._snapshot():
            authorized = self._is_authorized(item)
            for finding in item.get("xss", []):
                if not authorized:
                    skipped += 1
                    continue
                rec = poc_details(finding, source_file=item["url"], host=item["host"])
                shot = self._shots.get(rec["marker"])
                if shot:
                    rec["shot_b64"] = shot["b64"]
                    rec["shot_mime"] = shot.get("mime", "image/png")
                    rec["shot_bytes"] = shot.get("bytes")
                records.append(rec)
        # Highest severity first.
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        records.sort(key=lambda r: (order.get(r["severity"], 9), r.get("sourceFile") or "", r.get("line") or 0))
        return records, skipped

    def _on_export_pocs(self, evt):
        records, skipped = self._collect_pocs()
        if not records:
            msg = ("No PoCs to export. DOM XSS PoCs are only exported for hosts in "
                   "Burp's Target scope%s." % (" (%d finding(s) skipped as out-of-scope)" % skipped if skipped else ""))
            self._notify(msg)
            try:
                JOptionPane.showMessageDialog(self._root, msg, "JS Recon - Export PoCs",
                                              JOptionPane.INFORMATION_MESSAGE)
            except Exception:
                pass
            return
        try:
            from javax.swing import JFileChooser
            chooser = JFileChooser()
            chooser.setSelectedFile(File("js_recon_pocs.html"))
            if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
                return
            target = chooser.getSelectedFile()
        except Exception as e:
            self._log("Export dialog error: %s" % e)
            return
        path = _u(target.getAbsolutePath())
        html_path = path if path.lower().endswith((".html", ".htm")) else path + ".html"
        md_path = (html_path[:html_path.rfind(".")] if "." in html_path else html_path) + ".md"
        try:
            self._write_poc_html(html_path, records, skipped)
            self._write_poc_md(md_path, records, skipped)
            msg = u"Exported %d PoC(s) to %s and %s" % (len(records), html_path, md_path)
            if skipped:
                msg += u"  (%d out-of-scope finding(s) omitted)" % skipped
            self._log(msg)
            self._status.setText(msg)
        except Exception as e:
            self._log("PoC export error: %s" % e)

    def _write_poc_html(self, path, records, skipped):
        gen = _u(SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(Date()))
        sev_color = {"HIGH": "#c0152f", "MEDIUM": "#c07515", "LOW": "#4a5568", "INFO": "#2b6cb0"}
        blocks = []
        for n, r in enumerate(records, 1):
            steps = u"".join(u"<li>%s</li>" % _esc(s) for s in r["steps"])
            c = sev_color.get(r["severity"], "#4a5568")
            if r.get("shot_b64"):
                shot = (u'<h3>Screenshot (popup proof)</h3>'
                        u'<img class="shot" src="data:%s;base64,%s" alt="DOM XSS alert %s">' % (
                            r.get("shot_mime", "image/png"), r["shot_b64"], _esc(r["marker"])))
            else:
                shot = (u'<h3>Screenshot (popup proof)</h3>'
                        u'<p class="noshot">No screenshot attached. Fire the PoC, then use '
                        u'"Capture screenshot" or "Attach screenshot file" on this finding.</p>')
            blocks.append(u"""
  <section class="poc">
    <h2>%d. <span class="sev" style="background:%s">%s</span> DOM XSS via <code>%s</code></h2>
    <table class="meta">
      <tr><th>Location</th><td><code>%s</code> : line %s</td></tr>
      <tr><th>Host</th><td>%s</td></tr>
      <tr><th>Sink</th><td><code>%s</code> (target <code>%s</code>)</td></tr>
      <tr><th>Source-tainted</th><td>%s</td></tr>
      <tr><th>Likely source</th><td>%s</td></tr>
      <tr><th>Payload context</th><td>%s</td></tr>
      <tr><th>Marker</th><td><code>%s</code></td></tr>
    </table>
    <h3>Vulnerable code</h3>
    <pre class="code">%s</pre>
    <h3>Exact payload (copy verbatim)</h3>
    <pre class="payload">%s</pre>
    <h3>Steps to reproduce</h3>
    <ol>%s</ol>
    %s
  </section>""" % (
                n, c, _esc(r["severity"]), _esc(r["sink"]),
                _esc(r["sourceFile"]), r["line"], _esc(r["host"]),
                _esc(r["sink"]), _esc(r.get("target", "")),
                "yes (heuristic)" if r["tainted"] else "not confirmed",
                _esc(r["source"]), _esc(r["context"]), _esc(r["marker"]),
                _esc(r["snippet"]), _esc(r["payload"]), steps, shot))
        guide = u"".join(u"<li>%s</li>" % _esc(s) for s in EXECUTION_GUIDE)
        how_to = (u'<h2>How to execute a DOM XSS (general method)</h2>'
                  u'<ol class="guide">%s</ol>' % guide)
        note = (u"<p class='note'>%d finding(s) were omitted because their host is not in "
                u"Burp's Target scope.</p>" % skipped) if skipped else u""
        html = u"""<!doctype html><html><head><meta charset="utf-8">
<title>JS Recon - DOM XSS PoCs</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:32px;color:#1a202c;line-height:1.5}
 h1{border-bottom:3px solid #1a202c;padding-bottom:8px}
 .poc{border:1px solid #cbd5e0;border-radius:8px;padding:12px 18px;margin:18px 0}
 .sev{color:#fff;padding:2px 8px;border-radius:4px;font-size:13px;margin-right:6px}
 table.meta{border-collapse:collapse;margin:8px 0}
 table.meta th{text-align:left;padding:2px 12px 2px 0;color:#4a5568;white-space:nowrap;vertical-align:top}
 pre{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-word}
 pre.payload{background:#fff5f5;border-color:#fc8181;font-weight:600}
 code{background:#f1f5f9;padding:1px 4px;border-radius:3px}
 .note{background:#fffbea;border:1px solid #f0d878;padding:8px 12px;border-radius:6px}
 .disc{background:#fffbea;border:1px solid #f0d878;padding:10px 14px;border-radius:6px;font-size:13px}
 img.shot{max-width:100%%;border:1px solid #cbd5e0;border-radius:6px;margin-top:6px}
 .noshot{color:#718096;font-style:italic}
 ol.guide li{margin:3px 0}
</style></head><body>
<h1>DOM XSS Proof-of-Concept Payloads</h1>
<p><b>Generated:</b> %s &nbsp; <b>Findings:</b> %d</p>
<div class="disc">Each payload embeds a unique marker and, if executed, raises an alert and a console warning for unambiguous confirmation. Use only against hosts you are authorized to test. Findings are from static analysis and must be confirmed manually.</div>
%s
%s
%s
</body></html>""" % (_esc(gen), len(records), how_to, note, u"".join(blocks))
        with codecs.open(path, "w", "utf-8") as f:
            f.write(html)

    def _write_poc_md(self, path, records, skipped):
        import os
        gen = _u(SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(Date()))
        base_dir = os.path.dirname(path) or "."
        out = [u"# DOM XSS Proof-of-Concept Payloads", u"",
               u"Generated: %s  |  Findings: %d" % (gen, len(records)), u"",
               u"## How to execute a DOM XSS (general method)", u""]
        for i, s in enumerate(EXECUTION_GUIDE, 1):
            out.append(u"%d. %s" % (i, s))
        out.append(u"")
        if skipped:
            out.append(u"> %d finding(s) omitted (host not in Burp Target scope)." % skipped)
            out.append(u"")
        for n, r in enumerate(records, 1):
            out.append(u"## %d. [%s] DOM XSS via `%s`" % (n, r["severity"], r["sink"]))
            out.append(u"")
            out.append(u"- **Location:** `%s` line %s" % (r["sourceFile"], r["line"]))
            out.append(u"- **Host:** %s" % r["host"])
            out.append(u"- **Sink / target:** `%s` / `%s`" % (r["sink"], r.get("target", "")))
            out.append(u"- **Source-tainted:** %s" % ("yes (heuristic)" if r["tainted"] else "not confirmed"))
            out.append(u"- **Likely source:** %s" % r["source"])
            out.append(u"- **Payload context:** %s" % r["context"])
            out.append(u"- **Marker:** `%s`" % r["marker"])
            out.append(u"")
            out.append(u"**Vulnerable code:**")
            out.append(u"")
            out.append(u"```js")
            out.append(r["snippet"])
            out.append(u"```")
            out.append(u"")
            out.append(u"**Exact payload:**")
            out.append(u"")
            out.append(u"```")
            out.append(r["payload"])
            out.append(u"```")
            out.append(u"")
            out.append(u"**Steps to reproduce:**")
            out.append(u"")
            for i, s in enumerate(r["steps"], 1):
                out.append(u"%d. %s" % (i, s))
            out.append(u"")
            out.append(u"**Screenshot (popup proof):**")
            out.append(u"")
            if r.get("shot_bytes") is not None:
                png_name = u"poc-%s.png" % r["marker"]
                try:
                    from java.io import File as _JFile, FileOutputStream
                    fos = FileOutputStream(_JFile(base_dir, png_name))
                    fos.write(r["shot_bytes"])
                    fos.close()
                    out.append(u"![DOM XSS alert %s](%s)" % (r["marker"], png_name))
                except Exception:
                    out.append(u"_(screenshot captured; could not write %s)_" % png_name)
            else:
                out.append(u"_No screenshot attached. Fire the PoC, then use \"Capture screenshot\" or \"Attach screenshot file\" on this finding._")
            out.append(u"")
        with codecs.open(path, "w", "utf-8") as f:
            f.write(u"\n".join(out))

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
                for fn in item.get("functions", []):
                    row = ["function", item["url"], fn["line"], fn["name"], "", "", fn["why"]]
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
            if item.get("functions"):
                rows.append(u"<p><b>Sensitive functions</b></p><ul>")
                for fn in item["functions"]:
                    rows.append(u"<li>L%d <code>%s</code> <i>(%s)</i></li>" % (fn["line"], _esc(fn["name"]), _esc(fn["why"])))
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

    def _selected_xss(self, action):
        """(item, finding) for the selected DOM XSS row, or (None, None)."""
        row = self._xss_table.getSelectedRow()
        if row < 0:
            self._notify("%s: select a finding in the DOM XSS table." % action)
            return None, None
        idx = self._xss_table.convertRowIndexToModel(row)
        if idx >= len(self._xss_findings):
            self._notify("%s: selection is out of range." % action)
            return None, None
        return self._xss_by_row[idx], self._xss_findings[idx]

    def _on_copy_poc(self, evt):
        item, finding = self._selected_xss("Copy PoC")
        if finding is None:
            return
        self._generate_and_copy(item, finding)

    # -- Active verification (scope-gated, user-initiated) -------------------
    def _default_page_url(self, item):
        field = _u(self._page_url_field.getText()).strip()
        if field:
            return field
        # Default to the host root of the file's host (user edits if the
        # vulnerable script runs on a specific page).
        try:
            return u"https://%s/" % _u(item["host"])
        except Exception:
            return u""

    def _on_fire_in_browser(self, evt):
        item, finding = self._selected_xss("Fire in browser")
        if finding is None:
            return
        if not self._is_authorized(item):
            self._blocked(item)
            return
        marker, payload = payload_for_finding(finding)
        rec = poc_details(finding, source_file=item["url"], host=item["host"])
        page_url = self._default_page_url(item)
        self._page_url_field.setText(page_url)
        test_url, note = build_test_url(page_url, finding.get("sourceKey"), payload)
        if not test_url:
            JOptionPane.showMessageDialog(
                self._root,
                u"Automatic firing is only available for URL-based sources.\n\n"
                u"Source: %s\nReason: %s\n\nUse these manual steps:\n- %s" % (
                    rec["source"], note, u"\n- ".join(rec["steps"])),
                "JS Recon - Fire in browser", JOptionPane.INFORMATION_MESSAGE)
            return
        # Editable confirmation: the user sees and can fix the exact URL before
        # anything opens. This is an ACTIVE test against the live target.
        edited = JOptionPane.showInputDialog(
            self._root,
            u"This will OPEN the live target in your default browser to fire a DOM XSS PoC.\n"
            u"Host is in Burp scope (authorized). %s\n\n"
            u"Review/edit the exact URL, then OK to open (Cancel to abort):" % note,
            test_url)
        if edited is None:
            self._status.setText("Fire cancelled.")
            return
        edited = _u(edited).strip()
        if not edited:
            return
        try:
            from java.awt import Desktop
            from java.net import URI
            if Desktop.isDesktopSupported() and Desktop.getDesktop().isSupported(Desktop.Action.BROWSE):
                Desktop.getDesktop().browse(URI(edited))
                msg = u"Opened PoC URL in default browser (marker %s). When the alert shows, click 'Capture screenshot'." % marker
                self._log(msg)
                self._status.setText(msg)
            else:
                self._clip(edited)
                self._notify("Desktop browse not supported here; the URL was copied to the clipboard - paste it into your browser.")
        except Exception as e:
            self._clip(edited)
            self._notify("Could not open browser (%s); URL copied to clipboard instead." % e)

    def _clip(self, text):
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)
        except Exception:
            pass

    def _on_capture_screenshot(self, evt):
        item, finding = self._selected_xss("Capture screenshot")
        if finding is None:
            return
        marker = _stable_marker(finding)
        try:
            from java.awt import Robot, Rectangle
            from javax.imageio import ImageIO
            from java.io import ByteArrayOutputStream
            from java.util import Base64
            dim = Toolkit.getDefaultToolkit().getScreenSize()
            img = Robot().createScreenCapture(Rectangle(0, 0, dim.width, dim.height))
            baos = ByteArrayOutputStream()
            ImageIO.write(img, "png", baos)
            data = baos.toByteArray()
            b64 = _u(Base64.getEncoder().encodeToString(data))
            self._shots[marker] = {"b64": b64, "bytes": data}
            msg = u"Screenshot captured and attached to finding %s (%d bytes). It will appear in the PoC report." % (marker, len(data))
            self._log(msg)
            self._status.setText(msg)
        except Exception as e:
            self._notify("Screenshot capture failed (%s). Use 'Attach screenshot file' instead." % e)

    def _on_attach_screenshot(self, evt):
        item, finding = self._selected_xss("Attach screenshot")
        if finding is None:
            return
        marker = _stable_marker(finding)
        try:
            from javax.swing import JFileChooser
            from javax.swing.filechooser import FileNameExtensionFilter
            chooser = JFileChooser()
            chooser.setFileFilter(FileNameExtensionFilter("Images (png, jpg, gif)", ["png", "jpg", "jpeg", "gif"]))
            if chooser.showOpenDialog(self._root) != JFileChooser.APPROVE_OPTION:
                return
            f = chooser.getSelectedFile()
            from java.nio.file import Files
            from java.util import Base64
            data = Files.readAllBytes(f.toPath())
            b64 = _u(Base64.getEncoder().encodeToString(data))
            ext = _u(f.getName()).lower()
            mime = "image/png"
            if ext.endswith((".jpg", ".jpeg")):
                mime = "image/jpeg"
            elif ext.endswith(".gif"):
                mime = "image/gif"
            self._shots[marker] = {"b64": b64, "bytes": data, "mime": mime}
            msg = u"Attached %s to finding %s. It will appear in the PoC report." % (f.getName(), marker)
            self._log(msg)
            self._status.setText(msg)
        except Exception as e:
            self._notify("Attach screenshot failed: %s" % e)

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
