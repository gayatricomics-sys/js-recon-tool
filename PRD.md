# PRD: JS Recon Tool

## 1. Summary

An Electron desktop application for authorized JavaScript-focused web application
reconnaissance and security testing. It provides a real interactive browser for
navigating login/MFA/OTP-gated applications, passively captures every JavaScript
resource and network request that crosses the wire, statically analyzes captured
JS for endpoints, secrets, and DOM XSS sink patterns, and produces an executive
security testing report.

## 2. Problem

Manually pulling JS bundles from a target application, grepping for endpoints
and secrets, and reviewing sinks for DOM XSS is slow and repetitive. Existing
recon tooling is either web-based (can't easily drive authenticated,
OTP-gated flows the way a real browser session can) or CLI-only (no visual
review of what was found, no narrative explanation of what a given bundle
does). This tool combines a real browsing session with structured, explainable
static analysis and reporting in one desktop app.

## 3. Goals

- Provide a genuine interactive browser (not a headless scraper) so testers can
  log in, complete OTP/MFA flows, and navigate an app exactly as a real user
  would, while the tool passively observes.
- Capture every JavaScript file served during the session, plus the URL/method
  of every network request, without relying on regex string-matching to decide
  what is or isn't a URL -- endpoint candidates are validated using the WHATWG
  URL parser against strings found via AST traversal.
- Detect likely secrets/credentials in captured JS using known-format checks,
  sensitive-name heuristics, and entropy analysis, with values redacted by
  default in all UI and report output.
- Statically flag DOM XSS sink patterns (innerHTML/outerHTML, document.write,
  insertAdjacentHTML, eval, Function constructor, string-based
  setTimeout/setInterval, location assignment) and apply a best-effort,
  bounded taint-propagation heuristic against known client-controllable
  sources.
- Generate a human-readable, plain-English structural explanation of each
  captured JS file (frameworks detected, functions, imports, event listeners,
  narrative summary) without depending on a remote LLM call.
- Let the tester generate a plain-text, non-obfuscated proof-of-concept payload
  per DOM XSS finding, saved into the session's project folder, and optionally
  fire it into the specific tab/session they are already driving -- gated
  behind an explicit per-session authorization confirmation.
- Produce an "Executive JS Recon Security Testing Report" (HTML + PDF) with a
  summary, methodology, findings tables, per-file explanations, and a PoC
  appendix.

## 4. Non-Goals (explicit)

- **This tool does not attempt to evade antivirus, EDR, secure web gateways
  (e.g. McAfee Web Gateway), or firewalls.** PoC payloads are stored and fired
  as plain, readable text/HTML/JS. No packing, obfuscation, polymorphism, or
  detection-signature evasion is implemented, and none will be added. A tool
  whose payloads are engineered to be invisible to every defensive product in
  the world is a general-purpose evasion capability, not a scoped test of one
  authorized target, and is out of scope for this project on principle.
- Not a mass-scanning / unauthenticated-crawl tool. It is built around one
  human driving one browsing session against one target at a time.
- Not a full taint-analysis / symbolic-execution engine. The DOM XSS
  taint heuristic is bounded, best-effort, and explicitly labeled as such in
  every output; findings require manual confirmation.
- Does not auto-exploit anything outside the tab the tester is actively
  browsing, and never without the authorization checkbox enabled and the
  target hostname matching the current tab.
- Does not perform credential stuffing, brute forcing, or any OTP-bypass
  automation. OTP/login flows are completed by the human tester exactly as in
  a normal browser; the tool only observes.

## 5. Users

- Security researchers / penetration testers running an authorized engagement
  against a client's web application.
- Bug bounty hunters reviewing in-scope targets.
- AppSec engineers doing pre-release JS-surface review of their own
  application.

## 6. Core User Flow

1. Launch the app. It opens to a normal browser view (URL bar, back/forward,
   reload) backed by a persistent Chromium session (cookies/localStorage
   survive navigation, so login and OTP flows behave exactly as in a real
   browser).
2. Tester navigates to the target and logs in, including any OTP/MFA step.
3. Tester clicks **Start Session** once on the target. This creates a
   timestamped session folder under `captures/` and begins passive capture.
4. As the tester browses normally, every JS resource served is captured,
   parsed, and analyzed in the background; results stream live into the
   **JS Files**, **Endpoints**, **Secrets**, and **DOM XSS** tabs.
5. For any DOM XSS finding, the tester can generate a PoC payload (saved to
   disk) and, after checking the authorization box, fire it into the current
   tab to visually confirm (a unique marker string alerts/logs on success).
6. Tester clicks **Generate Report**, reviews the HTML preview in-app, then
   exports a PDF. Both are saved into the session folder.

## 7. Architecture

```
Electron main process
 ├─ BrowserWindow (renderer: toolbar + <webview> + tabbed panels)
 ├─ CDP capture (per-webview debugger attach: Network domain)
 │   -> passively receives every response body classified as JS,
 │      and every request URL, regardless of resource type
 ├─ Analysis pipeline (src/analysis/*)
 │   -> AST parse (acorn) -> endpoint extraction, secret scanning,
 │      DOM XSS static analysis, structural/narrative explanation
 ├─ Project store (src/store/projectStore.js)
 │   -> captures/<host>_<timestamp>/{js-files, payloads, index.json}
 └─ Report generator (src/report/*)
     -> HTML report (Executive summary, methodology, findings, PoCs)
     -> PDF export via headless BrowserWindow.printToPDF
```

Renderer never touches Node/Electron APIs directly; all privileged
operations (capture, analysis, file I/O, PDF export, payload firing) are
mediated through a narrow `contextBridge` API defined in `preload.js`.

## 8. Endpoint Extraction Approach (no regex)

Rather than regex-matching source text for URL-shaped substrings, the
extractor:

1. Parses each JS file into an AST (acorn).
2. Walks all `Literal` and `TemplateLiteral` nodes, plus the first argument of
   recognized HTTP call sites (`fetch`, `axios.*`, `XMLHttpRequest.open`,
   generic `.get/.post/.put/.patch/.delete`), collecting candidate strings.
3. Validates each candidate's *structure* using the built-in `URL` parser --
   first as an absolute URL, then (if it starts with `/`) as a path resolved
   against a placeholder base, then as a path-segmented relative reference.
   Strings that don't parse as a structurally valid URL/path are discarded.
4. Template literals are reconstructed into a pattern (e.g.
   `/api/v1/users/{param}/profile`) by concatenating the literal quasis and
   substituting a `{param}` placeholder for each interpolated expression, so
   dynamic endpoints are still captured in a readable form.

Secrets, by contrast, deliberately use known-prefix string checks, PEM/JWT
structural checks (via `split('.')` + base64 decode, not regex), and Shannon
entropy -- the same category of technique real-world tools such as
TruffleHog use for the generic/high-entropy case.

## 9. DOM XSS Static Analysis Approach

Sinks detected: `innerHTML`/`outerHTML` assignment, `document.write`/
`writeln`, `insertAdjacentHTML`, `eval`, `new Function(...)`, string-argument
`setTimeout`/`setInterval`, and `location.assign`/`location.replace`.

Taint heuristic: a bounded (max 6 iterations), fixed-point propagation over
variable assignments -- if a variable's initializer or right-hand side
textually references a known client-controllable source
(`location.search`/`hash`, `document.referrer`, `window.name`,
`postMessage`, storage APIs, `document.cookie`), or references another
already-tainted variable, it is marked tainted. A sink is flagged **HIGH**
severity only when the exact value flowing into it (or an identifier it
depends on, transitively) is tainted by this heuristic; otherwise it is
LOW/MEDIUM ("sink present, source not statically confirmed"). This is
explicitly not full dataflow analysis -- it has no cross-function, no
cross-file, and no control-flow modeling -- and every report states this
limitation.

## 10. Payload Handling

Payload templates are plain, readable text (see `src/report/payloadGenerator.js`)
embedding a unique per-generation marker for unambiguous confirmation. They
are written to `captures/<session>/payloads/*.json` as-is. Firing a payload
in-app requires: (a) the authorization checkbox enabled for the current
hostname, and (b) the tab's current hostname matching the authorized
hostname exactly -- checked in the main process, not just the renderer.

## 11. Report Contents

- Executive summary (counts: files, endpoints, secrets, DOM XSS findings by
  severity)
- Methodology (plain description of capture + analysis technique)
- Discovered endpoints table (context, kind, host, path, source file, line)
- Secret candidates table (type, **redacted** value, length, entropy, reason,
  source, line)
- DOM XSS findings table (severity, sink, target, taint status, source, line,
  snippet)
- Per-file plain-English explanation
- PoC payload appendix reference (payloads live in the session folder, not
  embedded as executable content in the report itself)

## 12. Risks / Limitations

- Static analysis cannot see runtime-only sinks reached exclusively via
  dynamically constructed property names (e.g. `el[computedProp] = x`).
- Taint heuristic is textual/identifier-based, not a real dataflow graph --
  it can both under- and over-approximate; treat HIGH severity as
  "prioritize for manual confirmation," not "confirmed."
- CDP `Network.getResponseBody` can only be read after `loadingFinished`;
  extremely large bundles may need a size cap to avoid renderer memory
  pressure (see `MAX_PREVIEW` truncation in `main/main.js`).
- Secret detection will have false positives on any high-entropy non-secret
  string (hashes, minified identifiers); all matches require manual triage.

## 13. Roadmap (suggested phases)

1. **Now (this build):** browsing capture, AST-based endpoint/secret/XSS
   analysis, static narrative explainer, PoC generation + manual/in-tab fire,
   HTML+PDF executive report.
2. **Next:** session diffing (compare two captures of the same app over
   time to spot new endpoints/secrets), export findings as SARIF/JSON for
   CI ingestion, optional Claude API integration for richer natural-language
   file explanations (opt-in, local API key only).
3. **Later:** multi-tab/multi-origin session support, source-map resolution
   for minified bundles, WebSocket/GraphQL traffic capture.
