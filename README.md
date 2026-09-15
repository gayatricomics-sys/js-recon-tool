# JS Recon Tool

Electron desktop app for authorized JavaScript reconnaissance and DOM XSS
static analysis: browse a target like a normal browser (login/OTP included),
passively capture every JS file and network request, get structural
explanations and endpoint/secret/DOM-XSS findings live, generate PoC payloads,
and export an executive HTML/PDF report.

See [PRD.md](PRD.md) for the full product spec, architecture, and explicit
non-goals (in particular: **this tool does not attempt to evade antivirus,
EDR, or firewalls** -- see PRD section 4).

## Requirements

- Node.js 18+ (tested on Node 26)
- macOS, Windows, or Linux desktop with a display (Electron GUI app)

## Setup

```bash
npm install
```

## Run

```bash
npm start
```

This opens a desktop window with a real browser pane. Navigate to your
**authorized** target, log in (including any OTP step) exactly as you
normally would, then click **Start Session**.

## Usage

1. **Browser** tab -- normal browsing; a persistent session partition keeps
   you logged in across navigation.
2. **Start Session** -- begins passive capture for the current site. Creates
   `captures/<host>_<timestamp>/` on disk.
3. **JS Files** tab -- every captured JS resource, click one to see its
   plain-English structural explanation and source preview.
4. **Endpoints** tab -- URL/path candidates found via AST-validated string
   literals, template literals, HTTP call arguments, and live network
   requests.
5. **Secrets** tab -- redacted secret/credential candidates (known-format
   matches, sensitive variable/property names, high-entropy strings).
6. **DOM XSS** tab -- static sink findings with severity and a best-effort
   taint indicator. Per finding you can:
   - **Generate PoC** -- writes a plain-text payload to
     `captures/<session>/payloads/`.
   - **Fire in tab** -- only enabled once you check the authorization box
     (top banner) for the current hostname; executes the payload in the tab
     you are already browsing via CDP `Runtime.evaluate`, nothing else.
7. **Report** tab -- **Generate Report** builds the executive HTML report
   (also saved to the session folder); **Export PDF** renders it to PDF next
   to the HTML.

## Authorization gate

The authorization checkbox in the top banner must be checked, and its
recorded hostname must match the tab you're currently on, before any
active-testing (payload-fire) action will run. This is enforced in the
Electron **main process**, not just the UI, so it can't be bypassed from
the renderer. Passive capture and static analysis run regardless, since they
don't touch the target.

## Project layout

```
main/main.js              Electron main process, IPC handlers, CDP wiring
preload.js                 contextBridge API exposed to the renderer
renderer/                  UI (toolbar, webview, tabbed panels)
src/capture/                CDP-based network/JS capture
src/analysis/                AST parsing, endpoint/secret/XSS analysis, explainer
src/report/                  payload templates, HTML report builder
src/store/                   on-disk session/capture persistence
captures/                    per-session output (gitignored)
test/                        analysis engine smoke test + fixture
```

## Verifying the analysis engine

The core analysis logic (endpoint extraction, secret scanning, DOM XSS
detection, explainer, report generation) is pure Node and can be exercised
without launching the GUI:

```bash
node test/run-analysis-smoke-test.js
```

This runs the pipeline against `test/fixture-vulnerable.js` (a deliberately
vulnerable sample), asserts expected findings, and writes
`test/sample-report.html` so you can preview report output directly.

## Burp Suite extension (Jython)

A Burp Suite extension version of this tool is available in
[burp/js_recon_burp.py](burp/js_recon_burp.py). It provides the passive
JavaScript reconnaissance engine inside Burp with a rich Swing GUI:

- **JS Files** tab with captured JavaScript resources, summaries, frameworks,
  and source preview
- **Endpoints** tab with URL/path candidates
- **Secrets** tab with redacted credential candidates
- **DOM XSS** tab with severity, sink, snippet, and taint indicators
- **Log** tab for live extension activity
- Passive capture from Burp Proxy
- Right-click **Send to JS Recon** in Proxy, HTTP history, Repeater, or
  Intruder
- Host filter, scope-only capture, text search, CSV export, and HTML report
- Authorization-gated PoC payload generation and clipboard copy

See [burp/README.md](burp/README.md) for installation and usage.

## Legal / ethical use

Only use this tool against applications you own or have explicit written
authorization to test. The in-app authorization checkbox is a safety
mechanism, not a substitute for actual authorization -- you are responsible
for having it before you browse, capture, or fire anything against a target.
