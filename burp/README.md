# JS Recon Burp Extension (Jython)

This is a Burp Suite extension that ports the JS Recon Tool into Burp as a
passive JavaScript reconnaissance panel.

## Install

1. Open Burp Suite -> `Extender` -> `Options`.
2. Configure Jython 2.7 if not already configured.
3. Go to `Extender` -> `Extensions` -> `Add`.
4. Set `Extension type` to **Python**.
5. Select `burp/js_recon_burp.py`.
6. A new top-level tab named **JS Recon** appears.

## Use

1. Browse an authorized target through Burp Proxy. Any JavaScript response is
   captured and analyzed automatically when `Passive capture` is enabled.
2. Use the JS Recon tab:
   - **JS Files**: captured JavaScript resources, with a narrative summary.
   - **Endpoints**: URL/path candidates found in string/template literals.
   - **Secrets**: redacted credential candidates.
   - **DOM XSS**: static sink findings with severity and taint hints.
   - **Log**: extension activity.
3. Right-click any request/response in Proxy, HTTP history, Repeater, or
   Intruder and choose **Send to JS Recon** to analyze it immediately.
4. Use toolbar controls to filter by host, search captured text, clear data, or
   export findings to CSV/HTML.
5. For DOM-XSS findings, select a finding in the DOM XSS table and click
   **Copy PoC** to copy a payload to the clipboard. This requires the
   authorization checkbox to be enabled for the matching host.

## Notes

- The extension is passive. It does not modify traffic or attack the target.
- Active PoC generation is only a payload generator; it does not fire anything
  automatically. You must manually test the copied payload in an authorized
  environment.
- The authorization checkbox is a UX safeguard, not proof of authorization.
  You are responsible for ensuring you have permission to test the target.
