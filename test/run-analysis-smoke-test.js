const fs = require('fs');
const path = require('path');
const { extractEndpoints } = require('../src/analysis/endpointExtractor');
const { scanForSecrets } = require('../src/analysis/secretScanner');
const { analyzeDomXss } = require('../src/analysis/domXssAnalyzer');
const { explainFile } = require('../src/analysis/jsExplainer');
const { generatePayloadForFinding } = require('../src/report/payloadGenerator');
const { buildReportHtml } = require('../src/report/reportGenerator');

const source = fs.readFileSync(path.join(__dirname, 'fixture-vulnerable.js'), 'utf8');
const fileMeta = { url: 'https://target.test/assets/app.js' };

const { endpoints } = extractEndpoints(source, fileMeta);
const { secrets } = scanForSecrets(source, fileMeta);
const { findings: domXss } = analyzeDomXss(source, fileMeta);
const explanation = explainFile(source, fileMeta);

console.log('--- ENDPOINTS ---');
console.log(JSON.stringify(endpoints, null, 2));

console.log('\n--- SECRETS ---');
console.log(JSON.stringify(secrets, null, 2));

console.log('\n--- DOM XSS ---');
console.log(JSON.stringify(domXss, null, 2));

console.log('\n--- EXPLANATION NARRATIVE ---');
console.log(explanation.narrative);

console.log('\n--- SAMPLE PAYLOAD (first finding) ---');
if (domXss.length) console.log(generatePayloadForFinding(domXss[0]));

const fakeIndex = {
  target: fileMeta.url,
  startedAt: new Date().toISOString(),
  files: [{ url: fileMeta.url, size: source.length }],
  endpoints,
  secrets,
  domXss,
  __sessionId: 'smoke-test'
};
const html = buildReportHtml(fakeIndex, [{ url: fileMeta.url, lineCount: explanation.lineCount, frameworks: explanation.frameworks, narrative: explanation.narrative }]);
const outPath = path.join(__dirname, 'sample-report.html');
fs.writeFileSync(outPath, html, 'utf8');
console.log('\n--- REPORT ---');
console.log('Wrote sample report to', outPath);

let failed = false;
function assert(cond, msg) {
  if (!cond) { console.error('ASSERTION FAILED:', msg); failed = true; }
}

assert(endpoints.some((e) => e.urlStructure.pathname === '/api/v1/users'), 'expected /api/v1/users endpoint');
assert(endpoints.some((e) => e.raw.includes('{param}')), 'expected templated endpoint with {param}');
assert(endpoints.some((e) => e.urlStructure.host === 'api.example.com'), 'expected absolute URL endpoint from axios.post call');
assert(secrets.some((s) => s.type === 'Google API Key'), 'expected Google API Key detection');
assert(secrets.some((s) => s.reason.includes('apiSecret') || s.reason.includes('property-name')), 'expected sensitive-named property detection');
assert(domXss.some((f) => f.sinkType === 'innerHTML' && f.taintedBySource), 'expected tainted innerHTML sink from location.search');
assert(domXss.some((f) => f.sinkType === 'write'), 'expected document.write sink');
assert(domXss.some((f) => f.sinkType === 'eval'), 'expected eval sink');

console.log(failed ? '\nSMOKE TEST: FAILED' : '\nSMOKE TEST: ALL ASSERTIONS PASSED');
process.exit(failed ? 1 : 0);
