const { parse, walk } = require('./astUtils');
const { extractEndpoints } = require('./endpointExtractor');
const { scanForSecrets } = require('./secretScanner');
const { analyzeDomXss } = require('./domXssAnalyzer');

const FRAMEWORK_SIGNATURES = [
  { name: 'React', tokens: ['React.createElement', 'react-dom', '_jsx', '__REACT_DEVTOOLS'] },
  { name: 'Vue', tokens: ['Vue.component', 'createApp', '__VUE__', 'vue-router'] },
  { name: 'Angular', tokens: ['angular.module', 'ng-app', '@angular/core'] },
  { name: 'jQuery', tokens: ['jQuery.fn.jquery', 'jQuery(', '$.ajax'] },
  { name: 'Webpack bundle', tokens: ['__webpack_require__', 'webpackJsonp'] },
  { name: 'Next.js', tokens: ['__NEXT_DATA__', 'next/router'] }
];

function detectFrameworks(source) {
  return FRAMEWORK_SIGNATURES.filter((sig) => sig.tokens.some((t) => source.includes(t))).map((s) => s.name);
}

function collectStructural(ast) {
  const functions = [];
  const imports = [];
  const eventListeners = [];

  walk.simple(ast, {
    FunctionDeclaration(node) {
      if (node.id && node.id.name) functions.push(node.id.name);
    },
    ImportDeclaration(node) {
      if (node.source && typeof node.source.value === 'string') imports.push(node.source.value);
    },
    CallExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0] && node.arguments[0].type === 'Literal') {
        imports.push(String(node.arguments[0].value));
      }
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'addEventListener' &&
        node.arguments[0] &&
        node.arguments[0].type === 'Literal'
      ) {
        eventListeners.push(String(node.arguments[0].value));
      }
    }
  });

  return { functions, imports, eventListeners };
}

function buildNarrative({ fileMeta, lineCount, frameworks, structural, endpointCount, secretCount, xssFindings }) {
  const sentences = [];
  const label = fileMeta && fileMeta.url ? fileMeta.url : 'This file';

  sentences.push(`${label} is a JavaScript resource of ${lineCount} lines.`);

  if (frameworks.length) {
    sentences.push(`It appears to use: ${frameworks.join(', ')}.`);
  } else {
    sentences.push('No recognized frontend framework signature was detected; it may be a plain script, utility bundle, or custom code.');
  }

  if (structural.functions.length) {
    const shown = structural.functions.slice(0, 8).join(', ');
    sentences.push(`It declares ${structural.functions.length} named top-level function(s), including: ${shown}${structural.functions.length > 8 ? ', ...' : ''}.`);
  }

  if (structural.imports.length) {
    const shown = [...new Set(structural.imports)].slice(0, 8).join(', ');
    sentences.push(`It imports/requires: ${shown}.`);
  }

  if (structural.eventListeners.length) {
    const unique = [...new Set(structural.eventListeners)];
    sentences.push(`It attaches event listeners for: ${unique.join(', ')}.`);
  }

  if (endpointCount > 0) {
    sentences.push(`Static analysis found ${endpointCount} candidate URL/endpoint string(s) referenced in this file.`);
  }

  if (secretCount > 0) {
    sentences.push(`WARNING: ${secretCount} string(s) matched secret/credential heuristics (see Secrets panel for redacted detail) and should be manually verified.`);
  }

  if (xssFindings.length > 0) {
    const high = xssFindings.filter((f) => f.severity === 'HIGH').length;
    sentences.push(`${xssFindings.length} potential DOM XSS sink(s) were identified, of which ${high} appear tainted by a client-controllable source and are flagged HIGH severity.`);
  } else {
    sentences.push('No DOM XSS sink patterns were identified by static analysis in this file.');
  }

  return sentences.join(' ');
}

function explainFile(source, fileMeta) {
  const { ast, error } = parse(source);
  const lineCount = source.split('\n').length;
  const frameworks = detectFrameworks(source);

  if (!ast) {
    return {
      narrative: `${fileMeta && fileMeta.url ? fileMeta.url : 'This file'} could not be fully parsed as JavaScript (${error ? error.message : 'unknown error'}). It is ${lineCount} lines long; frameworks detected via substring match: ${frameworks.join(', ') || 'none'}.`,
      structural: { functions: [], imports: [], eventListeners: [] },
      frameworks,
      lineCount,
      parseError: error ? error.message : 'unknown error'
    };
  }

  const structural = collectStructural(ast);
  const { endpoints } = extractEndpoints(source, fileMeta);
  const { secrets } = scanForSecrets(source, fileMeta);
  const { findings: xssFindings } = analyzeDomXss(source, fileMeta);

  const narrative = buildNarrative({
    fileMeta,
    lineCount,
    frameworks,
    structural,
    endpointCount: endpoints.length,
    secretCount: secrets.length,
    xssFindings
  });

  return { narrative, structural, frameworks, lineCount, parseError: null };
}

module.exports = { explainFile };
