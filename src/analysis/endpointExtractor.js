const { parse, lineOf, walk } = require('./astUtils');

const HTTP_CALL_NAMES = new Set([
  'fetch', 'get', 'post', 'put', 'patch', 'delete', 'head', 'open', 'request', 'axios'
]);

const PLACEHOLDER_BASE = 'http://recon-placeholder.local';

function templateLiteralToPattern(node, source) {
  let out = '';
  for (let i = 0; i < node.quasis.length; i++) {
    out += node.quasis[i].value.raw;
    if (i < node.expressions.length) out += '{param}';
  }
  return out;
}

function looksLikePathOrUrl(str) {
  if (typeof str !== 'string') return false;
  const trimmed = str.trim();
  if (trimmed.length === 0 || trimmed.length > 2000) return false;
  if (trimmed !== str) return false;
  if (trimmed.includes('\n') || trimmed.includes('\t')) return false;
  if (trimmed.includes(' ')) return false;
  if (!trimmed.includes('/') && !trimmed.startsWith('http')) return false;
  return true;
}

function classifyUrl(candidate) {
  try {
    const asAbsolute = new URL(candidate);
    return {
      kind: 'absolute',
      protocol: asAbsolute.protocol.replace(':', ''),
      host: asAbsolute.host,
      pathname: asAbsolute.pathname,
      search: asAbsolute.search,
      hash: asAbsolute.hash,
      full: asAbsolute.toString()
    };
  } catch (_) {
    // not absolute, fall through
  }

  if (candidate.startsWith('/') && !candidate.startsWith('//')) {
    try {
      const resolved = new URL(candidate, PLACEHOLDER_BASE);
      return {
        kind: 'relative-path',
        protocol: null,
        host: null,
        pathname: resolved.pathname,
        search: resolved.search,
        hash: resolved.hash,
        full: candidate
      };
    } catch (_) {
      return null;
    }
  }

  const looksRelativeSegmented =
    !candidate.includes('://') &&
    candidate.split('/').length >= 2 &&
    !candidate.startsWith('.') &&
    !candidate.startsWith('#');

  if (looksRelativeSegmented) {
    try {
      const resolved = new URL(candidate, PLACEHOLDER_BASE + '/');
      return {
        kind: 'relative-segment',
        protocol: null,
        host: null,
        pathname: resolved.pathname,
        search: resolved.search,
        hash: resolved.hash,
        full: candidate
      };
    } catch (_) {
      return null;
    }
  }

  return null;
}

function callDisplayName(calleeNode) {
  if (!calleeNode) return null;
  if (calleeNode.type === 'Identifier') return calleeNode.name;
  if (calleeNode.type === 'MemberExpression' && calleeNode.property && calleeNode.property.type === 'Identifier') {
    return calleeNode.property.name;
  }
  return null;
}

function extractEndpoints(source, fileMeta) {
  const { ast, error } = parse(source);
  const findings = [];
  const seen = new Set();

  const record = (candidate, node, context) => {
    if (!candidate) return;
    const classified = classifyUrl(candidate);
    if (!classified) return;
    const key = classified.full + '|' + (classified.pathname || '');
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      raw: candidate,
      urlStructure: classified,
      line: lineOf(node),
      context,
      sourceFile: fileMeta ? fileMeta.url : null
    });
  };

  if (!ast) {
    return { endpoints: [], parseError: error ? error.message : 'unknown parse error' };
  }

  walk.simple(ast, {
    Literal(node) {
      if (typeof node.value === 'string' && looksLikePathOrUrl(node.value)) {
        record(node.value, node, 'string-literal');
      }
    },
    TemplateLiteral(node) {
      const pattern = templateLiteralToPattern(node, source);
      if (looksLikePathOrUrl(pattern.replace(/\{param\}/g, 'x'))) {
        record(pattern, node, 'template-literal');
      }
    },
    CallExpression(node) {
      const name = callDisplayName(node.callee);
      if (!name || !HTTP_CALL_NAMES.has(name)) return;
      const arg = node.arguments[0];
      if (!arg) return;
      if (arg.type === 'Literal' && typeof arg.value === 'string') {
        record(arg.value, arg, `http-call:${name}`);
      } else if (arg.type === 'TemplateLiteral') {
        const pattern = templateLiteralToPattern(arg, source);
        record(pattern, arg, `http-call:${name}`);
      }
    }
  });

  return { endpoints: findings, parseError: null };
}

module.exports = { extractEndpoints, classifyUrl, looksLikePathOrUrl };
