const { parse, lineOf, sliceSource, walk } = require('./astUtils');

const SINK_PROPERTIES = new Set(['innerHTML', 'outerHTML']);
const SINK_CALL_NAMES = new Set(['write', 'writeln', 'insertAdjacentHTML', 'eval', 'setHTML']);
const SINK_LOCATION_CALLS = new Set(['assign', 'replace']);

const TAINT_SOURCE_TOKENS = [
  'location.search', 'location.hash', 'location.href', 'location.pathname',
  'document.referrer', 'document.URL', 'document.documentURI',
  'window.name', 'URLSearchParams', 'postMessage', '.data', 'localStorage',
  'sessionStorage', 'document.cookie'
];

function memberChainName(node) {
  const parts = [];
  let cur = node;
  while (cur) {
    if (cur.type === 'MemberExpression') {
      if (cur.property.type === 'Identifier') parts.unshift(cur.property.name);
      else if (cur.property.type === 'Literal') parts.unshift(String(cur.property.value));
      cur = cur.object;
    } else if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      cur = null;
    } else {
      cur = null;
    }
  }
  return parts.join('.');
}

function containsTaintSource(snippet) {
  return TAINT_SOURCE_TOKENS.some((token) => snippet.includes(token));
}

function collectIdentifierNames(node) {
  const names = new Set();
  if (!node) return names;
  if (node.type === 'Identifier') {
    names.add(node.name);
    return names;
  }
  walk.simple(node, {
    Identifier(n) {
      names.add(n.name);
    }
  });
  return names;
}

// Best-effort, multi-hop taint propagation: finds variables whose declared or
// assigned value textually references a known client-controllable source, or
// that derive from another already-tainted variable (var b = a.get(...) where
// a is tainted). Runs to a bounded fixed point. This is a heuristic, not full
// dataflow analysis -- it does not model control flow, object field
// granularity, or function boundaries.
function collectTaintedVariableNames(ast, source) {
  const assignments = [];

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id.type === 'Identifier' && node.init) {
        assignments.push({ name: node.id.name, node: node.init });
      }
    },
    AssignmentExpression(node) {
      if (node.left.type === 'Identifier') {
        assignments.push({ name: node.left.name, node: node.right });
      }
    }
  });

  const tainted = new Set();
  let changed = true;
  let iterations = 0;

  while (changed && iterations < 6) {
    changed = false;
    iterations++;
    for (const { name, node } of assignments) {
      if (tainted.has(name)) continue;
      const snippet = sliceSource(source, node);
      if (containsTaintSource(snippet)) {
        tainted.add(name);
        changed = true;
        continue;
      }
      for (const identName of collectIdentifierNames(node)) {
        if (tainted.has(identName)) {
          tainted.add(name);
          changed = true;
          break;
        }
      }
    }
  }

  return tainted;
}

function isTainted(node, source, taintedVars) {
  const snippet = sliceSource(source, node);
  if (containsTaintSource(snippet)) return true;
  const names = collectIdentifierNames(node);
  for (const name of names) {
    if (taintedVars.has(name)) return true;
  }
  return false;
}

function severityFor(sinkType, tainted) {
  if (tainted) return 'HIGH';
  if (sinkType === 'eval' || sinkType === 'Function-constructor') return 'MEDIUM';
  return 'LOW';
}

function analyzeDomXss(source, fileMeta) {
  const { ast, error } = parse(source);
  const findings = [];

  if (!ast) {
    return { findings: [], parseError: error ? error.message : 'unknown parse error' };
  }

  const taintedVars = collectTaintedVariableNames(ast, source);

  walk.simple(ast, {
    AssignmentExpression(node) {
      if (node.left.type !== 'MemberExpression') return;
      const propName = node.left.property.type === 'Identifier' ? node.left.property.name : null;
      if (!propName || !SINK_PROPERTIES.has(propName)) return;

      const tainted = isTainted(node.right, source, taintedVars);

      findings.push({
        sinkType: propName,
        target: memberChainName(node.left),
        line: lineOf(node),
        snippet: sliceSource(source, node).slice(0, 300),
        taintedBySource: tainted,
        severity: severityFor(propName, tainted),
        sourceFile: fileMeta ? fileMeta.url : null
      });
    },

    CallExpression(node) {
      let calleeName = null;
      let objectChain = '';

      if (node.callee.type === 'Identifier') {
        calleeName = node.callee.name;
      } else if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier') {
        calleeName = node.callee.property.name;
        objectChain = memberChainName(node.callee.object);
      }

      if (!calleeName) return;

      if (calleeName === 'eval') {
        const tainted = node.arguments[0] ? isTainted(node.arguments[0], source, taintedVars) : false;
        findings.push({
          sinkType: 'eval',
          target: 'eval()',
          line: lineOf(node),
          snippet: sliceSource(source, node).slice(0, 300),
          taintedBySource: tainted,
          severity: severityFor('eval', tainted),
          sourceFile: fileMeta ? fileMeta.url : null
        });
        return;
      }

      if (SINK_CALL_NAMES.has(calleeName) && (calleeName === 'write' || calleeName === 'writeln' || calleeName === 'insertAdjacentHTML' || calleeName === 'setHTML')) {
        const tainted = node.arguments.some((a) => isTainted(a, source, taintedVars));
        findings.push({
          sinkType: calleeName,
          target: objectChain || calleeName,
          line: lineOf(node),
          snippet: sliceSource(source, node).slice(0, 300),
          taintedBySource: tainted,
          severity: severityFor(calleeName, tainted),
          sourceFile: fileMeta ? fileMeta.url : null
        });
        return;
      }

      if ((calleeName === 'setTimeout' || calleeName === 'setInterval') && node.arguments[0]) {
        const first = node.arguments[0];
        if (first.type === 'Literal' && typeof first.value === 'string') {
          findings.push({
            sinkType: `${calleeName}-string-arg`,
            target: calleeName,
            line: lineOf(node),
            snippet: sliceSource(source, node).slice(0, 300),
            taintedBySource: containsTaintSource(first.value),
            severity: 'MEDIUM',
            sourceFile: fileMeta ? fileMeta.url : null
          });
        }
        return;
      }

      if (objectChain === 'location' && SINK_LOCATION_CALLS.has(calleeName) && node.arguments[0]) {
        const tainted = isTainted(node.arguments[0], source, taintedVars);
        findings.push({
          sinkType: `location.${calleeName}`,
          target: 'location',
          line: lineOf(node),
          snippet: sliceSource(source, node).slice(0, 300),
          taintedBySource: tainted,
          severity: severityFor('location', tainted),
          sourceFile: fileMeta ? fileMeta.url : null
        });
      }
    },

    NewExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function' && node.arguments.length) {
        const tainted = node.arguments.some((a) => isTainted(a, source, taintedVars));
        findings.push({
          sinkType: 'Function-constructor',
          target: 'new Function()',
          line: lineOf(node),
          snippet: sliceSource(source, node).slice(0, 300),
          taintedBySource: tainted,
          severity: severityFor('Function-constructor', tainted),
          sourceFile: fileMeta ? fileMeta.url : null
        });
      }
    }
  });

  return { findings, parseError: null };
}

module.exports = { analyzeDomXss };
