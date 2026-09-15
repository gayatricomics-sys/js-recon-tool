const { parse, lineOf, walk } = require('./astUtils');

const SENSITIVE_NAME_HINTS = [
  'apikey', 'api_key', 'secret', 'token', 'password', 'passwd', 'pwd',
  'authorization', 'auth_token', 'accesskey', 'access_key', 'privatekey',
  'private_key', 'clientsecret', 'client_secret', 'sessionid', 'session_id',
  'credential', 'bearer'
];

const KNOWN_PREFIXES = [
  { label: 'AWS Access Key ID', prefixes: ['AKIA', 'ASIA'], minLen: 20, maxLen: 20 },
  { label: 'Google API Key', prefixes: ['AIza'], minLen: 39, maxLen: 39 },
  { label: 'GitHub Token', prefixes: ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'], minLen: 20, maxLen: 255 },
  { label: 'Slack Token', prefixes: ['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-'], minLen: 20, maxLen: 200 },
  { label: 'Stripe Key', prefixes: ['sk_live_', 'pk_live_', 'rk_live_'], minLen: 15, maxLen: 200 },
  { label: 'Anthropic API Key', prefixes: ['sk-ant-'], minLen: 20, maxLen: 200 },
  { label: 'OpenAI API Key', prefixes: ['sk-'], minLen: 20, maxLen: 200 }
];

function isAlnumUpper(str) {
  for (const ch of str) {
    const isDigit = ch >= '0' && ch <= '9';
    const isUpper = ch >= 'A' && ch <= 'Z';
    if (!isDigit && !isUpper) return false;
  }
  return true;
}

function shannonEntropy(str) {
  if (!str.length) return 0;
  const counts = {};
  for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in counts) {
    const p = counts[ch] / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksBase64Charset(str) {
  const allowed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-';
  for (const ch of str) {
    if (!allowed.includes(ch)) return false;
  }
  return true;
}

function checkKnownPrefix(value) {
  for (const rule of KNOWN_PREFIXES) {
    for (const prefix of rule.prefixes) {
      if (value.startsWith(prefix) && value.length >= rule.minLen && value.length <= rule.maxLen) {
        return rule.label;
      }
    }
  }
  return null;
}

function checkPemBlock(value) {
  if (value.includes('-----BEGIN') && value.includes('PRIVATE KEY-----')) return 'PEM Private Key';
  if (value.includes('-----BEGIN CERTIFICATE-----')) return 'X.509 Certificate';
  return null;
}

function checkJwt(value) {
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  for (const part of parts) {
    if (part.length < 4) return null;
    if (!looksBase64Charset(part)) return null;
  }
  try {
    const headerJson = Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const header = JSON.parse(headerJson);
    if (header && (header.alg || header.typ)) return 'JWT';
  } catch (_) {
    return null;
  }
  return null;
}

function redact(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(Math.max(4, value.length - 8)) + value.slice(-4);
}

function nameHintsSensitive(name) {
  if (!name) return false;
  const lower = name.toLowerCase();
  return SENSITIVE_NAME_HINTS.some((hint) => lower.includes(hint));
}

function propertyKeyName(keyNode) {
  if (!keyNode) return null;
  if (keyNode.type === 'Identifier') return keyNode.name;
  if (keyNode.type === 'Literal' && typeof keyNode.value === 'string') return keyNode.value;
  return null;
}

function scanForSecrets(source, fileMeta) {
  const { ast, error } = parse(source);
  const findings = [];
  const seen = new Set();

  const record = (type, value, node, reason) => {
    const key = type + '|' + value;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      type,
      redacted: redact(value),
      length: value.length,
      entropy: Number(shannonEntropy(value).toFixed(2)),
      line: lineOf(node),
      reason,
      sourceFile: fileMeta ? fileMeta.url : null
    });
  };

  if (!ast) {
    return { secrets: [], parseError: error ? error.message : 'unknown parse error' };
  }

  walk.simple(ast, {
    Literal(node) {
      if (typeof node.value !== 'string') return;
      const value = node.value;
      if (value.length < 8) return;

      const known = checkKnownPrefix(value);
      if (known) {
        record(known, value, node, 'known-prefix-match');
        return;
      }

      const pem = checkPemBlock(value);
      if (pem) {
        record(pem, value, node, 'pem-block');
        return;
      }

      const jwt = checkJwt(value);
      if (jwt) {
        record(jwt, value, node, 'jwt-structure');
        return;
      }
    },

    Property(node) {
      const name = propertyKeyName(node.key);
      if (!nameHintsSensitive(name)) return;
      if (node.value && node.value.type === 'Literal' && typeof node.value.value === 'string' && node.value.value.length >= 6) {
        record('Sensitive-Named Property', node.value.value, node.value, `property-name:${name}`);
      }
    },

    VariableDeclarator(node) {
      const name = node.id && node.id.type === 'Identifier' ? node.id.name : null;
      if (!nameHintsSensitive(name)) return;
      if (node.init && node.init.type === 'Literal' && typeof node.init.value === 'string' && node.init.value.length >= 6) {
        record('Sensitive-Named Variable', node.init.value, node.init, `variable-name:${name}`);
      }
    },

    AssignmentExpression(node) {
      let name = null;
      if (node.left.type === 'Identifier') name = node.left.name;
      else if (node.left.type === 'MemberExpression' && node.left.property.type === 'Identifier') name = node.left.property.name;
      if (!nameHintsSensitive(name)) return;
      if (node.right.type === 'Literal' && typeof node.right.value === 'string' && node.right.value.length >= 6) {
        record('Sensitive-Named Assignment', node.right.value, node.right, `assignment-name:${name}`);
      }
    }
  });

  walk.simple(ast, {
    Literal(node) {
      if (typeof node.value !== 'string') return;
      const value = node.value;
      if (value.length < 24 || value.length > 4096) return;
      if (value.includes(' ') || value.includes('\n')) return;
      if (!looksBase64Charset(value)) return;
      if (isAlnumUpper(value)) return;
      const entropy = shannonEntropy(value);
      if (entropy >= 4.2) {
        record('High-Entropy String', value, node, `entropy:${entropy.toFixed(2)}`);
      }
    }
  });

  return { secrets: findings, parseError: null };
}

module.exports = { scanForSecrets, shannonEntropy, redact };
