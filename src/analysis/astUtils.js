const acorn = require('acorn');
const walk = require('acorn-walk');

function parse(source) {
  const attempts = [
    { ecmaVersion: 'latest', sourceType: 'module', locations: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true, allowAwaitOutsideFunction: true },
    { ecmaVersion: 'latest', sourceType: 'script', locations: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true }
  ];
  let lastError = null;
  for (const options of attempts) {
    try {
      return { ast: acorn.parse(source, options), error: null };
    } catch (err) {
      lastError = err;
    }
  }
  return { ast: null, error: lastError };
}

function lineOf(node) {
  return node && node.loc ? node.loc.start.line : null;
}

function sliceSource(source, node) {
  if (!node) return '';
  return source.slice(node.start, node.end);
}

module.exports = { parse, lineOf, sliceSource, walk };
