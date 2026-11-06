import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const ETH_METHODS = new Set([
  'eth_call', 'eth_sendTransaction', 'eth_estimateGas', 'eth_getBalance', 'eth_getCode',
  'eth_getStorageAt', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getLogs',
  'eth_blockNumber', 'eth_chainId', 'eth_gasPrice', 'eth_feeHistory', 'eth_getTransactionCount',
]);
const EXTENSIONS = { '.js': ts.ScriptKind.JS, '.jsx': ts.ScriptKind.JSX, '.mjs': ts.ScriptKind.JS, '.cjs': ts.ScriptKind.JS, '.ts': ts.ScriptKind.TS, '.tsx': ts.ScriptKind.TSX, '.mts': ts.ScriptKind.TS, '.cts': ts.ScriptKind.TS };

function unwrap(node) {
  while (node && (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node) || ts.isParenthesizedExpression(node))) node = node.expression;
  return node;
}
function propName(node) {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) return node.text;
  return null;
}
function memberName(expr) {
  expr = unwrap(expr);
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  if (ts.isElementAccessExpression(expr)) return propName(expr.argumentExpression);
  return null;
}
function rootIdentifier(expr) {
  expr = unwrap(expr);
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return rootIdentifier(expr.expression);
  if (ts.isElementAccessExpression(expr)) return rootIdentifier(expr.expression);
  if (ts.isCallExpression(expr)) return rootIdentifier(expr.expression);
  return null;
}
function textOf(node, sf) { return node ? node.getText(sf) : null; }
function literal(node, sf) {
  node = unwrap(node);
  if (!node) return null;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isObjectLiteralExpression(node)) {
    const out = {};
    for (const p of node.properties) {
      if (ts.isPropertyAssignment(p)) { const k = propName(p.name); if (k) out[k] = literal(p.initializer, sf) ?? textOf(p.initializer, sf); }
      else if (ts.isShorthandPropertyAssignment(p)) out[p.name.text] = p.name.text;
    }
    return out;
  }
  if (ts.isArrayLiteralExpression(node)) return node.elements.map((x) => literal(x, sf) ?? textOf(x, sf));
  return textOf(node, sf);
}
function objectProperty(node, name) {
  node = unwrap(node);
  if (!node || !ts.isObjectLiteralExpression(node)) return null;
  for (const p of node.properties) if (ts.isPropertyAssignment(p) && propName(p.name) === name) return p.initializer;
  return null;
}
function txDetails(object) {
  if (!object || typeof object !== 'object') return null;
  const account = object.account && typeof object.account === 'object' ? object.account.address : object.account;
  return {
    from: typeof object.from === 'string' && ADDRESS.test(object.from) ? object.from : typeof account === 'string' && ADDRESS.test(account) ? account : null,
    to: typeof object.to === 'string' && ADDRESS.test(object.to) ? object.to : null,
    value: object.value ?? null, gas: object.gas ?? object.gasLimit ?? null,
    gasPrice: object.gasPrice ?? null, maxFeePerGas: object.maxFeePerGas ?? null,
    nonce: object.nonce ?? null,
  };
}
function functionContext(node, sf) {
  let cur = node;
  while (cur && !ts.isSourceFile(cur)) {
    if ((ts.isFunctionDeclaration(cur) || ts.isMethodDeclaration(cur) || ts.isFunctionExpression(cur) || ts.isArrowFunction(cur)) && cur.name) return cur.name.getText(sf);
    if (ts.isVariableDeclaration(cur) && ts.isIdentifier(cur.name) && cur.initializer && (ts.isArrowFunction(cur.initializer) || ts.isFunctionExpression(cur.initializer))) return cur.name.text;
    cur = cur.parent;
  }
  return '(top level)';
}
export function scanSource(source, filePath = 'input.js') {
  const ext = path.extname(filePath).toLowerCase();
  const sf = ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, true, EXTENSIONS[ext] ?? ts.ScriptKind.TS);
  const vars = new Map();
  const contracts = new Map();
  const findings = [];
  const seen = new Set();
  const relativeFile = filePath;
  const resolve = (node, depth = 0) => {
    node = unwrap(node);
    if (!node || depth > 5) return null;
    if (ts.isIdentifier(node) && vars.has(node.text)) return resolve(vars.get(node.text), depth + 1);
    if (ts.isObjectLiteralExpression(node)) {
      const out = {};
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p)) { const key = propName(p.name); if (key) out[key] = resolve(p.initializer, depth + 1) ?? textOf(p.initializer, sf); }
        else if (ts.isShorthandPropertyAssignment(p)) out[p.name.text] = vars.has(p.name.text) ? resolve(vars.get(p.name.text), depth + 1) : p.name.text;
      }
      return out;
    }
    if (ts.isArrayLiteralExpression(node)) return node.elements.map((x) => resolve(x, depth + 1) ?? textOf(x, sf));
    return literal(node, sf);
  };
  const add = (node, data) => {
    const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    const key = `${pos.line}:${pos.character}:${data.kind}:${data.method ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    const endLine = sf.getLineAndCharacterOfPosition(node.getEnd()).line;
    findings.push({
      id: `${path.basename(filePath)}:${pos.line + 1}:${pos.character + 1}`,
      file: relativeFile, line: pos.line + 1, column: pos.character + 1, endLine: endLine + 1,
      function: functionContext(node, sf), snippet: node.getText(sf).slice(0, 600),
      address: null, functionName: null, parameters: null, rpcMethod: null, transaction: null,
      library: 'unknown', kind: 'contract', confidence: 'medium', notes: [], ...data,
    });
  };
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) vars.set(node.name.text, node.initializer);
    if (ts.isPropertyAssignment(node) && propName(node.name) === 'address') {
      const address = resolve(node.initializer);
      const parent = node.parent;
      if (ADDRESS.test(String(address)) && ts.isObjectLiteralExpression(parent)) {
        for (const p of parent.properties) if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.initializer === node.initializer) {
          // handled at call sites by inspecting their argument configuration
        }
      }
    }
    if (ts.isNewExpression(node)) {
      const ctor = rootIdentifier(node.expression);
      if (ctor === 'Contract' || ctor === 'Interface') {
        const name = ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)
          ? node.parent.name.text
          : ts.isIdentifier(unwrap(node.expression)) ? node.expression.text : null;
        const args = node.arguments ?? [];
        const address = resolve(args[0]);
        const abi = args[1];
        if (name && ADDRESS.test(String(address))) contracts.set(name, { address, abi });
      }
    }
    if (ts.isCallExpression(node)) {
      const method = memberName(node.expression) ?? (ts.isIdentifier(unwrap(node.expression)) ? unwrap(node.expression).text : null);
      const args = [...node.arguments];
      const receiver = ts.isPropertyAccessExpression(unwrap(node.expression)) || ts.isElementAccessExpression(unwrap(node.expression)) ? unwrap(node.expression).expression : null;
      const receiverName = receiver ? rootIdentifier(receiver) : null;
      const contract = receiverName ? contracts.get(receiverName) : null;

      // ethers Contract call methods: contract.balanceOf(...), contract.foo.staticCall(...)
      if (contract && method && !['connect', 'attach', 'interface', 'getAddress', 'waitForDeployment'].includes(method)) {
        const fnName = method === 'staticCall' || method === 'send' || method === 'estimateGas' ? memberName(unwrap(node.expression).expression) : method;
        if (fnName) add(node, { address: contract.address, transaction: txDetails({ to: contract.address }), functionName: fnName, parameters: args.map((x) => resolve(x)), library: 'ethers', kind: /^(?:staticCall|callStatic)$/.test(method) ? 'contract read' : 'contract interaction', confidence: 'high', notes: [] });
      }

      // viem actions. address and ABI are commonly supplied in a config object.
      if (method && ['readContract', 'writeContract', 'simulateContract', 'getContract'].includes(method)) {
        const cfg = args[0];
        const addressNode = objectProperty(cfg, 'address');
        const fnNode = objectProperty(cfg, 'functionName');
        const abiNode = objectProperty(cfg, 'abi');
        const address = resolve(addressNode);
        const fnName = resolve(fnNode);
        const argNode = objectProperty(cfg, 'args');
        const resolvedCfg = resolve(cfg);
        add(node, { address: ADDRESS.test(String(address)) ? address : null, transaction: txDetails({ ...resolvedCfg, to: address }), functionName: typeof fnName === 'string' ? fnName : null,
          parameters: argNode ? resolve(argNode) : [], library: 'viem', kind: method === 'readContract' ? 'contract read' : 'contract interaction', confidence: address && fnName ? 'high' : 'medium', notes: address ? [] : ['Address is dynamic or unresolved.'] });
      }

      // Generic JSON-RPC APIs: provider.request({method,params}), provider.send(method,params), client.request({method,params})
      if (method === 'request' && args.length) {
        const cfg = args[0]; const methodNode = objectProperty(cfg, 'method'); const paramsNode = objectProperty(cfg, 'params');
        const rpcMethod = resolve(methodNode);
        if (typeof rpcMethod === 'string' && ETH_METHODS.has(rpcMethod)) {
          const params = paramsNode ? resolve(paramsNode) : null;
          const first = Array.isArray(params) ? params[0] : null;
          const address = first && typeof first === 'object' ? first.to : null;
          const data = first && typeof first === 'object' ? first.data : null;
          add(node, { rpcMethod, address: ADDRESS.test(String(address)) ? address : null, transaction: txDetails(first), functionName: null, calldata: typeof data === 'string' ? data : null,
            parameters: data ?? null, library: 'native JSON-RPC', kind: rpcMethod === 'eth_call' ? 'contract read' : rpcMethod.startsWith('eth_') ? 'Ethereum JSON-RPC' : 'contract interaction',
            confidence: methodNode && rpcMethod ? 'high' : 'medium', notes: data ? ['Raw calldata captured; function name and decoded arguments require the matching ABI.'] : (rpcMethod === 'eth_call' ? ['Contract target or calldata is dynamic or unresolved.'] : []) });
        }
      }
      if ((method === 'send' || method === 'sendAsync') && args.length >= 1) {
        const rpcMethod = resolve(args[0]);
        if (typeof rpcMethod === 'string' && ETH_METHODS.has(rpcMethod)) {
          const params = args[1] ? resolve(args[1]) : null;
          const first = Array.isArray(params) ? params[0] : null;
          const address = first && typeof first === 'object' ? first.to : null;
          const data = first && typeof first === 'object' ? first.data : null;
          add(node, { rpcMethod, address: ADDRESS.test(String(address)) ? address : null, transaction: txDetails(first), calldata: typeof data === 'string' ? data : null, parameters: data ?? params,
            library: 'native JSON-RPC', kind: rpcMethod === 'eth_call' ? 'contract read' : 'Ethereum JSON-RPC', confidence: 'high',
            notes: data ? ['Raw calldata captured; function name and decoded arguments require the matching ABI.'] : [] });
        }
      }

      // fetch(url, { body: JSON.stringify({method:'eth_call', params:[...]}) })
      if (method === 'fetch' && args[1]) {
        const body = objectProperty(args[1], 'body');
        const bodyCall = body && unwrap(body);
        if (bodyCall && ts.isCallExpression(bodyCall) && memberName(bodyCall.expression) === 'stringify') {
          const payload = bodyCall.arguments[0]; const rpcMethod = resolve(objectProperty(payload, 'method'));
          if (typeof rpcMethod === 'string' && ETH_METHODS.has(rpcMethod)) {
            const params = resolve(objectProperty(payload, 'params')); const first = Array.isArray(params) ? params[0] : null;
            add(node, { rpcMethod, address: first?.to && ADDRESS.test(String(first.to)) ? first.to : null, transaction: txDetails(first), calldata: typeof first?.data === 'string' ? first.data : null, parameters: first?.data ?? params,
              library: 'native JSON-RPC (fetch)', kind: rpcMethod === 'eth_call' ? 'contract read' : 'Ethereum JSON-RPC', confidence: 'high',
              notes: ['Direct HTTP JSON-RPC request detected.', ...(first?.data ? ['Raw calldata requires an ABI to decode.'] : [])] });
          }
        }
      }
      // ethers provider.call({to,data}) and viem client.call({to,data})
      if (method === 'call' && args.length && objectProperty(args[0], 'to')) {
        const cfg = args[0]; const address = resolve(objectProperty(cfg, 'to')); const data = resolve(objectProperty(cfg, 'data'));
        add(node, { address: ADDRESS.test(String(address)) ? address : null, transaction: txDetails({ ...resolve(cfg), to: address }), calldata: typeof data === 'string' ? data : null, parameters: data, rpcMethod: 'eth_call',
          library: receiverName === 'provider' || receiverName === 'ethersProvider' ? 'ethers' : 'native JSON-RPC', kind: 'contract read', confidence: 'high',
          notes: ['Raw calldata captured; function name and decoded arguments require the matching ABI.'] });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

export function scanFiles(files) {
  const all = [];
  for (const file of files) {
    try { all.push(...scanSource(fs.readFileSync(file, 'utf8'), file)); }
    catch (error) { all.push({ id: `${file}:error`, file, line: 0, column: 0, function: '', snippet: '', library: 'parser', kind: 'parse error', confidence: 'low', notes: [error.message] }); }
  }
  return all;
}
