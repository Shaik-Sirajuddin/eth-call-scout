import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const SKIP_DIRECTORY_NAMES = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo']);

function isSourceFile(file) {
  return SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase()) && !/\.d\.(?:ts|mts|cts)$/i.test(file);
}

function walkDirectory(directory, found) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory() && !SKIP_DIRECTORY_NAMES.has(entry.name)) walkDirectory(target, found);
    else if (entry.isFile() && isSourceFile(target)) found.add(path.resolve(target));
  }
}

function importedSpecifiers(sourceFile) {
  const specifiers = new Set();
  const add = (node) => {
    if (node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))) specifiers.add(node.text);
  };
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) add(node.moduleSpecifier);
    else if (ts.isImportTypeNode(node)) add(node.argument);
    else if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if ((expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(expression) && expression.text === 'require')) && node.arguments.length === 1) add(node.arguments[0]);
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) add(node.moduleReference.expression);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return specifiers;
}

const compilerOptionsCache = new Map();
function compilerOptionsFor(file) {
  let directory = path.dirname(file);
  let configPath = null;
  while (true) {
    const candidate = path.join(directory, 'tsconfig.json');
    if (fs.existsSync(candidate)) { configPath = candidate; break; }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  if (!configPath) return {
    allowJs: true,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    resolveJsonModule: true,
    jsx: ts.JsxEmit.Preserve,
  };
  if (compilerOptionsCache.has(configPath)) return compilerOptionsCache.get(configPath);
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config ?? {}, ts.sys, path.dirname(configPath), undefined, configPath);
  const options = {
    ...parsed.options,
    allowJs: true,
    module: parsed.options.module ?? ts.ModuleKind.NodeNext,
    moduleResolution: parsed.options.moduleResolution ?? ts.ModuleResolutionKind.NodeNext,
    resolveJsonModule: true,
  };
  compilerOptionsCache.set(configPath, options);
  return options;
}

function resolveImport(specifier, importer) {
  if (specifier.startsWith('node:')) return null;
  const result = ts.resolveModuleName(specifier, importer, compilerOptionsFor(importer), ts.sys).resolvedModule;
  const resolved = result?.resolvedFileName;
  if (resolved && isSourceFile(resolved)) return path.resolve(resolved);
  return resolveRuntimePackageFile(specifier, importer, resolved);
}

function packageParts(specifier) {
  const parts = specifier.split('/');
  const packageName = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  return { packageName, subpath: parts.slice(packageName.split('/').length).join('/') };
}

function findPackageDirectory(packageName, importer) {
  let directory = path.dirname(importer);
  while (true) {
    const candidate = path.join(directory, 'node_modules', packageName);
    if (fs.existsSync(path.join(candidate, 'package.json'))) return candidate;
    const parent = path.dirname(directory);
    if (parent === directory) return null;
    directory = parent;
  }
}

function exportTarget(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    for (const item of value) { const target = exportTarget(item); if (target) return target; }
  }
  if (value && typeof value === 'object') {
    for (const condition of ['import', 'node', 'default', 'require', 'module']) {
      if (Object.hasOwn(value, condition)) { const target = exportTarget(value[condition]); if (target) return target; }
    }
  }
  return null;
}

function replaceExportWildcard(value, captured) {
  if (typeof value === 'string') return value.replaceAll('*', captured);
  if (Array.isArray(value)) return value.map((item) => replaceExportWildcard(item, captured));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceExportWildcard(item, captured)]));
  return value;
}

function fileCandidate(base) {
  const candidates = [base, ...['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx'].map((ext) => `${base}${ext}`), ...['index.js', 'index.mjs', 'index.cjs', 'index.ts'].map((name) => path.join(base, name))];
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile() && isSourceFile(candidate)) ?? null;
}

function resolveRuntimePackageFile(specifier, importer, declarationPath) {
  const { packageName, subpath } = packageParts(specifier);
  let packageDirectory = findPackageDirectory(packageName, importer);
  if (!packageDirectory && declarationPath) {
    let directory = path.dirname(declarationPath);
    while (directory !== path.dirname(directory)) {
      if (fs.existsSync(path.join(directory, 'package.json'))) { packageDirectory = directory; break; }
      directory = path.dirname(directory);
    }
  }
  if (!packageDirectory) return null;
  let metadata;
  try { metadata = JSON.parse(fs.readFileSync(path.join(packageDirectory, 'package.json'), 'utf8')); }
  catch { return null; }

  let target = null;
  const exports = metadata.exports;
  if (exports) {
    const exportKey = subpath ? `./${subpath}` : '.';
    let entry = typeof exports === 'string' || Array.isArray(exports) ? (exportKey === '.' ? exports : null) : exports[exportKey];
    if (entry === undefined && exports && typeof exports === 'object') {
      for (const key of Object.keys(exports)) {
        const star = key.indexOf('*');
        if (star < 0) continue;
        const prefix = key.slice(0, star), suffix = key.slice(star + 1);
        if (exportKey.startsWith(prefix) && exportKey.endsWith(suffix)) {
          const captured = exportKey.slice(prefix.length, exportKey.length - suffix.length || undefined);
          entry = replaceExportWildcard(exports[key], captured);
          break;
        }
      }
    }
    target = exportTarget(entry);
  }
  if (!target && subpath) target = `./${subpath}`;
  if (!target) target = metadata.module ?? metadata.main ?? metadata['jsnext:main'] ?? metadata.source ?? 'index.js';
  const absolute = path.resolve(packageDirectory, target);
  if (!absolute.startsWith(`${path.resolve(packageDirectory)}${path.sep}`)) return null;
  const resolved = fileCandidate(absolute);
  return resolved ? path.resolve(resolved) : null;
}

/** Collect explicit files/directories and the transitive JS/TS import graph reachable from them. */
export function collectProjectFiles(inputs) {
  const roots = new Set();
  for (const input of inputs) {
    const target = path.resolve(input);
    if (!fs.existsSync(target)) throw new Error(`Path does not exist: ${input}`);
    const stat = fs.statSync(target);
    if (stat.isDirectory()) walkDirectory(target, roots);
    else if (isSourceFile(target)) roots.add(target);
  }

  const visited = new Set();
  const queue = [...roots];
  while (queue.length) {
    const file = queue.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    let source;
    try {
      source = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.getScriptKindFromFileName(file));
    } catch {
      continue;
    }
    for (const specifier of importedSpecifiers(source)) {
      const dependency = resolveImport(specifier, file);
      if (dependency && !visited.has(dependency)) queue.push(dependency);
    }
  }
  return [...visited].sort();
}
