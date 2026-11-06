import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const MANIFEST = path.join(ROOT, 'parser-rs', 'Cargo.toml');
const RELEASE_BIN = path.join(ROOT, 'parser-rs', 'target', 'release', process.platform === 'win32' ? 'eth-call-scout-parser.exe' : 'eth-call-scout-parser');
const DEBUG_BIN = path.join(ROOT, 'parser-rs', 'target', 'debug', process.platform === 'win32' ? 'eth-call-scout-parser.exe' : 'eth-call-scout-parser');

export function scanProject(inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0) throw new Error('Provide one or more source files or directories');
  let command;
  let args;
  if (fs.existsSync(RELEASE_BIN)) {
    command = RELEASE_BIN;
    args = inputs;
  } else if (fs.existsSync(DEBUG_BIN)) {
    command = DEBUG_BIN;
    args = inputs;
  } else {
    command = 'cargo';
    args = ['run', '--quiet', '--manifest-path', MANIFEST, '--', ...inputs];
  }
  const result = spawnSync(command, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error((result.stderr || `Rust scanner exited with status ${result.status}`).trim());
  try {
    const output = JSON.parse(result.stdout);
    if (!Array.isArray(output.findings) || !Number.isInteger(output.scanned_files)) throw new Error('Invalid output shape');
    return output;
  } catch (error) {
    throw new Error(`Rust scanner returned invalid JSON: ${error.message}`);
  }
}
