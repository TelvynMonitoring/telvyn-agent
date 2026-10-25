'use strict';
// Original position of a line of compiled code (TypeScript and similar), read from the map the file points to.
// Positions are 1-based on both sides. Nothing is returned when the file has no usable map.
const fs = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');

const MAX_SOURCE = 16 * 1024 * 1024, MAX_MAP = 32 * 1024 * 1024, MAX_FILES = 2000;
const maps = new Map();

function readMap(file) {
  const { SourceMap } = require('node:module');
  if (typeof SourceMap !== 'function') return null;
  const stat = fs.statSync(file);
  if (stat.size > MAX_SOURCE) return null;
  // The reference is a comment at the end of the file.
  const source = fs.readFileSync(file, 'utf8');
  const found = [...source.slice(-4096).matchAll(/^\s*\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/gm)].pop();
  if (!found) return null;
  const reference = found[1];
  let text;
  if (reference.startsWith('data:')) {
    const comma = reference.indexOf(',');
    if (comma < 0) return null;
    const body = reference.slice(comma + 1);
    text = /;base64$/.test(reference.slice(0, comma)) ? Buffer.from(body, 'base64').toString('utf8') : decodeURIComponent(body);
  } else {
    const mapFile = reference.startsWith('file:') ? fileURLToPath(reference) : path.resolve(path.dirname(file), decodeURIComponent(reference));
    if (fs.statSync(mapFile).size > MAX_MAP) return null;
    text = fs.readFileSync(mapFile, 'utf8');
  }
  const payload = JSON.parse(text);
  return { map: new SourceMap(payload), root: payload.sourceRoot || '', dir: path.dirname(file) };
}

function mapOf(file) {
  if (maps.has(file)) return maps.get(file);
  let entry = null;
  try { entry = readMap(file); } catch (_) { /* no map, or an unreadable one */ }
  if (maps.size >= MAX_FILES) maps.clear();
  maps.set(file, entry);
  return entry;
}

function originalPosition(file, line, column) {
  if (!path.isAbsolute(file) || !(line >= 1)) return null;
  const entry = mapOf(file);
  if (!entry) return null;
  try {
    const mapped = entry.map.findEntry(line - 1, Math.max(0, (column || 1) - 1));
    if (!mapped || typeof mapped.originalSource !== 'string' || !(mapped.originalLine >= 0)) return null;
    const source = mapped.originalSource;
    const original = source.startsWith('file:') ? fileURLToPath(source) : path.resolve(entry.dir, entry.root, source);
    return { path: original, line: mapped.originalLine + 1, column: mapped.originalColumn + 1 };
  } catch (_) { return null; }
}

// Same answer as originalPosition, falling back to the compiled position itself.
function locate(file, line, column) {
  return originalPosition(file, line, column) ?? { path: file, line, column };
}

module.exports = { originalPosition, locate };
