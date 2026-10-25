'use strict';
// Motor do WAF do Telvyn para Node: carrega o conjunto de regras (waf-rules.json), e cada requisição abre um
// contexto que acumula os dados das fases e avalia as regras cujos endereços chegaram. Os resultados trazem a regra e
// onde ela casou (endereço e caminho de chaves), nunca o valor recebido. Mesmo formato de regras do agent Java.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const VERSION = 'telvyn-waf/1.0.0';

class Timeout extends Error {}

// ---- Tempo ---------------------------------------------------------------------------------------------------------

function budget(timeoutUs) {
  const deadline = process.hrtime.bigint() + BigInt(Math.floor(timeoutUs)) * 1000n;
  return { check() { if (process.hrtime.bigint() > deadline) throw new Timeout(); } };
}

// ---- libinjection (WebAssembly, sem modificação) -----------------------------------------------------------------

const MAX_INPUT = 64 * 1024;
let injection;
function wasmModule() {
  if (injection) return injection;
  const instance = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(path.join(__dirname, 'libinjection.wasm'))), {});
  if (instance.exports._initialize) instance.exports._initialize();
  injection = instance.exports;
  return injection;
}
function injectionTest(name, value) {
  const wasm = wasmModule();
  const bytes = Buffer.from(value, 'utf8');
  if (!bytes.length) return false;
  const length = Math.min(bytes.length, MAX_INPUT);
  const pointer = wasm.tlv_alloc(length);
  if (!pointer) return false;
  try {
    new Uint8Array(wasm.memory.buffer, pointer, length).set(bytes.subarray(0, length));
    return wasm[name](pointer, length) === 1;
  } finally { wasm.tlv_free(pointer); }
}

// ---- Transformações ------------------------------------------------------------------------------------------------

function hex(value, from, length) {
  if (from + length > value.length) return -1;
  const slice = value.slice(from, from + length);
  return /^[0-9a-fA-F]+$/.test(slice) ? parseInt(slice, 16) : -1;
}

function urlDecode(value, unicode) {
  if (!value.includes('%') && !value.includes('+')) return value;
  let out = '';
  let bytes = [];
  const flush = () => { if (bytes.length) { out += Buffer.from(bytes).toString('utf8'); bytes = []; } };
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '%' && unicode && i + 5 < value.length && (value[i + 1] === 'u' || value[i + 1] === 'U') && hex(value, i + 2, 4) >= 0) {
      flush(); out += String.fromCharCode(hex(value, i + 2, 4)); i += 5;
    } else if (c === '%' && i + 2 < value.length && hex(value, i + 1, 2) >= 0) {
      bytes.push(hex(value, i + 1, 2)); i += 2;
    } else { flush(); out += c === '+' ? ' ' : c; }
  }
  flush();
  return out;
}

const NAMED_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ', colon: ':', lpar: '(', rpar: ')', sol: '/', tab: '\t', newline: '\n', grave: '`', equals: '=', bsol: '\\' };
function entity(text) {
  if (/^#[xX]/.test(text)) return text.length > 2 && /^[0-9a-fA-F]+$/.test(text.slice(2)) ? parseInt(text.slice(2), 16) : -1;
  if (text.startsWith('#')) return text.length > 1 && /^\d+$/.test(text.slice(1)) ? parseInt(text.slice(1), 10) : -1;
  const named = NAMED_ENTITIES[text.toLowerCase()];
  return named === undefined ? -1 : named.codePointAt(0);
}
function htmlEntityDecode(value) {
  if (!value.includes('&')) return value;
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c !== '&') { out += c; continue; }
    let end = i + 1;
    while (end < value.length && end - i <= 10 && /[\p{L}\p{N}#]/u.test(value[end])) end++;
    const code = entity(value.slice(i + 1, end));
    if (code < 0 || code > 0x10ffff) { out += c; continue; }
    out += String.fromCodePoint(code);
    i = end < value.length && value[end] === ';' ? end : end - 1;
  }
  return out;
}

const ESCAPES = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\u000b', a: '\u0007' };
function jsDecode(value) {
  if (!value.includes('\\')) return value;
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c !== '\\' || i + 1 >= value.length) { out += c; continue; }
    const next = value[i + 1];
    if (next === 'u' && hex(value, i + 2, 4) >= 0) { out += String.fromCharCode(hex(value, i + 2, 4)); i += 5; }
    else if (next === 'x' && hex(value, i + 2, 2) >= 0) { out += String.fromCharCode(hex(value, i + 2, 2)); i += 3; }
    else if (next >= '0' && next <= '7') {
      let end = i + 1, code = 0;
      while (end < value.length && end < i + 4 && value[end] >= '0' && value[end] <= '7') code = code * 8 + (value.charCodeAt(end++) - 48);
      out += String.fromCharCode(code); i = end - 1;
    } else { out += ESCAPES[next] ?? next; i++; }
  }
  return out;
}

function cssDecode(value) {
  if (!value.includes('\\')) return value;
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c !== '\\' || i + 1 >= value.length) { out += c; continue; }
    let end = i + 1;
    while (end < value.length && end < i + 7 && /[0-9a-fA-F]/.test(value[end])) end++;
    if (end === i + 1) { if (value[end] !== '\n') out += value[end]; i = end; continue; }
    out += String.fromCodePoint(Math.min(parseInt(value.slice(i + 1, end), 16), 0x10ffff));
    i = end < value.length && /\s/.test(value[end]) ? end : end - 1;
  }
  return out;
}

function base64Decode(value) {
  const clean = value.replace(/[^A-Za-z0-9+/=_-]/g, '');
  if (clean.length < 4) return value;
  // Alfabeto inválido, padding no meio ou sobra de um caractere: o texto fica como está (não é base64).
  const url = /[-_]/.test(clean);
  if (url && /[+/]/.test(clean)) return value;
  const body = clean.replace(/=+$/, '');
  if (body.includes('=') || body.length % 4 === 1) return value;
  return Buffer.from(body, url ? 'base64url' : 'base64').toString('utf8');
}

function normalizePath(value, windows) {
  const text = windows ? value.replace(/\\/g, '/') : value;
  if (!text.includes('/') && !text.includes('.')) return text;
  const parts = [];
  const absolute = text.startsWith('/'), trailing = text.endsWith('/');
  for (const part of text.split(/\/+/)) {
    if (!part || part === '.') continue;
    if (part === '..') { if (parts.length && parts[parts.length - 1] !== '..') parts.pop(); else if (!absolute) parts.push(part); }
    else parts.push(part);
  }
  const joined = parts.join('/');
  return (absolute ? '/' : '') + joined + (trailing && joined ? '/' : '');
}

function comments(value, replacement) {
  if (!value.includes('/*') && !value.includes('--') && !value.includes('#') && !value.includes('<!--')) return value;
  let out = '';
  for (let i = 0; i < value.length; i++) {
    if (value.startsWith('/*', i)) { const end = value.indexOf('*/', i + 2); out += replacement; if (end < 0) break; i = end + 1; }
    else if (value.startsWith('<!--', i)) { const end = value.indexOf('-->', i + 4); out += replacement; if (end < 0) break; i = end + 2; }
    else if (value.startsWith('--', i) || value[i] === '#') { const end = value.indexOf('\n', i); out += replacement; if (end < 0) break; i = end - 1; }
    else out += value[i];
  }
  return out;
}

function cmdLine(value) {
  let out = '', space = false;
  for (const c of value) {
    if (c === '\\' || c === '"' || c === "'" || c === '^') continue;
    if (' ,;\t\n\r'.includes(c)) { space = true; continue; }
    if (space && c !== '/' && c !== '(' && out.length) out += ' ';
    space = false;
    out += c.toLowerCase();
  }
  return out;
}

const TRANSFORMS = {
  lowercase: v => v.toLowerCase(),
  removeNulls: v => v.includes('\0') ? v.replace(/\0/g, '') : v,
  urlDecode: v => urlDecode(v, false),
  urlDecodeUni: v => urlDecode(v, true),
  htmlEntityDecode,
  jsDecode,
  cssDecode,
  base64Decode,
  compressWhitespace: v => v.replace(/[\s\u000b]+/g, ' '),
  removeWhitespace: v => v.replace(/[\s\u000b]+/g, ''),
  normalizePath: v => normalizePath(v, false),
  normalizePathWin: v => normalizePath(v, true),
  removeComments: v => comments(v, ''),
  replaceComments: v => comments(v, ' '),
  removeCommentsChar: v => v.replace(/\/\*/g, '').replace(/\*\//g, '').replace(/--/g, '').replace(/#/g, ''),
  cmdLine,
  unicode_normalize: v => v.normalize('NFKC'),
  escapeSeqDecode: jsDecode,
  utf8toUnicode: v => v,
  none: v => v,
};

// ---- Regex (PCRE -> JavaScript) ------------------------------------------------------------------------------------

// As regras vêm no dialeto PCRE do CRS: troca o que o JavaScript não aceita e mantém o resto.
function regex(source, caseSensitive) {
  let flags = caseSensitive ? '' : 'i';
  let text = source;
  const inline = /^\(\?([a-z]+)\)/.exec(text);
  if (inline) {
    text = text.slice(inline[0].length);
    if (inline[1].includes('i') && !flags.includes('i')) flags += 'i';
    if (inline[1].includes('s')) flags += 's';
    if (inline[1].includes('m')) flags += 'm';
  }
  text = text.replace(/\\A/g, '^').replace(/\\[Zz]/g, '$').replace(/\(\?>/g, '(?:').replace(/(?<!\\)([*+?}])\+/g, '$1').replace(/\\h/g, '[ \\t]').replace(/\\x\{([0-9a-fA-F]+)\}/g, '\\u{$1}');
  try { return new RegExp(text, flags + 'u'); }
  catch (_) {
    try { return new RegExp(text, flags); }
    catch (invalid) { throw new Error('invalid regex: ' + invalid.message); }
  }
}

// ---- Frases (Aho-Corasick) -----------------------------------------------------------------------------------------

class Phrases {
  constructor(list, wordBoundary) {
    this.wordBoundary = wordBoundary;
    this.root = { next: new Map(), fail: null, length: -1 };
    for (const phrase of list) {
      if (!phrase) continue;
      let node = this.root;
      for (const c of phrase.toLowerCase()) {
        if (!node.next.has(c)) node.next.set(c, { next: new Map(), fail: null, length: -1 });
        node = node.next.get(c);
      }
      node.length = Math.max(node.length, phrase.length);
    }
    const queue = [];
    for (const child of this.root.next.values()) { child.fail = this.root; queue.push(child); }
    while (queue.length) {
      const node = queue.shift();
      for (const [key, child] of node.next) {
        let fail = node.fail;
        while (fail && !fail.next.has(key)) fail = fail.fail;
        child.fail = fail ? fail.next.get(key) : this.root;
        queue.push(child);
      }
    }
  }

  find(text) {
    const lower = text.toLowerCase();
    let node = this.root;
    for (let i = 0; i < lower.length; i++) {
      const c = lower[i];
      while (node !== this.root && !node.next.has(c)) node = node.fail;
      node = node.next.get(c) || this.root;
      for (let at = node; at && at !== this.root; at = at.fail) {
        if (at.length < 0) continue;
        if (!this.wordBoundary || boundary(text, i - at.length + 1, i + 1)) return true;
      }
    }
    return false;
  }
}
const wordChar = c => /[\p{L}\p{N}_]/u.test(c);
function boundary(text, start, end) {
  return (start <= 0 || !wordChar(text[start - 1])) && (end >= text.length || !wordChar(text[end]));
}

// ---- Percurso dos valores ------------------------------------------------------------------------------------------

const cut = (text, limits) => text.length > limits.text ? text.slice(0, limits.text) : text;

// Visita as folhas de value seguindo keyPath; keys: visita as chaves dos mapas em vez dos valores.
// Devolve true se o visitante pediu para parar (achou).
function walk(value, keyPath, keys, limits, timer, visitor) {
  let start = value;
  const prefix = [];
  if (keyPath) for (const key of keyPath) {
    if (Array.isArray(start) && /^\d{1,6}$/.test(key) && Number(key) < start.length) { start = start[Number(key)]; prefix.push(Number(key)); }
    else if (start && typeof start === 'object' && !Array.isArray(start) && Object.hasOwn(start, key)) { start = start[key]; prefix.push(key); }
    else return false;
    if (start == null) return false;
  }
  const count = { n: 0 };
  const visit = (node, trail, depth) => {
    if (node == null || depth > limits.depth || ++count.n > limits.elements) return false;
    timer.check();
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (visit(node[i], [...trail, i], depth + 1)) return true;
        if (count.n > limits.elements) return false;
      }
      return false;
    }
    if (typeof node === 'object') {
      for (const [key, item] of Object.entries(node)) {
        const next = [...trail, key];
        if (keys && visitor(cut(key, limits), next)) return true;
        if (visit(item, next, depth + 1)) return true;
        if (count.n > limits.elements) return false;
      }
      return false;
    }
    if (keys) return false;
    return visitor(cut(String(node), limits), trail);
  };
  return visit(start, prefix, 0);
}

// ---- Operadores ----------------------------------------------------------------------------------------------------

function ipMatcher(list) {
  const toNumber = text => {
    const kind = net.isIP(text);
    if (!kind) return null;
    let bits;
    if (kind === 4) bits = text.split('.').reduce((n, part) => (n << 8n) | BigInt(part), 0n);
    else {
      const [head, tail = ''] = text.split('::');
      const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
      const groups = text.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
      bits = groups.reduce((n, group) => (n << 16n) | BigInt(parseInt(group || '0', 16)), 0n);
    }
    return { bits, size: kind === 4 ? 32 : 128 };
  };
  const ranges = list.map(item => {
    const [address, prefix] = item.split('/');
    const parsed = toNumber(address);
    if (!parsed) throw new Error('invalid ip ' + item);
    const length = prefix === undefined ? parsed.size : Number(prefix);
    return { size: parsed.size, length, network: parsed.bits >> BigInt(parsed.size - length) };
  });
  return value => {
    const parsed = toNumber(value.trim());
    if (!parsed) return false;
    return ranges.some(range => range.size === parsed.size && (parsed.bits >> BigInt(range.size - range.length)) === range.network);
  };
}

const EXPLOIT = new Set(['lfi_detector', 'ssrf_detector', 'sqli_detector', 'shi_detector', 'cmdi_detector']);

function compileOperator(name, parameters) {
  let operator = name.includes('@') ? name.slice(0, name.indexOf('@')) : name;
  const negated = operator.startsWith('!');
  if (negated) operator = operator.slice(1);
  const options = parameters.options || {};
  const minLength = Number.isInteger(options.min_length) ? options.min_length : 0;
  let test;
  switch (operator) {
    case 'match_regex': { const pattern = regex(parameters.regex, options.case_sensitive === true); test = value => value.length >= minLength && pattern.test(value); break; }
    case 'phrase_match': { const phrases = new Phrases(parameters.list || [], options.enforce_word_boundary === true); test = value => phrases.find(value); break; }
    case 'exact_match': { const list = new Set(parameters.list || []); test = value => list.has(value); break; }
    case 'ip_match': test = ipMatcher(parameters.list || []); break;
    case 'equals': { const expected = String(parameters.value).toLowerCase(); test = value => expected === value.toLowerCase(); break; }
    case 'greater_than': case 'lower_than': {
      const limit = Number(parameters.value), greater = operator === 'greater_than';
      test = value => { const parsed = Number(value.trim()); return value.trim() !== '' && Number.isFinite(parsed) && (greater ? parsed > limit : parsed < limit); };
      break;
    }
    case 'is_sqli': test = value => injectionTest('tlv_sqli', value); break;
    case 'is_xss': test = value => injectionTest('tlv_xss', value); break;
    default:
      if (EXPLOIT.has(operator)) return exploitOperator(operator);
      throw new Error('unknown operator ' + name);
  }
  return negated ? (condition, data, limits, timer) => negatedHit(condition, data, limits, timer, test)
    : (condition, data, limits, timer) => hit(condition, data, limits, timer, test);
}

function hit(condition, data, limits, timer, test) {
  for (const input of condition.inputs) {
    const value = data[input.address];
    if (value == null) continue;
    let found = null;
    walk(value, input.keyPath, input.keys, limits, timer, (text, trail) => {
      if (!test(applyTransforms(input.transforms, text))) return false;
      found = { address: input.address, keyPath: trail };
      return true;
    });
    if (found) return found;
  }
  return null;
}

// Negado: casa quando a entrada existe e nenhum valor dela satisfaz o teste.
function negatedHit(condition, data, limits, timer, test) {
  for (const input of condition.inputs) {
    const value = data[input.address];
    if (value == null) continue;
    let seen = false, any = false;
    walk(value, input.keyPath, input.keys, limits, timer, text => {
      seen = true;
      if (test(applyTransforms(input.transforms, text))) { any = true; return true; }
      return false;
    });
    if (seen && !any) return { address: input.address, keyPath: input.keyPath ? [...input.keyPath] : [] };
  }
  return null;
}

function exploitOperator(operator) {
  return (condition, data, limits, timer) => {
    for (const resource of condition.resource) {
      const operation = data[resource.address];
      if (operation == null) continue;
      const system = typeof data['server.db.system'] === 'string' ? data['server.db.system'].toLowerCase() : '';
      for (const input of condition.inputs) {
        const value = data[input.address];
        if (value == null) continue;
        let found = null;
        walk(value, input.keyPath, false, limits, timer, (text, trail) => {
          if (!detect(operator, operation, text, system)) return false;
          found = { address: input.address, keyPath: trail, resourceAddress: resource.address };
          return true;
        });
        if (found) return found;
      }
    }
    return null;
  };
}

function applyTransforms(chain, value) {
  for (const step of chain) value = step(value);
  return value;
}

// ---- Prevenção de exploit (RASP) -----------------------------------------------------------------------------------
// Um valor da requisição chegou a uma operação perigosa (arquivo, URL de saída, SQL, comando) e mudou a estrutura
// dela. Só conta quando o valor aparece inteiro na operação, e só quando altera o que a operação faz.

function detect(detector, operation, param, system) {
  if (typeof param !== 'string' || param.length < 3) return false;
  switch (detector) {
    case 'lfi_detector': return typeof operation === 'string' && lfi(operation, param);
    case 'ssrf_detector': return typeof operation === 'string' && ssrf(operation, param);
    case 'sqli_detector': return typeof operation === 'string' && sqli(operation, param, system);
    case 'shi_detector': return typeof operation === 'string' && shell(operation, param);
    case 'cmdi_detector': return command(operation, param);
    default: return false;
  }
}

function lfi(file, param) {
  const normalizedPath = file.replace(/\\/g, '/'), value = param.replace(/\\/g, '/');
  if (!normalizedPath.includes(value)) return false;
  if (value.includes('../') || value.endsWith('/..') || value === '..') return true;
  const absolute = value.startsWith('/') || /^[a-z]:\//i.test(value);
  return absolute && normalizedPath.startsWith(value) && value.indexOf('/', 1) > 0;
}

function ssrf(url, param) {
  const at = url.indexOf(param);
  if (at < 0) return false;
  const scheme = url.indexOf('://');
  if (scheme < 0) return false;
  const authorityStart = scheme + 3;
  let authorityEnd = authorityStart;
  while (authorityEnd < url.length && !'/?#'.includes(url[authorityEnd])) authorityEnd++;
  const end = at + param.length;
  if (at < authorityEnd && end > 0 && (at < authorityStart || end > authorityStart)) {
    const authority = url.slice(authorityStart, authorityEnd);
    return !(at > authorityStart && end <= authorityEnd && /^\.[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/.test(authority.slice(end - authorityStart))
      && !param.includes('.') && !param.includes('@') && !param.includes(':'));
  }
  const lower = param.toLowerCase();
  return lower.includes('://') || lower.startsWith('//') || lower.includes('@');
}

const KEYWORDS = new Set(['SELECT', 'UNION', 'ALL', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE', 'DROP', 'TABLE',
  'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'HAVING', 'GROUP', 'ORDER', 'BY', 'LIMIT', 'OFFSET', 'LIKE', 'IN', 'IS', 'NULL', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY',
  'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'JOIN', 'XOR', 'DIV', 'MOD', 'BETWEEN', 'INFORMATION_SCHEMA', 'PG_SLEEP', 'CAST', 'CONVERT', 'CHAR', 'CONCAT', 'SUBSTRING',
  'ASCII', 'TRUE', 'FALSE', 'TRUNCATE', 'GRANT', 'REVOKE', 'SHUTDOWN', 'LOAD_FILE', 'OUTFILE']);
const isLetter = c => /\p{L}/u.test(c), isDigit = c => c >= '0' && c <= '9', isAlnum = c => isLetter(c) || isDigit(c);

// Tokens: s literal, n número, w palavra, k palavra-chave, o operador, ; separador, c comentário, p pontuação.
function sqlTokens(sql, system) {
  const out = [];
  const backslash = system.includes('mysql') || system.includes('mariadb');
  const n = sql.length;
  let i = 0;
  while (i < n) {
    const c = sql[i];
    if (/\s/.test(c)) { i++; continue; }
    const start = i;
    if (c === "'" || c === '"' || c === '`') {
      i++;
      while (i < n) {
        const d = sql[i];
        if (backslash && d === '\\' && i + 1 < n) { i += 2; continue; }
        if (d === c) { if (i + 1 < n && sql[i + 1] === c) { i += 2; continue; } i++; break; }
        i++;
      }
      out.push({ start, end: i, kind: c === "'" ? 's' : 'w' });
    } else if ((c === '-' && sql[i + 1] === '-') || (c === '#' && backslash)) {
      while (i < n && sql[i] !== '\n') i++;
      out.push({ start, end: i, kind: 'c' });
    } else if (c === '/' && sql[i + 1] === '*') {
      const close = sql.indexOf('*/', i + 2);
      i = close < 0 ? n : close + 2;
      out.push({ start, end: i, kind: 'c' });
    } else if (isDigit(c) || (c === '.' && i + 1 < n && isDigit(sql[i + 1]))) {
      while (i < n && (isAlnum(sql[i]) || sql[i] === '.')) i++;
      out.push({ start, end: i, kind: 'n' });
    } else if (isLetter(c) || c === '_' || c === '@' || c === '$') {
      while (i < n && (isAlnum(sql[i]) || '_$@.'.includes(sql[i]))) i++;
      out.push({ start, end: i, kind: KEYWORDS.has(sql.slice(start, i).toUpperCase()) ? 'k' : 'w' });
    } else if (c === ';') { i++; out.push({ start, end: i, kind: ';' }); }
    else if ('=<>!|&+-*/%^~'.includes(c)) {
      while (i < n && '=<>!|&'.includes(sql[i]) && i - start < 3) i++;
      if (i === start) i++;
      out.push({ start, end: i, kind: 'o' });
    } else { i++; out.push({ start, end: i, kind: 'p' }); }
  }
  return out;
}

// O valor ocupa mais de um token do SQL, ou abre/fecha um literal: ele escreveu SQL, não um dado.
function sqli(sql, param, system) {
  let at = sql.indexOf(param);
  if (at < 0) return false;
  const tokens = sqlTokens(sql, system);
  while (at >= 0) {
    const end = at + param.length;
    const touched = tokens.filter(token => token.end > at && token.start < end);
    let structure = false;
    for (const token of touched) {
      if (token.kind === 's' && (at <= token.start || end >= token.end)) structure = true;
      if ('ko;c'.includes(token.kind) && touched.length > 1) structure = true;
    }
    if (structure) return true;
    at = sql.indexOf(param, at + 1);
  }
  return false;
}

// Comando de shell: o valor traz operador do shell fora de aspas, ou vira mais de uma palavra do comando.
function shell(commandLine, param) {
  let at = commandLine.indexOf(param);
  while (at >= 0) {
    const end = at + param.length;
    let quote = '', operator = false, words = 0, inWord = false;
    for (let i = 0; i < end; i++) {
      const c = commandLine[i];
      const inside = i >= at;
      if (quote) {
        if (c === quote) quote = '';
        else if (quote === '"' && inside && (c === '`' || (c === '$' && i + 1 < end && commandLine[i + 1] === '('))) operator = true;
        continue;
      }
      if (c === "'" || c === '"') { quote = c; if (inside && !inWord) { words++; inWord = true; } continue; }
      if (inside && (';|&`\n<>'.includes(c) || (c === '$' && i + 1 < end && commandLine[i + 1] === '('))) operator = true;
      if (/\s/.test(c)) inWord = false;
      else if (inside && !inWord) { words++; inWord = true; }
      else if (!inside) inWord = true;
    }
    if (operator || words > 1) return true;
    at = commandLine.indexOf(param, at + 1);
  }
  return false;
}

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'ash', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh']);
const SHELL_FLAGS = new Set(['-c', '/c', '-command', '/k']);
function command(operation, param) {
  const argv = Array.isArray(operation) ? operation.map(String) : typeof operation === 'string' ? [operation] : [];
  if (!argv.length) return false;
  const executable = argv[0];
  if (executable === param || executable.endsWith('/' + param) || executable.endsWith('\\' + param)) return true;
  const name = executable.slice(Math.max(executable.lastIndexOf('/'), executable.lastIndexOf('\\')) + 1).toLowerCase();
  if (SHELLS.has(name)) for (let i = 1; i + 1 < argv.length; i++) if (SHELL_FLAGS.has(argv[i].toLowerCase())) return shell(argv[i + 1], param);
  return false;
}

// ---- Esquema da API ------------------------------------------------------------------------------------------------
// Esquema de cada parte da requisição e da resposta (tipos, nunca valores), com os campos sensíveis marcados pelos
// scanners. Codificação: escalar [tipo] (1 nulo, 2 booleano, 4 inteiro, 8 texto, 16 decimal), mapa [{chave: esquema}],
// lista [[esquemas dos itens], {"len": n}] e a marca do scanner como segundo item {"category", "type"}.

const MAX_DEPTH = 18, MAX_KEYS = 256, MAX_ITEMS = 10;

function luhn(text) {
  let sum = 0, digits = 0, twice = false;
  for (let i = text.length - 1; i >= 0; i--) {
    const c = text[i];
    if (c === ' ' || c === '-') continue;
    if (c < '0' || c > '9') return false;
    let digit = c.charCodeAt(0) - 48;
    if (twice && (digit *= 2) > 9) digit -= 9;
    sum += digit; twice = !twice; digits++;
  }
  return digits >= 9 && sum % 10 === 0;
}

function iban(text) {
  const clean = text.replace(/ /g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  let remainder = 0;
  for (const c of clean.slice(4) + clean.slice(0, 4)) {
    const value = c >= '0' && c <= '9' ? c.charCodeAt(0) - 48 : c >= 'A' && c <= 'Z' ? c.charCodeAt(0) - 55 : -1;
    if (value < 0) return false;
    remainder = (remainder * (value >= 10 ? 100 : 10) + value) % 97;
  }
  return remainder === 1;
}

function loadSchemas(rawScanners, config) {
  const scanners = (rawScanners || []).map(scanner => ({
    category: scanner.tags.category, type: scanner.tags.type,
    key: scanner.key ? regex(scanner.key.regex, false) : null,
    value: scanner.value ? regex(scanner.value.regex, scanner.value.case_sensitive === true) : null,
    minLength: scanner.value && Number.isInteger(scanner.value.min_length) ? scanner.value.min_length : 0,
    validator: scanner.value ? scanner.value.validator : null,
  }));
  const mappings = ((config && config.mappings) || []).map(mapping => ({ address: mapping.address, output: mapping.output, categories: new Set(mapping.scanners || []) }));
  const scan = (key, value, categories) => {
    for (const scanner of scanners) {
      if (!categories.has(scanner.category)) continue;
      if (scanner.key && (key == null || !scanner.key.test(key))) continue;
      if (scanner.value) {
        if (value == null || value.length < scanner.minLength || !scanner.value.test(value)) continue;
        if (scanner.validator === 'luhn' && !luhn(value)) continue;
        if (scanner.validator === 'iban' && !iban(value)) continue;
      }
      return scanner;
    }
    return null;
  };
  const schema = (value, key, categories, depth, timer) => {
    timer.check();
    if (depth > MAX_DEPTH) return [0];
    if (Array.isArray(value)) {
      const kinds = [];
      for (const item of value) {
        const kind = schema(item, key, categories, depth + 1, timer);
        const encoded = JSON.stringify(kind);
        if (!kinds.some(known => JSON.stringify(known) === encoded)) kinds.push(kind);
        if (kinds.length >= MAX_ITEMS) break;
      }
      return [kinds, { len: value.length }];
    }
    if (value && typeof value === 'object') {
      const fields = {};
      let count = 0;
      for (const [name, item] of Object.entries(value)) {
        if (count++ >= MAX_KEYS) break;
        fields[name] = schema(item, name, categories, depth + 1, timer);
      }
      return [fields];
    }
    const type = value == null ? 1 : typeof value === 'boolean' ? 2 : typeof value === 'number' ? (Number.isInteger(value) ? 4 : 16) : typeof value === 'bigint' ? 4 : 8;
    const match = scan(key, value == null ? null : String(value), categories);
    return match ? [type, { category: match.category, type: match.type }] : [type];
  };
  return (data, timer) => {
    const out = {};
    for (const mapping of mappings) {
      const value = data[mapping.address];
      if (value == null) continue;
      out['schema.' + mapping.output] = schema(value, null, mapping.categories, 0, timer);
    }
    return out;
  };
}

// ---- Motor ---------------------------------------------------------------------------------------------------------

function inputs(raw, keys, ruleTransforms) {
  if (!Array.isArray(raw)) return [];
  return raw.map(input => {
    let selectKeys = keys, transforms = ruleTransforms;
    if (Array.isArray(input.transformers)) {
      transforms = [];
      for (const name of input.transformers) {
        if (name === 'keys_only') { selectKeys = true; continue; }
        if (name === 'values_only') { selectKeys = false; continue; }
        if (!TRANSFORMS[name]) throw new Error('unknown transformer ' + name);
        transforms.push(TRANSFORMS[name]);
      }
    }
    return { address: input.address, keyPath: Array.isArray(input.key_path) ? input.key_path.map(String) : null, keys: selectKeys, transforms };
  });
}

function compileRule(rule) {
  const transforms = [];
  let keys = false;
  for (const name of rule.transformers || []) {
    if (name === 'keys_only') { keys = true; continue; }
    if (name === 'values_only') continue;
    if (!TRANSFORMS[name]) throw new Error('unknown transformer ' + name);
    transforms.push(TRANSFORMS[name]);
  }
  const addresses = new Set();
  const conditions = (rule.conditions || []).map(condition => {
    const parameters = condition.parameters || {};
    const own = inputs(parameters.params ?? parameters.inputs, keys, transforms);
    const resource = inputs(parameters.resource, false, []);
    for (const item of resource) addresses.add(item.address);
    // Detector de exploit avalia quando a operação (resource) chega; a regra comum, quando chega a entrada.
    if (!resource.length) for (const item of own) addresses.add(item.address);
    return { operator: condition.operator, inputs: own, resource, test: compileOperator(condition.operator, parameters) };
  });
  if (!conditions.length) throw new Error('no conditions');
  return { id: rule.id, name: rule.name || '', tags: rule.tags || {}, conditions, actions: rule.on_match || [], addresses };
}

class Context {
  constructor(waf) { this.waf = waf; this.data = {}; this.matched = new Set(); this.closed = false; }

  // Avalia o que chegou nesta fase. ephemeral: dados de uma operação (exploit prevention), que valem só nesta chamada.
  run({ persistent, ephemeral } = {}, timeoutUs = 10000, limits = this.waf.limits) {
    const phase = ephemeral || persistent || {};
    const isEphemeral = !!ephemeral;
    const timer = budget(timeoutUs);
    let view = this.data;
    if (isEphemeral) view = { ...this.data, ...phase };
    else Object.assign(this.data, phase);
    const candidates = new Set();
    for (const address of Object.keys(phase)) for (const rule of this.waf.byAddress.get(address) || []) candidates.add(rule);
    const events = [];
    try {
      for (const rule of candidates) {
        if (!isEphemeral && this.matched.has(rule.id)) continue;
        const hits = [];
        let all = true;
        for (const condition of rule.conditions) {
          const found = condition.test(condition, view, limits, timer);
          if (!found) { all = false; break; }
          hits.push(found);
        }
        if (!all) continue;
        if (!isEphemeral) this.matched.add(rule.id);
        events.push(event(rule, hits));
      }
      let derivatives;
      const processor = phase['waf.context.processor'];
      if (processor && processor['extract-schema'] === true) derivatives = this.waf.schemas(view, timer);
      return { timeout: false, events, derivatives };
    } catch (failure) {
      if (failure instanceof Timeout) return { timeout: true, events };
      throw failure;
    }
  }

  dispose() { this.closed = true; this.data = {}; }
}

function event(rule, hits) {
  const matches = hits.map((found, index) => {
    const keyPath = (found.keyPath || []).map(String);
    const parameter = found.resourceAddress
      ? { resource: { address: found.resourceAddress }, params: { address: found.address, key_path: keyPath } }
      : { address: found.address, key_path: keyPath };
    return { operator: rule.conditions[index].operator, parameters: [parameter] };
  });
  return { rule: { id: rule.id, name: rule.name, tags: rule.tags, on_match: rule.actions }, rule_matches: matches };
}

class Waf {
  // Compila o conjunto de regras; regra inválida falha a carga inteira (não sobe WAF pela metade).
  constructor(document, limits = { depth: 20, elements: 256, text: 4096 }) {
    this.limits = limits;
    this.byAddress = new Map();
    this.rules = [];
    const ids = new Set();
    for (const rule of document.rules || []) {
      if (rule.enabled === false) continue;
      if (!rule.id || ids.has(rule.id)) throw new Error('rule without id or duplicated: ' + rule.id);
      ids.add(rule.id);
      let compiled;
      try { compiled = compileRule(rule); } catch (invalid) { throw new Error(`invalid rule ${rule.id}: ${invalid.message}`); }
      this.rules.push(compiled);
      for (const address of compiled.addresses) {
        if (!this.byAddress.has(address)) this.byAddress.set(address, []);
        this.byAddress.get(address).push(compiled);
      }
    }
    if (!this.rules.length) throw new Error('no rules');
    this.schemas = loadSchemas(document.scanners, document.schemas);
    this.rulesVersion = String((document.metadata && document.metadata.rules_version) || 'unknown');
    this.warmUp();
  }

  // As primeiras execuções com o motor frio (módulo WebAssembly, regex e JIT) estouram o limite de tempo: aquece com
  // dados típicos, sem ataque, e com prazo folgado.
  warmUp() {
    const typical = {
      'server.request.headers.no_cookies': { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64)', accept: 'application/json', host: 'app.example.com' },
      'server.request.query': { page: ['2'], q: ['monitoramento de redes'] },
      'server.request.uri.raw': '/api/hosts?page=2&q=monitoramento+de+redes',
      'server.request.method': 'GET',
      'server.request.body': { name: 'João da Silva', note: 'Troca de equipamento na sexta-feira' },
    };
    for (let i = 0; i < 20; i++) {
      const context = this.createContext();
      context.run({ persistent: typical }, 2000000);
      context.dispose();
    }
  }

  createContext() { return new Context(this); }
  dispose() {}
  static version() { return VERSION; }
}

module.exports = { Waf, detect, injectionTest };
