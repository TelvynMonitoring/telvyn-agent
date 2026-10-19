'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { Server } = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { compileRoutes } = require('./routes.cjs');
const rewriterMethods = [{src: 'plusOperator', operator: true}, {src: 'tplOperator', operator: true},
  ...['concat', 'slice', 'substring', 'substr', 'trim', 'trimEnd', 'replace'].map(src => ({src})),
  {src: 'toUpperCase', dst: 'stringCase'}, {src: 'toLowerCase', dst: 'stringCase'}];

// The rewriter only instruments code inside a function with a block body, where it declares its temporaries. An arrow
// with an expression body outside any such function (`app.get('/x', (req, res) => db.query('...' + req.query.q))` at
// module level) is left as is, so its operations lose the mark. Those bodies get braces first: `{ return <body> }`.
// Text is only inserted, never a line break, so lines stay where they were; if the source does not parse, it is unchanged.
function blockTopLevelArrows(source, sourceType) {
  if (!source.includes('=>')) return source;
  let tree;
  try {
    tree = require('acorn').parse(source, {ecmaVersion: 'latest', sourceType, preserveParens: true, allowHashBang: true,
      allowReturnOutsideFunction: sourceType === 'script', allowAwaitOutsideFunction: true});
  } catch (_) { return source; }
  const bodies = [];
  (function visit(node, enclosed) {
    const expressionArrow = node.type === 'ArrowFunctionExpression' && node.expression;
    if (expressionArrow && !enclosed) bodies.push(node.body);
    const inside = enclosed || expressionArrow || (/Function/.test(node.type) && node.body?.type === 'BlockStatement');
    for (const key of Object.keys(node)) {
      const value = node[key];
      for (const child of Array.isArray(value) ? value : [value]) if (child && typeof child.type === 'string') visit(child, inside);
    }
  })(tree, false);
  let code = source;
  for (const {start, end} of bodies.sort((a, b) => b.start - a.start)) code = code.slice(0, start) + '{ return ' + code.slice(start, end) + ' }' + code.slice(end);
  return code;
}

function startIast(report) {
  if (process.env.TELVYN_IAST_ENABLED !== 'true') return { state: 'disabled', request() {}, stop() {} };
  const root = process.env.TELVYN_PROFILE_SOURCE_ROOT;
  const routes = compileRoutes(process.env.TELVYN_SECURITY_ROUTES);
  if (!root || !routes.size || globalThis._ddiast) throw new Error('IAST requires a source root, selected routes and an available instrumentation context');
  const sourceRoot = path.resolve(root);
  const native = require('@datadog/native-iast-taint-tracking');
  // The native package has a no-op fallback: verify loading before claiming coverage.
  const check = randomUUID();
  native.createTransaction(check);
  const works = native.isTainted(check, native.newTaintedString(check, 'telvyn-startup-check', 'q', 'query'));
  native.removeTransaction(check);
  if (!works) throw new Error('Native taint tracking unavailable');
  const { Rewriter } = require('@datadog/wasm-js-rewriter');
  const { cacheRewrittenSourceMap, getSourcePathAndLineFromSourceMaps } = require('@datadog/wasm-js-rewriter/js/source-map');
  const rewriter = new Rewriter({csiMethods: rewriterMethods, literals: true, chainSourceMap: true});
  if (!rewriter.rewrite('function check(a){return a+"x"}', '/check.cjs', ['iast']).content?.includes('_ddiast.plusOperator')) throw new Error('IAST rewriter unavailable');
  const storage = new AsyncLocalStorage();
  const active = new Set();
  let stopped = false;
  function propagate(operation, result, ...args) {
    const request = storage.getStore();
    if (!request || !active.has(request.id) || typeof result !== 'string') return result;
    try { return native[operation](request.id, result, ...args); }
    catch (_) { return result; }
  }
  const hooks = {
    plusOperator: (result, ...args) => propagate('concat', result, ...args),
    tplOperator: (result, ...args) => propagate('concat', result, ...args),
    stringCase: (result, fn, subject) => fn === String.prototype.toUpperCase || fn === String.prototype.toLowerCase ? propagate('stringCase', result, subject) : result,
  };
  for (const name of ['concat', 'slice', 'substring', 'substr', 'trim', 'trimEnd', 'replace']) {
    const original = String.prototype[name];
    hooks[name] = (result, fn, subject, ...args) => fn === original && typeof subject === 'string' ? propagate(name, result, subject, ...args) : result;
  }
  globalThis._ddiast = hooks;
  const originalCompile = Module.prototype._compile;
  // Every input of a selected route is marked with where it came from; only the name of the field is ever reported.
  const SOURCE_TYPES = new Set(['query', 'body', 'header', 'cookie', 'path']);
  const label = name => String(name).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 64) || 'value';
  const control = /[\u0000-\u001f\u007f]/g;
  // String, quoted-identifier, comment, dollar-quoted and numeric literals; an unterminated literal masks to the end.
  const sqlLiteral = /'(?:[^']|'')*(?:'|$)|"(?:[^"]|"")*(?:"|$)|\/\*[\s\S]*?(?:\*\/|$)|--[^\n]*|\$([A-Za-z_]*)\$[\s\S]*?(?:\$\1\$|$)|(?<![\w$])(?:0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)(?!\w)/gi;
  // Values never leave the application: keeps the statement structure and hides every literal.
  function maskSql(sql) {
    return sql.slice(0, 4096).replace(sqlLiteral, match => match[0] === "'" ? "'<redacted>'" : match[0] === '"' ? '"<redacted>"'
      : match.startsWith('/*') || match.startsWith('--') ? '/* <redacted> */' : /^\$[A-Za-z_]*\$/.test(match) ? '$$<redacted>$$' : '<redacted>').replace(control, ' ').slice(0, 2000);
  }
  // The path is the selected route, so a route parameter never reaches the report.
  function requestInfo(request, route) {
    const text = (value, max) => typeof value === 'string' ? value.replace(control, '').slice(0, max) : undefined;
    const agent = request.headers?.['user-agent'];
    return {method: /^[A-Z]{1,20}$/.test(request.method || '') ? request.method : undefined, path: text(route, 1024), userAgent: text(Array.isArray(agent) ? agent[0] : agent, 512)};
  }
  // Compiled code is what runs and is rewritten; reports name the original source when a source map says so (TypeScript).
  const COMPILED_FILE = /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:js|cjs|mjs)$/;
  const SOURCE_FILE = /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:js|cjs|mjs|jsx|ts|tsx|mts|cts)$/;
  function relativeFile(filename, pattern = SOURCE_FILE) {
    if (filename.startsWith('file:')) filename = fileURLToPath(filename);
    const relative = path.relative(sourceRoot, filename).split(path.sep).join('/');
    return relative && !relative.split('/').some(part => part === '..' || part === 'node_modules') && pattern.test(relative) ? relative : null;
  }
  // Application frames by relative path, libraries by package path, Node internals as reported; never absolute paths.
  function stackFrames(stack) {
    const frames = [];
    for (const line of stack.split('\n')) {
      const match = line.match(/^\s*at (?:(.*?) \()?([^()]+):(\d+):(\d+)\)?$/);
      if (!match) continue;
      let file = match[2];
      try { if (file.startsWith('file:')) file = fileURLToPath(file); } catch (_) { continue; }
      if (file.startsWith(__dirname)) continue;
      let application = relativeFile(file);
      let row = match[3];
      // Application code is rewritten by the IAST, so its lines go back through the source map like the finding's line.
      if (application) {
        try {
          const mapped = getSourcePathAndLineFromSourceMaps(file, Number(match[3]), Number(match[4]));
          row = String(mapped.line);
          application = relativeFile(mapped.path) || application;
        } catch (_) { /* keep the reported line */ }
      }
      // Windows paths use backslashes: compare with forward slashes.
      const posix = file.split(path.sep).join('/');
      const shown = application || (file.startsWith('node:') ? file : posix.includes('/node_modules/') ? 'node_modules/' + posix.split('/node_modules/').pop() : '(externo)');
      frames.push(`${(match[1] || 'anonymous').replace(control, '').slice(0, 120)} (${shown}:${row})`);
      if (frames.length >= 64) break;
    }
    return frames;
  }
  // Hardcoded credentials, judged when the module loads. The literal is only read here: the finding names the file and the line, never the value.
  const SECRET_FORMATS = [/^(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$/, /^(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})$/, /^xox[abprs]-[A-Za-z0-9-]{10,}$/,
    /^[sr]k_live_[A-Za-z0-9]{16,}$/, /^AIza[0-9A-Za-z_-]{35}$/, /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/, /^npm_[A-Za-z0-9]{36}$/, /^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/];
  // The name says it is a password: the word itself, or pass/pwd as a whole word once camelCase, _ and - are split.
  const passwordName = ident => /password|passwd/i.test(ident) || /\b(?:pass|passphrase|pwd)\b/i.test(ident.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_.-]+/g, ' '));
  const PLACEHOLDER = /^(?:\*+|x+|\.+|-+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[sd]|changeme|change[-_ ]me|password|passwd|your[-_ ]?password|example|sample|test|secret|placeholder|null|none|undefined)$/i;
  function entropy(text) {
    const counts = new Map();
    for (const character of text) counts.set(character, (counts.get(character) || 0) + 1);
    let bits = 0;
    for (const count of counts.values()) { const share = count / text.length; bits -= share * Math.log2(share); }
    return bits;
  }
  function inspectLiterals({literals}, filename) {
    const file = relativeFile(filename, COMPILED_FILE);
    if (!file || stopped || !Array.isArray(literals)) return;
    let found = 0;
    for (const {value, locations} of literals) {
      if (typeof value !== 'string' || value.length < 8 || value.length > 4096) continue;
      const secret = SECRET_FORMATS.some(format => format.test(value));
      for (const {ident, line} of locations || []) {
        // A password is a literal whose variable or property name says so; placeholders and low-variety text are not.
        const password = !secret && typeof ident === 'string' && passwordName(ident) && value.length <= 256 && !/\s/.test(value) && !PLACEHOLDER.test(value) && entropy(value) >= 2.5;
        if (!secret && !password || !(line >= 1) || found >= 32) continue;
        found++;
        report({rule_id: secret ? 'HARDCODED_SECRET' : 'HARDCODED_PASSWORD', code_method: `${file}#module`, code_line: line}, 0);
      }
    }
  }
  Module.prototype._compile = function (source, filename) {
    let code = source;
    if (!stopped && relativeFile(filename, COMPILED_FILE)) {
      try {
        const result = rewriter.rewrite(blockTopLevelArrows(source, 'script'), filename, ['iast']);
        code = result.content || source;
        if (code !== source) cacheRewrittenSourceMap(filename, code);
        if (result.literalsResult) inspectLiterals(result.literalsResult, filename);
      }
      catch (_) { console.warn('[Telvyn] IAST could not instrument an application module.'); }
    }
    return originalCompile.call(this, code, filename);
  };
  const emit = Server.prototype.emit;
  Server.prototype.emit = function (event, request, response, ...rest) {
    const route = stopped || event !== 'request' || active.size >= 32 ? null : routes.match(request.url?.split('?')[0]);
    if (!route) return emit.call(this, event, request, response, ...rest);
    wrapOutgoing();
    const scope = {id: randomUUID(), reported: new Set(), request: requestInfo(request, route)};
    try { native.createTransaction(scope.id); active.add(scope.id); scopes.set(request, scope); }
    catch (_) { return emit.call(this, event, request, response, ...rest); }
    markHeaders(scope, request);
    const cleanup = () => {
      clearTimeout(timer);
      if (active.delete(scope.id)) {
        try { native.removeTransaction(scope.id); }
        catch (_) { console.warn('[Telvyn] IAST transaction cleanup failed.'); }
      }
    };
    const timer = setTimeout(cleanup, 60000); timer.unref();
    response.once('finish', cleanup); response.once('close', cleanup);
    return storage.run(scope, () => emit.call(this, event, request, response, ...rest));
  };
  // The request scope is looked up by request: asynchronous body parsing can run outside the stored context.
  const scopes = new WeakMap();
  function taint(value, type, name, scope = storage.getStore()) {
    if (!scope || !active.has(scope.id) || typeof value !== 'string' || !value.length || value.length > 4096) return value;
    try { return native.newTaintedString(scope.id, value, label(name), type); } catch (_) { return value; }
  }
  // Strings, arrays and plain objects (parsed bodies, queries, parameters, cookies) are marked in place, leaf by leaf.
  const marked = new WeakMap();
  function mark(value, type, name, scope, budget = {left: 256}, depth = 0) {
    if (typeof value === 'string') return budget.left-- > 0 ? taint(value, type, name, scope) : value;
    if (!value || typeof value !== 'object' || depth > 5 || marked.has(value)) return value;
    // Plain data only; Fastify's null-object classes (query, params) carry nothing but `constructor`.
    const prototype = Object.getPrototypeOf(value);
    const plain = prototype === null || prototype === Object.prototype || (Object.getPrototypeOf(prototype) === null && Object.getOwnPropertyNames(prototype).every(key => key === 'constructor'));
    if (!Array.isArray(value) && !plain) return value;
    marked.set(value, {type, name: label(name)});
    for (const key of Object.keys(value)) {
      try {
        const child = value[key], next = Array.isArray(value) ? name : depth ? `${name}.${key}` : key;
        if (typeof child === 'string') value[key] = mark(child, type, next, scope, budget, depth + 1);
        else mark(child, type, next, scope, budget, depth + 1);
      } catch (_) { /* frozen or accessor-only: left untouched */ }
    }
    return value;
  }
  function markHeaders(scope, request) {
    try { mark(request.headers, 'header', '', scope); } catch (_) { /* headers stay unmarked */ }
  }
  const get = URLSearchParams.prototype.get, getAll = URLSearchParams.prototype.getAll;
  URLSearchParams.prototype.get = function (name) { return taint(get.call(this, name), 'query', name); };
  URLSearchParams.prototype.getAll = function (name) { return getAll.call(this, name).map(value => taint(value, 'query', name)); };
  // The first source that reached the value: where it came from, never what it was.
  function sourceOf(scope, value) {
    try {
      const info = native.getRanges(scope.id, value)?.[0]?.iinfo;
      return info && SOURCE_TYPES.has(info.type) ? {type: info.type, name: label(info.parameterName)} : null;
    } catch (_) { return null; }
  }
  // One reporting path for every sink: a finding exists when a value derived from a request input reaches the sink call.
  function inspectSink(rule, sink, values, statement, header) {
    const scope = storage.getStore();
    if (stopped || !scope || !active.has(scope.id)) return;
    const started = process.hrtime.bigint();
    try {
      const value = values.find(item => typeof item === 'string' && native.isTainted(scope.id, item));
      if (value === undefined) return;
      const source = sourceOf(scope, value);
      // Echoing a request header under the same name is the usual proxy behaviour, not an injection.
      if (header && source?.type === 'header' && source.name === label(header)) return;
      reportAt(scope, rule, sink, started, new Error().stack || '', statement, source);
    } catch (_) { console.warn('[Telvyn] IAST finding could not be reported.'); }
  }
  // The finding is placed at the first application frame of the stack; one report per rule and code line per request.
  function reportAt(scope, rule, sink, started, stack, statement, source) {
    const location = stack.split('\n').map(line => line.match(/^\s*at (?:(.*?) \()?([^()]+):(\d+):(\d+)\)?$/)).find(match => match && relativeFile(match[2]));
    if (!location) return;
    const filename = location[2].startsWith('file:') ? fileURLToPath(location[2]) : location[2];
    const mapped = getSourcePathAndLineFromSourceMaps(filename, Number(location[3]), Number(location[4]));
    const file = relativeFile(mapped.path);
    const method = (location[1] || 'anonymous').replace(/[^\w$]/g, '_');
    const key = `${rule}:${file}:${mapped.line}`;
    if (file && !scope.reported.has(key) && scope.reported.size < 8) {
      scope.reported.add(key);
      report({rule_id: rule, code_method: `${file}#${method}`, code_line: mapped.line, sink, ...(statement === undefined ? {} : {sql: maskSql(statement)}), stack: stackFrames(stack), source: source ? `${source.type}:${source.name}` : undefined, request_method: scope.request.method, request_path: scope.request.path, user_agent: scope.request.userAgent}, Number((process.hrtime.bigint() - started) / 1000n));
    }
  }
  // Findings that need no input: the unsafe call itself. Only inside a request of a selected route, like every other finding.
  // `direct`: the unsafe call must come from application code itself; a library using a weak algorithm internally
  // (Express computes ETags with SHA-1) is not the application's finding. Only the agent's own files are skipped: its
  // dependencies are libraries too (OpenTelemetry draws span ids with Math.random while the application calls a driver).
  function inspectFlaw(rule, sink, direct = false) {
    const scope = storage.getStore();
    if (stopped || !scope || !active.has(scope.id)) return;
    try {
      const stack = new Error().stack || '';
      if (direct) {
        const caller = stack.split('\n').slice(1).map(line => line.match(/^\s*at (?:(.*?) \()?([^()]+):(\d+):(\d+)\)?$/)).find(match => match && !match[2].startsWith('node:') && !(match[2].startsWith(__dirname) && !match[2].includes('node_modules')));
        if (!caller || !relativeFile(caller[2].startsWith('file:') ? fileURLToPath(caller[2]) : caller[2])) return;
      }
      reportAt(scope, rule, sink, process.hrtime.bigint(), stack);
    } catch (_) { console.warn('[Telvyn] IAST finding could not be reported.'); }
  }
  const patched = new WeakMap();
  function patchQuery(prototype, driver, methods = ['query']) {
    if (!prototype) return;
    if (!patched.has(prototype)) patched.set(prototype, new Set());
    const done = patched.get(prototype);
    for (const method of methods) {
      if (done.has(method) || typeof prototype[method] !== 'function') continue;
      done.add(method);
      const query = prototype[method];
      const wrapper = function (...args) {
        // pg takes `text`, mysql2 and mysql take `sql`, sequelize takes `query`.
        const sql = typeof args[0] === 'string' ? args[0] : args[0]?.text ?? args[0]?.sql ?? args[0]?.query;
        if (typeof sql === 'string') inspectSink('SQL_INJECTION', `${driver}.${method}`, [sql], sql);
        return query.apply(this, args);
      };
      // OpenTelemetry wraps pg twice (pg/lib/client.js, then pg), unwrapping its own layer first. Over a wrapped
      // method this one keeps the same markers, and unwrapping puts the check back on the original: one span per query.
      if (query.__wrapped === true && typeof query.__original === 'function') {
        Object.assign(wrapper, {__wrapped: true, __original: query.__original, __unwrap() {
          done.delete(method);
          prototype[method] = query.__original;
          patchQuery(prototype, driver, [method]);
        }});
      }
      prototype[method] = wrapper;
    }
  }
  // mysql2 prepared statements (`execute`) take the SQL text too; `mysql2/promise` wraps the core connection.
  function patchMysql2(core) {
    for (const holder of [core, core?.default]) {
      patchQuery(holder?.Connection?.prototype, 'mysql2', ['query', 'execute']);
      patchQuery(holder?.Pool?.prototype, 'mysql2', ['query', 'execute']);
    }
  }
  // The classic `mysql` package keeps its classes in lib/: a connection, and a pool that hands the call to one.
  function patchMysqlClassic(loadFile) {
    for (const file of ['Connection', 'Pool']) { try { patchQuery(loadFile(file)?.prototype, 'mysql', ['query']); } catch (_) { /* class unavailable in this version */ } }
  }
  // Sequelize builds its own text before the driver: the mark only exists at its entry call.
  // mariadb: the classes are internal; the factories expose them (see mariadb.cjs).
  function patchMariadb(library) { require('./mariadb.cjs').watch(library, prototype => patchQuery(prototype, 'mariadb', ['query', 'execute', 'batch', 'queryStream'])); }
  function patchSequelize(library) {
    for (const holder of [library?.Sequelize, library?.default?.Sequelize, library]) patchQuery(holder?.prototype, 'sequelize', ['query']);
  }
  // Non-SQL sinks. Only strings passed directly to the call are inspected; values rebuilt by a library lose the mark.
  const ours = new WeakSet();
  function wrap(owner, name, rule, sink, pick) {
    const original = owner?.[name];
    if (typeof original !== 'function' || ours.has(original)) return;
    const replacement = function (...args) {
      try { inspectSink(rule, sink, pick(args)); } catch (_) { /* never alters the call */ }
      return original.apply(this, args);
    };
    for (const key of Reflect.ownKeys(original)) {
      if (key === 'length' || key === 'prototype') continue;
      try { Object.defineProperty(replacement, key, Object.getOwnPropertyDescriptor(original, key)); } catch (_) { /* keep the default */ }
    }
    // Some Node.js versions expose deprecated functions as read-only: that point is skipped, the rest keeps working.
    try { owner[name] = replacement; ours.add(replacement); } catch (_) { /* not wrappable here */ }
  }
  const first = args => [args[0]];
  const strings = args => args.filter(value => typeof value === 'string');
  // Paths built with path.join/resolve/normalize keep the mark as a whole value.
  function carry(owner, name) {
    const original = owner[name];
    if (typeof original !== 'function') return;
    owner[name] = function (...args) {
      const result = original.apply(this, args);
      const scope = storage.getStore();
      try {
        const tainted = scope && active.has(scope.id) && typeof result === 'string' ? args.find(value => typeof value === 'string' && native.isTainted(scope.id, value)) : undefined;
        if (tainted !== undefined) { const source = sourceOf(scope, tainted); return native.newTaintedString(scope.id, result, source?.name ?? 'value', source?.type ?? 'query'); }
      } catch (_) { /* keep the untainted result */ }
      return result;
    };
  }
  // The OTel HTTP instrumentation rebuilds the arguments of http.request/get when the application loads the module,
  // which drops the mark. Wrapping again on the first request puts this check outside that instrumentation.
  const target = args => typeof args[0] === 'string' ? [args[0]] : args[0] && typeof args[0] === 'object' && !(args[0] instanceof URL) ? [args[0].href, args[0].host, args[0].hostname, args[0].path] : [];
  function wrapOutgoing() {
    let changed = false;
    for (const [module, label] of [[require('node:http'), 'http'], [require('node:https'), 'https']]) for (const name of ['request', 'get']) {
      const before = module[name]; wrap(module, name, 'SSRF', `${label}.${name}`, target); changed ||= module[name] !== before;
    }
    if (changed) Module.syncBuiltinESMExports();
  }
  // Weak algorithms and cookie attributes are judged on what the application passes, never on a value it holds.
  const WEAK_HASH = new Set(['md4', 'md5', 'ripemd', 'ripemd160', 'rmd160', 'sha1', 'sha-1', 'md5-sha1', 'rsa-md5', 'rsa-sha1', 'rsa-sha1-2', 'mdc2', 'whirlpool']);
  const WEAK_CIPHER = /^(?:des|des-ede|des-ede3|des3|des-cbc|des-ecb|des-cfb|des-ofb|des-ede-cbc|des-ede3-cbc|rc2|rc4|rc2-40|rc2-64|rc2-128|rc4-40|rc4-hmac-md5|bf|bf-cbc|bf-ecb|blowfish|idea|cast|cast5|seed|aes-128-ecb|aes-192-ecb|aes-256-ecb)(?:-.*)?$/i;
  function patchFlaws(crypto) {
    const algorithm = args => typeof args[0] === 'string' ? args[0].toLowerCase() : '';
    wrapFlaw(crypto, 'createHash', 'WEAK_HASH', 'crypto.createHash', args => WEAK_HASH.has(algorithm(args)));
    wrapFlaw(crypto, 'createHmac', 'WEAK_HASH', 'crypto.createHmac', args => WEAK_HASH.has(algorithm(args)));
    for (const name of ['createCipheriv', 'createCipher']) wrapFlaw(crypto, name, 'WEAK_CIPHER', `crypto.${name}`, args => WEAK_CIPHER.test(algorithm(args)));
  }
  function wrapFlaw(owner, name, rule, sink, flawed) {
    const original = owner?.[name];
    if (typeof original !== 'function' || ours.has(original)) return;
    const replacement = function (...args) {
      try { if (flawed(args)) inspectFlaw(rule, sink, true); } catch (_) { /* never alters the call */ }
      return original.apply(this, args);
    };
    for (const key of Reflect.ownKeys(original)) {
      if (key === 'length' || key === 'prototype') continue;
      try { Object.defineProperty(replacement, key, Object.getOwnPropertyDescriptor(original, key)); } catch (_) { /* keep the default */ }
    }
    // Some Node.js versions expose deprecated functions as read-only: that point is skipped, the rest keeps working.
    try { owner[name] = replacement; ours.add(replacement); } catch (_) { /* not wrappable here */ }
  }
  // Set-Cookie: missing Secure, HttpOnly or SameSite. Only the attributes are read; a removal (empty value or Max-Age=0) is not a finding.
  function inspectCookie(value) {
    if (typeof value !== 'string') return;
    const [pair, ...attributes] = value.split(';').map(part => part.trim());
    if (!pair || pair.slice(pair.indexOf('=') + 1) === '' || attributes.some(attribute => /^max-age=0+$/i.test(attribute))) return;
    const has = name => attributes.some(attribute => attribute.toLowerCase() === name || attribute.toLowerCase().startsWith(name + '='));
    if (!has('secure')) inspectFlaw('INSECURE_COOKIE', 'http.ServerResponse.setHeader');
    if (!has('httponly')) inspectFlaw('NO_HTTPONLY_COOKIE', 'http.ServerResponse.setHeader');
    if (!has('samesite')) inspectFlaw('NO_SAMESITE_COOKIE', 'http.ServerResponse.setHeader');
  }
  // Redirects, not modified, not found, gone and server errors are not judged.
  const IGNORED_STATUS = new Set([301, 302, 304, 307, 404, 410, 500]);
  const HTML_TYPES = ['text/html', 'application/xhtml+xml'];
  // Strict-Transport-Security is valid when it starts with max-age and the value up to ';' is a whole number above 0.
  function validHsts(value) {
    value = value.trim();
    if (!value.startsWith('max-age')) return false;
    const end = value.indexOf(';');
    const text = value.slice('max-age'.length + 1, end === -1 ? value.length : end);
    const seconds = Number.parseInt(text, 10);
    return seconds > 0 && String(seconds) === text;
  }
  function inspectHeaders(response, status, rest) {
    const code = Number(typeof status === 'number' ? status : response.statusCode);
    if (IGNORED_STATUS.has(code)) return;
    const given = {};
    const extra = rest.find(value => value && typeof value === 'object');
    if (Array.isArray(extra)) { for (let i = 0; i < extra.length; i++) { if (Array.isArray(extra[i])) given[String(extra[i][0]).toLowerCase()] = extra[i][1]; else if (i % 2 === 0) given[String(extra[i]).toLowerCase()] = extra[i + 1]; } }
    else if (extra) for (const key of Object.keys(extra)) given[key.toLowerCase()] = extra[key];
    // Every value of the header, each one judged on its own.
    const values = name => { const value = response.getHeader(name) ?? given[name]; return value == null ? [] : (Array.isArray(value) ? value : [value]).map(String); };
    if (!values('content-type').some(type => HTML_TYPES.some(html => type === html || type.startsWith(html + ';')))) return;
    const options = values('x-content-type-options');
    if (!options.length || options.some(value => value.trim().toLowerCase() !== 'nosniff')) inspectFlaw('XCONTENTTYPE_HEADER_MISSING', 'http.ServerResponse.writeHead');
    const request = response.req;
    if (request?.protocol === 'https' || request?.socket?.encrypted === true || request?.headers?.['x-forwarded-proto'] === 'https') {
      const hsts = values('strict-transport-security');
      if (!hsts.length || hsts.some(value => !validHsts(value))) inspectFlaw('HSTS_HEADER_MISSING', 'http.ServerResponse.writeHead');
    }
  }
  function patchBuiltins() {
    const childProcess = require('node:child_process'), fs = require('node:fs'), http = require('node:http'), vm = require('node:vm');
    for (const name of ['exec', 'execSync']) wrap(childProcess, name, 'COMMAND_INJECTION', `child_process.${name}`, first);
    // Without a shell only the executable is a command; with `shell` the arguments are part of the command line.
    for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) wrap(childProcess, name, 'COMMAND_INJECTION', `child_process.${name}`, args => {
      const options = args.find(value => value && typeof value === 'object' && !Array.isArray(value));
      return options?.shell ? [args[0], ...(Array.isArray(args[1]) ? args[1] : [])] : [args[0]];
    });
    for (const name of ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createReadStream', 'createWriteStream', 'readdir', 'readdirSync', 'open', 'openSync', 'unlink', 'unlinkSync', 'rm', 'rmSync']) wrap(fs, name, 'PATH_TRAVERSAL', `fs.${name}`, first);
    for (const name of ['readFile', 'writeFile', 'appendFile', 'readdir', 'open', 'unlink', 'rm']) wrap(fs.promises, name, 'PATH_TRAVERSAL', `fs.promises.${name}`, first);
    for (const name of ['join', 'resolve', 'normalize']) carry(path, name);
    wrap(globalThis, 'fetch', 'SSRF', 'fetch', args => typeof args[0] === 'string' ? [args[0]] : []);
    wrapOutgoing();
    for (const name of ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction']) wrap(vm, name, 'CODE_INJECTION', `vm.${name}`, first);
    patchFlaws(require('node:crypto'));
    // Math.random in application code; only the first calls of a request are looked at, so a hot loop costs nothing.
    const random = Math.random;
    Math.random = function () {
      const scope = storage.getStore();
      if (scope && (scope.randoms = (scope.randoms || 0) + 1) <= 8) { try { inspectFlaw('WEAK_RANDOMNESS', 'Math.random', true); } catch (_) { /* never alters the call */ } }
      return random.call(this);
    };
    const response = http.ServerResponse.prototype;
    const writeHead = response.writeHead;
    // An HTML answer without X-Content-Type-Options: nosniff, and, over HTTPS, without a valid Strict-Transport-Security (max-age above 0).
    response.writeHead = function (status, ...rest) {
      try { inspectHeaders(this, status, rest); } catch (_) { /* never alters the call */ }
      return writeHead.call(this, status, ...rest);
    };
    const setHeader = response.setHeader;
    response.setHeader = function (name, value, ...rest) {
      try {
        const lower = String(name).toLowerCase();
        if (lower === 'set-cookie') for (const cookie of Array.isArray(value) ? value : [value]) inspectCookie(cookie);
        inspectSink(lower === 'location' ? 'UNVALIDATED_REDIRECT' : 'HEADER_INJECTION', 'http.ServerResponse.setHeader', Array.isArray(value) ? value : [value], undefined, lower);
      } catch (_) { /* never alters the call */ }
      return setHeader.call(this, name, value, ...rest);
    };
    Module.syncBuiltinESMExports();
  }
  patchBuiltins();
  // NoSQL injection: query operators come from the request. A plain object read from the request (a string only matches
  // by equality) reaching a query filter, or request text inside $where / $function, is the finding.
  function inputObject(value, depth = 0) {
    if (!value || typeof value !== 'object' || depth > 5) return null;
    if (!Array.isArray(value) && marked.has(value)) return marked.get(value);
    for (const key of Object.keys(value)) { const found = inputObject(value[key], depth + 1); if (found) return found; }
    return null;
  }
  function scriptInput(scope, value, depth = 0) {
    if (!value || typeof value !== 'object' || depth > 5) return null;
    for (const key of Object.keys(value)) {
      const child = value[key];
      const text = key === '$where' ? child : key === '$function' ? child?.body : undefined;
      if (typeof text === 'string' && native.isTainted(scope.id, text)) return sourceOf(scope, text);
      const found = scriptInput(scope, child, depth + 1);
      if (found) return found;
    }
    return null;
  }
  function inspectNoSql(sink, filter) {
    const scope = storage.getStore();
    if (stopped || !scope || !active.has(scope.id)) return;
    const started = process.hrtime.bigint();
    try {
      const source = inputObject(filter) ?? scriptInput(scope, filter);
      if (source) reportAt(scope, 'NOSQL_INJECTION', sink, started, new Error().stack || '', undefined, source);
    } catch (_) { console.warn('[Telvyn] IAST finding could not be reported.'); }
  }
  function wrapNoSql(owner, name, index) {
    const original = owner?.[name];
    if (typeof original !== 'function' || ours.has(original)) return;
    const replacement = function (...args) {
      try { inspectNoSql(`mongodb.Collection.${name}`, args[index]); } catch (_) { /* never alters the call */ }
      return original.apply(this, args);
    };
    for (const key of Reflect.ownKeys(original)) {
      if (key === 'length' || key === 'prototype') continue;
      try { Object.defineProperty(replacement, key, Object.getOwnPropertyDescriptor(original, key)); } catch (_) { /* keep the default */ }
    }
    try { owner[name] = replacement; ours.add(replacement); } catch (_) { /* not wrappable here */ }
  }
  function patchMongo(driver) {
    const prototype = driver?.Collection?.prototype ?? driver?.default?.Collection?.prototype;
    for (const name of ['find', 'findOne', 'updateOne', 'updateMany', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'countDocuments', 'aggregate']) wrapNoSql(prototype, name, 0);
    wrapNoSql(prototype, 'distinct', 1);
  }
  // HTTP client libraries rebuild the destination from a parsed URL, so the mark only exists at their entry call.
  const clientUrl = args => [typeof args[0] === 'string' ? args[0] : args[0]?.url, args[0]?.baseURL, args[1]?.url, args[1]?.baseURL].filter(value => typeof value === 'string');
  const CLIENT_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request', 'stream']);
  const clients = new WeakMap();
  function clientProxy(library, sink) {
    if (typeof library !== 'function') return library;
    if (clients.has(library)) return clients.get(library);
    const check = args => { try { inspectSink('SSRF', sink, clientUrl(args)); } catch (_) { /* never alters the call */ } };
    const proxy = new Proxy(library, {
      apply(target, thisArg, args) { check(args); return Reflect.apply(target, thisArg, args); },
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        return typeof value === 'function' && CLIENT_METHODS.has(property) ? function (...args) { check(args); return value.apply(this === receiver ? target : this, args); } : value;
      },
    });
    clients.set(library, proxy);
    return proxy;
  }
  function patchAxios(axios) {
    const library = axios?.default ?? axios;
    wrap(library?.Axios?.prototype, 'request', 'SSRF', 'axios', clientUrl);
    return typeof axios === 'function' ? clientProxy(axios, 'axios') : axios;
  }
  // ESM namespaces: replace the exported function with the observing proxy.
  function patchClientModule(namespace, sink) {
    for (const key of ['default', 'got', 'axios']) {
      try { if (typeof namespace[key] === 'function') namespace[key] = clientProxy(namespace[key], sink); } catch (_) { /* read-only export */ }
    }
  }
  // LDAP: the distinguished name or the filter of a call is built from request input.
  function patchLdap(library) {
    const prototype = (library?.Client ? library : library?.default)?.Client?.prototype;
    wrap(prototype, 'search', 'LDAP_INJECTION', 'ldap.Client.search', args => [args[0], typeof args[1] === 'string' ? args[1] : args[1]?.filter]);
    for (const name of ['bind', 'add', 'compare', 'del', 'modify', 'modifyDN']) wrap(prototype, name, 'LDAP_INJECTION', `ldap.Client.${name}`, first);
  }
  // E-mail: the HTML body of a message is built from request input. Every transport made by the application is watched.
  function patchNodemailer(library) {
    const holder = typeof library?.createTransport === 'function' ? library : library?.default;
    const create = holder?.createTransport;
    if (typeof create !== 'function' || ours.has(create)) return;
    const replacement = function (...args) {
      const transporter = create.apply(this, args);
      wrap(transporter, 'sendMail', 'EMAIL_HTML_INJECTION', 'nodemailer.sendMail', call => [call[0]?.html]);
      return transporter;
    };
    try { holder.createTransport = replacement; ours.add(replacement); } catch (_) { /* not wrappable here */ }
  }
  function patchExpress(framework) { wrap((framework?.default ?? framework)?.response, 'redirect', 'UNVALIDATED_REDIRECT', 'express.redirect', strings); }
  const load = Module._load;
  Module._load = function (name, ...args) {
    const exported = load.call(this, name, ...args);
    if (name === 'pg') { patchQuery(exported.Client?.prototype, 'pg'); patchQuery(exported.Pool?.prototype, 'pg'); }
    else if (name === 'express') patchExpress(exported);
    else if (name === 'mongodb') patchMongo(exported);
    else if (name === 'axios') return patchAxios(exported);
    else if (name === 'mysql2') patchMysql2(exported);
    else if (name === 'mysql') patchMysqlClassic(file => load.call(this, `mysql/lib/${file}`, ...args));
    else if (name === 'sequelize') patchSequelize(exported);
    else if (name === 'mariadb' || name === 'mariadb/callback') patchMariadb(exported);
    else if (name === 'ldapjs' || name === 'ldapts') patchLdap(exported);
    else if (name === 'nodemailer') patchNodemailer(exported);
    else if (name === 'mysql2/promise') { try { patchMysql2(load.call(this, 'mysql2', ...args)); } catch (_) { /* core package unavailable */ } }
    return exported;
  };
  const { Hook } = require('import-in-the-middle');
  const sqlHook = new Hook(['pg', 'mysql2', 'mysql2/promise', 'express', 'mongodb', 'axios', 'got', 'ldapjs', 'ldapts', 'nodemailer', 'mysql', 'sequelize', 'mariadb', 'mariadb/callback'], (exported, name, baseDir) => {
    if (name.startsWith('mariadb')) { patchMariadb(exported); return; }
    if (name === 'express') { patchExpress(exported); return; }
    if (name === 'mongodb') { patchMongo(exported); return; }
    if (name === 'ldapjs' || name === 'ldapts') { patchLdap(exported); return; }
    if (name === 'nodemailer') { patchNodemailer(exported); return; }
    if (name === 'sequelize') { patchSequelize(exported); return; }
    if (name === 'mysql') { patchMysqlClassic(file => Module._load(path.join(baseDir, 'lib', file), module)); return; }
    if (name === 'axios' || name === 'got') { patchClientModule(exported, name); return; }
    if (name === 'pg') { patchQuery(exported.Client?.prototype, 'pg'); patchQuery(exported.Pool?.prototype, 'pg'); patchQuery(exported.default?.Client?.prototype, 'pg'); return; }
    patchMysql2(exported);
    if (name.endsWith('/promise')) { try { patchMysql2(Module._load(baseDir, module)); } catch (_) { /* core package unavailable */ } }
  });
  // Frameworks assign these properties after the first hook (body parsing, routing, cookies), so assignments are watched.
  function track(request, property, type, scope) {
    const marker = Symbol.for('telvyn.iast.' + property);
    if (Object.hasOwn(request, marker)) return;
    Object.defineProperty(request, marker, {value: true});
    let owner = request, descriptor;
    while (owner && !(descriptor = Object.getOwnPropertyDescriptor(owner, property))) owner = Object.getPrototypeOf(owner);
    const view = value => mark(value, type, property, scope);
    if (descriptor?.get && !descriptor.set) {
      // Express 5 parses the query again on every read: preserve that and mark each result.
      Object.defineProperty(request, property, {configurable: true, enumerable: descriptor.enumerable, get() { return view(descriptor.get.call(this)); }});
    } else if (descriptor?.get) {
      view(descriptor.get.call(request));
      Object.defineProperty(request, property, {configurable: true, enumerable: descriptor.enumerable, get() { return descriptor.get.call(this); }, set(value) { descriptor.set.call(this, view(value)); }});
    } else {
      let current = view(descriptor?.value);
      Object.defineProperty(request, property, {configurable: true, enumerable: descriptor ? descriptor.enumerable : true, get() { return current; }, set(value) { current = view(value); }});
    }
  }
  return {
    state: 'active',
    request(request) {
      const scope = scopes.get(request) ?? scopes.get(request?.raw);
      if (!scope || !active.has(scope.id)) return;
      // Re-enter the request context: asynchronous body parsing can leave it.
      if (storage.getStore() !== scope) storage.enterWith(scope);
      for (const [property, type] of [['query', 'query'], ['body', 'body'], ['params', 'path'], ['cookies', 'cookie']]) track(request, property, type, scope);
    },
    stop() { stopped = true; sqlHook.unhook(); for (const id of active) { try { native.removeTransaction(id); } catch (_) { console.warn('[Telvyn] IAST transaction cleanup failed.'); } } active.clear(); },
  };
}
module.exports = { startIast, rewriterMethods, blockTopLevelArrows };
