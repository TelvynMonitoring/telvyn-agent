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
  const rewriter = new Rewriter({csiMethods: rewriterMethods, literals: false, chainSourceMap: true});
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
  Module.prototype._compile = function (source, filename) {
    let code = source;
    if (!stopped && relativeFile(filename, COMPILED_FILE)) {
      try { code = rewriter.rewrite(source, filename, ['iast']).content || source; if (code !== source) cacheRewrittenSourceMap(filename, code); }
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
  const marked = new WeakSet();
  function mark(value, type, name, scope, budget = {left: 256}, depth = 0) {
    if (typeof value === 'string') return budget.left-- > 0 ? taint(value, type, name, scope) : value;
    if (!value || typeof value !== 'object' || depth > 5 || marked.has(value)) return value;
    // Plain data only; Fastify's null-object classes (query, params) carry nothing but `constructor`.
    const prototype = Object.getPrototypeOf(value);
    const plain = prototype === null || prototype === Object.prototype || (Object.getPrototypeOf(prototype) === null && Object.getOwnPropertyNames(prototype).every(key => key === 'constructor'));
    if (!Array.isArray(value) && !plain) return value;
    marked.add(value);
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
      const stack = new Error().stack || '';
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
      prototype[method] = function (...args) {
        // pg takes `text`, mysql2 takes `sql`.
        const sql = typeof args[0] === 'string' ? args[0] : args[0]?.text ?? args[0]?.sql;
        if (typeof sql === 'string') inspectSink('SQL_INJECTION', `${driver}.${method}`, [sql], sql);
        return query.apply(this, args);
      };
    }
  }
  // mysql2 prepared statements (`execute`) take the SQL text too; `mysql2/promise` wraps the core connection.
  function patchMysql2(core) {
    for (const holder of [core, core?.default]) {
      patchQuery(holder?.Connection?.prototype, 'mysql2', ['query', 'execute']);
      patchQuery(holder?.Pool?.prototype, 'mysql2', ['query', 'execute']);
    }
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
    ours.add(replacement);
    owner[name] = replacement;
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
    const response = http.ServerResponse.prototype;
    const setHeader = response.setHeader;
    response.setHeader = function (name, value, ...rest) {
      try { inspectSink(String(name).toLowerCase() === 'location' ? 'UNVALIDATED_REDIRECT' : 'HEADER_INJECTION', 'http.ServerResponse.setHeader', Array.isArray(value) ? value : [value], undefined, String(name).toLowerCase()); } catch (_) { /* never alters the call */ }
      return setHeader.call(this, name, value, ...rest);
    };
    Module.syncBuiltinESMExports();
  }
  patchBuiltins();
  function patchExpress(framework) { wrap((framework?.default ?? framework)?.response, 'redirect', 'UNVALIDATED_REDIRECT', 'express.redirect', strings); }
  const load = Module._load;
  Module._load = function (name, ...args) {
    const exported = load.call(this, name, ...args);
    if (name === 'pg') { patchQuery(exported.Client?.prototype, 'pg'); patchQuery(exported.Pool?.prototype, 'pg'); }
    else if (name === 'express') patchExpress(exported);
    else if (name === 'mysql2') patchMysql2(exported);
    else if (name === 'mysql2/promise') { try { patchMysql2(load.call(this, 'mysql2', ...args)); } catch (_) { /* core package unavailable */ } }
    return exported;
  };
  const { Hook } = require('import-in-the-middle');
  const sqlHook = new Hook(['pg', 'mysql2', 'mysql2/promise', 'express'], (exported, name, baseDir) => {
    if (name === 'express') { patchExpress(exported); return; }
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
module.exports = { startIast, rewriterMethods };
