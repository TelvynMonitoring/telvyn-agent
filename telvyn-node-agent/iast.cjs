'use strict';
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomUUID } = require('node:crypto');
const { Server } = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const rewriterMethods = [{src: 'plusOperator', operator: true}, {src: 'tplOperator', operator: true},
  ...['concat', 'slice', 'substring', 'substr', 'trim', 'trimEnd', 'replace'].map(src => ({src})),
  {src: 'toUpperCase', dst: 'stringCase'}, {src: 'toLowerCase', dst: 'stringCase'}];

function startIast(report) {
  if (process.env.TELVYN_IAST_ENABLED !== 'true') return { state: 'disabled', request() {}, stop() {} };
  const root = process.env.TELVYN_PROFILE_SOURCE_ROOT;
  const routes = new Set((process.env.TELVYN_SECURITY_ROUTES || '').split(',').filter(Boolean));
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
  function relativeFile(filename) {
    if (filename.startsWith('file:')) filename = fileURLToPath(filename);
    const relative = path.relative(sourceRoot, filename).split(path.sep).join('/');
    return relative && !relative.split('/').some(part => part === '..' || part === 'node_modules') && /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:js|cjs|mjs)$/.test(relative) ? relative : null;
  }
  Module.prototype._compile = function (source, filename) {
    let code = source;
    if (!stopped && relativeFile(filename)) {
      try { code = rewriter.rewrite(source, filename, ['iast']).content || source; if (code !== source) cacheRewrittenSourceMap(filename, code); }
      catch (_) { console.warn('[Telvyn] IAST could not instrument an application module.'); }
    }
    return originalCompile.call(this, code, filename);
  };
  const emit = Server.prototype.emit;
  Server.prototype.emit = function (event, request, response, ...rest) {
    if (stopped || event !== 'request' || active.size >= 32 || !routes.has(request.url?.split('?')[0])) return emit.call(this, event, request, response, ...rest);
    const scope = {id: randomUUID(), reported: new Set()};
    try { native.createTransaction(scope.id); active.add(scope.id); }
    catch (_) { return emit.call(this, event, request, response, ...rest); }
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
  function taint(value) {
    const scope = storage.getStore();
    if (!scope || !active.has(scope.id) || typeof value !== 'string' || value.length > 4096) return value;
    try { return native.newTaintedString(scope.id, value, 'q', 'query'); } catch (_) { return value; }
  }
  const get = URLSearchParams.prototype.get;
  URLSearchParams.prototype.get = function (name) { const value = get.call(this, name); return name === 'q' ? taint(value) : value; };
  const patched = new WeakSet();
  function patchQuery(prototype) {
    if (!prototype || patched.has(prototype) || typeof prototype.query !== 'function') return;
    patched.add(prototype);
    const query = prototype.query;
    prototype.query = function (...args) {
      const started = process.hrtime.bigint();
      const scope = storage.getStore();
      const sql = typeof args[0] === 'string' ? args[0] : args[0]?.text;
      try {
        if (scope && active.has(scope.id) && typeof sql === 'string' && native.isTainted(scope.id, sql)) {
          const stack = new Error().stack || '';
          const location = stack.split('\n').map(line => line.match(/^\s*at (?:(.*?) \()?([^()]+):(\d+):(\d+)\)?$/)).find(match => match && relativeFile(match[2]));
          if (location) {
            const filename = location[2].startsWith('file:') ? fileURLToPath(location[2]) : location[2];
            const mapped = getSourcePathAndLineFromSourceMaps(filename, Number(location[3]), Number(location[4]));
            const file = relativeFile(mapped.path);
            const method = (location[1] || 'anonymous').replace(/[^\w$]/g, '_');
            const key = `${file}:${mapped.line}`;
            if (file && !scope.reported.has(key) && scope.reported.size < 8) { scope.reported.add(key); report({code_method: `${file}#${method}`, code_line: mapped.line}, Number((process.hrtime.bigint() - started) / 1000n)); }
          }
        }
      } catch (_) { console.warn('[Telvyn] IAST finding could not be reported.'); }
      return query.apply(this, args);
    };
  }
  const load = Module._load;
  Module._load = function (name, ...args) {
    const exported = load.call(this, name, ...args);
    if (name === 'pg') { patchQuery(exported.Client?.prototype); patchQuery(exported.Pool?.prototype); }
    return exported;
  };
  const { Hook } = require('import-in-the-middle');
  const pgHook = new Hook(['pg'], exported => { patchQuery(exported.Client?.prototype); patchQuery(exported.Pool?.prototype); patchQuery(exported.default?.Client?.prototype); });
  return {
    state: 'active',
    request(request) {
      const scope = storage.getStore();
      if (!scope || !active.has(scope.id)) return;
      // Express 4 has a value; Express 5 exposes a getter. Preserve its parsing semantics.
      let owner = request, descriptor;
      while (owner && !(descriptor = Object.getOwnPropertyDescriptor(owner, 'query'))) owner = Object.getPrototypeOf(owner);
      if (!descriptor || Object.hasOwn(request, Symbol.for('telvyn.iast.query'))) return;
      const mark = query => {
        if (query && typeof query.q === 'string') query.q = taint(query.q);
        return query;
      };
      if (descriptor.get) Object.defineProperty(request, 'query', {configurable: true, enumerable: descriptor.enumerable, get() { return mark(descriptor.get.call(this)); }});
      else mark(request.query);
      Object.defineProperty(request, Symbol.for('telvyn.iast.query'), {value: true});
    },
    stop() { stopped = true; pgHook.unhook(); for (const id of active) { try { native.removeTransaction(id); } catch (_) { console.warn('[Telvyn] IAST transaction cleanup failed.'); } } active.clear(); },
  };
}
module.exports = { startIast, rewriterMethods };
