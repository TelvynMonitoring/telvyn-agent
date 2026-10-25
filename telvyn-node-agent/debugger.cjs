'use strict';
const Module = require('node:module');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { Session } = require('node:inspector');

function startDebugger(transport) {
  if (process.env.TELVYN_DEBUGGER_ENABLED !== 'true') return { stop() {} };
  if (!process.env.TELVYN_PROFILE_SOURCE_ROOT) throw new Error('Debugger requires an application source root');
  const root = path.resolve(process.env.TELVYN_PROFILE_SOURCE_ROOT);
  const { trace, metrics } = require('@opentelemetry/api');
  const meter = metrics.getMeter('telvyn.debugger');
  const instruments = new Map(), captures = new Map(), breakpoints = new Map();
  const errorIds = new WeakMap();
  const installed = new Set(), observed = new Map();
  const sessionId = require('node:crypto').randomBytes(16).toString('hex');
  let policies = new Map(), errors = [], stopped = false, lastConfig = 0, reportReady = false;
  function relative(filename) {
    const file = path.relative(root, filename).split(path.sep).join('/');
    return /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:cjs|js|mjs)$/.test(file) && !file.split('/').some(part => part === '..' || part === 'node_modules') ? file : null;
  }
  const scalar = value => typeof value === 'number' && Number.isFinite(value) || typeof value === 'boolean' || value == null ? value : '[redacted]';
  function snapshot(target, phase, payload, duration, error) {
    const now = Date.now();
    if (now - (captures.get(target) || 0) < 1000) return;
    if (!captures.has(target) && captures.size >= 200) return;
    captures.set(target, now);
    let errorId;
    if (error && (typeof error === 'object' || typeof error === 'function')) {
      errorId = errorIds.get(error);
      if (!errorId) { errorId = require('node:crypto').randomBytes(16).toString('hex'); errorIds.set(error, errorId); }
    }
    const span = trace.getActiveSpan()?.spanContext();
    transport.send('debug', {snapshots: [{method: target, phase, captured_unix_ms: now, payload, duration_ms: duration,
      error: error ? error.name === 'TypeError' ? 'TypeError' : 'Error' : undefined,
      ...(errorId ? {error_id: errorId} : {}),
      ...(span ? {trace_id: span.traceId, span_id: span.spanId} : {})}]});
  }
  function matches(condition, args, duration, error) {
    if (!condition) return true;
    const actual = condition.source === 'duration_ms' ? duration : condition.source === 'exception' ? !!error : args[condition.arg_index];
    const expected = condition.source === 'exception' ? condition.bool : condition.number;
    if (typeof actual !== typeof expected || typeof actual === 'number' && !Number.isFinite(actual)) return false;
    switch (condition.operator) {
      case 'gt': return actual > expected; case 'gte': return actual >= expected;
      case 'lt': return actual < expected; case 'lte': return actual <= expected;
      case 'eq': return actual === expected; case 'ne': return actual !== expected;
      default: return false;
    }
  }
  function observe(target, args, value, duration, error) {
    if (stopped || Date.now() - lastConfig > 60000) return;
    const policy = policies.get(target);
    if (!policy) { if (error && errors.some(prefix => target.startsWith(prefix))) snapshot(target, 'exception', {args: args.slice(0, 20).map(scalar)}, duration, error); return; }
    observed.set(target, Math.min(1000000000000, (observed.get(target) || 0) + 1));
    if (!matches(policy.condition, args, duration, error)) return;
    if (policy.action === 'snapshot') { snapshot(target, 'call', {args: args.slice(0, 20).map(scalar), returned: scalar(value)}, duration, error); return; }
    const key = `${policy.action}:${policy.metric_name}`;
    if (!instruments.has(key)) {
      if (instruments.size >= 200) return;
      const instrument = policy.action === 'count' ? meter.createCounter(policy.metric_name) : policy.action === 'duration' ? meter.createHistogram(policy.metric_name, {unit: 'ms'}) : meter.createGauge(policy.metric_name);
      instruments.set(key, instrument);
    }
    const instrument = instruments.get(key);
    if (policy.action === 'count') instrument.add(1);
    else if (policy.action === 'duration') instrument.record(duration);
    else { const sample = policy.value_source === 'returned' ? value : args[policy.value_arg_index]; if (typeof sample === 'number' && Number.isFinite(sample)) instrument.record(sample); }
  }
  const wrapped = new WeakMap();
  function wrap(fn, file, name) {
    if (wrapped.has(fn)) return wrapped.get(fn);
    const target = `${file}#${name}`;
    if (installed.size < 10000) installed.add(target);
    const proxy = new Proxy(fn, {apply(original, receiver, args) {
      if (stopped || !policies.has(target) && !errors.some(prefix => target.startsWith(prefix))) return Reflect.apply(original, receiver, args);
      const start = performance.now();
      const finish = (result, error) => { try { observe(target, args, result, performance.now() - start, error); } catch (_) { console.warn('[Telvyn] Debugger observation failed.'); } };
      try {
        const result = Reflect.apply(original, receiver, args);
        if (result instanceof Promise) return result.then(value => { finish(value); return value; }, error => { finish(undefined, error); throw error; });
        finish(result); return result;
      } catch (error) { finish(undefined, error); throw error; }
    }});
    wrapped.set(fn, proxy); wrapped.set(proxy, proxy); return proxy;
  }
  const visited = new WeakSet();
  function wrapMembers(object, file) {
    if (!object || visited.has(object)) return;
    visited.add(object);
    for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(object))) {
      if (name === 'constructor' || !descriptor.configurable || typeof descriptor.value !== 'function' || !/^[\w$]+$/.test(name)) continue;
      Object.defineProperty(object, name, {...descriptor, value: wrap(descriptor.value, file, name)});
      if (descriptor.value.prototype) wrapMembers(descriptor.value.prototype, file);
    }
  }
  const load = Module._load;
  Module._load = function (name, parent, ...args) {
    const exported = load.call(this, name, parent, ...args);
    if (stopped) return exported;
    try {
      const file = relative(Module._resolveFilename(name, parent));
      if (!file) return exported;
      wrapMembers(exported, file);
      if (typeof exported === 'function') { wrapMembers(exported.prototype, file); return wrap(exported, file, exported.name || 'default'); }
    } catch (_) { console.warn('[Telvyn] Debugger could not instrument an application export.'); }
    return exported;
  };
  const { Hook } = require('import-in-the-middle');
  const esmHook = new Hook((exported, name) => {
    try {
      const file = relative(name.startsWith('file:') ? fileURLToPath(name) : name);
      if (!file) return;
      for (const key of Object.keys(exported)) {
        const value = exported[key];
        if (typeof value === 'function') { wrapMembers(value.prototype, file); exported[key] = wrap(value, file, key === 'default' ? value.name || 'default' : key); }
        else if (key === 'default') wrapMembers(value, file);
      }
    } catch (_) { console.warn('[Telvyn] Debugger could not instrument an ESM export.'); }
  });
  const scripts = new Map(), installing = new Set();
  const originalLocation = require('./sourcemap.cjs').locate;
  const session = new Session(); session.connect();
  function installLineProbes() {
    for (const target of policies.keys()) {
      if (!target.includes('@') || installing.has(target) || [...breakpoints.values()].includes(target)) continue;
      const file = target.split('#')[0], line = Number(target.split('@')[1]);
      const script = scripts.get(file);
      if (!script) continue;
      installing.add(target);
      session.post('Debugger.getPossibleBreakpoints', {start: {scriptId: script.scriptId, lineNumber: 0}, end: {scriptId: script.scriptId, lineNumber: script.endLine}}, (error, result) => {
        if (error || stopped || !policies.has(target)) { installing.delete(target); return; }
        const location = result.locations.find(location => {
          const mapped = originalLocation(script.filename, location.lineNumber + 1, location.columnNumber + 1);
          return relative(mapped.path) === file && mapped.line === line;
        });
        if (!location) { installing.delete(target); return; }
        session.post('Debugger.setBreakpoint', {location}, (error, result) => {
          installing.delete(target);
          if (!error && !stopped && policies.has(target)) breakpoints.set(result.breakpointId, target);
          else if (!error && !stopped) session.post('Debugger.removeBreakpoint', {breakpointId: result.breakpointId}, () => {});
        });
      });
    }
  }
  session.on('Debugger.scriptParsed', ({params}) => {
    if (!params.url.startsWith('file:') || params.endLine > 10000 || scripts.size >= 256) return;
    try {
      const filename = fileURLToPath(params.url), file = relative(filename);
      if (file) { scripts.set(file, {...params, filename}); installLineProbes(); }
    } catch (_) {}
  });
  session.post('Debugger.enable');
  session.on('Debugger.paused', ({params}) => {
    try {
      const target = (params.hitBreakpoints || []).map(id => breakpoints.get(id)).find(Boolean);
      if (!target || stopped || Date.now() - lastConfig > 60000) return;
      const policy = policies.get(target);
      if (policy?.action === 'count') { observe(target, [], undefined, undefined); return; }
      observed.set(target, Math.min(1000000000000, (observed.get(target) || 0) + 1));
      const local = params.callFrames?.[0]?.scopeChain.find(scope => scope.type === 'local');
      const sourceLine = Number(target.split('@')[1]);
      if (!local) { snapshot(target, 'line', {source_line: sourceLine, locals_available: false}); return; }
      session.post('Runtime.getProperties', {objectId: local.object.objectId, ownProperties: true}, (error, result) => {
        if (error) return;
        const values = {};
        for (const property of (result.result || []).slice(0, 20)) values[property.name] = /password|secret|token|cookie|auth/i.test(property.name) ? '[redacted]' : scalar(property.value?.value);
        snapshot(target, 'line', {source_line: sourceLine, locals_available: true, locals: values});
      });
    } finally { session.post('Debugger.resume', () => {}); }
  });
  async function refresh() {
    try {
      const config = await transport.config();
      if (stopped) return;
      if (!Array.isArray(config.policies) || config.policies.length > 200 || !Array.isArray(config.exceptions)) throw new Error('Invalid debugger configuration');
      const next = new Map();
      for (const row of config.policies) {
        if (typeof row.target !== 'string' || !/^(?:[\w$.-]+\/)*[\w$.-]+\.(?:js|cjs|mjs)#[\w$]+(?:@[1-9][0-9]{0,5})?$/.test(row.target) || row.target.split('#')[0].split('/').includes('..')) continue;
        const policy = row.policy || {action: 'snapshot'};
        if (!['snapshot', 'count', 'duration', 'gauge'].includes(policy.action) || policy.action !== 'snapshot' && !/^debug\.[a-z][a-z0-9_.]{0,100}$/.test(policy.metric_name || '')) continue;
        next.set(row.target, policy);
      }
      policies = next; errors = config.exceptions.filter(prefix => typeof prefix === 'string' && prefix.length <= 255).slice(0, 200); lastConfig = Date.now();
      captures.clear();
      for (const [id, target] of breakpoints) if (!next.has(target)) { session.post('Debugger.removeBreakpoint', {breakpointId: id}); breakpoints.delete(id); }
      installLineProbes();
      if (reportReady && /^[a-f0-9]{64}$/.test(config.config_version) && Array.isArray(config.probes) && config.probes.length <= 200) {
        const lines = new Set(breakpoints.values());
        transport.send('debug/config/applied', {config_version: config.config_version, session: sessionId,
          statuses: config.probes.map(target => {
            const applied = policies.has(target) && (target.includes('@') ? lines.has(target) : installed.has(target));
            return {target, status: applied ? 'instrumented' : 'unmatched', instrumented_methods: applied ? 1 : 0, observed_calls: applied ? observed.get(target) || 0 : 0};
          })});
      }
      reportReady = true;
      for (const target of observed.keys()) if (!next.has(target)) observed.delete(target);
    } catch (_) {
      if (Date.now() - lastConfig > 60000) {
        policies.clear(); errors = [];
        for (const id of breakpoints.keys()) session.post('Debugger.removeBreakpoint', {breakpointId: id}, () => {});
        breakpoints.clear();
      }
      console.warn('[Telvyn] Debugger configuration refresh failed.');
    }
  }
  void refresh(); const timer = setInterval(refresh, 15000); timer.unref();
  return { stop() { stopped = true; esmHook.unhook(); clearInterval(timer); policies.clear(); session.disconnect(); } };
}
module.exports = { startDebugger };
