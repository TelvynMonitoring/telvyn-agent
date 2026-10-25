if ((process.env.OTEL_SDK_DISABLED || '').toLowerCase() !== 'true') {
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  const { AsyncLocalStorageContextManager } = require('@opentelemetry/context-async-hooks');
  const profileContext = require('./profile-context.cjs');
  const { isSpanContextValid, trace } = require('@opentelemetry/api');
  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-proto');
  const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
  const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
  const FastifyOtelInstrumentation = require('@fastify/otel');
  const { PgInstrumentation } = require('@opentelemetry/instrumentation-pg');
  const { MySQL2Instrumentation } = require('@opentelemetry/instrumentation-mysql2');
  const { MySQLInstrumentation } = require('@opentelemetry/instrumentation-mysql');
  const { PeriodicExportingMetricReader } = require('@opentelemetry/sdk-metrics');
  const { OTLPMetricExporter } = require('@opentelemetry/exporter-metrics-otlp-proto');
  const { ServerResponse, IncomingMessage } = require('node:http');
  // Startup failures keep the application running; the reason is short and single-line so the operator can act on it.
  const why = error => ` (${String(error?.message ?? error).replace(/\s+/g, ' ').slice(0, 160)})`;
  let security;
  try { security = require('./security.cjs').startSecurity(); }
  catch (error) { console.warn('[Telvyn] Security sensor could not start; application startup continues.' + why(error)); }
  let iast;
  try {
    if (process.env.TELVYN_IAST_ENABLED === 'true' && !security?.reportIast) throw new Error('IAST needs the security reporter, which did not start');
    iast = require('./iast.cjs').startIast((finding, elapsed) => { if (require('./remote.cjs').security('iast') !== false) security.reportIast(finding, elapsed, trace.getActiveSpan()); });
  } catch (error) { console.warn('[Telvyn] IAST sensor could not start; application startup continues.' + why(error)); }
  let sca;
  try { sca = require('./sca.cjs').startSca(); }
  catch (error) { console.warn('[Telvyn] Library inventory (SCA) could not start; application startup continues.' + why(error)); }
  let loaderPort;
  if (require('node:worker_threads').isMainThread && typeof require('node:module').register === 'function') {
    try {
      const { port1, port2 } = new (require('node:worker_threads').MessageChannel)();
      loaderPort = port1;
      port1.on('message', message => {
        if (message.error) { if (iast) iast.state = 'error'; console.warn('[Telvyn] ESM taint instrumentation failed.'); }
        else if (message.filename && message.source) require('@datadog/wasm-js-rewriter/js/source-map').cacheRewrittenSourceMap(message.filename, message.source);
        else if (message.module) sca?.noteUrl(message.module);
      });
      port1.unref();
      require('node:module').register(require('node:url').pathToFileURL(require('node:path').join(__dirname, 'loader.mjs')), {data: {sourceRoot: process.env.TELVYN_PROFILE_SOURCE_ROOT, iast: iast?.state === 'active', sca: !!sca, port: port2}, transferList: [port2]});
    } catch (error) { console.warn('[Telvyn] ESM instrumentation could not start.' + why(error)); loaderPort?.close(); }
  }

  // The collector and backend read the older database attribute names; the instrumentation emits the current ones.
  // The collector obfuscates only the copy it uses for statistics; the span relayed to the backend stays as exported, so literals are removed here.
  // Query strings keep the parameter names and lose every value, the same rule the collector applies to all languages.
  const redactPairs = query => query.split('&').map(part => part.includes('=') ? part.slice(0, part.indexOf('=')) + '=<redacted>' : part).join('&');
  const redactQuery = target => {
    const mark = target.indexOf('?');
    if (mark < 0) return target;
    const query = target.slice(mark + 1).split('#')[0];
    return query ? target.slice(0, mark) + '?' + redactPairs(query) : target.slice(0, mark);
  };
  const obfuscateSql = text => text.replace(/'(?:[^']|'')*'|(?<![\w$.])\d+(?:\.\d+)?(?![\w$])/g, '?');
  const databaseAliases = {'db.system.name': 'db.system', 'db.query.text': 'db.statement', 'db.namespace': 'db.name'};
  class QuerySafeExporter extends OTLPTraceExporter {
    export(spans, callback) {
      for (const span of spans) {
        span.attributes['telvyn.sdk.name'] = 'telvyn-node-agent';
        span.attributes['telvyn.sdk.version'] = require('./package.json').version;
        span.attributes['process.runtime.version'] = process.version;
        for (const key of ['http.url', 'http.target', 'url.full']) {
          if (typeof span.attributes[key] === 'string') span.attributes[key] = redactQuery(span.attributes[key]);
        }
        if (typeof span.attributes['url.query'] === 'string') span.attributes['url.query'] = redactPairs(span.attributes['url.query']);
        for (const [current, legacy] of Object.entries(databaseAliases)) {
          if (span.attributes[current] != null && span.attributes[legacy] == null) span.attributes[legacy] = span.attributes[current];
        }
        for (const key of ['db.statement', 'db.query.text']) {
          if (typeof span.attributes[key] === 'string') span.attributes[key] = obfuscateSql(span.attributes[key]);
        }
      }
      super.export(spans, callback);
    }
  }

  // mariadb has no OpenTelemetry instrumentation: one client span per call, with the attributes the pg and mysql2 spans carry.
  // Calls outside a request (startup, jobs) are traces of their own; a pool call that runs on one of its
  // connections is one span, not two.
  function startMariadbSpans() {
    const { context, createContextKey, SpanKind, SpanStatusCode } = require('@opentelemetry/api');
    const mariadb = require('./mariadb.cjs'), inside = createContextKey('telvyn.mariadb'), tracer = trace.getTracer('telvyn-mariadb');
    const patched = new WeakSet();
    const patchPrototype = prototype => {
      if (!prototype || patched.has(prototype)) return;
      patched.add(prototype);
      for (const method of ['query', 'execute', 'batch']) {
        const original = prototype[method];
        if (typeof original !== 'function') continue;
        prototype[method] = function (...args) {
          const sql = mariadb.sqlOf(args), active = context.active();
          if (typeof sql !== 'string' || active.getValue(inside)) return original.apply(this, args);
          const { host, port, database } = mariadb.optionsOf(this);
          const span = tracer.startSpan(`mariadb.${method}`, {kind: SpanKind.CLIENT, attributes: {
            'db.system.name': 'mariadb', 'db.query.text': sql, 'db.operation.name': sql.trim().split(/\s+/)[0].toUpperCase(),
            ...(database ? {'db.namespace': database} : {}), 'server.address': host || 'localhost', 'server.port': port || 3306}}, active);
          // The driver's message appends the SQL text and the parameter values; `text` is the server message alone.
          const finish = error => {
            if (error) {
              const message = String(error.text ?? String(error.message ?? error).split('\n')[0]).slice(0, 512);
              span.recordException({name: error.name, code: error.code, message}); span.setStatus({code: SpanStatusCode.ERROR, message});
            }
            span.end();
          };
          const callback = typeof args.at(-1) === 'function' ? args.length - 1 : -1;
          if (callback >= 0) { const done = args[callback]; args[callback] = function (error, ...rest) { finish(error); return done.call(this, error, ...rest); }; }
          let result;
          try { result = context.with(trace.setSpan(active, span).setValue(inside, true), () => original.apply(this, args)); }
          catch (error) { finish(error); throw error; }
          if (callback < 0 && typeof result?.then === 'function') result.then(() => finish(), finish);
          else if (callback < 0) finish();
          return result;
        };
      }
    };
    const Module = require('node:module'), load = Module._load;
    Module._load = function (name, ...args) {
      const exported = load.call(this, name, ...args);
      if (name === 'mariadb' || name === 'mariadb/callback') mariadb.watch(exported, patchPrototype);
      return exported;
    };
    const { Hook } = require('import-in-the-middle');
    new Hook(['mariadb', 'mariadb/callback'], exported => { mariadb.watch(exported, patchPrototype); });
  }
  // Attack detection and blocking run before the application handles the request. Installed before the SDK so the
  // OpenTelemetry server wrapper is outside: the request span is active and records the blocked response.
  if (security?.guard) {
    for (const module of [require('node:http'), require('node:https')]) {
      const emit = module.Server.prototype.emit;
      module.Server.prototype.emit = function (event, request, response) {
        if (event === 'request' && request instanceof IncomingMessage && response instanceof ServerResponse) {
          try { if (security.guard(request, response, trace.getActiveSpan())) return true; }
          catch (_) { /* Protection never breaks the application. */ }
          return security.within(request, () => emit.apply(this, arguments));
        }
        return emit.apply(this, arguments);
      };
    }
    try { require('./frameworks.cjs').watchFrameworks(security); }
    catch (error) { console.warn('[Telvyn] Route-level attack detection could not start.' + why(error)); }
    try { require('./rasp.cjs').startRasp(security); }
    catch (error) { console.warn('[Telvyn] Exploit prevention could not start.' + why(error)); }
  }
  const sdk = new NodeSDK({
    contextManager: new (profileContext.contextManager(AsyncLocalStorageContextManager))(),
    traceExporter: new QuerySafeExporter(),
    ...(process.env.TELVYN_DEBUGGER_ENABLED === 'true' ? {metricReader: new PeriodicExportingMetricReader({exporter: new OTLPMetricExporter(), exportIntervalMillis: 10000})} : {}),
    instrumentations: [new HttpInstrumentation({
      applyCustomAttributesOnSpan(span, request, response) {
        if (!(response instanceof ServerResponse) || !isSpanContextValid(span.spanContext())) return;
        const { traceId, spanId } = span.spanContext();
        console.log(JSON.stringify({service: process.env.OTEL_SERVICE_NAME, level: response.statusCode >= 500 ? 'error' : 'info', message: 'HTTP request completed', method: request.method, status: response.statusCode, trace_id: traceId, span_id: spanId}));
      },
    }), new ExpressInstrumentation({requestHook(span, info) { iast?.request(info.request); }}),
    new PgInstrumentation({ignoreConnectSpans: true}), new MySQL2Instrumentation({maskStatement: true}), new MySQLInstrumentation(),
    new FastifyOtelInstrumentation({registerOnInitialization: true, recordExceptions: false,
      requestHook(span, request) { iast?.request(request); }})],
  });
  sdk.start();
  try { startMariadbSpans(); }
  catch (error) { console.warn('[Telvyn] mariadb spans could not start.' + why(error)); }
  let transport, debuggerAgent, stopConfiguration;
  try {
    const { runtimeTransport, reportConfiguration } = require('./runtime.cjs');
    transport = runtimeTransport();
    if (require('node:worker_threads').isMainThread) stopConfiguration = reportConfiguration(transport, security, iast);
    debuggerAgent = require('./debugger.cjs').startDebugger(transport);
  } catch (error) { console.warn('[Telvyn] Runtime configuration or Debugger could not start.' + why(error)); }
  let profiler;
  try { profiler = require('./profiler.cjs').startProfiler(); }
  catch (error) { console.warn('[Telvyn] CPU profiling could not start.' + why(error)); }
  // Remote configuration (Telvyn UI): a profile turned on starts (or restarts with wall/alloc); turned off stops delivery.
  let stopRemote;
  try {
    if (transport && require('node:worker_threads').isMainThread) stopRemote = require('./remote.cjs').startRemoteConfig(transport, async remote => {
      const want = remote.profiling;
      const needed = want.enabled === true || want.wall === true || want.alloc === true;
      const missing = !profiler?.running || want.wall === true && !profiler.wall || want.alloc === true && !profiler.alloc;
      if (want.enabled !== false && needed && missing) {
        const previous = profiler;
        await previous?.stop();
        profiler = require('./profiler.cjs').startProfiler({enabled: true, wall: want.wall ?? previous?.wall, alloc: want.alloc ?? previous?.alloc});
      }
      if (typeof remote.security.attack === 'boolean') security?.setAttack?.(remote.security.attack);
    });
  } catch (error) { console.warn('[Telvyn] Remote configuration could not start.' + why(error)); }
  // Public API: setUser, isUserBlocked, blockRequest.
  module.exports.setUser = user => security?.setUser?.(user) ?? false;
  module.exports.isUserBlocked = user => security?.isUserBlocked?.(user) ?? false;
  // User activity (login, signup): returns 'blocked' when a blocked user's login was answered.
  module.exports.trackUserLoginSuccess = (login, user) => security?.trackUser?.('login_success', login, user) ?? false;
  module.exports.trackUserLoginFailure = (login, exists) => security?.trackUser?.('login_failure', login, undefined, exists) ?? false;
  module.exports.trackUserSignup = (login, user) => security?.trackUser?.('signup', login, user) ?? false;
  module.exports.blockRequest = (request, response) => security?.blockRequest?.(request, response) ?? false;
  let shutdown;
  module.exports.stop = () => {
    if (shutdown) return shutdown;
    iast?.stop();
    debuggerAgent?.stop(); stopConfiguration?.(); stopRemote?.();
    loaderPort?.close();
    shutdown = Promise.allSettled([sdk.shutdown(), profiler?.stop(), security?.stop(), transport?.stop()]);
    return shutdown;
  };
  process.once('SIGTERM', () => {
    // Applications with their own shutdown handler retain control of process exit.
    const exitAfterFlush = process.listenerCount('SIGTERM') === 0;
    module.exports.stop().finally(() => { if (exitAfterFlush) process.exit(0); });
  });
}
