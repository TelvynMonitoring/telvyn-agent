if ((process.env.OTEL_SDK_DISABLED || '').toLowerCase() !== 'true') {
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  const { AsyncLocalStorageContextManager } = require('@opentelemetry/context-async-hooks');
  const profileContext = require('./profile-context.cjs');
  const { isSpanContextValid, trace } = require('@opentelemetry/api');
  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-proto');
  const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
  const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
  const FastifyOtelInstrumentation = require('@fastify/otel');
  const { PeriodicExportingMetricReader } = require('@opentelemetry/sdk-metrics');
  const { OTLPMetricExporter } = require('@opentelemetry/exporter-metrics-otlp-proto');
  const { ServerResponse, IncomingMessage } = require('node:http');
  let security;
  try { security = require('./security.cjs').startSecurity(); }
  catch (_) { console.warn('[Telvyn] Security sensor could not start; application startup continues.'); }
  let iast;
  try {
    if (process.env.TELVYN_IAST_ENABLED === 'true' && !security?.reportIast) throw new Error('IAST reporter unavailable');
    iast = require('./iast.cjs').startIast((finding, elapsed) => security.reportIast(finding, elapsed, trace.getActiveSpan()));
  } catch (_) { console.warn('[Telvyn] IAST sensor could not start; application startup continues.'); }
  let loaderPort;
  if (require('node:worker_threads').isMainThread && typeof require('node:module').register === 'function') {
    try {
      const { port1, port2 } = new (require('node:worker_threads').MessageChannel)();
      loaderPort = port1;
      port1.on('message', message => {
        if (message.error) { if (iast) iast.state = 'error'; console.warn('[Telvyn] ESM taint instrumentation failed.'); }
        else if (message.filename && message.source) require('@datadog/wasm-js-rewriter/js/source-map').cacheRewrittenSourceMap(message.filename, message.source);
      });
      port1.unref();
      require('node:module').register(require('node:url').pathToFileURL(require('node:path').join(__dirname, 'loader.mjs')), {data: {sourceRoot: process.env.TELVYN_PROFILE_SOURCE_ROOT, iast: iast?.state === 'active', port: port2}, transferList: [port2]});
    } catch (_) { console.warn('[Telvyn] ESM instrumentation could not start.'); loaderPort?.close(); }
  }

  class QuerySafeExporter extends OTLPTraceExporter {
    export(spans, callback) {
      for (const span of spans) {
        span.attributes['telvyn.sdk.name'] = 'telvyn-node-agent';
        span.attributes['telvyn.sdk.version'] = require('./package.json').version;
        span.attributes['process.runtime.version'] = process.version;
        for (const key of ['http.url', 'http.target', 'url.full']) {
          if (typeof span.attributes[key] === 'string') span.attributes[key] = span.attributes[key].split('?')[0];
        }
        delete span.attributes['url.query'];
      }
      super.export(spans, callback);
    }
  }

  const sdk = new NodeSDK({
    contextManager: new (profileContext.contextManager(AsyncLocalStorageContextManager))(),
    traceExporter: new QuerySafeExporter(),
    ...(process.env.TELVYN_DEBUGGER_ENABLED === 'true' ? {metricReader: new PeriodicExportingMetricReader({exporter: new OTLPMetricExporter(), exportIntervalMillis: 10000})} : {}),
    instrumentations: [new HttpInstrumentation({
      requestHook(span, request) {
        if (request instanceof IncomingMessage) security?.inspect(request, span);
      },
      applyCustomAttributesOnSpan(span, request, response) {
        if (!(response instanceof ServerResponse) || !isSpanContextValid(span.spanContext())) return;
        const { traceId, spanId } = span.spanContext();
        console.log(JSON.stringify({service: process.env.OTEL_SERVICE_NAME, level: response.statusCode >= 500 ? 'error' : 'info', message: 'HTTP request completed', method: request.method, status: response.statusCode, trace_id: traceId, span_id: spanId}));
      },
    }), new ExpressInstrumentation({requestHook(span, info) { iast?.request(info.request); }}),
    new FastifyOtelInstrumentation({registerOnInitialization: true, recordExceptions: false,
      requestHook(span, request) { iast?.request(request); }})],
  });
  sdk.start();
  let transport, debuggerAgent, stopConfiguration;
  try {
    const { runtimeTransport, reportConfiguration } = require('./runtime.cjs');
    transport = runtimeTransport();
    if (require('node:worker_threads').isMainThread) stopConfiguration = reportConfiguration(transport, security, iast);
    debuggerAgent = require('./debugger.cjs').startDebugger(transport);
  } catch (_) { console.warn('[Telvyn] Runtime configuration or Debugger could not start.'); }
  let profiler;
  try { profiler = require('./profiler.cjs').startProfiler(); }
  catch (_) { console.warn('[Telvyn] CPU profiling could not start.'); }
  let shutdown;
  module.exports.stop = () => {
    if (shutdown) return shutdown;
    iast?.stop();
    debuggerAgent?.stop(); stopConfiguration?.();
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
