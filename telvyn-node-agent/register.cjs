if ((process.env.OTEL_SDK_DISABLED || '').toLowerCase() !== 'true') {
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  const { isSpanContextValid } = require('@opentelemetry/api');
  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-proto');
  const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
  const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
  const { ServerResponse } = require('node:http');

  class QuerySafeExporter extends OTLPTraceExporter {
    export(spans, callback) {
      for (const span of spans) {
        span.attributes['telvyn.sdk.name'] = 'telvyn-node-agent';
        span.attributes['telvyn.sdk.version'] = '0.1.0';
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
    traceExporter: new QuerySafeExporter(),
    instrumentations: [new HttpInstrumentation({
      applyCustomAttributesOnSpan(span, request, response) {
        if (!(response instanceof ServerResponse) || !isSpanContextValid(span.spanContext())) return;
        const { traceId, spanId } = span.spanContext();
        console.log(JSON.stringify({service: process.env.OTEL_SERVICE_NAME, level: response.statusCode >= 500 ? 'error' : 'info', message: 'HTTP request completed', method: request.method, status: response.statusCode, trace_id: traceId, span_id: spanId}));
      },
    }), new ExpressInstrumentation()],
  });
  sdk.start();
  let profiler;
  try { profiler = require('./profiler.cjs').startProfiler(); }
  catch (_) { console.warn('[Telvyn] CPU profiling could not start.'); }
  process.once('SIGTERM', () => {
    // Applications with their own shutdown handler retain control of process exit.
    const exitAfterFlush = process.listenerCount('SIGTERM') === 0;
    Promise.all([sdk.shutdown(), profiler?.stop()]).catch(() => console.error('Telvyn telemetry flush failed')).finally(() => { if (exitAfterFlush) process.exit(0); });
  });
}
