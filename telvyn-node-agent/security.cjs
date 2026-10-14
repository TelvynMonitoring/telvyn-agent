'use strict';
const { randomUUID } = require('node:crypto');
const os = require('node:os');

// Findings that need no input (weak algorithms, cookie attributes) have their own rule set.
const FLAW_RULES = new Set(['WEAK_HASH', 'WEAK_CIPHER', 'INSECURE_COOKIE', 'NO_HTTPONLY_COOKIE', 'NO_SAMESITE_COOKIE']);

// Only explicitly selected routes and q are inspected; reports never contain input values.
function startSecurity() {
  const enabled = process.env.TELVYN_SECURITY_ENABLED === 'true';
  if (!enabled && process.env.TELVYN_IAST_ENABLED !== 'true') return { state: 'disabled', inspect() {}, stop() {} };
  const routes = require('./routes.cjs').compileRoutes(process.env.TELVYN_SECURITY_ROUTES);
  if (!routes.size) throw new Error('Explicit security routes required');
  const service = process.env.OTEL_SERVICE_NAME;
  if (!service) throw new Error('Security requires service identity');
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return [pair.slice(0, i), pair.slice(i + 1)];
  }));
  const environment = attributes['deployment.environment.name'] || attributes['deployment.environment'];
  if (!environment) throw new Error('Security requires environment identity');
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/security/events';
  const { DDWAF } = require('@datadog/native-appsec');
  const waf = enabled ? new DDWAF(require('./security-rules.json'), 'telvyn-query') : null;
  if (waf && (waf.diagnostics.rules?.loaded?.length !== 2 || waf.diagnostics.rules?.failed?.length)) { waf.dispose(); throw new Error('Security rules unavailable'); }
  const pending = new Set();
  let stopped = false;
  function report(outcome, rule, elapsed, span, finding) {
    if (pending.size >= 32) { console.warn('[Telvyn] Security delivery saturated; event not queued.'); return; }
    const context = span?.spanContext();
    const body = JSON.stringify({id: randomUUID(), service, host: process.env.POD_NAME || os.hostname(), environment,
      service_version: attributes['service.version'], outcome, rule_id: rule, rules_version: finding ? (rule === 'SQL_INJECTION' ? 'iast-q-node-sql-1' : FLAW_RULES.has(rule) ? 'iast-node-flaws-1' : 'iast-q-node-sinks-1') : 'query-allowlist-1',
      engine_version: DDWAF.version(), elapsed_us: elapsed,
      ...finding,
      ...(context && /^[0-9a-f]{32}$/.test(context.traceId) && !/^0+$/.test(context.traceId) ? {trace_id: context.traceId, span_id: context.spanId} : {})});
    const destination = new URL(endpoint);
    if (finding) destination.pathname = destination.pathname.replace(/events$/, 'iast');
    const send = fetch(destination, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
      .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Delivery rejected'); })
      .catch(() => console.warn('[Telvyn] Security event delivery failed.'))
      .finally(() => pending.delete(send));
    pending.add(send);
  }
  return {
    state: enabled ? 'active' : 'disabled',
    reportIast({rule_id: rule, ...finding}, elapsed, span) { if (!stopped) report('match', rule, elapsed, span, finding); },
    inspect(request, span) {
      if (stopped || !waf || typeof request.url !== 'string') return;
      const started = process.hrtime.bigint();
      let context;
      try {
        const url = new URL(request.url, 'http://application.invalid');
        if (!routes.match(url.pathname)) return;
        const values = url.searchParams.getAll('q');
        if (!values.length) return;
        if (request.url.length > 8192 || values.length > 8 || values.some(value => value.length > 4096)) { report('limit', undefined, Number((process.hrtime.bigint() - started) / 1000n), span); return; }
        context = waf.createContext();
        const result = context.run({persistent: {'server.request.query': {q: values}}}, 5000);
        const elapsed = Number((process.hrtime.bigint() - started) / 1000n);
        if (result.timeout) report('timeout', undefined, elapsed, span);
        else if (result.errorCode) report('error', undefined, elapsed, span);
        else {
          const rules = new Set((result.events || []).map(event => event.rule?.id).filter(id => ['telvyn-lab-sqli-v1', 'telvyn-lab-xss-v1'].includes(id)));
          if (!rules.size) report('no_match', undefined, elapsed, span);
          for (const rule of rules) report('match', rule, elapsed, span);
        }
      } catch (_) { report('error', undefined, Number((process.hrtime.bigint() - started) / 1000n), span); }
      finally { context?.dispose(); }
    },
    async stop() { stopped = true; await Promise.allSettled(pending); waf?.dispose(); },
  };
}
module.exports = { startSecurity };
