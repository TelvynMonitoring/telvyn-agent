'use strict';
// Links Wall Time samples to the span that was active in their async continuation. The native
// profiler keeps the context in V8 continuation-preserved data, which only exists with
// AsyncContextFrame (Node.js 24+, or 22/23 with --experimental-async-context-frame). Without it
// no context is attached and samples stay unattributed.
const { trace, isSpanContextValid } = require('@opentelemetry/api');

const TRACE_LABEL = 'telvyn.trace', SPAN_LABEL = 'telvyn.span';
const SPAN_LIMIT = 8192, LINK_LIMIT = 128, LINK_CHARS = 250000;
const spans = new Map();
const holders = new WeakMap();
let run;

// Checks, with a real continuation, that the profiler context survives an await.
async function enable(time) {
  try {
    const seen = await time.runWithContext({probe: true}, async () => { await null; return time.getContext(); });
    if (!seen?.probe) return false;
    run = time.runWithContext;
    return true;
  } catch (_) { return false; }
}

function disable() { run = undefined; spans.clear(); }

function holderFor(context) {
  const span = trace.getSpan(context);
  if (!span) return undefined;
  let holder = holders.get(span);
  if (holder) return holder;
  const spanContext = span.spanContext();
  if (!isSpanContextValid(spanContext)) return undefined;
  holder = {trace: spanContext.traceId, span: spanContext.spanId};
  holders.set(span, holder);
  if (spans.size >= SPAN_LIMIT) spans.delete(spans.keys().next().value);
  spans.set(holder.trace + ':' + holder.span, {span, parent: span.parentSpanContext?.spanId});
  return holder;
}

// Runs each OpenTelemetry activation inside a profiler context carrying its trace and span ids.
function contextManager(Base) {
  return class extends Base {
    with(context, fn, thisArg, ...args) {
      const holder = run && holderFor(context);
      if (!holder) return super.with(context, fn, thisArg, ...args);
      let started = false;
      try {
        return run(holder, () => { started = true; return super.with(context, fn, thisArg, ...args); });
      } catch (error) {
        if (started) throw error;
        return super.with(context, fn, thisArg, ...args);
      }
    }
  };
}

function generateLabels({ context }) {
  const holder = context?.context;
  return holder ? {[TRACE_LABEL]: holder.trace, [SPAN_LABEL]: holder.span} : {};
}

// "METHOD route" from the server span ancestry; raw URLs are never used.
function endpointOf(traceId, id) {
  const visited = new Set();
  while (id && visited.add(id) && visited.size <= 128) {
    const entry = spans.get(traceId + ':' + id);
    if (!entry) return undefined;
    const { span } = entry;
    if (span.kind === 1) {
      const attributes = span.attributes || {};
      const route = attributes['http.route'], method = attributes['http.request.method'] || attributes['http.method'];
      const endpoint = typeof route === 'string' && typeof method === 'string' && /^[A-Z]{1,20}$/.test(method) && route.trim() ? `${method} ${route}` : undefined;
      return endpoint && endpoint.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(endpoint) ? endpoint : undefined;
    }
    id = entry.parent;
  }
  return undefined;
}

// samples: [{stack, weight, trace, span}] with the same stacks and weights as the uploaded profile.
function links(samples) {
  const byContext = new Map();
  for (const sample of samples) {
    if (!sample.trace || !sample.span) continue;
    const key = sample.trace + ':' + sample.span;
    let entry = byContext.get(key);
    if (!entry) byContext.set(key, entry = {trace: sample.trace, span: sample.span, total: 0, stacks: new Map()});
    entry.total += sample.weight;
    entry.stacks.set(sample.stack, (entry.stacks.get(sample.stack) || 0) + sample.weight);
  }
  const result = [];
  let chars = 0;
  for (const entry of [...byContext.values()].sort((a, b) => b.total - a.total)) {
    if (result.length >= LINK_LIMIT) break;
    const folded = [...entry.stacks].map(([stack, weight]) => `${stack} ${weight}`).join('\n');
    if (chars + folded.length > LINK_CHARS) continue;
    chars += folded.length;
    const link = {trace_id: entry.trace, span_id: entry.span, folded};
    const endpoint = endpointOf(entry.trace, entry.span);
    if (endpoint) link.endpoint = endpoint;
    result.push(link);
  }
  return result;
}

module.exports = { enable, disable, contextManager, generateLabels, links, TRACE_LABEL, SPAN_LABEL };
