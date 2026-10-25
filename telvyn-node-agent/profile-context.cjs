'use strict';
// Links Wall Time samples to the span that was running when each sample was taken. The context manager and the
// async hooks note every change of the active span with a timestamp; the profiler looks each sample's time up in that
// timeline. Nothing is attached to the samples themselves, so it works on every supported Node.js version.
const { createHook } = require('node:async_hooks');
const { context, trace, isSpanContextValid } = require('@opentelemetry/api');

const SPAN_LIMIT = 8192, LINK_LIMIT = 128, LINK_CHARS = 250000, TIMELINE_LIMIT = 262144;
const spans = new Map();
const holders = new WeakMap();
let recording = false, current = null, timeline = [], hook;

const clock = () => Number(process.hrtime.bigint()) / 1e6;
function note(holder) {
  if (!recording || holder === current && timeline.length) return;
  current = holder;
  if (timeline.length < TIMELINE_LIMIT) timeline.push({at: clock(), holder});
}

function enable() {
  if (recording) return true;
  try {
    // The continuation of an await runs without the context manager being called: the hooks note it.
    hook = createHook({
      before() { try { note(holderFor(context.active())); } catch (_) { /* the sample stays unattributed */ } },
      after() { note(null); },
    });
    hook.enable();
    recording = true; current = null; timeline = [];
    return true;
  } catch (_) { return false; }
}

function disable() { recording = false; hook?.disable(); hook = undefined; spans.clear(); timeline = []; current = null; }

// The notes since the last call, oldest first; the next ones start from the span that is active now.
function take() {
  const taken = timeline;
  timeline = current === null ? [] : [{at: clock(), holder: current}];
  return taken;
}

// The span active at the given time (ms, same clock as process.hrtime), by binary search.
function holderAt(notes, at) {
  let low = 0, high = notes.length - 1, found;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (notes[middle].at <= at) { found = notes[middle]; low = middle + 1; } else high = middle - 1;
  }
  return found?.holder ?? undefined;
}

function holderFor(ctx) {
  const span = trace.getSpan(ctx);
  if (!span) return null;
  let holder = holders.get(span);
  if (holder) return holder;
  const spanContext = span.spanContext();
  if (!isSpanContextValid(spanContext)) return null;
  holder = {trace: spanContext.traceId, span: spanContext.spanId};
  holders.set(span, holder);
  if (spans.size >= SPAN_LIMIT) spans.delete(spans.keys().next().value);
  spans.set(holder.trace + ':' + holder.span, {span, parent: span.parentSpanContext?.spanId});
  return holder;
}

// Notes each OpenTelemetry activation, for the time the code runs inside it.
function contextManager(Base) {
  return class extends Base {
    with(ctx, fn, thisArg, ...args) {
      if (!recording) return super.with(ctx, fn, thisArg, ...args);
      const previous = current;
      try { note(holderFor(ctx)); } catch (_) { /* unattributed */ }
      try { return super.with(ctx, fn, thisArg, ...args); }
      finally { note(previous); }
    }
  };
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

module.exports = { enable, disable, take, holderAt, clock, contextManager, links };
