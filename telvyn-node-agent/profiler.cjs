'use strict';
const { Session } = require('node:inspector/promises');
const { isMainThread } = require('node:worker_threads');
const os = require('node:os');

// Keep actual sample counts: V8 intervals are not exact CPU durations.
function foldedProfile(profile) {
  const nodes = new Map(profile.nodes.map(node => [node.id, node]));
  const parents = new Map();
  for (const node of profile.nodes) for (const child of node.children || []) parents.set(child, node.id);
  const stacks = new Map();
  for (const id of profile.samples || []) {
    if (nodes.get(id)?.callFrame.functionName === '(idle)') continue;
    const frames = [];
    let current = id;
    const seen = new Set();
    while (nodes.has(current) && !seen.has(current)) {
      seen.add(current);
      const frame = nodes.get(current).callFrame;
      if (frame.functionName !== '(root)') {
        const name = (frame.functionName || '(anonymous)').replace(/[;\r\n]/g, '_');
        frames.unshift(name);
      }
      current = parents.get(current);
    }
    if (frames.length) {
      const stack = frames.join(';');
      stacks.set(stack, (stacks.get(stack) || 0) + 1);
    }
  }
  return [...stacks].map(([stack, count]) => `${stack} ${count}`).join('\n');
}

function startProfiler() {
  if (!isMainThread || process.env.TELVYN_PROFILING_ENABLED !== 'true') return { stop: async () => {} };
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/profile';
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return i < 0 ? [pair, ''] : [pair.slice(0, i), pair.slice(i + 1)];
  }));
  const service = process.env.OTEL_SERVICE_NAME || attributes['service.name'];
  if (!service) throw new Error('Profiling requires service identity');
  const session = new Session();
  session.connect();
  let stopped = false, timer, startedAt;
  const warn = () => console.warn('[Telvyn] CPU profile could not be collected or delivered.');
  async function begin() {
    await session.post('Profiler.start');
    startedAt = Date.now();
    timer = setTimeout(rotate, 15000); timer.unref();
  }
  async function rotate() {
    try {
      const { profile } = await session.post('Profiler.stop');
      const from = startedAt;
      const seconds = Math.max(1, Math.round((Date.now() - from) / 1000));
      if (!stopped) await begin();
      const folded = foldedProfile(profile);
      if (!folded) return;
      const body = JSON.stringify({service, runtime: 'nodejs', source: 'v8', profile_type: 'cpu', period_ms: 10,
        window_start_unix_ms: from, window_seconds: seconds, folded,
        env: attributes['deployment.environment.name'] || attributes['deployment.environment'], version: attributes['service.version'],
        namespace: process.env.POD_NAMESPACE || '', pod: process.env.POD_NAME || os.hostname()});
      if (Buffer.byteLength(body) > 4 * 1024 * 1024) throw new Error('Profile too large');
      // One bounded upload per window; no unbounded backlog inside the application.
      const response = await fetch(endpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('Profile delivery failed');
      await response.arrayBuffer();
    } catch (_) { warn(); }
  }
  const ready = session.post('Profiler.enable').then(() => session.post('Profiler.setSamplingInterval', {interval: 10000})).then(begin).catch(() => { warn(); session.disconnect(); });
  return { stop: async () => { stopped = true; await ready; clearTimeout(timer); try { await session.post('Profiler.stop'); } catch (_) {} session.disconnect(); } };
}
module.exports = { startProfiler, foldedProfile };
