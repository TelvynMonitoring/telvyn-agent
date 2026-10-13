'use strict';
const { Session } = require('node:inspector/promises');
const { threadId } = require('node:worker_threads');
const { randomUUID } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');

function sourceFile(frame) {
  if (!process.env.TELVYN_PROFILE_SOURCE_ROOT || !frame.url?.startsWith('file:')) return '';
  try {
    const relative = path.relative(path.resolve(process.env.TELVYN_PROFILE_SOURCE_ROOT), fileURLToPath(frame.url)).split(path.sep).join('/');
    return /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:cjs|mjs|js|ts)$/.test(relative) && !relative.split('/').includes('..') ? relative : '';
  } catch (_) { return ''; }
}

function frameName(frame) {
  const file = sourceFile(frame);
  return (file ? `${file}#` : '') + (frame.functionName || '(anonymous)').replace(/[;\r\n]/g, '_');
}

function heapProfile(profile) {
  const stacks = new Map();
  const visit = (node, parent) => {
    const frames = node.callFrame.functionName === '(root)' ? parent : [...parent, frameName(node.callFrame)];
    if (node.selfSize > 0 && frames.length) {
      const key = frames.join(';');
      stacks.set(key, (stacks.get(key) || 0) + node.selfSize);
    }
    for (const child of node.children || []) visit(child, frames);
  };
  visit(profile.head, []);
  return [...stacks].map(([stack, size]) => `${stack} ${size}`).join('\n');
}

function wallProfile(profile) {
  const strings = profile.stringTable.strings;
  const index = profile.sampleType.findIndex(type => strings[type.type] === 'wall' && strings[type.unit] === 'nanoseconds');
  if (index < 0) throw new Error('Native wall profile unit unavailable');
  const functions = new Map(profile.function.map(fn => [fn.id, fn]));
  const locations = new Map(profile.location.map(location => [location.id, location]));
  const stacks = new Map();
  for (const sample of profile.sample) {
    const weight = sample.value[index];
    if (!Number.isSafeInteger(weight) || weight <= 0) continue;
    const frames = sample.locationId.slice().reverse().flatMap(id => (locations.get(id)?.line || []).map(line => {
      const fn = functions.get(line.functionId);
      if (!fn) return '';
      const filename = strings[fn.filename];
      return frameName({url: filename && path.isAbsolute(filename) ? pathToFileURL(filename).href : '', functionName: strings[fn.name]});
    })).filter(Boolean);
    if (frames.length) { const stack = frames.join(';'); stacks.set(stack, (stacks.get(stack) || 0) + weight); }
  }
  return [...stacks].map(([stack, weight]) => `${stack} ${weight}`).join('\n');
}

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
        const name = frameName(frame);
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
  if (process.env.TELVYN_PROFILING_ENABLED !== 'true') return { stop: async () => {} };
  const instance = `${randomUUID()}:${threadId}`;
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/profile';
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return i < 0 ? [pair, ''] : [pair.slice(0, i), pair.slice(i + 1)];
  }));
  const service = process.env.OTEL_SERVICE_NAME || attributes['service.name'];
  if (!service) throw new Error('Profiling requires service identity');
  const repository = process.env.TELVYN_GIT_REPOSITORY_URL;
  const revision = process.env.TELVYN_GIT_COMMIT_SHA;
  const sourceRoot = process.env.TELVYN_GIT_SOURCE_ROOT || '';
  let build;
  if (repository || revision) {
    if (!/^https:\/\/(github\.com|gitlab\.com)\/[\w.-]+(?:\/[\w.-]+)+$/.test(repository || '') || !/^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(revision || '') || !/^(?:[\w$.-]+\/)*[\w$.-]*$/.test(sourceRoot) || sourceRoot.split('/').includes('..')) throw new Error('Invalid profile build identity');
    build = {repository_url: repository, commit_sha: revision, source_root: sourceRoot};
  }
  const session = new Session();
  session.connect();
  let wall;
  if (process.env.TELVYN_PROFILE_WALL_ENABLED === 'true') {
    try { wall = require('@datadog/pprof').time; wall.start({intervalMicros: 10000, lineNumbers: true}); }
    catch (_) { wall = undefined; console.warn('[Telvyn] Native wall profiler unavailable; CPU/heap remain enabled.'); }
  }
  let stopped = false, timer, startedAt, rotating = Promise.resolve();
  const warn = () => console.warn('[Telvyn] Profile could not be collected or delivered.');
  async function begin() {
    await session.post('Profiler.start');
    startedAt = Date.now();
    if (stopped) return;
    timer = setTimeout(() => { rotating = rotate(); }, 15000); timer.unref();
  }
  async function rotate() {
    try {
      const { profile } = await session.post('Profiler.stop');
      const from = startedAt;
      const seconds = Math.max(1, Math.round((Date.now() - from) / 1000));
      if (stopped) return;
      await begin();
      const uploads = [upload('cpu', foldedProfile(profile), from, seconds, 10)];
      if (wall) {
        try { uploads.push(upload('wall', wallProfile(wall.stop(true)), from, seconds, 0)); }
        catch (_) { warn(); }
      }
      try {
        const { profile: heap } = await session.post('HeapProfiler.getSamplingProfile');
        uploads.push(upload('heap', heapProfile(heap), from, seconds, 0));
      } catch (_) { warn(); }
      for (const result of await Promise.allSettled(uploads)) if (result.status === 'rejected') warn();
    } catch (_) {
      warn();
      if (!stopped) { timer = setTimeout(() => { rotating = rotate(); }, 15000); timer.unref(); }
    }
  }
  async function upload(type, folded, from, seconds, period) {
      if (!folded) return;
      const body = JSON.stringify({service, runtime: 'nodejs', source: 'v8', profile_instance: instance, build_metadata: build, profile_type: type, period_ms: period,
        window_start_unix_ms: from, window_seconds: seconds, folded,
        env: attributes['deployment.environment.name'] || attributes['deployment.environment'], version: attributes['service.version'],
        namespace: process.env.POD_NAMESPACE || process.env.TELVYN_POD_NAMESPACE || attributes['k8s.namespace.name'] || '', pod: process.env.POD_NAME || process.env.TELVYN_POD_NAME || attributes['k8s.pod.name'] || os.hostname()});
      if (Buffer.byteLength(body) > 4 * 1024 * 1024) throw new Error('Profile too large');
      // One bounded upload per window; no unbounded backlog inside the application.
      const response = await fetch(endpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('Profile delivery failed');
      await response.arrayBuffer();
  }
  const ready = session.post('Profiler.enable').then(() => session.post('Profiler.setSamplingInterval', {interval: 10000}))
    .then(() => session.post('HeapProfiler.startSampling', {samplingInterval: 524288})).then(begin).catch(() => { warn(); session.disconnect(); });
  return { stop: async () => { stopped = true; await ready; clearTimeout(timer); await rotating; try { await session.post('Profiler.stop'); await session.post('HeapProfiler.stopSampling'); } catch (_) {} try { if (wall?.isStarted()) wall.stop(); } catch (_) {} session.disconnect(); } };
}
module.exports = { startProfiler, foldedProfile, heapProfile, wallProfile };
