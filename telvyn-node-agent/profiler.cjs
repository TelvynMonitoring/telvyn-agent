'use strict';
const { Session } = require('node:inspector/promises');
const { threadId, isInternalThread } = require('node:worker_threads');
const { randomUUID } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');
const profileContext = require('./profile-context.cjs');

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

function wallSamples(profile) {
  const strings = profile.stringTable.strings;
  const index = profile.sampleType.findIndex(type => strings[type.type] === 'wall' && strings[type.unit] === 'nanoseconds');
  if (index < 0) throw new Error('Native wall profile unit unavailable');
  const functions = new Map(profile.function.map(fn => [fn.id, fn]));
  const locations = new Map(profile.location.map(location => [location.id, location]));
  const samples = [];
  for (const sample of profile.sample) {
    const weight = sample.value[index];
    if (!Number.isSafeInteger(weight) || weight <= 0) continue;
    const frames = sample.locationId.slice().reverse().flatMap(id => (locations.get(id)?.line || []).map(line => {
      const fn = functions.get(line.functionId);
      if (!fn) return '';
      const filename = strings[fn.filename];
      return frameName({url: filename && path.isAbsolute(filename) ? pathToFileURL(filename).href : '', functionName: strings[fn.name]});
    })).filter(Boolean);
    if (!frames.length) continue;
    const labels = Object.fromEntries((sample.label || []).map(label => [strings[label.key], strings[label.str]]));
    samples.push({stack: frames.join(';'), weight, trace: labels[profileContext.TRACE_LABEL], span: labels[profileContext.SPAN_LABEL]});
  }
  return samples;
}

function foldWall(samples) {
  const stacks = new Map();
  for (const { stack, weight } of samples) stacks.set(stack, (stacks.get(stack) || 0) + weight);
  return [...stacks].map(([stack, weight]) => `${stack} ${weight}`).join('\n');
}

function wallProfile(profile) { return foldWall(wallSamples(profile)); }

function allocationProfiles(root) {
  const allocated = new Map(), live = new Map(), objects = new Map();
  const visit = (node, parent) => {
    const frame = frameName({functionName: node.name, url: node.scriptName && path.isAbsolute(node.scriptName) ? pathToFileURL(node.scriptName).href : ''});
    const frames = node.name === '(root)' || !node.name ? parent : [...parent, frame];
    for (const allocation of node.allocations || []) {
      for (const [map, key] of [[allocated, 'allocSpaceBytes'], [live, 'inuseSpaceBytes']]) {
        const weight = allocation[key];
        if (frames.length && Number.isSafeInteger(weight) && weight > 0) { const stack = frames.join(';'); map.set(stack, (map.get(stack) || 0) + weight); }
      }
      // Live objects: Node 26 reports inuseObjects, older versions report the live sample count.
      const count = Math.round(allocation.inuseObjects ?? allocation.count);
      if (frames.length && Number.isSafeInteger(count) && count > 0) { const stack = frames.join(';'); objects.set(stack, (objects.get(stack) || 0) + count); }
    }
    for (const child of node.children || []) visit(child, frames);
  };
  visit(root, []);
  const folded = map => [...map].map(([stack, weight]) => `${stack} ${weight}`).join('\n');
  return {allocated: folded(allocated), live: folded(live), objects: folded(objects)};
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
  if (process.env.TELVYN_PROFILING_ENABLED !== 'true' || isInternalThread === true) return { stop: async () => {} };
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
  let wall, wallContexts = false;
  if (process.env.TELVYN_PROFILE_WALL_ENABLED === 'true') {
    try {
      wall = require('@datadog/pprof').time;
      // Span context needs V8 continuation-preserved data; otherwise Wall Time starts without it.
      try { wall.start({intervalMicros: 10000, withContexts: true, useCPED: true}); wallContexts = true; }
      catch (_) { wall.start({intervalMicros: 10000, lineNumbers: true}); }
    } catch (_) { wall = undefined; console.warn('[Telvyn] Native wall profiler unavailable; CPU/heap remain enabled.'); }
    if (wallContexts) profileContext.enable(wall).then(supported => {
      if (supported) return;
      wallContexts = false;
      try { wall.stop(); wall.start({intervalMicros: 10000, lineNumbers: true}); }
      catch (_) { wall = undefined; console.warn('[Telvyn] Native wall profiler unavailable; CPU/heap remain enabled.'); }
    });
  }
  let allocation, allocationFrom, liveHeap;
  if (process.env.TELVYN_PROFILE_ALLOCATION_ENABLED === 'true') {
    try {
      if (Number(process.versions.node.split('.')[0]) < 26) throw new Error('Allocation profiling requires Node.js 26 or newer');
      allocation = require('@datadog/pprof').heap;
      allocation.start(524288, 64, true); allocationFrom = Date.now();
    } catch (_) { allocation = undefined; console.warn('[Telvyn] Allocation profiling unavailable (requires Node.js 26+ and native addon); CPU/heap remain enabled.'); }
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
        try {
          const samples = wallSamples(wallContexts ? wall.stop(true, profileContext.generateLabels) : wall.stop(true));
          uploads.push(upload('wall', foldWall(samples), from, seconds, 0, wallContexts ? profileContext.links(samples) : []));
        }
        catch (_) { warn(); }
      }
      try {
        if (allocation) {
          const profiles = allocationProfiles(allocation.v8Profile());
          const allocationSeconds = Math.max(1, Math.round((Date.now() - allocationFrom) / 1000));
          allocation.stop(); allocation.start(524288, 64, true);
          const previousFrom = allocationFrom; allocationFrom = Date.now();
          uploads.push(upload('alloc', profiles.allocated, previousFrom, allocationSeconds, 0));
          uploads.push(upload('heap', profiles.live, previousFrom, allocationSeconds, 0));
          uploads.push(upload('heap_objects', profiles.objects, previousFrom, allocationSeconds, 0));
        } else {
          const { profile: heap } = await session.post('HeapProfiler.getSamplingProfile');
          uploads.push(upload('heap', heapProfile(heap), from, seconds, 0));
          if (liveHeap) uploads.push(upload('heap_objects', allocationProfiles(liveHeap.v8Profile()).objects, from, seconds, 0));
        }
      } catch (_) { warn(); }
      for (const result of await Promise.allSettled(uploads)) if (result.status === 'rejected') warn();
    } catch (_) {
      warn();
      if (!stopped) { timer = setTimeout(() => { rotating = rotate(); }, 15000); timer.unref(); }
    }
  }
  async function upload(type, folded, from, seconds, period, links = []) {
      if (!folded) return;
      const body = JSON.stringify({service, runtime: 'nodejs', source: 'v8', profile_instance: instance, build_metadata: build, profile_type: type, period_ms: period,
        window_start_unix_ms: from, window_seconds: seconds, folded, ...(links.length ? {sample_links: links} : {}),
        env: attributes['deployment.environment.name'] || attributes['deployment.environment'], version: attributes['service.version'],
        namespace: process.env.POD_NAMESPACE || process.env.TELVYN_POD_NAMESPACE || attributes['k8s.namespace.name'] || '', pod: process.env.POD_NAME || process.env.TELVYN_POD_NAME || attributes['k8s.pod.name'] || os.hostname()});
      if (Buffer.byteLength(body) > 4 * 1024 * 1024) throw new Error('Profile too large');
      // One bounded upload per window; no unbounded backlog inside the application.
      const response = await fetch(endpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('Profile delivery failed');
      await response.arrayBuffer();
  }
  const ready = session.post('Profiler.enable').then(() => session.post('Profiler.setSamplingInterval', {interval: 10000}))
    .then(async () => {
      if (allocation) return;
      await session.post('HeapProfiler.startSampling', {samplingInterval: 524288});
      // The native heap profiler reads the sampler started above, which is where live object counts come from.
      try { liveHeap = require('@datadog/pprof').heap; liveHeap.start(524288, 64); } catch (_) { liveHeap = undefined; }
    }).then(begin).catch(() => { warn(); session.disconnect(); });
  return { stop: async () => { stopped = true; await ready; clearTimeout(timer); await rotating; try { await session.post('Profiler.stop'); if (allocation) allocation.stop(); else await session.post('HeapProfiler.stopSampling'); } catch (_) {} try { liveHeap?.stop(); } catch (_) {} profileContext.disable(); try { if (wall?.isStarted()) wall.stop(); } catch (_) {} session.disconnect(); } };
}
module.exports = { startProfiler, foldedProfile, heapProfile, wallProfile, wallSamples, allocationProfiles };
