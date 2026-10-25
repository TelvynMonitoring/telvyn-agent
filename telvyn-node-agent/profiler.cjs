'use strict';
const { threadId, isInternalThread } = require('node:worker_threads');
const { randomUUID } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');
const profileContext = require('./profile-context.cjs');
const { originalPosition } = require('./sourcemap.cjs');

// node:inspector/promises exists from Node.js 19; Node.js 18 only has the callback API.
function inspectorSession() {
  try { return new (require('node:inspector/promises').Session)(); }
  catch (_) {
    const session = new (require('node:inspector').Session)();
    const post = session.post.bind(session);
    session.post = (method, params) => new Promise((resolve, reject) => post(method, params ?? {}, (error, result) => error ? reject(error) : resolve(result)));
    return session;
  }
}

// Original sources of transpiled code (TypeScript and similar) are valid frame files too.
const SOURCE_FILE = /^(?:[\w$.-]+\/)*[\w$.-]+\.(?:cjs|mjs|js|jsx|ts|tsx|mts|cts)$/;
let sourceMapper = false;
const mappedFiles = new Map();
const relativeSource = file => {
  const relative = path.relative(path.resolve(process.env.TELVYN_PROFILE_SOURCE_ROOT), file).split(path.sep).join('/');
  return SOURCE_FILE.test(relative) && !relative.split('/').includes('..') ? relative : '';
};
// Function start positions go through the source map; a result outside the source root keeps the compiled file.
// The line comes with the file: a position that resolves to another file keeps its own line (-1 when the map has none).
function mappedPosition(file, line, column) {
  const key = `${file}:${line}:${column}`;
  if (mappedFiles.has(key)) return mappedFiles.get(key);
  let result = {file, line};
  try {
    const original = originalPosition(file, line, column);
    if (original && path.isAbsolute(original.path) && relativeSource(original.path)) result = {file: original.path, line: original.line > 0 ? original.line : -1};
  } catch (_) { /* keep the compiled position */ }
  if (mappedFiles.size >= 20000) mappedFiles.clear();
  mappedFiles.set(key, result);
  return result;
}
function mappedFile(file, line, column) { return mappedPosition(file, line, column).file; }
// Frame line and column are 1-based here.
function sourceFile(frame) {
  if (!process.env.TELVYN_PROFILE_SOURCE_ROOT || !frame.url?.startsWith('file:')) return '';
  try {
    let file = fileURLToPath(frame.url);
    if (sourceMapper && frame.line > 0) file = mappedFile(file, frame.line, frame.column > 0 ? frame.column : 1);
    return relativeSource(file);
  } catch (_) { return ''; }
}
// Executed line (1-based) of a frame, -1 when it cannot be tied to the source file the frame name carries.
// V8 reports lines of the compiled code, and the source maps give the way back.
function frameLine(frame, line) {
  if (!(line > 0) || !process.env.TELVYN_PROFILE_SOURCE_ROOT || !frame.url?.startsWith('file:')) return -1;
  try {
    const file = fileURLToPath(frame.url);
    const position = sourceMapper ? mappedPosition(file, line, 1) : {file, line};
    const named = sourceFile(frame);
    return named && named === relativeSource(position.file) && position.line > 0 ? position.line : -1;
  } catch (_) { return -1; }
}
// Line ranges of the functions in a compiled file (1-based, inclusive), read once per file. Optimized code reports the lines
// of functions inlined into a caller on the caller's node, so a line outside the caller's own range is not its executed line.
const functionRanges = new Map();
// Looked up by the position V8 gives (line and column).
function functionRange(url, line, column) {
  if (!url?.startsWith('file:')) return undefined;
  let ranges = functionRanges.get(url);
  if (ranges === undefined) {
    ranges = null;
    try {
      const file = fileURLToPath(url), fs = require('node:fs');
      if (fs.statSync(file).size <= 5 * 1024 * 1024) {
        const source = fs.readFileSync(file, 'utf8');
        let tree;
        for (const sourceType of ['module', 'script']) {
          try { tree = require('acorn').parse(source, {ecmaVersion: 'latest', sourceType, locations: true, allowHashBang: true, allowReturnOutsideFunction: sourceType === 'script', allowAwaitOutsideFunction: true}); break; }
          catch (_) { /* try the other module type */ }
        }
        if (tree) {
          ranges = [];
          (function visit(node, name) {
            // The name V8 gives a function: its own, or the variable, property or method it is assigned to.
            if (/Function/.test(node.type) && node.loc) ranges.push({loc: node.loc, name: node.id?.name || name});
            const named = node.type === 'VariableDeclarator' ? node.id?.name
              : ['Property', 'MethodDefinition', 'PropertyDefinition'].includes(node.type) ? node.key?.name : undefined;
            for (const key of Object.keys(node)) {
              const value = node[key];
              const childName = named && (key === 'init' || key === 'value') ? named : undefined;
              if (Array.isArray(value)) { for (const item of value) if (item && typeof item.type === 'string') visit(item); }
              else if (value && typeof value.type === 'string') visit(value, childName);
            }
          })(tree);
        }
      }
    } catch (_) { ranges = null; }
    if (functionRanges.size >= 2000) functionRanges.clear();
    functionRanges.set(url, ranges);
  }
  if (!ranges) return undefined;
  // V8 places a function at a position inside its own node (the parameter list); the innermost enclosing function is it.
  const inside = loc => (line > loc.start.line || line === loc.start.line && column - 1 >= loc.start.column) && (line < loc.end.line || line === loc.end.line && column - 1 <= loc.end.column);
  let best;
  for (const {loc} of ranges) if (inside(loc) && (!best || loc.start.line > best.start.line || loc.start.line === best.start.line && loc.start.column >= best.start.column)) best = loc;
  return best && {start: best.start.line, end: best.end.line};
}

// Observed line weights, stack by stack. The ingest keeps only weights that fit the preserved stack and ignores the rest.
const MAX_LINE_STACKS = 4096, MAX_LINE_STACK_FRAMES = 256, MAX_LINE_STACK_CHARS = 250000;
function lineStacksDetails(entries) {
  const stacks = new Map();
  for (const {folded, lines, weight} of entries) {
    if (!(weight >= 1) || lines.length > MAX_LINE_STACK_FRAMES || !lines.some(line => line > 0)) continue;
    const key = `${folded}\n${lines.join(',')}`;
    const known = stacks.get(key);
    if (known) known.weight += weight; else stacks.set(key, {folded, weight, lines});
  }
  const kept = [];
  let chars = 0;
  for (const origin of [...stacks.values()].sort((a, b) => b.weight - a.weight)) {
    chars += JSON.stringify(origin).length + 1;
    if (kept.length >= MAX_LINE_STACKS || chars > MAX_LINE_STACK_CHARS) break;
    kept.push(origin);
  }
  return kept.length ? {line_stacks: kept} : undefined;
}
// Source maps are read the first time a compiled file shows up in a profile. Disable with TELVYN_PROFILE_SOURCE_MAPS=false.
function enableSourceMaps() {
  sourceMapper = !!process.env.TELVYN_PROFILE_SOURCE_ROOT && process.env.TELVYN_PROFILE_SOURCE_MAPS !== 'false';
}

const frameNames = new Map();
function frameName(frame) {
  // The heap profiler names the script by its path, the CPU profiler by a file URL.
  if (frame.url && path.isAbsolute(frame.url)) frame = {...frame, url: pathToFileURL(frame.url).href};
  // Inspector frames carry 0-based positions; callers that already know the 1-based position pass line and column.
  const line = frame.line ?? (Number.isInteger(frame.lineNumber) ? frame.lineNumber + 1 : 0);
  const column = frame.column ?? (Number.isInteger(frame.columnNumber) ? frame.columnNumber + 1 : 0);
  // Every sample repeats its frames: resolve each distinct frame once per source map state.
  const key = `${frame.url}|${line}|${column}|${frame.functionName}|${sourceMapper ? 1 : 0}`;
  const known = frameNames.get(key);
  if (known !== undefined) return known;
  const file = sourceFile({url: frame.url, line, column});
  const name = (file ? `${file}#` : '') + (frame.functionName || '(anonymous)').replace(/[;\r\n]/g, '_');
  if (frameNames.size >= 50000) frameNames.clear();
  frameNames.set(key, name);
  return name;
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

// Estimated number of live objects per stack from the samples of the heap profile: a sample of `size` bytes stands for
// 1 / (1 - e^(-size / interval)) objects (the same scale V8 applies to bytes).
function heapObjects(profile) {
  const frames = new Map();
  const visit = (node, parent) => {
    const names = node.callFrame.functionName === '(root)' ? parent : [...parent, frameName(node.callFrame)];
    frames.set(node.id, names);
    for (const child of node.children || []) visit(child, names);
  };
  visit(profile.head, []);
  const interval = profile.samplingInterval || 524288, counts = new Map();
  for (const {nodeId, size} of profile.samples || []) {
    const names = frames.get(nodeId);
    if (!names?.length || !(size > 0)) continue;
    const stack = names.join(';');
    counts.set(stack, (counts.get(stack) || 0) + 1 / (1 - Math.exp(-size / interval)));
  }
  return [...counts].map(([stack, count]) => [stack, Math.round(count)]).filter(([, count]) => count > 0).map(([stack, count]) => `${stack} ${count}`).join('\n');
}

// Keep actual sample counts: V8 intervals are not exact CPU durations.
// V8 gives the executed lines only for the node that was running (positionTicks), so only the last frame of a stack
// carries a line; the callers' call-site lines are not part of this profile and stay unrecorded.
function cpuProfile(profile) {
  const nodes = new Map(profile.nodes.map(node => [node.id, node]));
  const parents = new Map();
  for (const node of profile.nodes) for (const child of node.children || []) parents.set(child, node.id);
  const counts = new Map();
  for (const id of profile.samples || []) {
    if (nodes.get(id)?.callFrame.functionName === '(idle)') continue;
    counts.set(id, (counts.get(id) || 0) + 1);
  }
  const stacks = new Map(), lineEntries = [];
  for (const [id, count] of counts) {
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
    if (!frames.length) continue;
    const stack = frames.join(';');
    stacks.set(stack, (stacks.get(stack) || 0) + count);
    const node = nodes.get(id), ticks = node.positionTicks;
    if (!ticks?.length) continue;
    const frame = {url: node.callFrame.url, line: node.callFrame.lineNumber + 1, column: node.callFrame.columnNumber + 1};
    let used = 0, range;
    for (const {line, ticks: weight} of [...ticks].sort((a, b) => b.ticks - a.ticks)) {
      // Optimized code reports the lines of functions inlined into this one on this node (measured: an inlined callee's
      // line attributed to its caller); without the function's range the line is not recorded.
      if (range === undefined) range = functionRange(node.callFrame.url, frame.line, frame.column) || null;
      if (!range || line < range.start || line > range.end) continue;
      const mapped = frameLine(frame, line);
      const share = Math.min(weight, count - used);
      if (mapped < 1 || share < 1) continue;
      used += share;
      lineEntries.push({folded: stack, weight: share, lines: [...Array(frames.length - 1).fill(-1), mapped]});
    }
  }
  return {folded: [...stacks].map(([stack, count]) => `${stack} ${count}`).join('\n'), details: lineStacksDetails(lineEntries), lineEntries};
}
function foldedProfile(profile) { return cpuProfile(profile).folded; }

// Time on the thread, in nanoseconds per stack: each sample stands for the time until the next one. A sample is
// linked to the span the timeline says was active at its time (`offset` moves profile time onto the timeline's clock).
function wallSamples(profile, notes = [], offset = 0) {
  const nodes = new Map(profile.nodes.map(node => [node.id, node]));
  const parents = new Map();
  for (const node of profile.nodes) for (const child of node.children || []) parents.set(child, node.id);
  const stackOf = new Map();
  const stackFor = id => {
    if (stackOf.has(id)) return stackOf.get(id);
    const frames = [], seen = new Set();
    for (let current = id; nodes.has(current) && !seen.has(current); current = parents.get(current)) {
      seen.add(current);
      const frame = nodes.get(current).callFrame;
      if (frame.functionName !== '(root)') frames.unshift(frameName(frame));
    }
    const stack = frames.join(';');
    stackOf.set(id, stack);
    return stack;
  };
  const samples = profile.samples || [], deltas = profile.timeDeltas || [];
  const grouped = new Map();
  let at = profile.startTime;
  for (let i = 0; i < samples.length; i++) {
    at += deltas[i] || 0;
    const node = nodes.get(samples[i]);
    if (!node || node.callFrame.functionName === '(idle)') continue;
    // Capped: a stalled profiler must not turn into hours of "time".
    const weight = Math.min(Math.round((deltas[i + 1] ?? deltas[i] ?? 0) * 1000), 1e9);
    const stack = stackFor(samples[i]);
    if (!(weight > 0) || !stack) continue;
    const holder = notes.length ? profileContext.holderAt(notes, at / 1000 + offset) : undefined;
    const key = `${stack}\n${holder?.trace ?? ''}:${holder?.span ?? ''}`;
    const known = grouped.get(key);
    if (known) known.weight += weight; else grouped.set(key, {stack, weight, trace: holder?.trace, span: holder?.span});
  }
  return [...grouped.values()];
}

function foldWall(samples) {
  const stacks = new Map();
  for (const { stack, weight } of samples) stacks.set(stack, (stacks.get(stack) || 0) + weight);
  return [...stacks].map(([stack, weight]) => `${stack} ${weight}`).join('\n');
}

function wallProfile(profile) { return foldWall(wallSamples(profile)); }

// Executed lines of the wall profile: the lines the CPU profile recorded, weighted by the time each stack took.
function wallDetails(cpu, samples) {
  const time = new Map();
  for (const { stack, weight } of samples) time.set(stack, (time.get(stack) || 0) + weight);
  const ticks = new Map();
  for (const entry of cpu.lineEntries) ticks.set(entry.folded, (ticks.get(entry.folded) || 0) + entry.weight);
  const entries = [];
  for (const entry of cpu.lineEntries) {
    const total = time.get(entry.folded);
    if (total) entries.push({...entry, weight: Math.round(total * entry.weight / ticks.get(entry.folded))});
  }
  return lineStacksDetails(entries);
}

// Same names, ranges and fallback as the Javaagent (JfrCpuProfiler.intConf): an out-of-range integer is clamped,
// anything that is not a 32-bit integer uses the default.
function intSetting(name, fallback, min, max) {
  const raw = process.env[name]?.trim();
  if (!raw || !/^[+-]?\d+$/.test(raw)) return fallback;
  const value = Number(raw);
  if (value < -2147483648 || value > 2147483647) return fallback;
  return Math.max(min, Math.min(max, value));
}

// options override the environment when remote configuration turns a profile on (wall, alloc).
function startProfiler(options = {}) {
  const enabled = options.enabled ?? process.env.TELVYN_PROFILING_ENABLED === 'true';
  if (!enabled || isInternalThread === true) return { running: false, stop: async () => {} };
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
  const periodMs = intSetting('TELVYN_PROFILING_PERIOD_MS', 10, 1, 1000);
  const flushMs = intSetting('TELVYN_PROFILING_FLUSH_SEC', 15, 2, 600) * 1000;
  const session = inspectorSession();
  session.connect();
  // Wall Time comes from the same sampling as CPU, weighted by elapsed time; its samples are linked to spans through
  // the timeline of active spans. Allocated memory samples every allocation, live heap only the objects still alive.
  const wall = !!(options.wall ?? process.env.TELVYN_PROFILE_WALL_ENABLED === 'true');
  const allocation = !!(options.alloc ?? process.env.TELVYN_PROFILE_ALLOCATION_ENABLED === 'true');
  const wallContexts = wall && profileContext.enable();
  enableSourceMaps();
  let allocationFrom;
  let stopped = false, timer, startedAt, startedClock, rotating = Promise.resolve();
  const warn = () => console.warn('[Telvyn] Profile could not be collected or delivered.');
  async function begin() {
    await session.post('Profiler.start');
    startedAt = Date.now(); startedClock = profileContext.clock();
    if (stopped) return;
    timer = setTimeout(() => { rotating = rotate(); }, flushMs); timer.unref();
  }
  async function rotate() {
    try {
      const { profile } = await session.post('Profiler.stop');
      const from = startedAt, started = startedClock, notes = wallContexts ? profileContext.take() : [];
      const seconds = Math.max(1, Math.round((Date.now() - from) / 1000));
      if (stopped) return;
      await begin();
      const cpu = cpuProfile(profile);
      const uploads = [upload('cpu', cpu.folded, from, seconds, periodMs, [], cpu.details)];
      if (wall) {
        try {
          // The profile and the timeline share a clock on most systems; when they do not, the start of the window aligns them.
          const gap = started - profile.startTime / 1000;
          const samples = wallSamples(profile, notes, Math.abs(gap) < 1000 ? 0 : gap);
          uploads.push(upload('wall', foldWall(samples), from, seconds, 0, wallContexts ? profileContext.links(samples) : [], wallDetails(cpu, samples)));
        }
        catch (_) { warn(); }
      }
      try {
        if (allocation) {
          // Every allocation since the window began, including objects already collected.
          const { profile: allocated } = await session.post('HeapProfiler.stopSampling');
          const allocationSeconds = Math.max(1, Math.round((Date.now() - allocationFrom) / 1000));
          const previousFrom = allocationFrom; allocationFrom = Date.now();
          await startHeapSampling();
          uploads.push(upload('alloc', heapProfile(allocated), previousFrom, allocationSeconds, 0));
        } else {
          const { profile: heap } = await session.post('HeapProfiler.getSamplingProfile');
          uploads.push(upload('heap', heapProfile(heap), from, seconds, 0));
          uploads.push(upload('heap_objects', heapObjects(heap), from, seconds, 0));
        }
      } catch (_) { warn(); }
      for (const result of await Promise.allSettled(uploads)) if (result.status === 'rejected') warn();
    } catch (_) {
      warn();
      if (!stopped) { timer = setTimeout(() => { rotating = rotate(); }, flushMs); timer.unref(); }
    }
  }
  async function upload(type, folded, from, seconds, period, links = [], details) {
      if (!folded || !require('./remote.cjs').profileAllowed(type)) return;
      const body = JSON.stringify({service, runtime: 'nodejs', source: 'v8', profile_instance: instance, build_metadata: build, profile_type: type, period_ms: period,
        window_start_unix_ms: from, window_seconds: seconds, folded, ...(links.length ? {sample_links: links} : {}), ...(details ? {details} : {}),
        env: attributes['deployment.environment.name'] || attributes['deployment.environment'], version: attributes['service.version'],
        namespace: process.env.POD_NAMESPACE || process.env.TELVYN_POD_NAMESPACE || attributes['k8s.namespace.name'] || '', pod: process.env.POD_NAME || process.env.TELVYN_POD_NAME || attributes['k8s.pod.name'] || os.hostname()});
      if (Buffer.byteLength(body) > 4 * 1024 * 1024) throw new Error('Profile too large');
      // One bounded upload per window; no unbounded backlog inside the application.
      const response = await fetch(endpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('Profile delivery failed');
      await response.arrayBuffer();
  }
  // V8 keeps one heap sampler: it runs in the mode the settings ask for.
  const startHeapSampling = () => session.post('HeapProfiler.startSampling', {samplingInterval: 524288, ...(allocation ? {includeObjectsCollectedByMajorGC: true, includeObjectsCollectedByMinorGC: true} : {})});
  const ready = session.post('Profiler.enable').then(() => session.post('Profiler.setSamplingInterval', {interval: periodMs * 1000}))
    .then(() => { allocationFrom = Date.now(); return startHeapSampling(); }).then(begin).catch(() => { warn(); session.disconnect(); });
  return { running: true, wall, alloc: allocation, stop: async () => { stopped = true; await ready; clearTimeout(timer); await rotating; try { await session.post('Profiler.stop'); await session.post('HeapProfiler.stopSampling'); } catch (_) {} profileContext.disable(); session.disconnect(); } };
}
module.exports = { startProfiler, cpuProfile, foldedProfile, heapProfile, heapObjects, wallProfile, wallSamples };
