'use strict';
const { threadId, isInternalThread } = require('node:worker_threads');
const { randomUUID } = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');
const profileContext = require('./profile-context.cjs');

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
let sourceMapper;
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
    // With the IAST on, application modules run rewritten: V8 positions belong to that code, and the rewriter keeps
    // the way back (to the compiled file, or to the original source when it chains a source map).
    let original = {path: file, line, column};
    if (process.env.TELVYN_IAST_ENABLED === 'true') {
      try { original = require('@datadog/wasm-js-rewriter/js/source-map').getSourcePathAndLineFromSourceMaps(file, line, column) || original; } catch (_) { /* IAST unavailable */ }
    }
    if (original.path && original.path !== file) { if (path.isAbsolute(original.path) && relativeSource(original.path)) result = {file: original.path, line: original.line > 0 ? original.line : -1}; }
    else {
      const info = sourceMapper?.mappingInfo({file, line: original.line > 0 ? original.line : line, column: original.column > 0 ? original.column : column});
      if (info?.file && path.isAbsolute(info.file) && relativeSource(info.file)) result = {file: info.file, line: info.line > 0 ? info.line : -1};
      else if (original.line > 0) result = {file, line: original.line};
    }
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
// V8 reports lines of the compiled code, and the source maps give the way back. With the IAST on the code runs rewritten and
// V8 reports a line without a column, which the rewriter cannot map back reliably (measured: lines of neighbouring statements),
// so no executed line is recorded then; file names still come from the function start position.
function frameLine(frame, line) {
  if (!(line > 0) || !process.env.TELVYN_PROFILE_SOURCE_ROOT || !frame.url?.startsWith('file:')) return -1;
  try {
    if (process.env.TELVYN_IAST_ENABLED === 'true') return -1;
    const file = fileURLToPath(frame.url);
    const position = sourceMapper ? mappedPosition(file, line, 1) : {file, line};
    const named = sourceFile(frame);
    return named && named === relativeSource(position.file) && position.line > 0 ? position.line : -1;
  } catch (_) { return -1; }
}
// Line ranges of the functions in a compiled file (1-based, inclusive), read once per file. Optimized code reports the lines
// of functions inlined into a caller on the caller's node, so a line outside the caller's own range is not its executed line.
const functionRanges = new Map();
// Looked up by the position V8 gives (line and column) or, when only the function name is known, by that name.
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
  if (typeof line === 'string') {
    // Only the name is known (native wall profiler): the one function with that name in the file, none when ambiguous.
    const named = ranges.filter(range => range.name === line.split('.').pop());
    return named.length === 1 ? {start: named[0].loc.start.line, end: named[0].loc.end.line} : undefined;
  }
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
// Reads the source maps found under the source root, once. Disable with TELVYN_PROFILE_SOURCE_MAPS=false.
async function loadSourceMapper() {
  if (!process.env.TELVYN_PROFILE_SOURCE_ROOT || process.env.TELVYN_PROFILE_SOURCE_MAPS === 'false') return;
  try { sourceMapper = await require('@datadog/pprof').SourceMapper.create([path.resolve(process.env.TELVYN_PROFILE_SOURCE_ROOT)]); }
  catch (_) { sourceMapper = undefined; }
}

const frameNames = new Map();
function frameName(frame) {
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

// withLines: only the native profiler started with lineNumbers records executed lines; with trace context it reports the
// line where the function starts, which would read as an executed line, so those are left unrecorded.
function wallSamples(profile, withLines = false) {
  const strings = profile.stringTable.strings;
  const index = profile.sampleType.findIndex(type => strings[type.type] === 'wall' && strings[type.unit] === 'nanoseconds');
  if (index < 0) throw new Error('Native wall profile unit unavailable');
  const functions = new Map(profile.function.map(fn => [fn.id, fn]));
  const locations = new Map(profile.location.map(location => [location.id, location]));
  const samples = [];
  for (const sample of profile.sample) {
    const weight = sample.value[index];
    if (!Number.isSafeInteger(weight) || weight <= 0) continue;
    // Without trace context the native profiler records the line of every frame (call site, or the running line for the last one).
    const located = sample.locationId.slice().reverse().flatMap(id => (locations.get(id)?.line || []).map(line => {
      const fn = functions.get(line.functionId);
      if (!fn) return null;
      const filename = strings[fn.filename];
      const frame = {url: filename && path.isAbsolute(filename) ? pathToFileURL(filename).href : '', functionName: strings[fn.name], line: Number(fn.startLine) || Number(line.line) || 0, column: 1};
      const executed = Number(line.line), range = withLines && frame.functionName ? functionRange(frame.url, frame.functionName) : undefined;
      // Same inlining guard as the CPU profile: a line outside the function's own range is not recorded.
      const own = range && executed >= range.start && executed <= range.end;
      return {name: frameName(frame), line: own ? frameLine(frame, executed) : -1};
    })).filter(frame => frame?.name);
    const frames = located.map(frame => frame.name);
    if (!frames.length) continue;
    const labels = Object.fromEntries((sample.label || []).map(label => [strings[label.key], strings[label.str]]));
    samples.push({stack: frames.join(';'), weight, lines: located.map(frame => frame.line), trace: labels[profileContext.TRACE_LABEL], span: labels[profileContext.SPAN_LABEL]});
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
    const frame = frameName({functionName: node.name, url: node.scriptName && path.isAbsolute(node.scriptName) ? pathToFileURL(node.scriptName).href : '', line: node.lineNumber > 0 ? node.lineNumber : 0, column: node.columnNumber > 0 ? node.columnNumber : 1});
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
  return {folded: [...stacks].map(([stack, count]) => `${stack} ${count}`).join('\n'), details: lineStacksDetails(lineEntries)};
}
function foldedProfile(profile) { return cpuProfile(profile).folded; }

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
  let wall, wallContexts = false;
  if (options.wall ?? process.env.TELVYN_PROFILE_WALL_ENABLED === 'true') {
    try {
      wall = require('@datadog/pprof').time;
      // Span context needs V8 continuation-preserved data; otherwise Wall Time starts without it.
      try { wall.start({intervalMicros: periodMs * 1000, withContexts: true, useCPED: true}); wallContexts = true; }
      catch (_) { wall.start({intervalMicros: periodMs * 1000, lineNumbers: true}); }
    } catch (_) { wall = undefined; console.warn('[Telvyn] Native wall profiler unavailable; CPU/heap remain enabled.'); }
    if (wallContexts) profileContext.enable(wall).then(supported => {
      if (supported) return;
      wallContexts = false;
      try { wall.stop(); wall.start({intervalMicros: periodMs * 1000, lineNumbers: true}); }
      catch (_) { wall = undefined; console.warn('[Telvyn] Native wall profiler unavailable; CPU/heap remain enabled.'); }
    });
  }
  let allocation, allocationFrom, liveHeap;
  if (options.alloc ?? process.env.TELVYN_PROFILE_ALLOCATION_ENABLED === 'true') {
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
    timer = setTimeout(() => { rotating = rotate(); }, flushMs); timer.unref();
  }
  async function rotate() {
    try {
      const { profile } = await session.post('Profiler.stop');
      const from = startedAt;
      const seconds = Math.max(1, Math.round((Date.now() - from) / 1000));
      if (stopped) return;
      await begin();
      const cpu = cpuProfile(profile);
      const uploads = [upload('cpu', cpu.folded, from, seconds, periodMs, [], cpu.details)];
      if (wall) {
        try {
          const samples = wallSamples(wallContexts ? wall.stop(true, profileContext.generateLabels) : wall.stop(true), !wallContexts);
          uploads.push(upload('wall', foldWall(samples), from, seconds, 0, wallContexts ? profileContext.links(samples) : [], lineStacksDetails(samples.map(sample => ({folded: sample.stack, lines: sample.lines, weight: sample.weight})))));
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
  // The first window waits (briefly) for the maps so one function keeps one file name across windows.
  const mapsReady = Promise.race([loadSourceMapper(), new Promise(resolve => setTimeout(resolve, 10000).unref())]);
  const ready = mapsReady.then(() => session.post('Profiler.enable')).then(() => session.post('Profiler.setSamplingInterval', {interval: periodMs * 1000}))
    .then(async () => {
      if (allocation) return;
      await session.post('HeapProfiler.startSampling', {samplingInterval: 524288});
      // The native heap profiler reads the sampler started above, which is where live object counts come from.
      try { liveHeap = require('@datadog/pprof').heap; liveHeap.start(524288, 64); } catch (_) { liveHeap = undefined; }
    }).then(begin).catch(() => { warn(); session.disconnect(); });
  return { running: true, wall: !!wall, alloc: !!allocation, stop: async () => { stopped = true; await ready; clearTimeout(timer); await rotating; try { await session.post('Profiler.stop'); if (allocation) allocation.stop(); else await session.post('HeapProfiler.stopSampling'); } catch (_) {} try { liveHeap?.stop(); } catch (_) {} profileContext.disable(); try { if (wall?.isStarted()) wall.stop(); } catch (_) {} session.disconnect(); } };
}
module.exports = { startProfiler, cpuProfile, foldedProfile, heapProfile, wallProfile, wallSamples, allocationProfiles };
