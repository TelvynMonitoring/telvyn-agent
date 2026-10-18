'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { fileURLToPath } = require('node:url');

// Runtime SCA (as Datadog): the packages the application loaded — CommonJS through require.cache, ES modules through
// the loader thread — each with the name and version of its package.json, sent to the collector in batches. Matching
// against advisories runs in the backend, so a new advisory shows without a new report.
const FIRST_MS = 15000, EVERY_MS = 60000, RESEND_MS = 12 * 3600000, BATCH = 400;
const NAME = /^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]{0,213}\/)?[A-Za-z0-9~][A-Za-z0-9._~-]{0,213}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}$/;
const MARK = `${path.sep}node_modules${path.sep}`;
// The SDK itself is not reported, as the Java agent leaves out its own jar; what it loads is.
const OWN = path.resolve(__dirname);

function startSca() {
  if (process.env.TELVYN_SCA_ENABLED !== 'true') return null;
  const service = process.env.OTEL_SERVICE_NAME;
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return [pair.slice(0, i), pair.slice(i + 1)];
  }));
  const environment = attributes['deployment.environment.name'] || attributes['deployment.environment'];
  if (!service) throw new Error('SCA requires service identity');
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/security/libraries';
  const roots = new Set();
  const known = new Set();
  let found = [];
  // The package a file belongs to: the folder after the last node_modules (two levels for a scoped package).
  function note(filename) {
    if (typeof filename !== 'string') return;
    const at = filename.lastIndexOf(MARK);
    if (at < 0) return;
    const parts = filename.slice(at + MARK.length).split(path.sep);
    const depth = parts[0]?.startsWith('@') ? 2 : 1;
    if (parts.length <= depth) return;
    const root = filename.slice(0, at + MARK.length) + parts.slice(0, depth).join(path.sep);
    if (roots.has(root) || root === OWN) return;
    roots.add(root);
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string' || !NAME.test(pkg.name) || !VERSION.test(pkg.version)) return;
      const key = `${pkg.name}@${pkg.version}`;
      if (!known.has(key)) { known.add(key); found.push([pkg.name, pkg.version]); }
    } catch (_) { /* Without a readable package.json the package is not reported. */ }
  }
  function send(libraries) {
    const body = JSON.stringify({id: randomUUID(), service, host: process.env.POD_NAME || os.hostname(), environment, service_version: attributes['service.version'],
      libraries: libraries.map(([name, version]) => ({ecosystem: 'npm', name, version}))});
    return fetch(endpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
      .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Delivery rejected'); })
      .catch(() => console.warn('[Telvyn] Library inventory delivery failed.'));
  }
  let resend = Date.now() + RESEND_MS;
  function flush() {
    for (const filename of Object.keys(require.cache)) note(filename);
    // Seen again: the whole list returns now and then, so the finding stays open while the service runs.
    if (Date.now() >= resend) { resend = Date.now() + RESEND_MS; found = [...known].map(key => { const at = key.lastIndexOf('@'); return [key.slice(0, at), key.slice(at + 1)]; }); }
    const batch = found; found = [];
    for (let i = 0; i < batch.length; i += BATCH) send(batch.slice(i, i + BATCH));
  }
  let timer = setTimeout(function tick() { try { flush(); } catch (_) { /* The inventory never breaks the application. */ } timer = setTimeout(tick, EVERY_MS); timer.unref(); }, FIRST_MS);
  timer.unref();
  return {
    // ES modules arrive from the loader thread as file URLs.
    noteUrl(url) { try { if (typeof url === 'string' && url.startsWith('file:')) note(fileURLToPath(url)); } catch (_) { /* Not a file. */ } },
    stop() { clearTimeout(timer); },
  };
}

module.exports = { startSca };
