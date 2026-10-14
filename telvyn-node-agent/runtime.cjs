'use strict';
const os = require('node:os');

function runtimeTransport() {
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return i > 0 ? [pair.slice(0, i), pair.slice(i + 1)] : ['', ''];
  }));
  const identity = {service: process.env.OTEL_SERVICE_NAME || attributes['service.name'], host: process.env.POD_NAME || os.hostname(),
    environment: attributes['deployment.environment.name'] || attributes['deployment.environment'], service_version: attributes['service.version']};
  if (!identity.service) throw new Error('Runtime reporting requires service identity');
  const pending = new Set();
  function url(signal) {
    if (!['sdk/configuration', 'debug', 'debug/config', 'debug/config/applied'].includes(signal)) throw new Error('Unsupported runtime signal');
    const target = new URL(endpoint); target.pathname = target.pathname.replace(/\/$/, '') + '/v1/' + signal; return target;
  }
  return {
    identity,
    send(signal, report) {
      const body = JSON.stringify({...identity, ...report});
      if (Buffer.byteLength(body) > 64 * 1024 || pending.size >= 32) { console.warn('[Telvyn] Runtime report exceeded delivery limits.'); return; }
      const work = fetch(url(signal), {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
        .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Runtime delivery rejected'); })
        .catch(() => console.warn('[Telvyn] Runtime report delivery failed.')).finally(() => pending.delete(work));
      pending.add(work);
    },
    async config() {
      const target = url('debug/config');
      target.searchParams.set('service', identity.service); target.searchParams.set('env', identity.environment || ''); target.searchParams.set('version', identity.service_version || '');
      const response = await fetch(target, {redirect: 'error', signal: AbortSignal.timeout(5000)});
      if (!response.ok) throw new Error('Debugger configuration unavailable');
      const body = await response.text();
      if (Buffer.byteLength(body) > 1024 * 1024) throw new Error('Debugger configuration too large');
      return JSON.parse(body);
    },
    stop: () => Promise.allSettled(pending),
  };
}

function flag(name) { return {value: String(process.env[name] === 'true'), source: process.env[name] === undefined ? 'default' : 'environment'}; }

function reportConfiguration(transport, security, iast) {
  const send = () => transport.send('sdk/configuration', {sdk_name: 'telvyn-node-agent', sdk_version: require('./package.json').version, runtime: process.version,
    configurations: [
      {name: 'telvyn.profiling.enabled', ...flag('TELVYN_PROFILING_ENABLED')},
      {name: 'telvyn.profiling.wall.enabled', ...flag('TELVYN_PROFILE_WALL_ENABLED')},
      {name: 'telvyn.profiling.alloc.enabled', ...flag('TELVYN_PROFILE_ALLOCATION_ENABLED')},
      {name: 'telvyn.security.attack.state', value: security?.state || (process.env.TELVYN_SECURITY_ENABLED === 'true' ? 'error' : 'disabled'), source: 'runtime'},
      {name: 'telvyn.security.iast.state', value: iast?.state || (process.env.TELVYN_IAST_ENABLED === 'true' ? 'error' : 'disabled'), source: 'runtime'},
    ]});
  send(); const timer = setInterval(send, 60000); timer.unref();
  return () => clearInterval(timer);
}
module.exports = { runtimeTransport, reportConfiguration };
