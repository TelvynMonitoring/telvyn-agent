'use strict';
// Remote configuration set in the Telvyn UI: profiling and security per
// service and environment, applied without restarting. An absent option keeps the application's own setting.
// IAST can only be turned off: its instrumentation is installed when modules load.
const PROFILING = ['enabled', 'wall', 'alloc'];
const SECURITY = ['attack', 'iast', 'evidence'];
const state = {revision: 0, protection: '', profiling: {}, security: {}, exclusions: {parameters: new Set(), headers: new Set()}};

// Nomes que não são analisados nem enviados como evidência (configuração por serviço na tela).
const NAME = /^[A-Za-z0-9_.-]{1,64}$/;
function cleanExclusions(raw) {
  const list = value => Array.isArray(value) ? value.filter(name => typeof name === 'string' && NAME.test(name)).slice(0, 32) : [];
  return {parameters: new Set(list(raw?.parameters)), headers: new Set(list(raw?.headers).map(name => name.toLowerCase()))};
}
const exclusions = () => state.exclusions;

function pick(object, keys) {
  const out = {};
  for (const key of keys) if (typeof object?.[key] === 'boolean') out[key] = object[key];
  return out;
}

const profiling = key => state.profiling[key];
const security = key => state.security[key];

// A profile type whose delivery the UI turned off is dropped before upload.
function profileAllowed(type) {
  if (state.profiling.enabled === false) return false;
  const key = type === 'wall' ? 'wall' : type === 'alloc' ? 'alloc' : undefined;
  return key === undefined || state.profiling[key] !== false;
}

function startRemoteConfig(transport, apply) {
  let stopped = false;
  const poll = async () => {
    try {
      const body = await transport.remoteConfig();
      if (!Number.isSafeInteger(body?.revision)) return;
      // Attack blocking (protection, rule modes) has its own revision: an IP list change reaches the SDK on its own.
      const protection = typeof body.protection?.revision === 'string' ? body.protection.revision : '';
      require('./protection.cjs').update(body.protection, body.rules);
      if (body.revision === state.revision && protection === state.protection) return;
      state.protection = protection;
      if (body.revision === state.revision) return;
      state.profiling = pick(body.profiling, PROFILING);
      state.security = pick(body.security, SECURITY);
      state.exclusions = cleanExclusions(body.exclusions);
      await apply(state);
      state.revision = body.revision;
      console.log(`[Telvyn] Remote configuration applied (revision ${body.revision}).`);
    } catch (_) { /* Remote configuration never interrupts the application. */ }
  };
  poll();
  const timer = setInterval(() => { if (!stopped) poll(); }, 30000);
  timer.unref();
  return () => { stopped = true; clearInterval(timer); };
}

module.exports = { state, profiling, security, exclusions, profileAllowed, startRemoteConfig };
