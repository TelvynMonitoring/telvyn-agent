'use strict';
const { randomUUID } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const os = require('node:os');

// Findings that need no input (weak algorithms, cookie attributes) have their own rule set.
const FLAW_RULES = new Set(['WEAK_HASH', 'WEAK_CIPHER', 'INSECURE_COOKIE', 'NO_HTTPONLY_COOKIE', 'NO_SAMESITE_COOKIE', 'WEAK_RANDOMNESS', 'HSTS_HEADER_MISSING', 'XCONTENTTYPE_HEADER_MISSING', 'HARDCODED_SECRET', 'HARDCODED_PASSWORD']);
const WAF_RULES = require('./waf-rules.json');
const RULES_VERSION = 'waf-' + WAF_RULES.metadata.rules_version;
const DEFAULT_BUDGET_US = 10000;
const TIMEOUT_REPORT_INTERVAL_MS = 60000;

// Tempo máximo do WAF por avaliação (µs), de 1 ms a 1 s. Processo com pouca CPU estoura os 10 ms até numa
// requisição vazia, e a requisição passa sem inspeção completa.
function parseBudget(value) {
  if (value === undefined || String(value).trim() === '') return DEFAULT_BUDGET_US;
  const parsed = Number(String(value).trim());
  if (Number.isInteger(parsed) && parsed >= 1000 && parsed <= 1000000) return parsed;
  console.warn(`[telvyn] invalid TELVYN_SECURITY_WAF_TIMEOUT_US (${value}); expected 1000 to 1000000 microseconds. Using ${DEFAULT_BUDGET_US}.`);
  return DEFAULT_BUDGET_US;
}
const BUDGET_US = parseBudget(process.env.TELVYN_SECURITY_WAF_TIMEOUT_US);

// Relatar cada timeout enche o painel quando muitos estouram: um relato por minuto, e o log diz o que fazer.
let lastTimeoutReport = 0;
let timeoutsSinceReport = 0;
function shouldReportTimeout(now) {
  timeoutsSinceReport += 1;
  if (now - lastTimeoutReport < TIMEOUT_REPORT_INTERVAL_MS) return false;
  if (timeoutsSinceReport > 1) {
    console.warn(`[telvyn] the WAF exceeded its analysis time limit (${BUDGET_US} microseconds) on ${timeoutsSinceReport} requests in the last minute; they were not fully inspected. The process may be short of CPU: give it more, or raise TELVYN_SECURITY_WAF_TIMEOUT_US.`);
  }
  lastTimeoutReport = now;
  timeoutsSinceReport = 0;
  return true;
}

// Attack detection and blocking: the recommended ruleset over every request — headers, cookies,
// query, URI and client IP at request start; body, path parameters and user once the framework parsed them; response
// status at the end. Reports name the rule and where it matched (address and key), never the input value.
function startSecurity() {
  const enabled = process.env.TELVYN_SECURITY_ENABLED === 'true';
  const service = process.env.OTEL_SERVICE_NAME;
  const attributes = Object.fromEntries((process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',').map(pair => {
    const i = pair.indexOf('='); return [pair.slice(0, i), pair.slice(i + 1)];
  }));
  const environment = attributes['deployment.environment.name'] || attributes['deployment.environment'];
  // Without identity, remote configuration cannot turn detection on later: keep the application untouched.
  if (!enabled && process.env.TELVYN_IAST_ENABLED !== 'true' && (!service || !environment)) return { state: 'disabled', setAttack() {}, guard() { return false; }, inspectRoute() { return false; }, block() {}, stop() {} };
  if (!service) throw new Error('Security requires service identity');
  if (!environment) throw new Error('Security requires environment identity');
  const endpoint = new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318');
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Invalid collector endpoint');
  endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/v1/security/events';
  const { DDWAF } = require('@datadog/native-appsec');
  const protection = require('./protection.cjs');
  const createWaf = () => {
    const created = new DDWAF(WAF_RULES, 'telvyn-recommended');
    if (!created.diagnostics.rules?.loaded?.length || created.diagnostics.rules?.failed?.length) { created.dispose(); throw new Error('Security rules unavailable'); }
    return created;
  };
  let waf = enabled ? createWaf() : null;
  const pending = new Set();
  const requests = new WeakMap();
  const store = new AsyncLocalStorage();
  let stopped = false;
  function report(outcome, rule, elapsed, span, finding, request) {
    if (pending.size >= 32) { console.warn('[Telvyn] Security delivery saturated; event not queued.'); return; }
    const context = span?.spanContext();
    const body = JSON.stringify({id: randomUUID(), service, host: process.env.POD_NAME || os.hostname(), environment,
      service_version: attributes['service.version'], outcome, rule_id: rule, rules_version: finding ? (rule === 'SQL_INJECTION' ? 'iast-q-node-sql-1' : FLAW_RULES.has(rule) ? 'iast-node-flaws-1' : 'iast-q-node-sinks-1') : RULES_VERSION,
      engine_version: DDWAF.version(), elapsed_us: elapsed,
      ...finding, ...request,
      ...(context && /^[0-9a-f]{32}$/.test(context.traceId) && !/^0+$/.test(context.traceId) ? {trace_id: context.traceId, span_id: context.spanId} : {})});
    const destination = new URL(endpoint);
    if (finding) destination.pathname = destination.pathname.replace(/events$/, 'iast');
    const send = fetch(destination, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
      .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Delivery rejected'); })
      .catch(() => console.warn('[Telvyn] Security event delivery failed.'))
      .finally(() => pending.delete(send));
    pending.add(send);
  }

  const cookies = header => Object.fromEntries(String(header || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const i = part.indexOf('='); return i < 0 ? [part, ''] : [part.slice(0, i).trim(), part.slice(i + 1).trim()];
  }));
  const query = url => {
    const out = {};
    for (const [key, value] of url.searchParams) (out[key] ??= []).push(value);
    return out;
  };
  // Where the rule matched: address and key path, never the value.
  const where = event => {
    const first = event.rule_matches?.[0]?.parameters?.[0];
    // Exploit prevention matches name the request input (params) and the operation (resource) separately.
    const parameter = first?.address ? first : first?.params ?? first?.resource;
    if (!parameter?.address) return undefined;
    const key = (parameter.key_path || []).map(String).join('.').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 200);
    return key ? `${parameter.address}:${key}` : parameter.address;
  };

  // Runs one phase on the request's WAF context; reports new matches and returns whether a blocking rule matched.
  // blockable=false: detection only (a phase where answering would break the framework's own response).
  // ephemeral: data of one operation (exploit prevention), not kept in the request context.
  function evaluate(state, data, span, blockable = true, ephemeral = false) {
    if (!state.context || state.closed) return false;
    const started = process.hrtime.bigint();
    let result;
    try { result = state.context.run(ephemeral ? {ephemeral: data} : {persistent: data}, BUDGET_US); }
    catch (_) { report('error', undefined, Number((process.hrtime.bigint() - started) / 1000n), span, undefined, state.details); return false; }
    const elapsed = Number((process.hrtime.bigint() - started) / 1000n);
    if (result.timeout && !state.timeoutReported) { state.timeoutReported = true; if (shouldReportTimeout(Date.now())) report('timeout', undefined, elapsed, span, undefined, state.details); }
    state.derivatives = result.derivatives ?? result.attributes;
    if (result.errorCode) { report('error', undefined, elapsed, span, undefined, state.details); return false; }
    const matches = (result.events || []).filter(event => event.rule?.id && !state.reported.has(event.rule.id) && protection.ruleMode(event.rule.id) !== 'disabled');
    if (!matches.length) return false;
    const block = blockable && protection.state.allow && !protection.passed(state.ip) && !state.blocked && matches.some(event => protection.ruleMode(event.rule.id) === 'blocking');
    for (const event of matches) {
      state.reported.add(event.rule.id);
      const blocking = block && protection.ruleMode(event.rule.id) === 'blocking';
      report('match', event.rule.id, elapsed, span, undefined, {...state.details, ...(state.user ? {usr_id: state.user} : {}), match_address: where(event), ...(blocking ? {blocked: true, blocked_by: 'rule'} : {})});
    }
    return block;
  }
  function blockRequest(state, request, response, span, by, elapsed = 0) {
    state.blocked = true;
    protection.respond(request, response);
    if (by !== 'rule') report('blocked', undefined, elapsed, span, undefined, {...state.details, ...(state.user ? {usr_id: state.user} : {}), blocked: true, blocked_by: by});
  }
  // Automatic user events: login success/failure and signup, never the password.
  // Mode: TELVYN_SECURITY_USER_TRACKING (identification, anonymization, disabled) or the UI; a local "disabled" always wins.
  const localTracking = String(process.env.TELVYN_SECURITY_USER_TRACKING || 'identification').trim().toLowerCase();
  const tracking = () => localTracking === 'disabled' ? 'disabled' : protection.state.tracking || (localTracking === 'anonymization' ? 'anonymization' : 'identification');
  const anonymize = protection.anonymize;
  // User identifier from the user object: id, _id, email, username, login, user.
  const userIdentifier = user => {
    if (user == null || typeof user !== 'object') return undefined;
    for (const field of ['id', '_id', 'email', 'username', 'login', 'user']) {
      const value = user[field];
      if (value == null || value === '') continue;
      if (['string', 'number', 'bigint'].includes(typeof value) || field === '_id') return String(value).slice(0, 255);
    }
    return undefined;
  };
  const usersEndpoint = new URL(endpoint);
  usersEndpoint.pathname = usersEndpoint.pathname.replace(/events$/, 'users');
  function reportUser(event, user, login, exists, state, framework, mode) {
    if (pending.size >= 32) { console.warn('[Telvyn] Security delivery saturated; user event not queued.'); return; }
    const context = state.span?.spanContext();
    const hide = value => value == null ? undefined : mode === 'anonymization' ? anonymize(value) : value;
    const body = JSON.stringify({id: randomUUID(), service, host: process.env.POD_NAME || os.hostname(), environment, service_version: attributes['service.version'],
      event, usr_id: hide(user), usr_login: hide(login), ...(typeof exists === 'boolean' ? {usr_exists: exists} : {}),
      client_ip: state.details.client_ip, user_agent: state.details.user_agent, framework, collection_mode: mode,
      ...(context && /^[0-9a-f]{32}$/.test(context.traceId) && !/^0+$/.test(context.traceId) ? {trace_id: context.traceId, span_id: context.spanId} : {})});
    const send = fetch(usersEndpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
      .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Delivery rejected'); })
      .catch(() => console.warn('[Telvyn] User activity delivery failed.'))
      .finally(() => pending.delete(send));
    pending.add(send);
  }
  // Body worth a WAF run: a non-empty object or string (body parsers leave {} when they do not handle the type).
  const hasBody = body => typeof body === 'string' ? body.length > 0 : !!body && typeof body === 'object' && Object.keys(body).length > 0;
  // API Security: the WAF extracts the schema of each endpoint (types of headers, query, path params,
  // body and response headers, with sensitive data and credentials flagged by the scanners), sampled once per method,
  // route and status every 30 seconds.
  const API_SAMPLE_MS = 30000;
  const sampled = new Map();
  const apiEndpoint = new URL(endpoint);
  apiEndpoint.pathname = apiEndpoint.pathname.replace(/events$/, 'api');
  function apiSample(state, status) {
    const route = state.route || state.details.request_path;
    const key = `${state.request.method} ${route} ${status}`;
    const now = Date.now();
    if ((sampled.get(key) ?? 0) > now - API_SAMPLE_MS) return false;
    if (sampled.size >= 4096) sampled.delete(sampled.keys().next().value);
    sampled.set(key, now);
    return true;
  }
  function reportApi(state, status, derivatives) {
    const schemas = {};
    for (const [name, value] of Object.entries(derivatives || {})) if (name.startsWith('_dd.appsec.s.')) schemas[name.slice('_dd.appsec.s.'.length)] = value;
    if (!Object.keys(schemas).length || pending.size >= 32) return;
    const body = JSON.stringify({id: randomUUID(), service, host: process.env.POD_NAME || os.hostname(), environment, service_version: attributes['service.version'],
      method: state.request.method, route: String(state.route || state.details.request_path).slice(0, 1024), status, schemas});
    if (body.length > 32768) return;
    const send = fetch(apiEndpoint, {method: 'POST', headers: {'content-type': 'application/json'}, body, redirect: 'error', signal: AbortSignal.timeout(5000)})
      .then(async response => { await response.arrayBuffer(); if (!response.ok) throw new Error('Delivery rejected'); })
      .catch(() => console.warn('[Telvyn] API schema delivery failed.'))
      .finally(() => pending.delete(send));
    pending.add(send);
  }
  function setUser(state, user, request, response, span) {
    const id = user == null ? '' : String(typeof user === 'object' ? user.id ?? '' : user).slice(0, 255);
    if (!id || state.user === id) return false;
    state.user = id;
    if (protection.state.allow && protection.userBlocked(id) && !protection.passed(state.ip) && response) { blockRequest(state, request, response, span, 'user'); return true; }
    return false;
  }

  return {
    get state() { return waf ? 'active' : 'disabled'; },
    // Runs the application's request handling with the request state available to setUser / blockRequest.
    within(request, fn) { const state = requests.get(request); return state ? store.run(state, fn) : fn(); },
    // Remote configuration: turns attack detection on or off while the application runs.
    setAttack(on) {
      if (on && !waf && !stopped) waf = createWaf();
      else if (!on && waf) { const previous = waf; waf = null; previous.dispose(); }
    },
    reportIast({rule_id: rule, ...finding}, elapsed, span) { if (!stopped) report('match', rule, elapsed, span, finding); },
    // Request start, before the application. Returns true when the request was blocked and answered.
    guard(request, response, span) {
      if (stopped || !waf || typeof request.url !== 'string') return false;
      let url;
      try { url = new URL(request.url, 'http://application.invalid'); } catch (_) { return false; }
      const ip = protection.clientIp(request);
      const agent = typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'].slice(0, 512) : undefined;
      const state = {ip, request, response, span, reported: new Set(), blocked: false,
        details: {...(ip ? {client_ip: ip} : {}), ...(/^[A-Z]{1,20}$/.test(request.method || '') ? {request_method: request.method} : {}), request_path: url.pathname.slice(0, 1024), ...(agent ? {user_agent: agent} : {})}};
      requests.set(request, state);
      if (protection.state.allow && protection.denied(ip)) { blockRequest(state, request, response, span, 'ip'); return true; }
      state.context = waf.createContext();
      const done = () => {
        if (state.closed) return;
        const status = response.statusCode;
        const data = {'server.response.status': String(status)};
        const schema = !state.blocked && apiSample(state, status);
        if (schema) {
          const headers = {...response.getHeaders()};
          delete headers['set-cookie'];
          data['server.response.headers.no_cookies'] = headers;
          data['waf.context.processor'] = {'extract-schema': true};
        }
        evaluate(state, data, span);
        if (schema) reportApi(state, status, state.derivatives);
        state.closed = true;
        state.context.dispose();
      };
      response.once('finish', done);
      response.once('close', done);
      const headers = {...request.headers};
      delete headers.cookie;
      const data = {'server.request.headers.no_cookies': headers, 'server.request.query': query(url), 'server.request.uri.raw': request.url, 'server.request.method': request.method};
      if (request.headers.cookie) data['server.request.cookies'] = cookies(request.headers.cookie);
      if (ip) data['http.client_ip'] = ip;
      if (evaluate(state, data, span)) { blockRequest(state, request, response, span, 'rule'); return true; }
      return false;
    },
    // Route phase (Express route handler, Fastify preHandler): body, path parameters and the logged-in user.
    // Returns true when the request must be blocked; the caller answers with block().
    inspectRoute(request, {body, params, user, route} = {}) {
      const state = requests.get(request);
      if (state && typeof route === 'string' && route && !state.route) state.route = route.slice(0, 1024);
      if (!state || state.blocked || state.routeInspected || !waf) return false;
      state.routeInspected = true;
      if (user != null && setUser(state, user, request, null, state.span)) return true;
      if (state.user && protection.state.allow && protection.userBlocked(state.user) && !protection.passed(state.ip)) { state.blockedBy = 'user'; return true; }
      const data = {};
      if (!state.bodyInspected && hasBody(body)) { state.bodyInspected = true; data['server.request.body'] = body; }
      if (params && typeof params === 'object' && Object.keys(params).length) data['server.request.path_params'] = params;
      if (state.user) data['usr.id'] = state.user;
      if (Object.keys(data).length && evaluate(state, data, state.span)) { state.blockedBy = 'rule'; return true; }
      return false;
    },
    // Body parsed after the route matched (multer) or read by the application (Next.js NextRequest): inspected once.
    // Returns true when blocked; the block response was already sent. blockable=false only detects (as on
    // the Next.js body, which blocks at request start only).
    inspectBody(request, body, blockable = true) {
      const state = request ? requests.get(request) : store.getStore();
      if (!state || state.blocked || state.bodyInspected || !waf || !hasBody(body)) return false;
      state.bodyInspected = true;
      if (!evaluate(state, {'server.request.body': body}, state.span, blockable) || !blockable) return false;
      blockRequest(state, state.request, state.response, state.span, 'rule');
      return true;
    },
    // GraphQL (graphql.server.all_resolvers, every resolver with its arguments). Inside Apollo Server's
    // HTTP handling a blocking match stops execution and Apollo answers with the block response; elsewhere it only
    // detects. Returns true when execution must stop.
    inspectGraphql(resolvers) {
      const state = store.getStore();
      if (!state || state.blocked || !waf || !resolvers || !Object.keys(resolvers).length) return false;
      const blockable = !!state.apollo;
      if (!evaluate(state, {'graphql.server.all_resolvers': resolvers}, state.span, blockable) || !blockable) return false;
      state.blocked = true;
      state.graphqlBlocked = true;
      return true;
    },
    // Apollo Server request: marks the request so GraphQL blocking can answer through Apollo, and returns the block
    // response (status, headers, body) once execution was stopped.
    apolloStart() { const state = store.getStore(); if (state) state.apollo = true; },
    apolloBlock() {
      const state = store.getStore();
      return state?.graphqlBlocked ? protection.blockPayload(state.request) : null;
    },
    // Exploit prevention: a dangerous operation (SQL, outgoing URL, file, command) checked against
    // the request's input. Returns true when a blocking rule matched: the block response was sent and the caller
    // aborts the operation.
    inspectOperation(data) {
      const state = store.getStore();
      if (stopped || !waf || !state || state.blocked || state.closed) return false;
      if (!evaluate(state, data, state.span, true, true)) return false;
      blockRequest(state, state.request, state.response, state.span, 'rule');
      return true;
    },
    // Whether a Web API Request is the incoming request being handled (Next.js wraps it), not one the application builds.
    isIncoming(webRequest) {
      const state = store.getStore();
      if (!state || typeof webRequest?.url !== 'string') return false;
      try { return webRequest.method === state.request.method && new URL(webRequest.url).pathname === state.details.request_path; } catch (_) { return false; }
    },
    block(request, response) {
      const state = requests.get(request);
      if (!state) return;
      blockRequest(state, request, response, state.span, state.blockedBy || 'rule');
    },
    // Public SDK API (like tracer.setUser / appsec.isUserBlocked / appsec.blockRequest).
    setUser(user) {
      const state = store.getStore();
      if (!state) return false;
      const id = user == null ? '' : String(typeof user === 'object' ? user.id ?? '' : user).slice(0, 255);
      if (id) state.user = id;
      return true;
    },
    // Login seen by an authentication library (Passport): reports it and, for a blocked user's successful login,
    // answers with the block response. Returns true when blocked (the library callback must not continue).
    trackLogin(framework, login, user, success) {
      const state = store.getStore();
      if (stopped || !waf || !state || state.blocked) return false;
      const mode = tracking();
      const id = success ? userIdentifier(user) : undefined;
      const name = typeof login === 'string' && login ? login.slice(0, 255) : undefined;
      if (mode !== 'disabled' && (id || name)) reportUser(success ? 'login_success' : 'login_failure', id ?? (success ? name : undefined), name, success ? true : undefined, state, framework, mode);
      return !!(success && id && setUser(state, id, state.request, state.response, state.span));
    },
    // Public SDK API for logins and signups outside Passport (like eventTrackingV2): always reported, as given.
    trackUser(event, login, user, exists) {
      const state = store.getStore();
      const name = typeof login === 'string' && login ? login.slice(0, 255) : undefined;
      const id = user == null ? undefined : typeof user === 'object' ? userIdentifier(user) : String(user).slice(0, 255);
      if (stopped || !waf || !state || !(name || id)) return false;
      reportUser(event, id, name, event === 'login_failure' && typeof exists === 'boolean' ? exists : event === 'login_success' ? true : undefined, state, 'sdk', 'identification');
      if (event === 'login_success' && id && setUser(state, id, state.request, state.response, state.span)) return 'blocked';
      return true;
    },
    isUserBlocked(user) {
      const id = user == null ? '' : String(typeof user === 'object' ? user.id ?? '' : user);
      return !!id && protection.state.allow && protection.userBlocked(id);
    },
    blockRequest(request, response) {
      const state = request ? requests.get(request) : store.getStore();
      if (!state || state.blocked) return false;
      blockRequest(state, state.request, response || state.response, state.span, state.user && protection.userBlocked(state.user) ? 'user' : 'manual');
      return true;
    },
    async stop() { stopped = true; await Promise.allSettled(pending); waf?.dispose(); },
  };
}
module.exports = { startSecurity };
