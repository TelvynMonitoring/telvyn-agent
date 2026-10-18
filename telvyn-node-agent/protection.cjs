'use strict';
// Attack blocking set in the Telvyn UI (as Datadog App and API Protection): "allow blocking" switch, block response,
// IP/CIDR denylist and passlist (with expiry), and each rule's mode (monitoring, blocking, disabled). Blocking needs
// attack detection on, as in Datadog.
const net = require('node:net');
const { randomUUID, createHash } = require('node:crypto');

const state = {revision: '', allow: true, status: 403, redirect: null, deny: new net.BlockList(), pass: new net.BlockList(), users: new Map(), rules: {}, tracking: null};
let entries = {deny: [], pass: []}, timer;

function blockList(items) {
  const list = new net.BlockList();
  const now = Date.now();
  for (const {cidr, expires_at_ms: expires} of items) {
    if (expires != null && expires <= now) continue;
    const [address, prefix] = String(cidr).split('/');
    const type = net.isIPv6(address) ? 'ipv6' : net.isIPv4(address) ? 'ipv4' : null;
    if (!type) continue;
    try { list.addSubnet(address, Number(prefix ?? (type === 'ipv4' ? 32 : 128)), type); } catch (_) { /* invalid entry is skipped */ }
  }
  return list;
}

// Entries expire at their own time, not only at the next poll.
function rebuild() {
  clearTimeout(timer);
  state.deny = blockList(entries.deny);
  state.pass = blockList(entries.pass);
  const next = [...entries.deny, ...entries.pass].map(e => e.expires_at_ms).filter(t => t != null && t > Date.now()).sort((a, b) => a - b)[0];
  if (next) { timer = setTimeout(rebuild, Math.min(next - Date.now() + 10, 2147483647)); timer.unref(); }
}

function update(protection, rules) {
  state.rules = rules && typeof rules === 'object' ? rules : {};
  if (!protection || protection.revision === state.revision) return;
  state.revision = protection.revision;
  state.allow = protection.allow_blocking !== false;
  state.status = [200, 403, 404, 301, 302].includes(protection.response?.status) ? protection.response.status : 403;
  state.redirect = typeof protection.response?.redirect_url === 'string' ? protection.response.redirect_url : null;
  entries = {deny: Array.isArray(protection.denylist) ? protection.denylist : [], pass: Array.isArray(protection.passlist) ? protection.passlist : []};
  // User tracking mode set in the UI (identification, anonymization, disabled); null keeps the local setting.
  state.tracking = ['identification', 'anonymization', 'disabled'].includes(protection.user_tracking_mode) ? protection.user_tracking_mode : null;
  state.users = new Map((Array.isArray(protection.blocked_users) ? protection.blocked_users : []).filter(u => typeof u?.id === 'string').map(u => [u.id, u.expires_at_ms ?? null]));
  rebuild();
}

// Client IP as Datadog resolves it: the first public address in the usual proxy headers, else the connection address.
// TELVYN_CLIENT_IP_HEADER (as DD_TRACE_CLIENT_IP_HEADER): only that header is trusted, the others are ignored —
// for applications behind a known proxy, so a client cannot forge its address with another header.
const TRUSTED = String(process.env.TELVYN_CLIENT_IP_HEADER || '').trim().toLowerCase();
const HEADERS = TRUSTED ? [TRUSTED] : ['x-forwarded-for', 'x-real-ip', 'true-client-ip', 'x-client-ip', 'x-forwarded', 'forwarded-for', 'x-cluster-client-ip', 'fastly-client-ip', 'cf-connecting-ip', 'cf-connecting-ipv6'];
const PRIVATE = new net.BlockList();
for (const [address, prefix, type] of [['10.0.0.0', 8, 'ipv4'], ['172.16.0.0', 12, 'ipv4'], ['192.168.0.0', 16, 'ipv4'], ['127.0.0.0', 8, 'ipv4'], ['169.254.0.0', 16, 'ipv4'], ['100.64.0.0', 10, 'ipv4'], ['::1', 128, 'ipv6'], ['fc00::', 7, 'ipv6'], ['fe80::', 10, 'ipv6']]) PRIVATE.addSubnet(address, prefix, type);
const normalize = value => {
  let ip = String(value || '').trim().replace(/^\[|\]$/g, '');
  if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(ip)) ip = ip.split(':')[0];
  if (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
  return net.isIP(ip) ? ip : null;
};
const isPrivate = ip => PRIVATE.check(ip, net.isIPv6(ip) ? 'ipv6' : 'ipv4');
function clientIp(request) {
  let fallback;
  for (const name of HEADERS) {
    const header = request.headers?.[name];
    if (!header) continue;
    for (const part of String(header).split(',')) {
      const ip = normalize(part);
      if (!ip) continue;
      if (!isPrivate(ip)) return ip;
      fallback ??= ip;
    }
  }
  return fallback ?? normalize(request.socket?.remoteAddress);
}

const listed = (list, ip) => !!ip && list.check(ip, net.isIPv6(ip) ? 'ipv6' : 'ipv4');
const denied = ip => listed(state.deny, ip) && !listed(state.pass, ip);
const passed = ip => listed(state.pass, ip);
// Same format as Datadog's anonymization: "anon_" + the first 128 bits of SHA-256, in hex.
const anonymize = value => 'anon_' + createHash('sha256').update(String(value)).digest('hex').slice(0, 32);
// Logged-in user blocked in the UI (entries expire at their own time).
const userListed = id => { if (!state.users.has(id)) return false; const expires = state.users.get(id); return expires == null || expires > Date.now(); };
// A user blocked from an anonymized event is listed by its hash: both forms match.
const userBlocked = id => state.users.size > 0 && id != null && (userListed(id) || userListed(anonymize(id)));
// Rule mode from the UI; without a choice a rule only monitors, as Datadog's default policy.
const ruleMode = rule => ['monitoring', 'blocking', 'disabled'].includes(state.rules[rule]) ? state.rules[rule] : 'monitoring';

const TITLE = "You've been blocked";
const DETAIL = 'Sorry, you cannot access this page. Please contact the customer service team. Security provided by Telvyn.';
// Block response as configured in the UI: redirect, or HTML when the browser asks for HTML and JSON otherwise.
function blockPayload(request) {
  const id = randomUUID();
  if (state.status === 301 || state.status === 302) {
    const target = new URL(state.redirect);
    target.searchParams.set('security_response_id', id);
    return {id, status: state.status, headers: {location: target.toString(), 'content-length': '0'}, body: ''};
  }
  const html = /text\/html/i.test(String(request?.headers?.accept || ''));
  const body = html
    ? `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${TITLE}</title></head><body><h1>${TITLE}</h1><p>${DETAIL}</p><p>Security Response ID: ${id}</p></body></html>`
    : JSON.stringify({errors: [{title: TITLE, detail: DETAIL}], security_response_id: id});
  return {id, status: state.status, headers: {'content-type': html ? 'text/html; charset=utf-8' : 'application/json', 'content-length': String(Buffer.byteLength(body))}, body};
}
function respond(request, response) {
  if (response.headersSent) { response.destroy(); return randomUUID(); }
  const block = blockPayload(request);
  response.writeHead(block.status, block.headers);
  response.end(block.body);
  return block.id;
}

module.exports = { state, update, clientIp, denied, passed, userBlocked, ruleMode, respond, blockPayload, anonymize };
