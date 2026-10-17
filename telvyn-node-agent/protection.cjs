'use strict';
// Attack blocking set in the Telvyn UI (as Datadog App and API Protection): "allow blocking" switch, block response,
// IP/CIDR denylist and passlist (with expiry), and each rule's mode (monitoring, blocking, disabled). Blocking needs
// attack detection on, as in Datadog.
const net = require('node:net');
const { randomUUID } = require('node:crypto');

const state = {revision: '', allow: true, status: 403, redirect: null, deny: new net.BlockList(), pass: new net.BlockList(), users: new Map(), rules: {}};
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
  state.users = new Map((Array.isArray(protection.blocked_users) ? protection.blocked_users : []).filter(u => typeof u?.id === 'string').map(u => [u.id, u.expires_at_ms ?? null]));
  rebuild();
}

// Client IP as Datadog resolves it: the first public address in the usual proxy headers, else the connection address.
const HEADERS = ['x-forwarded-for', 'x-real-ip', 'true-client-ip', 'x-client-ip', 'x-forwarded', 'forwarded-for', 'x-cluster-client-ip', 'fastly-client-ip', 'cf-connecting-ip', 'cf-connecting-ipv6'];
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
// Logged-in user blocked in the UI (entries expire at their own time).
const userBlocked = id => { if (!state.users.has(id)) return false; const expires = state.users.get(id); return expires == null || expires > Date.now(); };
// Rule mode from the UI; without a choice a rule only monitors, as Datadog's default policy.
const ruleMode = rule => ['monitoring', 'blocking', 'disabled'].includes(state.rules[rule]) ? state.rules[rule] : 'monitoring';

const TITLE = "You've been blocked";
const DETAIL = 'Sorry, you cannot access this page. Please contact the customer service team. Security provided by Telvyn.';
function respond(request, response) {
  const id = randomUUID();
  if (response.headersSent) { response.destroy(); return id; }
  if (state.status === 301 || state.status === 302) {
    const target = new URL(state.redirect);
    target.searchParams.set('security_response_id', id);
    response.writeHead(state.status, {location: target.toString(), 'content-length': '0'});
    response.end();
    return id;
  }
  const html = /text\/html/i.test(String(request.headers?.accept || ''));
  const body = html
    ? `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${TITLE}</title></head><body><h1>${TITLE}</h1><p>${DETAIL}</p><p>Security Response ID: ${id}</p></body></html>`
    : JSON.stringify({errors: [{title: TITLE, detail: DETAIL}], security_response_id: id});
  response.writeHead(state.status, {'content-type': html ? 'text/html; charset=utf-8' : 'application/json', 'content-length': Buffer.byteLength(body)});
  response.end(body);
  return id;
}

module.exports = { state, update, clientIp, denied, passed, userBlocked, ruleMode, respond };
