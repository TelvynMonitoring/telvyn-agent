'use strict';
// Mede o motor do agent Node contra o corpus gerado por corpus.py (mesma medição do CorpusReport do agent Java).
// Uso: node corpus-node.cjs <corpus.json>
const fs = require('node:fs');
const path = require('node:path');
const { Waf, xmlValues } = require(path.join(__dirname, '..', '..', 'telvyn-node-agent', 'waf.cjs'));

const waf = new Waf(JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'telvyn-node-agent', 'waf-rules.json'), 'utf8')));
const loaded = new Set(waf.rules.map(rule => rule.id.slice(4)));
const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

function form(raw) {
  const out = {};
  for (const pair of raw.split('&')) {
    if (!pair) continue;
    const i = pair.indexOf('=');
    try { (out[decodeURIComponent((i < 0 ? pair : pair.slice(0, i)).replace(/\+/g, ' '))] ??= []).push(i < 0 ? '' : decodeURIComponent(pair.slice(i + 1).replace(/\+/g, ' '))); }
    catch (_) { (out[pair] ??= []).push(''); }
  }
  return out;
}
function request(c) {
  const headers = {}, cookies = {};
  let contentType = '';
  for (const [key, value] of Object.entries(c.headers)) {
    const name = key.toLowerCase();
    if (name === 'cookie') { for (const pair of value.split(/;\s*/)) { const i = pair.indexOf('='); cookies[i < 0 ? pair : pair.slice(0, i)] = i < 0 ? '' : pair.slice(i + 1); } continue; }
    if (name === 'content-type') contentType = value.toLowerCase();
    headers[name] = value;
  }
  // O go-ftw manda corpo de formulário quando o teste não diz o tipo.
  if (c.body != null && !contentType) contentType = 'application/x-www-form-urlencoded';
  if (c.body != null && !Object.keys(c.headers).some(key => key.toLowerCase() === 'content-length')) headers['content-length'] = String(Buffer.byteLength(c.body));
  const data = { 'server.request.headers.no_cookies': headers, 'server.request.method': c.method, 'server.request.uri.raw': c.uri };
  if (Object.keys(cookies).length) data['server.request.cookies'] = cookies;
  const question = c.uri.indexOf('?');
  try { data['server.request.path'] = decodeURIComponent(question < 0 ? c.uri : c.uri.slice(0, question)); } catch (_) { data['server.request.path'] = c.uri; }
  if (question >= 0) data['server.request.query_string'] = c.uri.slice(question + 1);
  data['server.request.line'] = `${c.method} ${c.uri} HTTP/1.1`;
  data['server.request.protocol'] = 'HTTP/1.1';
  data['server.request.query'] = form(question < 0 ? '' : c.uri.slice(question + 1));
  if (c.body != null) {
    let body = contentType.includes('x-www-form-urlencoded') ? form(c.body) : c.body;
    if (contentType.includes('json')) { try { body = JSON.parse(c.body); } catch (_) { /* fica como texto */ } }
    if (contentType.includes('xml') && typeof body === 'string') body = xmlValues(body);
    data['server.request.body'] = body;
  }
  return data;
}

const total = { attacks: 0, detected: 0, clean: 0, falsePositives: 0, notConverted: 0 };
const misses = [], falsePositives = [];
for (const c of cases) {
  const fired = new Set(waf.createContext().run({ persistent: request(c) }, 500000).events.map(event => event.rule.id.slice(4)));
  if (c.expect.length) {
    if (!c.expect.every(id => loaded.has(id))) { total.notConverted++; continue; }
    total.attacks++;
    if (c.expect.every(id => fired.has(id))) total.detected++; else misses.push(`${c.test} (${c.file})`);
  }
  if (c.forbid.length) {
    total.clean++;
    if (c.forbid.some(id => fired.has(id))) { total.falsePositives++; falsePositives.push(`${c.test} (${c.file})`); }
  }
}
console.log(JSON.stringify(total));
if (process.argv[3]) fs.writeFileSync(process.argv[3], `não detectados:\n${misses.join('\n')}\n\nfalsos positivos:\n${falsePositives.join('\n')}\n`);
