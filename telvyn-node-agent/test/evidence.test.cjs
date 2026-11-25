'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {build, payload, redactQuery, redactValue, headers, sensitiveLocation} = require('../evidence.cjs');

test('guarda o payload do ataque sem mexer', () => {
  const out = payload("') UNION SELECT sql FROM sqlite_master--", 'server.request.query:q.0');
  assert.equal(out.value, "') UNION SELECT sql FROM sqlite_master--");
  assert.equal(out.redacted, false);
  assert.equal(out.truncated, false);
});

test('campo sensível ou cookie não envia o valor', () => {
  for (const location of ['server.request.query:password', 'server.request.body:user.token', 'server.request.headers.no_cookies:authorization', 'server.request.cookies:sid']) {
    const out = payload('hunter2', location);
    assert.equal(out.value, '<redacted>', location);
    assert.equal(out.redacted, true, location);
  }
});

test('redige JWT, bearer, chave AWS e cartão (Luhn)', () => {
  const text = redactValue('x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk y Bearer abcdefghijklmnop z AKIA' + 'ABCDEFGHIJKLMNOP w 4111 1111 1111 1111');
  for (const secret of ['eyJ', 'abcdefghijklmnop', 'AKIA' + 'ABCDEFGHIJKLMNOP', '4111']) assert.ok(!text.includes(secret), text);
});

test('número longo que não é cartão fica como estava', () => {
  assert.equal(payload('1234567890123456', 'server.request.query:id').value, '1234567890123456');
});

test('trunca em 256 e marca', () => {
  const out = payload('a'.repeat(600), 'server.request.query:q');
  assert.equal(out.value.length, 256);
  assert.equal(out.truncated, true);
});

test('troca caracteres de controle e mantém a quebra de linha', () => {
  assert.equal(payload('a\u0000b\r\nSet-Cookie: x', 'server.request.query:q').value, 'a?b\r\nSet-Cookie: x');
});

test('consulta redige só os campos sensíveis', () => {
  assert.equal(redactQuery("q=%27%20OR%201%3D1--&password=abc&Token=zzz&page=2"), "q=%27%20OR%201%3D1--&password=<redacted>&Token=<redacted>&page=2");
});

test('cabeçalhos: só a lista permitida, e nunca autorização nem cookie', () => {
  const out = headers({headers: {'user-agent': 'curl/8', authorization: 'Bearer abcdefghijkl', cookie: 's=1', 'x-session-id': 'abc', referer: 'https://a.example/x', 'x-custom': 'y'}});
  assert.deepEqual(out, {'user-agent': 'curl/8', referer: 'https://a.example/x'});
});

test('build junta payload, consulta e cabeçalhos', () => {
  const out = build({value: "' OR 1=1--", location: 'server.request.query:q.0', request: {url: '/rest/products/search?q=%27%20OR%201%3D1--&password=x', headers: {'user-agent': 'curl/8'}}});
  assert.equal(out.payload.value, "' OR 1=1--");
  assert.equal(out.query, 'q=%27%20OR%201%3D1--&password=<redacted>');
  assert.deepEqual(out.headers, {'user-agent': 'curl/8'});
});

test('sem nada a mostrar devolve undefined', () => {
  assert.equal(build({value: undefined, location: undefined, request: {url: '/x', headers: {}}}), undefined);
});

test('match na resposta não é payload', () => {
  assert.equal(payload('500', 'server.response.status'), undefined);
  assert.equal(build({value: '500', location: 'server.response.status', request: {url: '/x', headers: {}}}), undefined);
});

test('sensitiveLocation', () => {
  assert.equal(sensitiveLocation('server.request.query:q.0'), false);
  assert.equal(sensitiveLocation('server.request.query:password'), true);
  assert.equal(sensitiveLocation(undefined), false);
});
