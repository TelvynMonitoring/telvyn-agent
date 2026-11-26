'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Visto no Marketplace: o destino vem de req.query.backend, mas só seis valores fixos chegam ao http.get. O IAST reportava SSRF
// porque o dado marcado chegou ao destino. Um valor que é exatamente um literal do código da aplicação é um destino que o
// desenvolvedor escreveu; o que o atacante escolhe fora disso continua sendo achado.
const APP = [
  "const http = require('node:http');", // 1
  "const BACKENDS = ['java', 'django', 'fastapi', 'ruby', 'node', 'php'];", // 2
  'module.exports = () => {', // 3
  '  const server = http.createServer((req, res) => {', // 4
  "    const url = new URL(req.url, 'http://x');", // 5
  "    const base = () => 'http://127.0.0.1:' + process.env.UPSTREAM + '/ping/';", // 6
  '    const done = r => { r.resume(); r.on("end", () => res.end("ok")); };', // 7
  "    if (url.pathname === '/q') {", // 8
  "      const backend = url.searchParams.get('backend');", // 9
  "      if (!BACKENDS.includes(backend)) { res.statusCode = 400; return res.end('no'); }", // 10
  '      return http.get(base() + backend, done);', // 11
  '    }', // 12
  "    if (url.pathname === '/raw') {", // 13
  "      const target = url.searchParams.get('target');", // 14
  '      return http.get(base() + target, done);', // 15
  '    }', // 16
  "    if (url.pathname === '/mix') {", // 17
  "      const backend = url.searchParams.get('backend'), target = url.searchParams.get('target');", // 18
  "      return http.get(base() + backend + '/' + target, done);", // 19
  '    }', // 20
  "    res.end('pong');", // 21
  '  });', // 22
  '  return server;', // 23
  '};', // 24
].join('\n');

test('SSRF: valor que é literal do código não é achado; o que o atacante escolhe fora disso é', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telvyn-iast-ssrf-'));
  try {
    fs.writeFileSync(path.join(dir, 'app.cjs'), APP);
    fs.writeFileSync(path.join(dir, 'run.cjs'), [
      "const { startIast } = require(" + JSON.stringify(path.resolve(__dirname, '..', 'iast.cjs')) + ');',
      'const findings = [];',
      'startIast(finding => findings.push(finding));',
      "const upstream = require('node:http').createServer((q, r) => r.end('pong')).listen(0);",
      "process.env.UPSTREAM = String(upstream.address().port);",
      "const server = require('./app.cjs')();",
      'server.listen(0, async () => {',
      "  const base = 'http://127.0.0.1:' + server.address().port;",
      "  const get = async (p, label) => { await fetch(base + p); findings.push({ marca: label }); };",
      "  await get('/q?backend=java', 'q-java');",
      "  await get('/q?backend=django', 'q-django');",
      "  await get('/q?backend=evil', 'q-evil');",
      "  await get('/raw?target=metadata', 'raw-metadata');",
      "  await get('/mix?backend=java&target=metadata', 'mix');",
      "  console.log(JSON.stringify(findings.map(({ rule_id, code_line, source, marca }) => ({ rule_id, code_line, source, marca }))));",
      '  process.exit(0);',
      '});',
    ].join('\n'));
    const result = spawnSync(process.execPath, ['run.cjs'], {
      cwd: dir, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, TELVYN_IAST_ENABLED: 'true', TELVYN_PROFILE_SOURCE_ROOT: dir, TELVYN_SECURITY_ROUTES: '/q,/raw,/mix' },
    });
    const all = JSON.parse(result.stdout.trim().split('\n').pop());
    // Cada achado de SSRF fica entre as marcas das requisições; a marca vem depois que a requisição terminou.
    const porRequisicao = {};
    let pendentes = [];
    for (const item of all) {
      if (item.marca) { porRequisicao[item.marca] = pendentes; pendentes = []; } else if (item.rule_id === 'SSRF') pendentes.push([item.source, item.code_line]);
    }
    assert.deepEqual(porRequisicao['q-java'], [], 'valor da lista permitida em /q não é SSRF\n' + result.stdout + result.stderr);
    assert.deepEqual(porRequisicao['q-django'], []);
    assert.deepEqual(porRequisicao['q-evil'], [], 'rejeitado antes do sink: nem chega a chamar');
    assert.deepEqual(porRequisicao['raw-metadata'], [['query:target', 15]], 'valor desconhecido sem validação continua sendo SSRF');
    assert.deepEqual(porRequisicao['mix'], [['query:target', 19]], 'o valor conhecido não pode esconder o que o atacante escolheu na mesma URL');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
