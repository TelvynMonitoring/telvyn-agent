'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { collectLiterals } = require('../iast.cjs');
const { originalPosition } = require('../sourcemap.cjs');
const { cpuProfile, wallSamples, heapObjects } = require('../profiler.cjs');

test('literais do módulo com o nome a que são atribuídos', () => {
  const found = collectLiterals('const dbPassword = "Zx9!kLp2#qR";\nconst cfg = { api: { adminPwd: `Qw8$rT5&yU` } };\nrun("AKIAIOSFODNN7EXAMPLE");\n');
  const by = value => found.find(item => item.value === value)?.locations;
  assert.deepEqual(by('Zx9!kLp2#qR'), [{ ident: 'dbPassword', line: 1 }]);
  assert.deepEqual(by('Qw8$rT5&yU'), [{ ident: 'adminPwd', line: 2 }]);
  assert.deepEqual(by('AKIAIOSFODNN7EXAMPLE'), [{ ident: undefined, line: 3 }]);
});

test('posição original pelo mapa de fontes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telvyn-map-'));
  try {
    // Linha 1 do JavaScript gerado vem da linha 11, coluna 5 de src/app.ts.
    const map = { version: 3, file: 'app.js', sources: ['src/app.ts'], names: [], mappings: 'AAUI' };
    fs.writeFileSync(path.join(dir, 'app.js'), 'run();\n//# sourceMappingURL=data:application/json;base64,' + Buffer.from(JSON.stringify(map)).toString('base64') + '\n');
    fs.writeFileSync(path.join(dir, 'plain.js'), 'run();\n');
    const mapped = originalPosition(path.join(dir, 'app.js'), 1, 1);
    assert.equal(mapped.path, path.join(dir, 'src', 'app.ts'));
    assert.equal(mapped.line, 11);
    assert.equal(originalPosition(path.join(dir, 'plain.js'), 1, 1), null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

const node = (id, name, children = [], extra = {}) => ({ id, callFrame: { functionName: name, url: '', lineNumber: 0, columnNumber: 0 }, children, ...extra });

test('wall pesa pelo tempo até a próxima amostra e liga ao span da linha do tempo', () => {
  const profile = {
    startTime: 1000000, nodes: [node(1, '(root)', [2, 3]), node(2, 'handler'), node(3, '(idle)')],
    samples: [2, 2, 3, 2], timeDeltas: [0, 1000, 5000, 2000],
  };
  const notes = [{ at: 1000, holder: { trace: 'a'.repeat(32), span: 'b'.repeat(16) } }, { at: 1000.5, holder: null }];
  const samples = wallSamples(profile, notes, 0);
  const linked = samples.find(sample => sample.span);
  assert.equal(linked.stack, 'handler');
  assert.equal(linked.weight, 1000 * 1000); // amostra de 1001 ms: 1 ms até a seguinte
  const unlinked = samples.find(sample => !sample.span);
  assert.equal(unlinked.weight, 5000 * 1000 + 2000 * 1000); // as de 1001 ms e 1008 ms
});

test('contagem de objetos vivos a partir das amostras do heap', () => {
  const profile = { samplingInterval: 1000, head: node(1, '(root)', [node(2, 'build')]), samples: [{ nodeId: 2, size: 1000, ordinal: 1 }, { nodeId: 2, size: 1000, ordinal: 2 }] };
  const lines = heapObjects(profile).split('\n');
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^build 3$/); // 2 / (1 - e^-1) = 3.16
});

test('perfil de CPU continua dobrando as pilhas', () => {
  const profile = { nodes: [node(1, '(root)', [2]), node(2, 'work')], samples: [2, 2, 2] };
  assert.equal(cpuProfile(profile).folded, 'work 3');
});

test('IAST: entrada da requisição que chega ao sink, sem reescrita de código', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telvyn-iast-'));
  try {
    fs.writeFileSync(path.join(dir, 'app.cjs'), [
      "const http = require('node:http'), fs = require('node:fs'), path = require('node:path');",
      "const adminPassword = 'Zx9!kLp2#qR';",
      'module.exports = () => http.createServer((req, res) => {',
      "  const name = new URL(req.url, 'http://x').searchParams.get('name');",
      "  const file = path.join(__dirname, 'data', name);",
      "  try { fs.readFileSync(file); } catch (_) {}",
      "  try { fs.readFileSync(path.join(__dirname, 'data', 'fixed.txt')); } catch (_) {}",
      "  res.end('ok');",
      '});',
    ].join('\n'));
    fs.writeFileSync(path.join(dir, 'run.cjs'), [
      "const { startIast } = require(" + JSON.stringify(path.resolve(__dirname, '..', 'iast.cjs')) + ');',
      'const findings = [];',
      'startIast(finding => findings.push(finding));',
      "const server = require('./app.cjs')();",
      "server.listen(0, async () => {",
      "  const base = 'http://127.0.0.1:' + server.address().port;",
      "  await fetch(base + '/q?name=..%2F..%2Fetc%2Fpasswd');",
      "  await fetch(base + '/q?name=ok');",
      "  console.log(JSON.stringify(findings.map(({ rule_id, code_method, code_line, source }) => ({ rule_id, code_method, code_line, source }))));",
      "  process.exit(0);",
      '});',
    ].join('\n'));
    const result = spawnSync(process.execPath, ['run.cjs'], {
      cwd: dir, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, TELVYN_IAST_ENABLED: 'true', TELVYN_PROFILE_SOURCE_ROOT: dir, TELVYN_SECURITY_ROUTES: '/q' },
    });
    const findings = JSON.parse(result.stdout.trim().split('\n').pop());
    const traversal = findings.filter(finding => finding.rule_id === 'PATH_TRAVERSAL');
    // Uma por requisição, sempre na linha que monta o caminho com a entrada; o caminho fixo da linha 7 não é achado.
    assert.deepEqual(traversal.map(finding => [finding.source, finding.code_line]), [['query:name', 6], ['query:name', 6]], result.stdout + result.stderr);
    const secret = findings.filter(finding => finding.rule_id === 'HARDCODED_PASSWORD');
    assert.deepEqual(secret.map(finding => finding.code_line), [2]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
