'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

// Instalação manual no Linux: só NODE_OPTIONS=--require=bootstrap.cjs, sem TELVYN_SECURITY_ENABLED e sem
// deployment.environment. A segurança fica desligada e a aplicação NÃO pode cair na primeira requisição.
const pronto = fs.existsSync(path.join(__dirname, '..', 'node_modules', '@opentelemetry'));

test('aplicação com o agente e segurança desligada atende requisições sem cair', { skip: !pronto && 'dependências do agente não instaladas' }, async () => {
  const app = `
    const http = require('http');
    const server = http.createServer((req, res) => res.end('ok'));
    server.listen(0, '127.0.0.1', () => {
      http.get({ port: server.address().port, host: '127.0.0.1' }, res => {
        res.resume();
        res.on('end', () => { console.log('RESPONDEU ' + res.statusCode); server.close(); setTimeout(() => process.exit(0), 200); });
      });
    });`;
  const env = { ...process.env, OTEL_SERVICE_NAME: 'teste-sem-seguranca', OTEL_TRACES_EXPORTER: 'none', OTEL_METRICS_EXPORTER: 'none', OTEL_LOGS_EXPORTER: 'none',
    NODE_OPTIONS: `--require=${path.join(__dirname, '..', 'bootstrap.cjs')}` };
  delete env.TELVYN_SECURITY_ENABLED;
  delete env.TELVYN_IAST_ENABLED;
  delete env.OTEL_RESOURCE_ATTRIBUTES;
  const child = spawn(process.execPath, ['-e', app], { env });
  let out = '';
  let err = '';
  child.stdout.on('data', d => { out += d; });
  child.stderr.on('data', d => { err += d; });
  const code = await new Promise(resolve => child.on('close', resolve));
  assert.equal(code, 0, err);
  assert.match(out, /RESPONDEU 200/);
  assert.doesNotMatch(err, /security\.within/);
});
