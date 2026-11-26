'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

// module.register() sobe uma thread interna só para os hooks do loader ESM, e o --require/NODE_OPTIONS também roda nela.
// Sem guarda, o agente inteiro (sensores, exportadores, polling de configuração) inicia duas vezes e todo aviso sai duplicado.
// Um Worker criado pela aplicação, ao contrário, continua sendo instrumentado.
const pronto = fs.existsSync(path.join(__dirname, '..', 'node_modules', '@opentelemetry'));
const semSuporte = typeof require('node:worker_threads').isInternalThread === 'undefined' && 'Node sem worker_threads.isInternalThread (não dá para distinguir a thread do loader)';
const AVISO = /Runtime configuration or Debugger could not start/g;

async function rodar(app) {
  const env = { ...process.env, TELVYN_ENABLED: 'true', OTEL_TRACES_EXPORTER: 'none', OTEL_METRICS_EXPORTER: 'none', OTEL_LOGS_EXPORTER: 'none',
    NODE_OPTIONS: `--require=${path.join(__dirname, '..', 'register.cjs')}` };
  for (const k of ['OTEL_SERVICE_NAME', 'OTEL_RESOURCE_ATTRIBUTES', 'TELVYN_SECURITY_ENABLED']) delete env[k]; // sem identidade de serviço cada carga avisa que não iniciou: é o sinal de cada carga
  const child = spawn(process.execPath, ['-e', app], { env });
  let err = '';
  child.stderr.on('data', d => { err += d; });
  child.stdout.on('data', () => {});
  const code = await new Promise(resolve => child.on('close', resolve));
  return { code, avisos: (err.match(AVISO) || []).length, err };
}

test('o agente carrega uma vez só, não também na thread interna do loader', { skip: (!pronto && 'dependências do agente não instaladas') || semSuporte }, async () => {
  const { code, avisos, err } = await rodar('setTimeout(() => process.exit(0), 1000)');
  assert.equal(code, 0, err);
  assert.equal(avisos, 1, `esperava 1 carga, houve ${avisos}:\n${err}`);
});

test('um Worker da aplicação continua sendo instrumentado', { skip: (!pronto && 'dependências do agente não instaladas') || semSuporte }, async () => {
  const app = `new (require('node:worker_threads').Worker)('setTimeout(() => {}, 500)', { eval: true }).on('exit', () => setTimeout(() => process.exit(0), 300));`;
  const { code, avisos, err } = await rodar(app);
  assert.equal(code, 0, err);
  assert.equal(avisos, 2, `esperava 2 cargas (principal + Worker da aplicação), houve ${avisos}:\n${err}`);
});
