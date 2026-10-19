'use strict';
// Exploit prevention: each dangerous operation made while serving a request is checked
// against that request's input by the exploit-prevention rules (rasp-*): SQL statements (pg, mysql2), outgoing requests
// (http, https, fetch), file paths (fs) and commands (child_process). A rule in blocking mode answers the request with
// the block response and aborts the operation with TelvynRaspAbortError; an abort that the application does not
// handle is kept from crashing the process, since the response was already sent.
const path = require('node:path');

class TelvynRaspAbortError extends Error {
  constructor() { super('Operation blocked by Telvyn exploit prevention'); this.name = 'TelvynRaspAbortError'; }
}
const isAbort = error => {
  for (let current = error, depth = 0; current && depth < 10; current = current.cause, depth++) if (current instanceof TelvynRaspAbortError) return true;
  return false;
};

function check(security, data) {
  let blocked = false;
  try { blocked = security.inspectOperation(data); } catch (_) { /* Protection never breaks the application. */ }
  if (blocked) throw new TelvynRaspAbortError();
}

const text = value => typeof value === 'string' ? value : value instanceof URL ? value.href : Buffer.isBuffer(value) ? value.toString('utf8') : undefined;

// fs: the path of operations that read, write or list files.
const FS = ['access', 'appendFile', 'chmod', 'chown', 'copyFile', 'createReadStream', 'createWriteStream', 'lstat', 'mkdir', 'open', 'opendir',
  'readFile', 'readdir', 'readlink', 'realpath', 'rename', 'rm', 'rmdir', 'stat', 'truncate', 'unlink', 'writeFile'];
function patchFs(security) {
  const wrap = (target, name) => {
    const original = target?.[name];
    if (typeof original !== 'function' || original.telvynRasp) return;
    const patched = function (file) {
      const value = text(file);
      if (value) check(security, {'server.io.fs.file': value});
      return original.apply(this, arguments);
    };
    Object.defineProperties(patched, Object.getOwnPropertyDescriptors(original));
    patched.telvynRasp = true;
    target[name] = patched;
  };
  const fs = require('node:fs');
  for (const name of FS) { wrap(fs, name); wrap(fs, name + 'Sync'); wrap(fs.promises, name); }
}

// child_process: shell commands (exec, shell option) and executed programs with arguments.
function patchChildProcess(security) {
  const childProcess = require('node:child_process');
  const wrap = (name, shell) => {
    const original = childProcess[name];
    if (typeof original !== 'function' || original.telvynRasp) return;
    const patched = function (file, args, options) {
      if (typeof file === 'string') {
        const list = Array.isArray(args) ? args.map(String) : [];
        const opts = Array.isArray(args) ? options : args;
        if (shell || opts?.shell) check(security, {'server.sys.shell.cmd': [file, ...list].join(' ')});
        else check(security, {'server.sys.exec.cmd': [file, ...list]});
      }
      return original.apply(this, arguments);
    };
    Object.defineProperties(patched, Object.getOwnPropertyDescriptors(original));
    patched.telvynRasp = true;
    childProcess[name] = patched;
  };
  for (const name of ['exec', 'execSync']) wrap(name, true);
  for (const name of ['execFile', 'execFileSync', 'spawn', 'spawnSync']) wrap(name, false);
}

// Outgoing requests: http/https request and get, and the global fetch.
function patchOutgoing(security) {
  const target = args => {
    const [first, second] = args;
    if (typeof first === 'string' || first instanceof URL) return text(first);
    const options = first && typeof first === 'object' ? first : second;
    if (!options || typeof options !== 'object') return undefined;
    if (options.href) return options.href;
    const host = options.hostname || options.host;
    if (!host) return undefined;
    return `${options.protocol || 'http:'}//${host}${options.port ? ':' + options.port : ''}${options.path || '/'}`;
  };
  for (const name of ['node:http', 'node:https']) {
    const module = require(name);
    for (const method of ['request', 'get']) {
      const original = module[method];
      if (typeof original !== 'function' || original.telvynRasp) continue;
      const patched = function () {
        const url = target(arguments);
        if (url) check(security, {'server.io.net.url': url});
        return original.apply(this, arguments);
      };
      patched.telvynRasp = true;
      module[method] = patched;
    }
  }
  const fetch = globalThis.fetch;
  if (typeof fetch === 'function' && !fetch.telvynRasp) {
    const patched = function (input) {
      const url = typeof input === 'string' || input instanceof URL ? text(input) : typeof input?.url === 'string' ? input.url : undefined;
      if (url) {
        try { check(security, {'server.io.net.url': url}); } catch (error) { return Promise.reject(error); }
      }
      return fetch.apply(this, arguments);
    };
    patched.telvynRasp = true;
    globalThis.fetch = patched;
  }
}

// SQL: the statement and the database system (pg, mysql2).
function patchQuery(proto, method, system, security) {
  const original = proto?.[method];
  if (typeof original !== 'function' || original.telvynRasp) return;
  const patched = function (query) {
    const statement = typeof query === 'string' ? query : typeof query?.text === 'string' ? query.text : typeof query?.sql === 'string' ? query.sql : undefined;
    if (statement) {
      try { check(security, {'server.db.statement': statement, 'server.db.system': system}); }
      catch (error) {
        const callback = [...arguments].reverse().find(arg => typeof arg === 'function');
        if (callback) { process.nextTick(callback, error); return undefined; }
        if (system === 'postgresql') return Promise.reject(error);
        throw error;
      }
    }
    return original.apply(this, arguments);
  };
  patched.telvynRasp = true;
  proto[method] = patched;
}

function patchDatabases(security, name, exported, file) {
  if (name === 'pg') patchQuery(exported?.Client?.prototype, 'query', 'postgresql', security);
  else if (name === 'mysql2' || name === 'mysql2/promise') {
    try {
      const base = require(path.join(path.dirname(file), 'lib', 'base', 'connection.js'));
      patchQuery(base?.prototype, 'query', 'mysql', security);
      patchQuery(base?.prototype, 'execute', 'mysql', security);
    } catch (_) {
      try {
        const connection = require(path.join(path.dirname(file), 'lib', 'connection.js'));
        patchQuery(connection?.prototype, 'query', 'mysql', security);
        patchQuery(connection?.prototype, 'execute', 'mysql', security);
      } catch (__) { /* mysql2 layout not recognized */ }
    }
  }
}

// An abort the application did not handle must not crash the process: the request was already answered.
function guardProcess() {
  process.on('uncaughtExceptionMonitor', error => {
    if (!isAbort(error)) return;
    if (process.hasUncaughtExceptionCaptureCallback()) return;
    const listeners = process.listeners('uncaughtException');
    process.removeAllListeners('uncaughtException');
    const ignore = () => {};
    process.once('uncaughtException', ignore);
    setImmediate(() => {
      process.removeListener('uncaughtException', ignore);
      for (const listener of listeners) process.on('uncaughtException', listener);
    });
  });
}

// Express's final handler destroys the socket when a response was already sent: an abort is not an application error.
function patchFinalHandler(exported) {
  if (typeof exported !== 'function' || exported.telvynRasp) return exported;
  const wrapped = function () {
    const done = exported.apply(this, arguments);
    return function (error) { return isAbort(error) ? undefined : done.apply(this, arguments); };
  };
  wrapped.telvynRasp = true;
  return wrapped;
}

function startRasp(security) {
  patchFs(security);
  patchChildProcess(security);
  patchOutgoing(security);
  // ESM named imports of built-in modules (import { readFile } from 'node:fs') see the patched functions.
  require('node:module').syncBuiltinESMExports();
  guardProcess();
  const Module = require('node:module'), load = Module._load;
  Module._load = function (name, parent, ...rest) {
    const exported = load.call(this, name, parent, ...rest);
    if (name === 'pg' || name === 'mysql2' || name === 'mysql2/promise') {
      try { patchDatabases(security, name, exported, Module._resolveFilename(name, parent)); } catch (_) { /* Protection never breaks the application. */ }
    } else if (name === 'finalhandler') return patchFinalHandler(exported);
    return exported;
  };
}

module.exports = { startRasp, TelvynRaspAbortError, isAbort };
