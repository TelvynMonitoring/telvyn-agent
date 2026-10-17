'use strict';
// Route phase of attack detection (as Datadog): once the framework parsed the body and matched the route, the WAF
// sees the body, path parameters and the logged-in user (req.user / request.user, as set by Passport and similar),
// and a blocking match stops the request before the route handler runs.
const path = require('node:path');

// Logged-in user identifier, as Datadog's automatic user collection: the user's id.
const userId = user => user == null ? undefined : typeof user === 'object' ? (user.id ?? user._id) : undefined;

function patchLayer(Layer, method, security) {
  const original = Layer?.prototype?.[method];
  if (typeof original !== 'function' || original.telvynSecurity) return;
  const patched = function (request, response) {
    // Route handlers (layers inside a Route) carry the HTTP method; middlewares do not.
    if (this.method !== undefined && request && response && !response.headersSent) {
      try {
        if (security.inspectRoute(request, {body: request.body, params: request.params, user: userId(request.user)})) { security.block(request, response); return; }
      } catch (_) { /* Protection never breaks the application. */ }
    }
    return original.apply(this, arguments);
  };
  patched.telvynSecurity = true;
  Layer.prototype[method] = patched;
}

function watchExpress(expressFile, security) {
  const directory = path.dirname(expressFile);
  // Express 4 keeps its router inside; Express 5 uses the "router" package.
  try { patchLayer(require(path.join(directory, 'lib', 'router', 'layer.js')), 'handle_request', security); } catch (_) { /* not Express 4 */ }
  try { patchLayer(require(path.join(path.dirname(require.resolve('router', {paths: [directory]})), 'lib', 'layer.js')), 'handleRequest', security); } catch (_) { /* not Express 5 */ }
}

function wrapFastify(factory, security) {
  if (typeof factory !== 'function' || factory.telvynSecurity) return factory;
  const wrapped = function (...args) {
    const app = factory.apply(this, args);
    try {
      app.addHook('preHandler', async (request, reply) => {
        try {
          if (security.inspectRoute(request.raw, {body: request.body, params: request.params, user: userId(request.user)})) {
            reply.hijack();
            security.block(request.raw, reply.raw);
            return reply;
          }
        } catch (_) { /* Protection never breaks the application. */ }
      });
    } catch (_) { /* hooks unavailable: request-start protection still applies */ }
    return app;
  };
  Object.assign(wrapped, factory);
  wrapped.fastify = wrapped;
  wrapped.default = wrapped;
  wrapped.telvynSecurity = true;
  return wrapped;
}

function watchFrameworks(security) {
  const Module = require('node:module'), load = Module._load;
  Module._load = function (name, parent, ...rest) {
    const exported = load.call(this, name, parent, ...rest);
    try {
      if (name === 'express') watchExpress(Module._resolveFilename(name, parent), security);
      else if (name === 'fastify') return wrapFastify(exported, security);
    } catch (_) { /* Protection never breaks the application. */ }
    return exported;
  };
  try {
    const { Hook } = require('import-in-the-middle');
    new Hook(['express', 'fastify'], (exported, name, baseDir) => {
      try {
        if (name === 'express' && baseDir) watchExpress(path.join(baseDir, 'index.js'), security);
        else if (name === 'fastify') { const wrapped = wrapFastify(exported.default, security); exported.default = wrapped; exported.fastify = wrapped; }
      } catch (_) { /* Protection never breaks the application. */ }
      return exported;
    });
  } catch (_) { /* ESM hooks unavailable */ }
}

module.exports = { watchFrameworks };
