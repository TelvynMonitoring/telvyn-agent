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

// Passport login (as Datadog: passport-local and passport-http Basic): the strategy's verify callback tells the login
// tried and whether it succeeded. A blocked user's successful login is answered with the block response and the
// strategy does not continue.
function patchStrategy(Strategy, framework, security) {
  const original = Strategy?.prototype?.authenticate;
  if (typeof original !== 'function' || original.telvynUsers) return;
  const authenticate = function (request) {
    const verify = this._verify;
    if (typeof verify === 'function' && !verify.telvynUsers) {
      const passRequest = !!this._passReqToCallback;
      const wrapped = function (...args) {
        const login = args[passRequest ? 1 : 0];
        const done = args[args.length - 1];
        if (typeof done === 'function') args[args.length - 1] = function (error, user) {
          // An error is neither a success nor a failure.
          if (!error) {
            try { if (security.trackLogin(framework, login, user, !!user)) return; } catch (_) { /* Protection never breaks the application. */ }
          }
          return done.apply(this, arguments);
        };
        return verify.apply(this, args);
      };
      wrapped.telvynUsers = true;
      this._verify = wrapped;
    }
    return original.apply(this, arguments);
  };
  authenticate.telvynUsers = true;
  Strategy.prototype.authenticate = authenticate;
}

function watchFrameworks(security) {
  const Module = require('node:module'), load = Module._load;
  Module._load = function (name, parent, ...rest) {
    const exported = load.call(this, name, parent, ...rest);
    try {
      if (name === 'express') watchExpress(Module._resolveFilename(name, parent), security);
      else if (name === 'fastify') return wrapFastify(exported, security);
      else if (name === 'passport-local') patchStrategy(exported?.Strategy, 'passport-local', security);
      else if (name === 'passport-http') patchStrategy(exported?.BasicStrategy, 'passport-http', security);
    } catch (_) { /* Protection never breaks the application. */ }
    return exported;
  };
  try {
    const { Hook } = require('import-in-the-middle');
    new Hook(['express', 'fastify', 'passport-local', 'passport-http'], (exported, name, baseDir) => {
      try {
        if (name === 'passport-local') patchStrategy(exported.Strategy ?? exported.default?.Strategy, 'passport-local', security);
        if (name === 'passport-http') patchStrategy(exported.BasicStrategy ?? exported.default?.BasicStrategy, 'passport-http', security);
        if (name === 'express' && baseDir) watchExpress(path.join(baseDir, 'index.js'), security);
        else if (name === 'fastify') { const wrapped = wrapFastify(exported.default, security); exported.default = wrapped; exported.fastify = wrapped; }
      } catch (_) { /* Protection never breaks the application. */ }
      return exported;
    });
  } catch (_) { /* ESM hooks unavailable */ }
}

module.exports = { watchFrameworks };
