'use strict';
// Route phase of attack detection: once the framework parsed the body and matched the route, the WAF
// sees the body, path parameters and the logged-in user (req.user / request.user, as set by Passport and similar),
// and a blocking match stops the request before the route handler runs.
const path = require('node:path');

// Logged-in user identifier: the user's id.
const userId = user => user == null ? undefined : typeof user === 'object' ? (user.id ?? user._id) : undefined;

function patchLayer(Layer, method, security) {
  const original = Layer?.prototype?.[method];
  if (typeof original !== 'function' || original.telvynSecurity) return;
  const patched = function (request, response) {
    // Route handlers (layers inside a Route) carry the HTTP method; middlewares do not.
    if (this.method !== undefined && request && response && !response.headersSent) {
      try {
        const route = request.route?.path != null ? (request.baseUrl || '') + request.route.path : undefined;
        if (security.inspectRoute(request, {body: request.body, params: request.params, user: userId(request.user), route})) { security.block(request, response); return; }
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
          if (security.inspectRoute(request.raw, {body: request.body, params: request.params, user: userId(request.user), route: request.routeOptions?.url ?? request.routerPath})) {
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

// Passport login (passport-local and passport-http Basic): the strategy's verify callback tells the login
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

// multer (body blocking on Express needs body-parser or multer): multipart fields are parsed by the
// route's own middleware, after the route phase; they are inspected once multer finishes.
function patchMulter(multer, security) {
  if (typeof multer !== 'function' || multer.telvynSecurity) return;
  multer.telvynSecurity = true;
  let proto;
  try { proto = Object.getPrototypeOf(multer()); } catch (_) { return; }
  const original = proto?._makeMiddleware;
  if (typeof original !== 'function' || original.telvynSecurity) return;
  const makeMiddleware = function () {
    const middleware = original.apply(this, arguments);
    return function (request, response, next) {
      return middleware.call(this, request, response, function (error) {
        if (!error) {
          try { if (security.inspectBody(request, request.body)) return; } catch (_) { /* Protection never breaks the application. */ }
        }
        return next.apply(this, arguments);
      });
    };
  };
  makeMiddleware.telvynSecurity = true;
  proto._makeMiddleware = makeMiddleware;
}

// Next.js App Router: the body is inspected when the route handler reads the incoming request with
// text(), json() or formData(). Detection only: Next.js is blocked at request start (IP, user, rules on
// headers, query, URI); failing the read would make Next.js log an error and record the request as a 500.
function patchWebRequest(security) {
  const proto = globalThis.Request?.prototype;
  if (!proto || proto.telvynSecurity) return;
  proto.telvynSecurity = true;
  const form = data => {
    const out = {};
    for (const [key, value] of data) if (typeof value === 'string') (out[key] ??= []).push(value);
    return out;
  };
  for (const method of ['text', 'json', 'formData']) {
    const original = proto[method];
    if (typeof original !== 'function') continue;
    proto[method] = function () {
      const result = original.apply(this, arguments);
      let incoming = false;
      try { incoming = security.isIncoming(this); } catch (_) { /* Protection never breaks the application. */ }
      if (!incoming) return result;
      return result.then(body => {
        try { security.inspectBody(null, method === 'formData' ? form(body) : body, false); } catch (_) { /* Protection never breaks the application. */ }
        return body;
      });
    };
  }
}

// GraphQL arguments as graphql.server.all_resolvers: { field: [ { argument: value } ] } for every field of
// the executed operation, with variables resolved.
function resolverArguments(document, variables, operationName) {
  const out = {}, fragments = {};
  for (const definition of document?.definitions ?? []) if (definition.kind === 'FragmentDefinition') fragments[definition.name.value] = definition;
  const value = node => {
    switch (node?.kind) {
      case 'Variable': return variables?.[node.name.value];
      case 'IntValue': case 'FloatValue': case 'StringValue': case 'BooleanValue': case 'EnumValue': return node.value;
      case 'ListValue': return node.values.map(value);
      case 'ObjectValue': return Object.fromEntries(node.fields.map(field => [field.name.value, value(field.value)]));
      default: return null;
    }
  };
  const visit = (selectionSet, seen) => {
    for (const selection of selectionSet?.selections ?? []) {
      if (selection.kind === 'Field') {
        if (selection.arguments?.length) (out[selection.name.value] ??= []).push(Object.fromEntries(selection.arguments.map(arg => [arg.name.value, value(arg.value)])));
        visit(selection.selectionSet, seen);
      } else if (selection.kind === 'InlineFragment') visit(selection.selectionSet, seen);
      else if (selection.kind === 'FragmentSpread' && !seen.has(selection.name.value)) { seen.add(selection.name.value); visit(fragments[selection.name.value]?.selectionSet, seen); }
    }
  };
  for (const definition of document?.definitions ?? []) {
    if (definition.kind !== 'OperationDefinition' || operationName && definition.name?.value !== operationName) continue;
    visit(definition.selectionSet, new Set());
  }
  return out;
}

// graphql-js execute (used by Apollo Server and most Node GraphQL servers).
function patchGraphql(graphqlFile, security) {
  let execution;
  try { execution = require(path.join(path.dirname(graphqlFile), 'execution', 'execute.js')); } catch (_) { return; }
  const original = execution?.execute;
  if (typeof original !== 'function' || original.telvynSecurity) return;
  const execute = function (args) {
    try {
      const options = arguments.length === 1 && args && typeof args === 'object' && args.document ? args
        : {document: arguments[1], variableValues: arguments[4], operationName: arguments[5]};
      if (security.inspectGraphql(resolverArguments(options.document, options.variableValues, options.operationName))) return {errors: [new Error('Request blocked by Telvyn')]};
    } catch (_) { /* Protection never breaks the application. */ }
    return original.apply(this, arguments);
  };
  execute.telvynSecurity = true;
  execution.execute = execute;
}

// Apollo Server (ApolloServer.executeHTTPGraphQLRequest): a request blocked during execution is
// answered by Apollo itself with the block response.
function patchApollo(exported, security) {
  const proto = exported?.ApolloServer?.prototype;
  const original = proto?.executeHTTPGraphQLRequest;
  if (typeof original !== 'function' || original.telvynSecurity) return;
  const execute = async function () {
    try { security.apolloStart(); } catch (_) { /* Protection never breaks the application. */ }
    const result = await original.apply(this, arguments);
    let block = null;
    try { block = security.apolloBlock(); } catch (_) { /* Protection never breaks the application. */ }
    if (!block || typeof result?.headers?.constructor !== 'function') return result;
    const headers = new result.headers.constructor();
    for (const [name, value] of Object.entries(block.headers)) headers.set(name, value);
    return {status: block.status, headers, body: {kind: 'complete', string: block.body}};
  };
  execute.telvynSecurity = true;
  proto.executeHTTPGraphQLRequest = execute;
}

function watchFrameworks(security) {
  try { patchWebRequest(security); } catch (_) { /* Protection never breaks the application. */ }
  const Module = require('node:module'), load = Module._load;
  Module._load = function (name, parent, ...rest) {
    const exported = load.call(this, name, parent, ...rest);
    try {
      if (name === 'express') watchExpress(Module._resolveFilename(name, parent), security);
      else if (name === 'fastify') return wrapFastify(exported, security);
      else if (name === 'multer') patchMulter(exported, security);
      else if (name === 'graphql') patchGraphql(Module._resolveFilename(name, parent), security);
      else if (name === '@apollo/server') patchApollo(exported, security);
      else if (name === 'passport-local') patchStrategy(exported?.Strategy, 'passport-local', security);
      else if (name === 'passport-http') patchStrategy(exported?.BasicStrategy, 'passport-http', security);
    } catch (_) { /* Protection never breaks the application. */ }
    return exported;
  };
  try {
    const { Hook } = require('import-in-the-middle');
    new Hook(['express', 'fastify', 'passport-local', 'passport-http', 'multer', 'graphql', '@apollo/server'], (exported, name, baseDir) => {
      try {
        if (name === 'graphql' && baseDir) patchGraphql(path.join(baseDir, 'index.js'), security);
        if (name === '@apollo/server') patchApollo(exported, security);
        if (name === 'multer') patchMulter(exported.default ?? exported, security);
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
