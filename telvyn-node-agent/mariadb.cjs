// The `mariadb` package has no OpenTelemetry instrumentation. Its classes are internal, so they are reached through the
// factories: every connection or pool they return exposes the prototype to patch, and remembers the options it was opened with.
// Spans (register.cjs) and IAST (iast.cjs) both register here; the factories are wrapped once and every patch reaches every class.
const factories = ['createConnection', 'createPool', 'createPoolCluster'];
const options = new WeakMap(), patches = new Set();
const sqlOf = args => typeof args[0] === 'string' ? args[0] : args[0]?.sql;
const optionsOf = instance => options.get(instance) ?? {};

function remember(instance, opts) {
  if (!instance || typeof instance !== 'object') return instance;
  options.set(instance, opts);
  const prototype = Object.getPrototypeOf(instance);
  // The 3.x line keeps the methods on the class; the 2.x line (the one Sequelize 6 uses) assigns them on each object.
  const own = ['query', 'execute', 'batch', 'queryStream'].some(method => Object.hasOwn(instance, method));
  for (const patch of patches) { patch(prototype); if (own) patch(instance); }
  // A pool hands out connections of its own class; they keep the pool options.
  if (typeof instance.getConnection === 'function' && !Object.hasOwn(instance, 'getConnection')) {
    const getConnection = instance.getConnection;
    instance.getConnection = function (...args) {
      const callback = typeof args.at(-1) === 'function' ? args.pop() : null;
      if (callback) return getConnection.call(this, ...args, (error, connection) => callback(error, remember(connection, opts)));
      const result = getConnection.apply(this, args);
      return typeof result?.then === 'function' ? result.then(connection => remember(connection, opts)) : result;
    };
  }
  return instance;
}
function watch(library, patch) {
  patches.add(patch);
  for (const holder of [library, library?.default]) {
    for (const name of factories) {
      const factory = holder?.[name];
      if (typeof factory !== 'function' || factory.telvynMariadb) continue;
      const replacement = function (opts, ...rest) {
        const settings = typeof opts === 'string' ? parseUri(opts) : opts ?? {};
        const result = factory.call(this, opts, ...rest);
        return typeof result?.then === 'function' ? result.then(instance => remember(instance, settings)) : remember(result, settings);
      };
      replacement.telvynMariadb = true;
      try { holder[name] = replacement; } catch (_) { /* namespace not writable here */ }
    }
  }
}
function parseUri(uri) {
  try { const url = new URL(uri); return {host: url.hostname, port: url.port ? Number(url.port) : undefined, database: url.pathname.slice(1) || undefined}; }
  catch (_) { return {}; }
}
module.exports = {watch, sqlOf, optionsOf};
