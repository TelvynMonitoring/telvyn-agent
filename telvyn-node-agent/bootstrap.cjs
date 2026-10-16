'use strict';
// Keep the application available when its runtime cannot load this package.
// The OpenTelemetry packages in this bundle support Node.js 18.19+ and 20.6+.
const [major, minor] = process.versions.node.split('.').map(Number);
const threads = require('node:worker_threads');
// Node's module-hooks thread also receives --require; the application never runs there. Older Node versions have no
// isInternalThread: that thread is the only non-main one without a parentPort (application workers always have one).
if (threads.isInternalThread ?? (!threads.isMainThread && threads.parentPort === null)) {
} else if (major < 18 || (major === 18 && minor < 19)) {
  console.warn('[Telvyn] Instrumentation skipped: Node.js 18.19 or newer is required.');
} else {
  try { require('./register.cjs'); }
  catch (_) { console.warn('[Telvyn] Instrumentation could not start; application startup continues.'); }
}
