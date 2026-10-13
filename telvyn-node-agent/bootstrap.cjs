'use strict';
// Keep the application available when its runtime cannot load this package.
if (Number(process.versions.node.split('.')[0]) < 20) {
  console.warn('[Telvyn] Instrumentation skipped: Node.js 20 or newer is required.');
} else {
  try { require('./register.cjs'); }
  catch (_) { console.warn('[Telvyn] Instrumentation could not start; application startup continues.'); }
}
