'use strict';
// Keep the application available when its runtime cannot load this package.
// The OpenTelemetry packages in this bundle support Node.js 18.19+ and 20.6+.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 18 || (major === 18 && minor < 19)) {
  console.warn('[Telvyn] Instrumentation skipped: Node.js 18.19 or newer is required.');
} else {
  try { require('./register.cjs'); }
  catch (_) { console.warn('[Telvyn] Instrumentation could not start; application startup continues.'); }
}
