import * as instrumentation from '@opentelemetry/instrumentation/hook.mjs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const require = createRequire(import.meta.url);
let rewriter, root, port, blockTopLevelArrows;

export async function initialize(options) {
  // The loader thread inherits preloads but is not an application worker.
  void require('./register.cjs').stop?.();
  port = options?.port; port?.unref();
  if (options?.iast && options.sourceRoot) {
    try {
      root = path.resolve(options.sourceRoot);
      const { Rewriter } = require('@datadog/wasm-js-rewriter');
      ({ blockTopLevelArrows } = require('./iast.cjs'));
      rewriter = new Rewriter({csiMethods: require('./iast.cjs').rewriterMethods, literals: false, chainSourceMap: true});
    } catch (_) { port?.postMessage({error: true}); }
  }
  return instrumentation.initialize?.({});
}
export const resolve = instrumentation.resolve;
export async function load(url, context, nextLoad) {
  return instrumentation.load(url, context, async (target, settings) => {
    const result = await nextLoad(target, settings);
    if (!rewriter || result.format !== 'module' || !target.startsWith('file:')) return result;
    const filename = fileURLToPath(target), relative = path.relative(root, filename).split(path.sep).join('/');
    if (!/^(?:[\w$.-]+\/)*[\w$.-]+\.(?:js|mjs)$/.test(relative) || relative.split('/').some(part => part === '..' || part === 'node_modules')) return result;
    try {
      const original = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8');
      const source = rewriter.rewrite(blockTopLevelArrows(original, 'module'), filename, ['iast']).content || original;
      if (source !== original) port?.postMessage({filename, source});
      return {...result, source};
    } catch (_) { port?.postMessage({error: true}); return result; }
  });
}
