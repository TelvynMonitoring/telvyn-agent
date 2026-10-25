import * as instrumentation from '@opentelemetry/instrumentation/hook.mjs';
let port, sca;

export async function initialize(options) {
  // The loader thread inherits preloads but is not an application worker; bootstrap.cjs never starts the SDK here.
  port = options?.port; port?.unref();
  sca = options?.sca === true;
  return instrumentation.initialize?.({});
}
export const resolve = instrumentation.resolve;
export async function load(url, context, nextLoad) {
  return instrumentation.load(url, context, async (target, settings) => {
    const result = await nextLoad(target, settings);
    // Runtime SCA: ES modules from installed packages go to the main thread, which reads their package.json.
    if (sca && target.startsWith('file:') && target.includes('/node_modules/')) port?.postMessage({module: target});
    return result;
  });
}
