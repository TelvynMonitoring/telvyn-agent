'use strict';
// Selected routes: exact paths, or `*` standing for exactly one path segment (route parameters such as /users/*).
function compileRoutes(list) {
  const routes = String(list || '').split(',').filter(Boolean);
  if (routes.some(route => !/^\/[\w/.*-]*$/.test(route) || route.includes('..') || route.includes('**'))) throw new Error('Explicit security routes required');
  const exact = new Set(routes.filter(route => !route.includes('*')));
  const dynamic = routes.filter(route => route.includes('*')).map(route => [new RegExp('^' + route.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^/]+') + '$'), route]);
  // Returns the selected route that matches, so reports carry the pattern and never a parameter value.
  return {size: routes.length, match(pathname) {
    if (typeof pathname !== 'string') return null;
    if (exact.has(pathname)) return pathname;
    for (const [pattern, route] of dynamic) if (pattern.test(pathname)) return route;
    return null;
  }};
}
module.exports = { compileRoutes };
