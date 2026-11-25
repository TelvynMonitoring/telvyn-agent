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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Padrão de rota a partir do caminho concreto: o que parece identificador (número, UUID, hexadecimal ou token longo) vira ":id",
// para o relatório nunca levar o valor de um parâmetro de rota.
function routePattern(pathname) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) return null;
  return pathname.slice(0, 1024).split('/')
    .map(part => part && (/^\d+$/.test(part) || UUID.test(part) || /^[0-9a-f]{12,}$/i.test(part) || /^[\w-]{24,}$/.test(part) ? ':id' : part))
    .join('/').replace(/[^\w/:.*{}-]/g, '_');
}
// Sem lista explícita de rotas, toda rota é analisada.
function anyRoute() { return { size: 0, any: true, match: routePattern }; }
module.exports = { compileRoutes, routePattern, anyRoute };
