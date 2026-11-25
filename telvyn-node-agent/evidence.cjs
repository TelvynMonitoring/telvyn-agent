'use strict';
// Evidência de um ataque: o valor que casou, a consulta e os cabeçalhos com que a requisição chegou.
// A redação acontece aqui, antes de qualquer dado sair da aplicação; o backend valida e redige de novo pela mesma regra.

const VALUE_MAX = 256;
const QUERY_MAX = 1024;
const HEADER_VALUE_MAX = 256;
const REDACTED = '<redacted>';

// Campos cujo valor nunca é enviado.
const SENSITIVE_KEY = /(pass(word|wd|phrase)?|pwd|secret|token|authorization|auth|api[-_]?key|cookie|session|csrf|xsrf|credential|private|signature|otp|cvv|cvc|card|ssn|cpf|cnpj)/i;
// Só estes cabeçalhos são considerados, e mesmo assim os sensíveis ficam de fora.
const SAFE_HEADERS = ['user-agent', 'content-type', 'content-length', 'accept', 'accept-language', 'referer', 'origin', 'host', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'x-request-id'];
const JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
const BEARER = /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const AWS_KEY = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const CARD = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

function luhn(candidate) {
  let sum = 0;
  let alternate = false;
  let any = false;
  for (let i = candidate.length - 1; i >= 0; i--) {
    const c = candidate.charCodeAt(i);
    if (c < 48 || c > 57) continue;
    any = true;
    let digit = c - 48;
    if (alternate) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
    alternate = !alternate;
  }
  return any && sum % 10 === 0;
}

function redactValue(text) {
  return text
    .replace(JWT, REDACTED)
    .replace(BEARER, REDACTED)
    .replace(AWS_KEY, REDACTED)
    .replace(CARD, match => luhn(match) ? REDACTED : match);
}

const clean = text => String(text).replace(CONTROL, '?');

// "server.request.query:password" -> a parte depois dos dois pontos é o nome do campo; cookies nunca vão.
function sensitiveLocation(location) {
  if (typeof location !== 'string') return false;
  if (/cookie/i.test(location)) return true;
  const colon = location.indexOf(':');
  return colon >= 0 && SENSITIVE_KEY.test(location.slice(colon + 1));
}

// Só entradas da requisição têm valor a mostrar: um match na resposta (ex.: server.response.status) não é um payload.
const isRequestInput = location => typeof location === 'string' && location.startsWith('server.request.');

function payload(value, location) {
  if (typeof value !== 'string' || !isRequestInput(location)) return undefined;
  let text = clean(value);
  let truncated = false;
  let redacted = false;
  if (text.length > VALUE_MAX) { text = text.slice(0, VALUE_MAX); truncated = true; }
  if (sensitiveLocation(location)) { text = REDACTED; redacted = true; }
  else { const cleaned = redactValue(text); if (cleaned !== text) { text = cleaned; redacted = true; } }
  return {value: text, truncated, redacted};
}

function safeDecode(text) {
  try { return decodeURIComponent(text.replace(/\+/g, ' ')); } catch (_) { return text; }
}

function redactQuery(query) {
  return String(query).split('&').filter(Boolean).map(pair => {
    const equals = pair.indexOf('=');
    if (equals < 0) return redactValue(clean(pair));
    const key = pair.slice(0, equals);
    return key + '=' + (SENSITIVE_KEY.test(safeDecode(key)) ? REDACTED : redactValue(clean(pair.slice(equals + 1))));
  }).join('&').slice(0, QUERY_MAX);
}

function headers(request) {
  const source = request?.headers;
  if (!source || typeof source !== 'object') return undefined;
  const out = {};
  for (const name of SAFE_HEADERS) {
    let value = source[name];
    if (Array.isArray(value)) value = value.join(', ');
    if (typeof value !== 'string' || !value.length || SENSITIVE_KEY.test(name)) continue;
    out[name] = redactValue(clean(value)).slice(0, HEADER_VALUE_MAX);
  }
  return Object.keys(out).length ? out : undefined;
}

function queryOf(request) {
  const url = String(request?.originalUrl || request?.url || '');
  const mark = url.indexOf('?');
  return mark < 0 ? '' : url.slice(mark + 1);
}

// Monta a evidência de um evento do WAF. Devolve undefined quando não há nada a mostrar.
function build({value, location, request}) {
  const evidence = {};
  const matched = payload(value, location);
  if (matched) evidence.payload = matched;
  const query = redactQuery(queryOf(request));
  if (query) evidence.query = query;
  const selected = headers(request);
  if (selected) evidence.headers = selected;
  return Object.keys(evidence).length ? evidence : undefined;
}

module.exports = {build, payload, redactQuery, redactValue, headers, sensitiveLocation, VALUE_MAX, QUERY_MAX, REDACTED};
