/**
 * DDNS Pro v21 · Worker Admin Proxy + DNS Maintenance API
 * Frontend is deployed as remote static assets; Worker serves it through same-origin proxy.
 */

const VERSION = '29.0.0-manual-pool-txt';
const JSON_TYPE = 'application/json; charset=UTF-8';
const CHECK_CACHE_KEY = 'check_cache_v2';
const CHECK_FAIL_KEY = 'check_fail_v2';
const MAINTAIN_CURSOR_KEY = 'maintain_cursor_v2';
const MAINTAIN_LOCK_KEY = 'maintain_lock_v2';

const DEFAULTS = Object.freeze({
  checkApi: 'https://cf.090227.xyz/check?proxyip=',
  checkApiBackup: 'https://api.090227.xyz/check?proxyip=',
  dohApi: 'https://cloudflare-dns.com/dns-query',
  adminOrigin: 'https://mlyo.github.io',
  dnsTtl: 60,
  proxied: false,
  defaultMinActive: 3,
  checkConcurrency: 5,
  checkTimeout: 5000,
  dohTimeout: 5000,
  cfTimeout: 10000,
  remoteTimeout: 8000,
  maxCheckPerDomain: 10,
  checkBatchSize: 5,
  maintainMaxDomains: 2,
  maxPoolLines: 5000,
  maxRemoteBytes: 1024 * 1024,
  maxTrashSize: 1000,
  failThreshold: 3,
  checkCacheEnabled: true,
  checkCacheTtlMinutes: 420,
  maxTxtContentLength: 768,
  maxTxtTargets: 25,
  maintainLockTtlSeconds: 300,
  txtOnly: true,
  enableARecords: false,
  preferTxtResolve: true,
  allowAResolve: true,
  publicTxtEndpoint: true,
  publicTxtAllowAny: false,
  txtStrictPort: true,
  enableRemoteImport: false,
});

const SYSTEM_POOLS = new Set(['pool', 'pool_trash']);
const MODE_LABELS = { TXT: 'TXT记录', A: 'A记录(兼容)', ALL: 'A+TXT(兼容)' };

const toBool = (value, fallback = false) => {
  if (value === undefined || value === null || value === '') return fallback;
  const s = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(s)) return false;
  return fallback;
};

const toInt = (value, fallback, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
};

const envText = (env, key, fallback = '') => String(env?.[key] ?? fallback ?? '').trim();
const nowISO = () => new Date().toISOString();
const cnTime = () => new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
const logLine = (message) => `[${cnTime()}] ${message}`;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': JSON_TYPE, ...headers } });
}
const ok = (data = {}, status = 200) => json({ success: true, data }, status);
const fail = (code, message, status = 400, detail = undefined) => json({ success: false, error: { code, message, detail } }, status);

function safeJSONParse(value, fallback) {
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

async function fetchWithTimeout(url, options = {}, timeout = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('timeout'), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function createConfig(env, request = null) {
  const config = {
    version: VERSION,
    apiKey: envText(env, 'CF_KEY'),
    zoneId: envText(env, 'CF_ZONEID'),
    authKey: envText(env, 'AUTH_KEY'),
    sessionSecret: envText(env, 'SESSION_SECRET', envText(env, 'AUTH_SECRET', envText(env, 'AUTH_KEY'))),
    tgToken: envText(env, 'TG_TOKEN'),
    tgId: envText(env, 'TG_ID'),
    checkApi: envText(env, 'CHECK_API', DEFAULTS.checkApi),
    checkApiToken: envText(env, 'CHECK_API_TOKEN'),
    checkApiBackup: envText(env, 'CHECK_API_BACKUP', DEFAULTS.checkApiBackup),
    checkApiBackupToken: envText(env, 'CHECK_API_BACKUP_TOKEN'),
    checkBatchApi: envText(env, 'CHECK_BATCH_API'),
    checkBatchApiBackup: envText(env, 'CHECK_BATCH_API_BACKUP'),
    dohApi: envText(env, 'DOH_API', DEFAULTS.dohApi),
    adminOrigin: envText(env, 'ADMIN_ORIGIN', DEFAULTS.adminOrigin).replace(/\/$/, ''),
    dnsTtl: toInt(env?.DNS_TTL, DEFAULTS.dnsTtl, 60, 86400),
    proxied: toBool(env?.DNS_PROXIED, DEFAULTS.proxied),
    defaultMinActive: toInt(env?.DEFAULT_MIN_ACTIVE, DEFAULTS.defaultMinActive, 1, 200),
    checkConcurrency: toInt(env?.CONCURRENT_CHECKS, DEFAULTS.checkConcurrency, 1, 20),
    checkTimeout: toInt(env?.CHECK_TIMEOUT, DEFAULTS.checkTimeout, 1000, 30000),
    dohTimeout: toInt(env?.DOH_TIMEOUT, DEFAULTS.dohTimeout, 1000, 30000),
    cfTimeout: toInt(env?.CF_TIMEOUT, DEFAULTS.cfTimeout, 1000, 30000),
    remoteTimeout: toInt(env?.REMOTE_LOAD_TIMEOUT, DEFAULTS.remoteTimeout, 1000, 30000),
    maxCheckPerDomain: toInt(env?.MAX_CHECK_PER_DOMAIN, DEFAULTS.maxCheckPerDomain, 0, 500),
    checkBatchSize: toInt(env?.CHECK_BATCH_SIZE, DEFAULTS.checkBatchSize, 1, 20),
    maintainMaxDomains: toInt(env?.MAINTAIN_MAX_DOMAINS ?? env?.MAINTAIN_DOMAIN_LIMIT, DEFAULTS.maintainMaxDomains, 1, 100),
    maxPoolLines: toInt(env?.MAX_POOL_LINES, DEFAULTS.maxPoolLines, 1, 50000),
    maxRemoteBytes: toInt(env?.MAX_REMOTE_BYTES, DEFAULTS.maxRemoteBytes, 1024, 5 * 1024 * 1024),
    maxTrashSize: toInt(env?.MAX_TRASH_SIZE, DEFAULTS.maxTrashSize, 10, 10000),
    failThreshold: toInt(env?.CHECK_FAIL_THRESHOLD, DEFAULTS.failThreshold, 1, 50),
    removeFailedImmediately: toBool(env?.REMOVE_FAILED_IMMEDIATELY, false),
    removeUnhealthyWithoutReplacement: toBool(env?.REMOVE_UNHEALTHY_WITHOUT_REPLACEMENT, false),
    deleteEmptyTxt: toBool(env?.DELETE_EMPTY_TXT, false),
    checkCacheEnabled: toBool(env?.CHECK_CACHE_ENABLED, DEFAULTS.checkCacheEnabled),
    checkCacheTtlMinutes: toInt(env?.CHECK_CACHE_TTL_MINUTES, DEFAULTS.checkCacheTtlMinutes, 1, 10080),
    maxTxtContentLength: toInt(env?.MAX_TXT_CONTENT_LENGTH, DEFAULTS.maxTxtContentLength, 80, 1024),
    maxTxtTargets: toInt(env?.MAX_TXT_TARGETS, DEFAULTS.maxTxtTargets, 1, 200),
    maintainLockTtlSeconds: toInt(env?.MAINTAIN_LOCK_TTL_SECONDS, DEFAULTS.maintainLockTtlSeconds, 60, 1800),
    ipInfoEnabled: toBool(env?.IP_INFO_ENABLED, false),
    ipInfoApi: envText(env, 'IP_INFO_API', 'http://ip-api.com/json'),
    allowedOrigins: envText(env, 'ALLOWED_ORIGINS'),
    txtOnly: toBool(env?.TXT_ONLY, DEFAULTS.txtOnly),
    enableARecords: toBool(env?.ENABLE_A_RECORDS, DEFAULTS.enableARecords),
    preferTxtResolve: toBool(env?.PREFER_TXT_RESOLVE, DEFAULTS.preferTxtResolve),
    allowAResolve: toBool(env?.ALLOW_A_RESOLVE, DEFAULTS.allowAResolve),
    publicTxtEndpoint: toBool(env?.PUBLIC_TXT_ENDPOINT, DEFAULTS.publicTxtEndpoint),
    publicTxtAllowAny: toBool(env?.PUBLIC_TXT_ALLOW_ANY, DEFAULTS.publicTxtAllowAny),
    txtStrictPort: toBool(env?.TXT_STRICT_PORT, DEFAULTS.txtStrictPort),
    enableRemoteImport: toBool(env?.ENABLE_REMOTE_IMPORT, DEFAULTS.enableRemoteImport),
    targets: parseTargets(envText(env, 'CF_DOMAIN'), toInt(env?.DEFAULT_MIN_ACTIVE, DEFAULTS.defaultMinActive, 1, 200), toBool(env?.ENABLE_A_RECORDS, DEFAULTS.enableARecords)),
    projectUrl: request ? new URL(request.url).origin : '',
  };
  return Object.freeze(config);
}

function getKVBinding(env) {
  const candidates = [['IP_DATA', env?.IP_DATA], ['KV', env?.KV], ['IPDATA', env?.IPDATA], ['KV_DATA', env?.KV_DATA]];
  for (const [name, store] of candidates) {
    if (store && typeof store.get === 'function' && typeof store.put === 'function') return { name, store };
  }
  return { name: 'missing', store: null };
}
const getKV = env => getKVBinding(env).store;
function requireKV(env) {
  const { store } = getKVBinding(env);
  if (!store) throw new Error('KV 未绑定：请绑定 KV Namespace，推荐变量名 IP_DATA。');
  return store;
}

function originOf(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  try { return new URL(text).origin; } catch { return text.replace(/\/$/, ''); }
}
function getAllowedOrigins(env, config) {
  const raw = config?.allowedOrigins || envText(env, 'ALLOWED_ORIGINS');
  if (raw) return raw.split(',').map(s => s.trim()).filter(Boolean).map(originOf);
  return config?.adminOrigin ? [originOf(config.adminOrigin)] : [];
}
function getCorsOrigin(request, env, config) {
  const origin = request.headers.get('Origin') || '';
  if (!origin) return '';
  const allowed = getAllowedOrigins(env, config);
  if (!allowed.length) return '';
  if (allowed.includes('*')) return '*';
  return allowed.includes(origin) ? origin : '';
}
function corsPreflight(request, env, config) {
  const headers = new Headers();
  const origin = getCorsOrigin(request, env, config);
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    if (origin !== '*') headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Vary', 'Origin');
  }
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Key');
  headers.set('Access-Control-Max-Age', '86400');
  return new Response(null, { status: 204, headers });
}
function withCors(response, request, env, config) {
  const origin = getCorsOrigin(request, env, config);
  if (!origin) return response;
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  if (origin !== '*') headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Vary', 'Origin');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Key');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function parseCookies(cookieHeader) {
  const out = {};
  String(cookieHeader || '').split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx < 0) return;
    const key = part.slice(0, idx).trim();
    if (!key) return;
    try { out[key] = decodeURIComponent(part.slice(idx + 1).trim()); } catch { out[key] = part.slice(idx + 1).trim(); }
  });
  return out;
}
async function sha256Hex(text) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sessionToken(request, config) {
  const ua = request.headers.get('User-Agent') || '';
  return await sha256Hex(`${config.authKey}:${config.sessionSecret}:${ua}`);
}
async function checkAuth(request, url, config) {
  if (!config.authKey) return { enabled: false, ok: true, setCookie: false };
  const auth = request.headers.get('Authorization') || '';
  const bearer = auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '';
  const xKey = (request.headers.get('X-Auth-Key') || '').trim();
  const qKey = (url.searchParams.get('key') || '').trim();
  const cookie = parseCookies(request.headers.get('Cookie') || '').ddns_auth || '';
  const token = await sessionToken(request, config);
  const directOk = bearer === config.authKey || xKey === config.authKey || qKey === config.authKey;
  const ok = directOk || cookie === token || cookie === config.authKey;
  return { enabled: true, ok, setCookie: ok && (directOk || cookie !== token), token };
}
function authCookie(token, maxAge = 86400) {
  return `ddns_auth=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}


async function handleApiHome(config) {
  return ok({
    name: 'DDNS Pro API',
    version: config.version,
    frontend: config.adminOrigin || '',
  });
}

async function handleAuthLogin(request, config) {
  if (!config.authKey) {
    return ok({ authenticated: true, authRequired: false, message: 'AUTH_KEY 未配置，API 未启用访问保护。' });
  }

  let password = '';
  const type = request.headers.get('Content-Type') || '';
  if (type.includes('application/json')) {
    const body = await readJson(request);
    password = String(body?.password || body?.key || body?.authKey || '').trim();
  } else {
    password = String(new URLSearchParams(await request.text()).get('password') || '').trim();
  }

  if (password !== config.authKey) {
    return fail('BAD_AUTH', 'AUTH_KEY 错误', 401);
  }

  const token = await sessionToken(request, config);
  return json({ success: true, data: { authenticated: true, authRequired: true } }, 200, {
    'Set-Cookie': authCookie(token),
  });
}

function handleAuthLogout() {
  return json({ success: true, data: { authenticated: false } }, 200, {
    'Set-Cookie': 'ddns_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict',
  });
}

function staticOrigin(config) {
  const origin = String(config.adminOrigin || DEFAULTS.adminOrigin || '').trim().replace(/\/+$/, '');
  if (!origin) return '';
  try {
    const url = new URL(origin);
    if (url.protocol !== 'https:') return '';
    return url.origin + url.pathname.replace(/\/+$/, '');
  } catch {
    return '';
  }
}

function staticPathCandidates(pathname) {
  const path = String(pathname || '/');
  if (path === '/login' || path === '/login/' || path === '/login.html') {
    return ['/login.html', '/login/', '/login/index.html'];
  }
  if (path === '/admin' || path === '/admin/') {
    return ['/admin/index.html', '/admin/'];
  }
  if (path.startsWith('/admin/')) return [path];
  if (path === '/' || path === '') return ['/admin/index.html', '/admin/'];
  return [path];
}

function copyStaticHeaders(originResponse, pathname, originUrl) {
  const headers = new Headers(originResponse.headers);
  headers.delete('content-security-policy');
  headers.delete('content-security-policy-report-only');
  headers.delete('x-frame-options');
  headers.delete('set-cookie');
  headers.set('X-Admin-Origin', originUrl.host);
  headers.set('Vary', 'Cookie');
  headers.set('Cache-Control', 'no-store');
  return headers;
}

async function fetchAdminStatic(request, config) {
  const origin = staticOrigin(config);
  if (!origin) return fail('ADMIN_ORIGIN_INVALID', 'ADMIN_ORIGIN 无效，请配置为 https://... 静态前端源站。', 500);

  const requestUrl = new URL(request.url);
  const originUrl = new URL(origin);
  const candidates = staticPathCandidates(requestUrl.pathname);
  let lastResponse = null;
  for (const candidate of candidates) {
    const target = new URL(originUrl.href);
    target.pathname = joinUrlPath(originUrl.pathname, candidate);
    target.search = requestUrl.search;
    const headers = new Headers(request.headers);
    headers.set('Host', target.host);
    headers.set('Referer', target.origin + '/');
    headers.set('Origin', target.origin);
    headers.delete('Cookie');
    headers.delete('Authorization');
    headers.delete('X-Auth-Key');
    const upstream = await fetch(target.href, {
      method: 'GET',
      headers,
      redirect: 'follow',
      cf: { cacheTtl: 0, cacheEverything: false }
    });
    lastResponse = upstream;
    if (upstream.status !== 404) {
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: copyStaticHeaders(upstream, requestUrl.pathname, target)
      });
    }
  }
  return new Response(lastResponse?.body || 'Admin asset not found', {
    status: lastResponse?.status || 404,
    statusText: lastResponse?.statusText || 'Not Found',
    headers: { 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'no-store' }
  });
}

function joinUrlPath(basePath, childPath) {
  const base = String(basePath || '/').replace(/\/+$/, '');
  const child = String(childPath || '').replace(/^\/+/, '');
  const path = `${base}/${child}`.replace(/\/+/g, '/');
  return path.startsWith('/') ? path : `/${path}`;
}

function localRedirect(location, headers = {}) {
  return new Response('重定向中...', { status: 302, headers: { Location: location, ...headers } });
}

function redirectWithoutKey(url, setCookieValue = '') {
  const clean = new URL(url.href);
  clean.searchParams.delete('key');
  const location = clean.pathname + clean.search + clean.hash;
  const headers = new Headers({ Location: location || '/admin/' });
  if (setCookieValue) headers.set('Set-Cookie', setCookieValue);
  return new Response('重定向中...', { status: 302, headers });
}


function parseTargets(raw, defaultMinActive, enableARecords = false) {
  return String(raw || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean).map((entry, index) => {
    let text = entry.split('#')[0].trim();
    let minActive = defaultMinActive;
    const minMatch = text.match(/&([0-9]{1,4})$/);
    if (minMatch) {
      minActive = Math.max(1, Number(minMatch[1]));
      text = text.replace(/&[0-9]{1,4}$/, '').trim();
    }

    // TXT-only 是默认维护模式：
    //   example.com       -> TXT
    //   txt@example.com   -> TXT
    //   all@example.com   -> TXT（避免误写 A）
    // 只有显式设置 ENABLE_A_RECORDS=1 时，a@ / all@ 才会恢复旧的 A/ALL 维护能力。
    let mode = 'TXT';
    if (/^txt@/i.test(text)) {
      mode = 'TXT'; text = text.replace(/^txt@/i, '');
    } else if (/^all@/i.test(text)) {
      mode = enableARecords ? 'ALL' : 'TXT'; text = text.replace(/^all@/i, '');
    } else if (/^a@/i.test(text)) {
      mode = enableARecords ? 'A' : 'TXT'; text = text.replace(/^a@/i, '');
    }

    const parsed = parseHostPort(text, '443');
    const domain = normalizeDomain(parsed.host);
    return { id: index, mode, domain, port: String(parsed.port || '443'), minActive, raw: entry };
  }).filter(t => t.domain);
}

function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}
function stripBrackets(host) {
  const h = String(host || '').trim();
  return h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
}
function isValidPortValue(port) {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}
function isIPv4(host) {
  const parts = String(host || '').split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}
function isIPv6(host) {
  const h = stripBrackets(host).toLowerCase();
  if (!h || !/^[0-9a-f:.]+$/.test(h) || (h.match(/::/g) || []).length > 1) return false;
  const hasCompress = h.includes('::');
  const parts = h.split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const groups = [...left, ...right];
  if (groups.some(g => !g || !/^[0-9a-f]{1,4}$/.test(g))) return false;
  const groupCount = groups.length;
  return hasCompress ? groupCount < 8 : groupCount === 8;
}
function isIpHost(host) {
  const h = stripBrackets(host);
  return isIPv4(h) || isIPv6(h);
}
function isValidHostname(host) {
  const h = normalizeDomain(host);
  if (!h || h.length > 253 || h.includes('..') || h.includes(':') || /\s/.test(h)) return false;
  if (/^(?:\d+\.){3}\d+$/.test(h)) return false;
  return h.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}
function formatHostPort(host, port = '443') {
  const h = stripBrackets(host);
  const p = isValidPortValue(port) ? String(Math.floor(Number(port))) : '443';
  if (!h) return '';
  return isIPv6(h) ? `[${h}]:${p}` : `${h}:${p}`;
}
function parseHostPort(input, defaultPort = '443') {
  let text = String(input || '').split('#')[0].trim();
  const fallbackPort = isValidPortValue(defaultPort) ? String(Math.floor(Number(defaultPort))) : '443';
  if (!text) return { host: '', port: fallbackPort };
  if (/^https?:\/\//i.test(text)) {
    try {
      const u = new URL(text);
      return { host: stripBrackets(u.hostname), port: isValidPortValue(u.port || fallbackPort) ? String(u.port || fallbackPort) : fallbackPort };
    } catch { return { host: '', port: fallbackPort }; }
  }
  let port = fallbackPort;
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end <= 0) return { host: '', port };
    const host = text.slice(1, end);
    const rest = text.slice(end + 1).trim();
    if (rest) {
      if (!rest.startsWith(':') || !isValidPortValue(rest.slice(1))) return { host: '', port };
      port = String(Math.floor(Number(rest.slice(1))));
    }
    return { host, port };
  }
  const colonCount = (text.match(/:/g) || []).length;
  if (colonCount === 1) {
    const idx = text.lastIndexOf(':');
    const tail = text.slice(idx + 1);
    if (!isValidPortValue(tail)) return { host: '', port };
    port = String(Math.floor(Number(tail)));
    text = text.slice(0, idx);
  } else if (colonCount > 1 && !isIPv6(text)) {
    return { host: '', port };
  }
  return { host: stripBrackets(text), port };
}
function normalizeAddr(input, defaultPort = '443', options = {}) {
  const p = parseHostPort(input, defaultPort);
  const host = stripBrackets(p.host);
  if (!host) return '';
  if (options.requireIp && !isIpHost(host)) return '';
  if (!isIpHost(host) && !isValidHostname(host)) return '';
  return formatHostPort(host, p.port);
}
function extractAddr(line) {
  return String(line || '').split('#')[0].trim();
}
function splitComment(line) {
  const s = String(line || '');
  const idx = s.indexOf('#');
  return idx >= 0 ? { main: s.slice(0, idx).trim(), comment: s.slice(idx).trim() } : { main: s.trim(), comment: '' };
}
function unique(values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const v = String(value || '').trim();
    if (!v || seen.has(v)) continue;
    seen.add(v); out.push(v);
  }
  return out;
}
function parsePool(raw) {
  const seen = new Set();
  const entries = [];
  for (const line of String(raw || '').split(/\r?\n/)) {
    const { main, comment } = splitComment(line);
    const addr = normalizeAddr(main, '443', { requireIp: true });
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    const { host, port } = parseHostPort(addr);
    entries.push({ addr, host, port, comment, line: comment ? `${addr} ${comment}` : addr });
  }
  return entries;
}
function serializePool(entries) {
  const seen = new Set();
  const lines = [];
  for (const entry of entries || []) {
    const addr = normalizeAddr(entry.addr || entry.line || entry, '443', { requireIp: true });
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    const comment = entry.comment ? ` ${String(entry.comment).trim().startsWith('#') ? entry.comment.trim() : '#' + entry.comment.trim()}` : '';
    lines.push(`${addr}${comment}`);
  }
  return lines.join('\n');
}
function normalizeInputList(value) {
  const arr = Array.isArray(value) ? value : String(value || '').split(/[\r\n,;]+/);
  return unique(arr.map(v => String(v || '').split('#')[0].trim()).filter(Boolean));
}

async function dohQuery(name, type, config) {
  const clean = normalizeDomain(name);
  if (!clean) return [];
  const url = `${config.dohApi}?name=${encodeURIComponent(clean)}&type=${encodeURIComponent(type)}`;
  try {
    const res = await fetchWithTimeout(url, { headers: { Accept: 'application/dns-json' }, cf: { cacheTtl: 30 } }, config.dohTimeout);
    if (!res.ok) return [];
    const payload = await res.json();
    return Array.isArray(payload.Answer) ? payload.Answer.map(a => ({ name: a.name || clean, type: a.type, TTL: a.TTL, data: normalizeTxtValue(a.data) })) : [];
  } catch { return []; }
}
function normalizeTxtValue(value) {
  let s = String(value ?? '').trim();
  if (!s) return '';
  const quoted = [];
  const re = /"((?:\\.|[^"])*)"/g;
  let m;
  while ((m = re.exec(s))) quoted.push(m[1].replace(/\\"/g, '"'));
  if (quoted.length && quoted.join('').length >= s.replace(/["\s]/g, '').length * 0.5) s = quoted.join('');
  else if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  return s.replace(/\\"/g, '"').trim();
}
function parseTXTContent(content) {
  return unique(normalizeTxtValue(content).split(/[,，\s]+/).map(v => normalizeAddr(v, '443', { requireIp: true })).filter(Boolean));
}
async function resolveTarget(input, config) {
  let raw = String(input || '').trim();
  let forceTxt = false;
  let forceA = false;
  if (/^txt@/i.test(raw)) { forceTxt = true; raw = raw.replace(/^txt@/i, ''); }
  else if (/^a@/i.test(raw)) { forceA = true; raw = raw.replace(/^a@/i, ''); }

  const { host, port } = parseHostPort(raw);
  if (!host) throw new Error('目标为空');
  if (isIPv4(host) || isIPv6(host)) return [formatHostPort(host, port)];

  const readTxt = async () => {
    const txt = await dohQuery(host, 'TXT', config);
    const out = [];
    for (const record of txt.filter(x => x.type === 16)) out.push(...parseTXTContent(record.data));
    return unique(out);
  };

  // 默认 TXT 优先：让普通域名也能直接得到 TXT 内保存的 IP:PORT。
  // 这样 CF_DOMAIN=pool.example.com 时，对外查询也能返回 121.153.133.83:30001 这类结果。
  if (forceTxt || (!forceA && config.preferTxtResolve !== false)) {
    const out = await readTxt();
    if (out.length) return out;
    if (forceTxt || config.allowAResolve === false) throw new Error('TXT 记录为空或无法解析');
  }

  if (config.allowAResolve === false) throw new Error('未启用 A/AAAA 回退解析');
  const [a, aaaa] = await Promise.all([dohQuery(host, 'A', config), dohQuery(host, 'AAAA', config)]);
  const out = [];
  for (const r of a.filter(x => x.type === 1 && x.data)) out.push(formatHostPort(r.data, port));
  for (const r of aaaa.filter(x => x.type === 28 && x.data)) out.push(formatHostPort(r.data, port));
  if (!out.length) throw new Error('域名无 TXT/A/AAAA 解析结果');
  return unique(out);
}


async function fetchCF(config, path, method = 'GET', body = null) {
  if (!config.apiKey || !config.zoneId) return { ok: false, status: 0, error: '缺少 CF_KEY 或 CF_ZONEID' };
  const headers = { Authorization: `Bearer ${config.apiKey}`, 'Content-Type': JSON_TYPE };
  try {
    const res = await fetchWithTimeout(`https://api.cloudflare.com/client/v4${path}`, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
    }, config.cfTimeout);
    const text = await res.text();
    let data = safeJSONParse(text, null);
    if (!data) data = { success: res.ok, raw: text };
    const cfOk = res.ok && data.success !== false;
    return { ok: cfOk, status: res.status, result: data.result, resultInfo: data.result_info || data.resultInfo || null, errors: data.errors || [], messages: data.messages || [], raw: data };
  } catch (e) {
    return { ok: false, status: 0, error: e.message || 'Cloudflare API 请求失败' };
  }
}
function cfError(r) {
  if (!r) return '未知错误';
  if (r.error) return r.error;
  if (Array.isArray(r.errors) && r.errors.length) return r.errors.map(e => e.message || e.code || JSON.stringify(e)).join('; ');
  return `HTTP ${r.status || 0}`;
}
async function cfListRecords(config, domain, type) {
  const out = [];
  const perPage = 100;
  const maxPages = 5;
  for (let page = 1; page <= maxPages; page++) {
    const q = `/zones/${config.zoneId}/dns_records?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}&per_page=${perPage}&page=${page}`;
    const r = await fetchCF(config, q);
    if (!r.ok) throw new Error(cfError(r));
    if (Array.isArray(r.result)) out.push(...r.result);
    const totalPages = Number(r.resultInfo?.total_pages || r.resultInfo?.totalPages || 1);
    if (!totalPages || page >= totalPages || r.result?.length < perPage) break;
  }
  return out;
}
async function cfCreateRecord(config, record) {
  const body = { ttl: config.dnsTtl, proxied: config.proxied, ...record };
  if (body.type === 'TXT') delete body.proxied;
  return await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', body);
}
async function cfUpdateRecord(config, id, record) {
  const body = { ttl: config.dnsTtl, proxied: config.proxied, ...record };
  if (body.type === 'TXT') delete body.proxied;
  return await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'PUT', body);
}
async function cfDeleteRecord(config, id) {
  return await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
}

function pickRows(raw) {
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw?.results)) return raw.results;
  if (Array.isArray(raw?.data)) return raw.data;
  if (Array.isArray(raw?.data?.results)) return raw.data.results;
  if (raw && typeof raw === 'object' && typeof raw.success === 'boolean') return [raw];
  return [];
}
function normalizeCheckRow(row, candidate, source, ms = 0) {
  const probe = row?.probe_results || row?.probeResults || {};
  const ipv4Ok = Boolean(row?.supports_ipv4 ?? row?.supportsIPv4 ?? probe.ipv4?.ok);
  const ipv6Ok = Boolean(row?.supports_ipv6 ?? row?.supportsIPv6 ?? probe.ipv6?.ok);
  const exit = probe.ipv4?.exit || probe.ipv6?.exit || row?.exit || {};
  const success = Boolean(row?.success === true || row?.ok === true || row?.status === 'success' || ipv4Ok || ipv6Ok);
  return {
    candidate: normalizeAddr(candidate),
    success,
    source,
    colo: String(row?.colo || row?.checkColo || row?.cfColo || exit.colo || ''),
    responseTime: Number(row?.responseTime ?? row?.time ?? row?.ms ?? row?.latency ?? ms ?? 0),
    proxyIP: String(row?.proxyIP || row?.proxyip || candidate || ''),
    message: String(row?.message || row?.error || (success ? 'OK' : '检测未通过')),
    exitIP: String(exit.ip || row?.ip || ''),
    country: String(exit.country || row?.country || exit.countryCode || ''),
    city: String(exit.city || row?.city || exit.region || exit.regionCode || ''),
    asn: exit.asn ?? row?.asn ?? null,
    org: String(exit.asOrganization || exit.org || row?.asOrganization || row?.org || ''),
    raw: row || null,
  };
}
function buildCheckUrl(apiUrl, targets, token = '') {
  const base = String(apiUrl || '').trim();
  if (!base) return '';
  const joined = targets.map(v => normalizeAddr(v)).filter(Boolean).join(',');
  const encoded = encodeURIComponent(joined);
  let url;
  if (base.includes('{proxyip}')) url = base.replace('{proxyip}', encoded);
  else if (/[?&]proxyip=$/i.test(base) || base.endsWith('=')) url = base + encoded;
  else url = base + (base.includes('?') ? (base.endsWith('&') || base.endsWith('?') ? '' : '&') : '?') + 'proxyip=' + encoded;
  if (token && !/[?&]token=/i.test(url)) url += (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
  return url;
}
async function checkApiOnce(targets, apiUrl, token, source, config) {
  const list = targets.map(v => normalizeAddr(v)).filter(Boolean);
  if (!list.length) return [];
  const started = Date.now();
  const headers = { Accept: JSON_TYPE };
  if (token) { headers.Authorization = `Bearer ${token}`; headers['X-Auth-Key'] = token; }
  try {
    const res = await fetchWithTimeout(buildCheckUrl(apiUrl, list, token), { headers, cf: { cacheTtl: 0 } }, config.checkTimeout);
    const text = await res.text();
    let raw = safeJSONParse(text, { success: false, message: text || `HTTP ${res.status}` });
    if (!res.ok) raw = { success: false, message: raw?.message || `HTTP ${res.status}` };
    const rows = pickRows(raw);
    const byCandidate = new Map();
    rows.forEach((row, index) => {
      const key = normalizeAddr(row?.candidate || row?.target || row?.proxyIP || row?.proxyip || list[index] || '');
      if (key) byCandidate.set(key, row);
    });
    return list.map((candidate, index) => normalizeCheckRow(byCandidate.get(candidate) || rows[index] || { success: false, message: '检测接口未返回该目标' }, candidate, source, Date.now() - started));
  } catch (e) {
    return list.map(candidate => normalizeCheckRow({ success: false, message: e.message || '检测异常' }, candidate, source, Date.now() - started));
  }
}
async function checkPostBatch(targets, apiUrl, token, source, config) {
  const list = targets.map(v => normalizeAddr(v)).filter(Boolean);
  if (!list.length || !apiUrl) return [];
  const started = Date.now();
  const headers = { 'Content-Type': JSON_TYPE, Accept: JSON_TYPE };
  if (token) { headers.Authorization = `Bearer ${token}`; headers['X-Auth-Key'] = token; }
  try {
    const res = await fetchWithTimeout(apiUrl, { method: 'POST', headers, body: JSON.stringify({ targets: list }) }, config.checkTimeout * Math.max(1, Math.ceil(list.length / 2)));
    let raw = safeJSONParse(await res.text(), {});
    if (!res.ok) raw = { success: false, message: raw?.message || `HTTP ${res.status}` };
    const rows = pickRows(raw);
    return list.map((candidate, i) => normalizeCheckRow(rows.find(r => normalizeAddr(r?.candidate || r?.target || r?.proxyIP || r?.proxyip || '') === candidate) || rows[i] || { success: false, message: '批量接口未返回该目标' }, candidate, source, Date.now() - started));
  } catch (e) {
    return list.map(candidate => normalizeCheckRow({ success: false, message: e.message || '批量检测异常' }, candidate, source, Date.now() - started));
  }
}
async function checkTargets(targets, config, useBackupOnly = false) {
  const list = unique(targets.map(v => normalizeAddr(v)).filter(Boolean));
  if (!list.length) return [];
  const chunkSize = Math.max(1, config.checkBatchSize);
  const out = [];
  const hasBackup = Boolean(config.checkApiBackup || config.checkBatchApiBackup);
  const runPrimary = (chunk) => config.checkBatchApi
    ? checkPostBatch(chunk, config.checkBatchApi, config.checkApiToken, 'main-batch', config)
    : checkApiOnce(chunk, config.checkApi, config.checkApiToken, 'main', config);
  const runBackup = (chunk) => config.checkBatchApiBackup
    ? checkPostBatch(chunk, config.checkBatchApiBackup, config.checkApiBackupToken, 'backup-batch', config)
    : checkApiOnce(chunk, config.checkApiBackup, config.checkApiBackupToken, 'backup', config);

  for (let i = 0; i < list.length; i += chunkSize) {
    const chunk = list.slice(i, i + chunkSize);
    let rows = useBackupOnly ? await runBackup(chunk) : await runPrimary(chunk);

    // 节省优先：主接口有失败且配置了备用时，只回退失败项，不重复检测已成功项。
    if (!useBackupOnly && hasBackup) {
      const current = resultMap(rows);
      const failed = chunk.filter(addr => current.get(addr)?.success !== true);
      if (failed.length) {
        const backupRows = await runBackup(failed);
        const backup = resultMap(backupRows);
        rows = chunk.map(addr => {
          const primary = current.get(addr);
          const secondary = backup.get(addr);
          return secondary?.success ? secondary : (primary || secondary || { candidate: addr, success: false, source: 'main', message: '未返回检测结果' });
        });
      }
    }
    out.push(...rows);
  }
  return out;
}
function resultMap(results) {
  const m = new Map();
  for (const r of results || []) m.set(normalizeAddr(r.candidate), r);
  return m;
}

async function loadJsonKV(env, key, fallback) {
  try { return safeJSONParse(await requireKV(env).get(key), fallback); } catch { return fallback; }
}
async function saveJsonKV(env, key, value) {
  await requireKV(env).put(key, JSON.stringify(value || {}));
}
function isFreshCache(item, minutes) {
  if (!item || item.success !== true || !item.time) return false;
  return Date.now() - Number(item.time) < minutes * 60_000;
}
async function checkWithState(targets, config, state) {
  const list = unique(targets.map(v => normalizeAddr(v)).filter(Boolean));
  const out = [];
  const miss = [];
  for (const addr of list) {
    const cached = state.cache?.[addr];
    if (config.checkCacheEnabled && isFreshCache(cached, config.checkCacheTtlMinutes)) out.push({ ...cached, candidate: addr, source: 'cache', cached: true });
    else miss.push(addr);
  }
  if (miss.length) {
    const checked = await checkTargets(miss, config);
    for (const row of checked) {
      if (row.success) {
        const key = normalizeAddr(row.candidate);
        state.cache[key] = { ...row, time: Date.now() };
        state.cacheDirty = true;
      }
      out.push(row);
    }
  }
  return out;
}
function updateFailState(state, addr, check, config) {
  const key = normalizeAddr(addr);
  if (!key) return { failCount: 0, shouldTrash: false };
  if (check?.success === true) {
    if (state.failCount[key]) {
      delete state.failCount[key];
      state.failDirty = true;
    }
    return { failCount: 0, shouldTrash: false };
  }
  const prev = state.failCount[key] || { count: 0 };
  const count = config.removeFailedImmediately ? config.failThreshold : Number(prev.count || 0) + 1;
  state.failCount[key] = { count, lastFailureAt: nowISO(), message: check?.message || '检测失败' };
  state.failDirty = true;
  return { failCount: count, shouldTrash: count >= config.failThreshold };
}
async function addTrash(env, entries, config) {
  if (!entries.length) return;
  const store = requireKV(env);
  const current = parsePool(await store.get('pool_trash') || '');
  const existing = new Set(current.map(e => e.addr));
  const next = [...current];
  for (const entry of entries) {
    const addr = normalizeAddr(entry.addr || entry.ip || entry);
    if (!addr || existing.has(addr)) continue;
    existing.add(addr);
    next.unshift({ addr, comment: `# ${entry.reason || '失效'} ${nowISO()} 来自 ${entry.poolKey || 'pool'}` });
  }
  await store.put('pool_trash', serializePool(next.slice(0, config.maxTrashSize)));
}
async function removeFromPool(env, poolKey, addrs) {
  const store = requireKV(env);
  const remove = new Set(addrs.map(v => normalizeAddr(v)).filter(Boolean));
  const entries = parsePool(await store.get(poolKey) || '').filter(e => !remove.has(e.addr));
  await store.put(poolKey, serializePool(entries));
  return entries.length;
}

async function getMapping(env) {
  return safeJSONParse(await requireKV(env).get('domain_pool_mapping') || '{}', {});
}
async function setMapping(env, mapping) {
  await requireKV(env).put('domain_pool_mapping', JSON.stringify(mapping || {}, null, 2));
}
function pickPoolKey(mapping, domain) {
  const d = normalizeDomain(domain);
  const value = mapping?.[d] || mapping?.[domain] || 'pool';
  return normalizePoolKey(value);
}
function normalizePoolKey(value, fallback = 'pool') {
  let key = String(value || '').trim();
  if (!key) return fallback;
  if (key === 'pool' || key === 'pool_trash') return key;
  key = key.replace(/[^\w\u4e00-\u9fa5-]/g, '_').replace(/_+/g, '_').slice(0, 80);
  if (!key || /^_+$/.test(key)) return fallback;
  return key.startsWith('pool_') ? key : `pool_${key}`;
}

async function getPoolCandidates(env, poolKey, target, config) {
  const entries = parsePool(await requireKV(env).get(poolKey) || '');
  const out = [];
  const needIPv4 = target.mode === 'A';
  for (const entry of entries) {
    if (out.length >= config.maxCheckPerDomain) break;
    if ((target.mode === 'A' || (target.mode === 'TXT' && config.txtStrictPort)) && String(entry.port) !== String(target.port)) continue;
    if (needIPv4 && !isIPv4(entry.host)) continue;
    out.push(entry.addr);
  }
  return unique(out);
}

function newReport(target, poolKey) {
  return { domain: target.domain, mode: target.mode, port: target.port, minActive: target.minActive, poolKey, status: 'pending', beforeActive: 0, afterActive: 0, currentCount: 0, checkedCount: 0, added: [], removed: [], keptFailed: [], poolRemoved: 0, poolExhausted: false, configError: false, logs: [] };
}
function addReportLog(report, message) {
  const line = logLine(message);
  report.logs.push(line);
  console.log(line);
}
async function collectReplacementCandidates(env, poolKey, target, need, activeAddrs, state, config, report) {
  const existing = new Set(activeAddrs.map(v => target.mode === 'TXT' ? normalizeAddr(v) : parseHostPort(v).host));
  const candidates = (await getPoolCandidates(env, poolKey, target, config)).filter(addr => !existing.has(target.mode === 'TXT' ? normalizeAddr(addr) : parseHostPort(addr).host));
  if (!candidates.length) {
    report.poolExhausted = true;
    const portHint = target.mode === 'TXT' && !config.txtStrictPort ? '任意端口' : `${target.port} 端口`;
    addReportLog(report, `⚠️ ${poolKey} 没有可用于 ${portHint} 的候选`);
    return [];
  }
  const replacements = [];
  const toTrash = [];
  for (let i = 0; i < candidates.length && replacements.length < need; i += config.checkBatchSize) {
    const chunk = candidates.slice(i, i + config.checkBatchSize);
    addReportLog(report, `📡 检测候选 ${i + 1}-${Math.min(i + chunk.length, candidates.length)}/${candidates.length}`);
    const rows = await checkWithState(chunk, config, state);
    const m = resultMap(rows);
    report.checkedCount += chunk.length;
    for (const addr of chunk) {
      const row = m.get(addr) || { success: false, candidate: addr, message: '未返回检测结果' };
      if (row.success) {
        replacements.push(row);
        updateFailState(state, addr, row, config);
        addReportLog(report, `  ✅ ${addr} 可用 ${row.colo || ''} ${row.responseTime || 0}ms`);
        if (replacements.length >= need) break;
      } else {
        const st = updateFailState(state, addr, row, config);
        addReportLog(report, `  ❌ ${addr} 失败：${row.message || 'success=false'}，失败次数 ${st.failCount}/${config.failThreshold}`);
        if (st.shouldTrash) toTrash.push({ addr, reason: `候选检测失败：${row.message || 'success=false'}`, poolKey });
      }
    }
  }
  if (toTrash.length) {
    await addTrash(env, toTrash, config);
    report.poolRemoved += toTrash.length;
    await removeFromPool(env, poolKey, toTrash.map(x => x.addr));
    addReportLog(report, `🗑️ 已将 ${toTrash.length} 个连续失败候选移入垃圾桶`);
  }
  if (replacements.length < need) report.poolExhausted = true;
  return replacements;
}

async function maintainA(env, target, poolKey, state, config) {
  const report = newReport({ ...target, mode: 'A' }, poolKey);
  addReportLog(report, `🚀 维护 A: ${target.domain}:${target.port}，最小活跃 ${target.minActive}`);
  let records;
  try { records = await cfListRecords(config, target.domain, 'A'); }
  catch (e) { report.configError = true; report.status = 'failed'; addReportLog(report, `❌ 获取 A 记录失败：${e.message}`); return report; }

  report.currentCount = records.length;
  const current = records
    .filter(r => isIPv4(r.content))
    .map(r => ({ id: r.id, host: r.content, addr: formatHostPort(r.content, target.port), record: r }));
  const ignored = records.length - current.length;
  if (ignored > 0) addReportLog(report, `⚠️ 忽略 ${ignored} 条非 IPv4 A 内容`);
  if (!current.length) addReportLog(report, '当前没有 A 记录，需要从 IP 池补充');

  const active = [];
  const inactive = [];
  if (current.length) {
    addReportLog(report, `🔎 检测当前 A 记录 ${current.length} 条`);
    const rows = await checkWithState(current.map(x => x.addr), config, state);
    const m = resultMap(rows);
    report.checkedCount += current.length;
    for (const item of current) {
      const row = m.get(item.addr) || { success: false, candidate: item.addr, message: '未返回检测结果' };
      const st = updateFailState(state, item.addr, row, config);
      if (row.success) {
        active.push(item);
        addReportLog(report, `  ✅ ${item.addr} 活跃 ${row.colo || ''} ${row.responseTime || 0}ms`);
      } else {
        inactive.push({ ...item, reason: row.message || '检测失败', failCount: st.failCount, removable: st.shouldTrash });
        addReportLog(report, `  ❌ ${item.addr} 失效：${row.message || 'success=false'}，失败次数 ${st.failCount}/${config.failThreshold}`);
      }
    }
  }
  report.beforeActive = active.length;

  const need = Math.max(0, target.minActive - active.length);
  const replacements = need > 0 ? await collectReplacementCandidates(env, poolKey, { ...target, mode: 'A' }, need, current.map(x => x.addr), state, config, report) : [];

  const addedHosts = [];
  for (const row of replacements) {
    const { host } = parseHostPort(row.candidate);
    if (!isIPv4(host)) {
      addReportLog(report, `  ⚠️ 跳过非 IPv4 候选：${row.candidate}`);
      continue;
    }
    const r = await cfCreateRecord(config, { type: 'A', name: target.domain, content: host });
    if (r.ok) {
      addedHosts.push(host);
      report.added.push({ ip: formatHostPort(host, target.port), colo: row.colo, time: row.responseTime });
      addReportLog(report, `  ➕ 已添加 A ${host}`);
    } else {
      addReportLog(report, `  ⚠️ 添加 A ${host} 失败：${cfError(r)}`);
    }
  }

  const projectedActive = active.length + addedHosts.length;
  const removableInactive = inactive.filter(x => x.removable);
  const protectedInactive = inactive.filter(x => !x.removable);
  if (protectedInactive.length) {
    report.keptFailed.push(...protectedInactive.map(x => ({ ip: x.addr, reason: `连续失败 ${x.failCount}/${config.failThreshold}，未到删除阈值` })));
    addReportLog(report, `🛡️ ${protectedInactive.length} 条失效 A 未到阈值，暂不删除`);
  }

  const canDelete = removableInactive.length && (projectedActive >= target.minActive || config.removeUnhealthyWithoutReplacement);
  if (canDelete) {
    for (const item of removableInactive) {
      const r = await cfDeleteRecord(config, item.id);
      if (r.ok) {
        report.removed.push({ ip: item.addr, reason: item.reason });
        addReportLog(report, `  🧹 已删除失效 A ${item.host}`);
      } else {
        report.keptFailed.push({ ip: item.addr, reason: `删除失败：${cfError(r)}` });
        addReportLog(report, `  ⚠️ 删除 A ${item.host} 失败：${cfError(r)}`);
      }
    }
  } else if (removableInactive.length) {
    report.keptFailed.push(...removableInactive.map(x => ({ ip: x.addr, reason: '安全保护：没有足够可用替换，暂不删除' })));
    addReportLog(report, `🛡️ 安全保护：没有足够替换，暂不删除 ${removableInactive.length} 条失效 A 记录`);
  }

  report.afterActive = projectedActive;
  report.status = report.configError ? 'failed' : (projectedActive >= target.minActive ? 'success' : (projectedActive > 0 ? 'partial' : 'failed'));
  addReportLog(report, `📊 A 维护完成：${report.afterActive}/${target.minActive}，新增 ${report.added.length}，移除 ${report.removed.length}`);
  return report;
}

function managedTxtRecords(records) {
  return (records || []).map(record => ({ record, addrs: parseTXTContent(record.content || '') })).filter(x => x.addrs.length > 0);
}
function txtContentFromList(list) {
  return unique(list).join(',');
}
function fitTxtList(list, config) {
  const out = [];
  for (const addr of unique(list)) {
    if (out.length >= config.maxTxtTargets) break;
    const next = [...out, addr];
    if (txtContentFromList(next).length > config.maxTxtContentLength) break;
    out.push(addr);
  }
  return out;
}

async function maintainTXT(env, target, poolKey, state, config) {
  const report = newReport({ ...target, mode: 'TXT' }, poolKey);
  addReportLog(report, `🚀 维护 TXT: ${target.domain}，最小活跃 ${target.minActive}`);
  let records;
  try { records = await cfListRecords(config, target.domain, 'TXT'); }
  catch (e) { report.configError = true; report.status = 'failed'; addReportLog(report, `❌ 获取 TXT 失败：${e.message}`); return report; }

  const managed = managedTxtRecords(records);
  const primary = managed[0]?.record || null;
  const original = unique(managed.flatMap(x => x.addrs));
  const extraManaged = managed.slice(1).map(x => x.record);
  report.currentCount = original.length;
  if (!primary) addReportLog(report, '当前没有可识别的 ProxyIP TXT 记录，需要创建');
  else addReportLog(report, `当前 TXT 包含 ${original.length} 个目标${extraManaged.length ? `，另有 ${extraManaged.length} 条同名可识别 TXT 将在写入成功后清理` : ''}`);

  const active = [];
  const removable = [];
  const protectedFailed = [];
  if (original.length) {
    addReportLog(report, `🔎 检测当前 TXT 目标 ${original.length} 个`);
    const rows = await checkWithState(original, config, state);
    const m = resultMap(rows);
    report.checkedCount += original.length;
    for (const addr of original) {
      const row = m.get(addr) || { success: false, candidate: addr, message: '未返回检测结果' };
      const st = updateFailState(state, addr, row, config);
      if (row.success) {
        active.push(addr);
        addReportLog(report, `  ✅ ${addr} 活跃 ${row.colo || ''} ${row.responseTime || 0}ms`);
      } else if (st.shouldTrash) {
        removable.push({ addr, reason: row.message || '检测失败', failCount: st.failCount });
        addReportLog(report, `  ❌ ${addr} 失效：${row.message || 'success=false'}，失败次数 ${st.failCount}/${config.failThreshold}`);
      } else {
        protectedFailed.push({ addr, reason: row.message || '检测失败', failCount: st.failCount });
        addReportLog(report, `  ❌ ${addr} 暂不移除：${row.message || 'success=false'}，失败次数 ${st.failCount}/${config.failThreshold}`);
      }
    }
  }
  report.beforeActive = active.length;

  const need = Math.max(0, target.minActive - active.length);
  const replacements = need > 0 ? await collectReplacementCandidates(env, poolKey, { ...target, mode: 'TXT' }, need, original, state, config, report) : [];
  const added = replacements.map(r => normalizeAddr(r.candidate, target.port, { requireIp: true })).filter(Boolean);

  for (const r of replacements) {
    const ip = normalizeAddr(r.candidate, target.port, { requireIp: true });
    if (ip) report.added.push({ ip, colo: r.colo, time: r.responseTime });
  }

  let final = unique([...active, ...protectedFailed.map(x => x.addr), ...added]);
  let plannedRemoved = removable.map(x => ({ ip: x.addr, reason: x.reason }));

  if (final.length === 0 && original.length > 0 && !config.deleteEmptyTxt && !config.removeUnhealthyWithoutReplacement) {
    final = original;
    plannedRemoved = [];
    report.keptFailed.push(...removable.map(x => ({ ip: x.addr, reason: '安全保护：全部失败且无替换，未清空 TXT' })));
    addReportLog(report, '🛡️ 安全保护：全部失败且无替换，未清空 TXT');
  } else if (protectedFailed.length) {
    report.keptFailed.push(...protectedFailed.map(x => ({ ip: x.addr, reason: `连续失败 ${x.failCount}/${config.failThreshold}，未到删除阈值` })));
    addReportLog(report, `🛡️ ${protectedFailed.length} 个 TXT 目标未到删除阈值，暂时保留`);
  }

  const fitted = fitTxtList(final, config);
  if (fitted.length < final.length) {
    addReportLog(report, `⚠️ TXT 内容超过限制，仅保留 ${fitted.length}/${final.length} 个目标；可调大 MAX_TXT_TARGETS/MAX_TXT_CONTENT_LENGTH`);
    const fittedSet = new Set(fitted);
    const dropped = final.filter(x => !fittedSet.has(x));
    report.keptFailed.push(...dropped.map(ip => ({ ip, reason: 'TXT 内容长度限制，未写入' })));
  }
  final = fitted;

  const changed = txtContentFromList(final) !== txtContentFromList(original) || extraManaged.length > 0;
  let writeOk = true;
  if (changed) {
    if (final.length === 0 && primary) {
      const r = await cfDeleteRecord(config, primary.id);
      writeOk = r.ok;
      if (r.ok) addReportLog(report, '🧹 TXT 已删除（最终列表为空）');
      else addReportLog(report, `⚠️ TXT 删除失败：${cfError(r)}`);
    } else if (final.length > 0) {
      const content = txtContentFromList(final);
      const r = primary
        ? await cfUpdateRecord(config, primary.id, { type: 'TXT', name: target.domain, content })
        : await cfCreateRecord(config, { type: 'TXT', name: target.domain, content });
      writeOk = r.ok;
      if (r.ok) addReportLog(report, primary ? '📝 TXT 已更新' : '📝 TXT 已创建');
      else addReportLog(report, `⚠️ TXT 写入失败：${cfError(r)}`);
    }

    if (writeOk && extraManaged.length) {
      for (const record of extraManaged) {
        const r = await cfDeleteRecord(config, record.id);
        if (r.ok) addReportLog(report, `  🧹 已清理重复 TXT ${record.id}`);
        else addReportLog(report, `  ⚠️ 清理重复 TXT 失败：${cfError(r)}`);
      }
    }
  } else {
    addReportLog(report, '✨ TXT 无需变更');
  }

  if (writeOk) report.removed.push(...plannedRemoved);
  else {
    report.writeFailed = true;
    report.keptFailed.push(...plannedRemoved.map(x => ({ ip: x.ip, reason: `写入失败，未确认移除：${x.reason}` })));
  }

  const finalSet = new Set(final);
  if (writeOk) report.added = report.added.filter(a => finalSet.has(a.ip));
  else report.added = [];
  const healthy = new Set([...active, ...added]);
  report.afterActive = final.filter(x => healthy.has(x)).length;
  report.status = report.configError || report.writeFailed ? 'failed' : (report.afterActive >= target.minActive ? 'success' : (report.afterActive > 0 ? 'partial' : 'failed'));
  addReportLog(report, `📊 TXT 维护完成：${report.afterActive}/${target.minActive}，新增 ${report.added.length}，移除 ${report.removed.length}`);
  return report;
}

function summarizeModeReport(target, reports) {
  if (reports.length === 1) return reports[0];
  const main = newReport(target, reports[0]?.poolKey || 'pool');
  main.children = reports;
  main.logs = reports.flatMap(r => r.logs || []);
  main.added = reports.flatMap(r => r.added || []);
  main.removed = reports.flatMap(r => r.removed || []);
  main.keptFailed = reports.flatMap(r => r.keptFailed || []);
  main.poolRemoved = reports.reduce((n, r) => n + (r.poolRemoved || 0), 0);
  main.checkedCount = reports.reduce((n, r) => n + (r.checkedCount || 0), 0);
  main.beforeActive = reports.reduce((n, r) => Math.max(n, r.beforeActive || 0), 0);
  main.afterActive = reports.reduce((n, r) => Math.max(n, r.afterActive || 0), 0);
  main.configError = reports.some(r => r.configError);
  main.poolExhausted = reports.some(r => r.poolExhausted);
  main.status = reports.some(r => r.status === 'failed') ? 'failed' : (reports.some(r => r.status === 'partial') ? 'partial' : 'success');
  return main;
}
async function maintainTarget(env, target, mapping, state, config) {
  const poolKey = pickPoolKey(mapping, target.domain);
  if (!config.enableARecords) return await maintainTXT(env, { ...target, mode: 'TXT' }, poolKey, state, config);
  if (target.mode === 'A') return await maintainA(env, target, poolKey, state, config);
  if (target.mode === 'TXT') return await maintainTXT(env, target, poolKey, state, config);
  const a = await maintainA(env, { ...target, mode: 'A' }, poolKey, state, config);
  const txt = await maintainTXT(env, { ...target, mode: 'TXT' }, poolKey, state, config);
  return summarizeModeReport(target, [a, txt]);
}
async function acquireMaintainLock(env, config, isManual) {
  const store = requireKV(env);
  const now = Date.now();
  const current = safeJSONParse(await store.get(MAINTAIN_LOCK_KEY), null);
  if (current?.expiresAt && Number(current.expiresAt) > now) {
    return { acquired: false, current };
  }
  const owner = `${isManual ? 'manual' : 'cron'}-${now}-${Math.random().toString(16).slice(2)}`;
  const lock = { owner, mode: isManual ? 'manual' : 'cron', startedAt: nowISO(), expiresAt: now + config.maintainLockTtlSeconds * 1000 };
  await store.put(MAINTAIN_LOCK_KEY, JSON.stringify(lock), { expirationTtl: config.maintainLockTtlSeconds });
  const verify = safeJSONParse(await store.get(MAINTAIN_LOCK_KEY), null);
  return verify?.owner === owner ? { acquired: true, owner } : { acquired: false, current: verify || current };
}
async function releaseMaintainLock(env, owner) {
  if (!owner) return;
  try {
    const store = requireKV(env);
    const current = safeJSONParse(await store.get(MAINTAIN_LOCK_KEY), null);
    if (!current?.owner || current.owner === owner) await store.delete(MAINTAIN_LOCK_KEY);
  } catch {}
}

async function maintainAllDomains(env, isManual, config) {
  const start = Date.now();
  const store = requireKV(env);
  const targets = config.targets || [];
  if (!targets.length) {
    return { processedTargets: 0, totalTargets: 0, nextCursor: 0, reports: [], notified: false, tgStatus: { sent: false, reason: 'no_targets' }, processingTime: Date.now() - start };
  }

  const lock = await acquireMaintainLock(env, config, isManual);
  if (!lock.acquired) {
    return { processedTargets: 0, totalTargets: targets.length, nextCursor: 0, reports: [], skipped: true, reason: 'maintain_locked', lock: lock.current || null, notified: false, tgStatus: { sent: false, reason: 'locked' }, processingTime: Date.now() - start };
  }

  try {
    const mapping = await getMapping(env);
    const state = {
      cache: config.checkCacheEnabled ? await loadJsonKV(env, CHECK_CACHE_KEY, {}) : {},
      failCount: await loadJsonKV(env, CHECK_FAIL_KEY, {}),
      cacheDirty: false,
      failDirty: false,
    };
    const reports = [];
    let cursor = toInt(await store.get(MAINTAIN_CURSOR_KEY), 0, 0, Math.max(0, targets.length - 1));
    const max = Math.min(config.maintainMaxDomains, targets.length);
    for (let i = 0; i < max; i++) {
      const idx = (cursor + i) % targets.length;
      const target = targets[idx];
      reports.push(await maintainTarget(env, target, mapping, state, config));
    }

    const nextCursor = (cursor + max) % targets.length;
    if (max > 0) await store.put(MAINTAIN_CURSOR_KEY, String(nextCursor));
    if (config.checkCacheEnabled && state.cacheDirty) await saveJsonKV(env, CHECK_CACHE_KEY, state.cache);
    if (state.failDirty) await saveJsonKV(env, CHECK_FAIL_KEY, state.failCount);

    const notify = isManual || reports.some(r => r.added?.length || r.removed?.length || r.status !== 'success');
    const tgStatus = notify ? await sendTelegram(reports, config, isManual) : { sent: false, reason: 'no_need' };
    return { processedTargets: reports.length, totalTargets: targets.length, nextCursor, reports, notified: tgStatus.sent, tgStatus, processingTime: Date.now() - start };
  } finally {
    await releaseMaintainLock(env, lock.owner);
  }
}

async function sendTelegram(reports, config, isManual) {
  if (!config.tgToken || !config.tgId) return { sent: false, reason: 'not_configured' };
  let text = `${isManual ? '手动' : '自动'} DNS 维护报告\n${cnTime()}\n`;
  for (const r of reports) {
    text += `\n${r.status === 'success' ? '✅' : r.status === 'partial' ? '⚠️' : '❌'} ${r.domain} ${MODE_LABELS[r.mode] || r.mode}\n`;
    text += `活跃 ${r.afterActive}/${r.minActive} · 新增 ${r.added?.length || 0} · 移除 ${r.removed?.length || 0}\n`;
    for (const a of (r.added || []).slice(0, 8)) text += `+ ${a.ip}\n`;
    for (const d of (r.removed || []).slice(0, 8)) text += `- ${d.ip}\n`;
  }
  if (text.length > 3900) text = text.slice(0, 3890) + '\n…已截断';
  try {
    const res = await fetchWithTimeout(`https://api.telegram.org/bot${config.tgToken}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': JSON_TYPE }, body: JSON.stringify({ chat_id: config.tgId, text, disable_web_page_preview: true })
    }, 10000);
    return { sent: res.ok, reason: res.ok ? 'success' : `HTTP_${res.status}` };
  } catch (e) { return { sent: false, reason: e.message || 'network_error' }; }
}

async function handleVersion(env, config) {
  return ok({ name: 'DDNS Pro', version: VERSION, authEnabled: !!config.authKey, kvBinding: getKVBinding(env).name, targets: config.targets.length });
}
async function handleHealth(env, config) {
  const binding = getKVBinding(env);
  let kv = false;
  try { if (binding.store) { await binding.store.get('pool'); kv = true; } } catch {}
  return ok({ ok: true, version: VERSION, kv, kvBinding: binding.name, targets: config.targets.length, timestamp: nowISO() });
}
async function handleConfig(env, config) {
  return ok({ version: VERSION, targets: config.targets, settings: { txtOnly: config.txtOnly, enableARecords: config.enableARecords, preferTxtResolve: config.preferTxtResolve, allowAResolve: config.allowAResolve, publicTxtEndpoint: config.publicTxtEndpoint, checkConcurrency: config.checkConcurrency, checkBatchSize: config.checkBatchSize, maxCheckPerDomain: config.maxCheckPerDomain, maintainMaxDomains: config.maintainMaxDomains, failThreshold: config.failThreshold, checkCacheEnabled: config.checkCacheEnabled, checkCacheTtlMinutes: config.checkCacheTtlMinutes, maxTxtTargets: config.maxTxtTargets, maxTxtContentLength: config.maxTxtContentLength, txtStrictPort: config.txtStrictPort, enableRemoteImport: config.enableRemoteImport, manualPoolOnly: !config.enableRemoteImport, removeFailedImmediately: config.removeFailedImmediately, removeUnhealthyWithoutReplacement: config.removeUnhealthyWithoutReplacement }, authEnabled: !!config.authKey });
}
async function handlePools(env) {
  const store = requireKV(env);
  const listed = await store.list({ prefix: 'pool' });
  const set = new Set(['pool', 'pool_trash']);
  for (const item of listed.keys || []) if (item.name === 'pool' || item.name === 'pool_trash' || item.name.startsWith('pool_')) set.add(item.name);
  return ok({ pools: Array.from(set).sort((a,b) => (a === 'pool' ? -1 : b === 'pool' ? 1 : a.localeCompare(b, 'zh-CN'))) });
}
async function handleGetPool(url, env) {
  const key = normalizePoolKey(url.searchParams.get('poolKey') || 'pool');
  const pool = await requireKV(env).get(key) || '';
  return ok({ poolKey: key, pool, count: parsePool(pool).length });
}
async function handleSavePool(request, env, config) {
  const body = await readJson(request);
  if (!body) return fail('INVALID_JSON', '请求体不是有效 JSON');
  const key = normalizePoolKey(body.poolKey || 'pool');
  const mode = String(body.mode || 'append');
  const incoming = parsePool(body.pool || '').slice(0, config.maxPoolLines);
  const store = requireKV(env);
  const existing = parsePool(await store.get(key) || '');
  let next = existing;
  if (mode === 'replace') next = incoming;
  else if (mode === 'remove') {
    const remove = new Set(incoming.map(e => e.addr));
    next = existing.filter(e => !remove.has(e.addr));
  } else {
    const m = new Map(existing.map(e => [e.addr, e]));
    for (const e of incoming) m.set(e.addr, e);
    next = Array.from(m.values());
  }
  await store.put(key, serializePool(next));
  return ok({ poolKey: key, count: next.length, mode });
}
async function handleCreatePool(request, env) {
  const body = await readJson(request);
  const key = normalizePoolKey(body?.poolKey || '');
  if (!/^pool_[\u4e00-\u9fa5a-zA-Z0-9_-]{1,50}$/.test(key)) return fail('BAD_POOL_KEY', '池名称必须是 pool_ 开头，且仅含中文、字母、数字、下划线、横杠');
  const store = requireKV(env);
  if ((await store.get(key)) !== null) return fail('POOL_EXISTS', 'IP 池已存在');
  await store.put(key, '');
  return ok({ poolKey: key });
}
async function handleDeletePool(url, env) {
  const key = normalizePoolKey(url.searchParams.get('poolKey') || '');
  if (SYSTEM_POOLS.has(key)) return fail('PROTECTED_POOL', '系统池不能删除');
  await requireKV(env).delete(key);
  return ok({ poolKey: key });
}
async function handleClearTrash(env) {
  await requireKV(env).put('pool_trash', '');
  return ok({ cleared: true });
}
async function handleRestoreTrash(request, env) {
  const body = await readJson(request);
  const addrs = normalizeInputList(body?.ips || body?.targets || '');
  const targetPool = normalizePoolKey(body?.targetPool || 'pool');
  if (!addrs.length) return fail('MISSING_IPS', '没有要恢复的 IP');
  const store = requireKV(env);
  const trash = parsePool(await store.get('pool_trash') || '');
  const restore = new Set(addrs.map(v => normalizeAddr(v)).filter(Boolean));
  const restored = [];
  const restTrash = [];
  for (const item of trash) {
    if (restore.has(item.addr)) restored.push({ addr: item.addr });
    else restTrash.push(item);
  }
  const pool = parsePool(await store.get(targetPool) || '');
  const m = new Map(pool.map(e => [e.addr, e]));
  restored.forEach(e => m.set(e.addr, e));
  await store.put(targetPool, serializePool(Array.from(m.values())));
  await store.put('pool_trash', serializePool(restTrash));
  return ok({ restored: restored.length, targetPool });
}
async function handleResolve(url, config) {
  const target = url.searchParams.get('target') || url.searchParams.get('proxyip') || url.searchParams.get('domain') || '';
  if (!target) return fail('MISSING_TARGET', '缺少 target 参数');
  return ok({ input: target, targets: await resolveTarget(target, config) });
}
async function handleResolveBatch(request, config) {
  const body = await readJson(request);
  if (!body) return fail('INVALID_JSON', '请求体不是有效 JSON');
  const inputs = normalizeInputList(body.targets || body.proxyips || body.text || '');
  if (!inputs.length) return fail('MISSING_TARGETS', '缺少 targets');
  if (inputs.length > 100) return fail('TOO_MANY_TARGETS', '一次最多解析 100 条');
  const results = await Promise.all(inputs.map(async input => {
    try { return { input, targets: await resolveTarget(input, config) }; }
    catch (e) { return { input, targets: [], error: e.message || '解析失败' }; }
  }));
  return ok({ results });
}
async function handleCheckIP(url, config) {
  const ip = url.searchParams.get('ip') || url.searchParams.get('target') || '';
  if (!ip) return fail('MISSING_IP', '缺少 ip 参数');
  const rows = await checkTargets([normalizeAddr(ip)], config, url.searchParams.get('useBackup') === 'true');
  return ok(rows[0] || { success: false, candidate: ip, message: '无检测结果' });
}
async function handleCheckBatch(request, config) {
  const body = await readJson(request);
  if (!body) return fail('INVALID_JSON', '请求体不是有效 JSON');
  const inputs = normalizeInputList(body.targets || body.text || body.ip || '');
  if (!inputs.length) return fail('MISSING_TARGETS', '缺少检测目标');
  if (inputs.length > 100) return fail('TOO_MANY_TARGETS', '一次最多检测 100 条');
  const resolved = [];
  const candidates = [];
  for (const input of inputs) {
    try {
      const targets = body.resolve === false ? [normalizeAddr(input)] : await resolveTarget(input, config);
      resolved.push({ input, targets }); candidates.push(...targets);
    } catch (e) { resolved.push({ input, targets: [], error: e.message || '解析失败' }); }
  }
  const results = await checkTargets(unique(candidates), config, body.useBackup === true);
  return ok({ resolved, results, successCount: results.filter(r => r.success).length });
}
async function handleLookupDomain(url, config) {
  const domain = url.searchParams.get('domain') || '';
  if (!domain) return fail('MISSING_DOMAIN', '缺少 domain 参数');
  const isTxt = /^txt@/i.test(domain) || config.preferTxtResolve !== false;
  const normalized = domain.replace(/^txt@/i, '').replace(/^a@/i, '');
  const { host, port } = parseHostPort(normalized);
  return ok({ type: isTxt ? 'TXT优先' : 'A/AAAA', domain: host, port, targets: await resolveTarget(domain, config) });
}
async function handleDomainStatus(url, env, config) {
  const domain = normalizeDomain(url.searchParams.get('domain') || '');
  if (!domain) return fail('MISSING_DOMAIN', '缺少 domain 参数');
  const txt = await dohQuery(domain, 'TXT', config);
  let a = [], aaaa = [];
  if (config.enableARecords || url.searchParams.get('includeA') === '1') {
    [a, aaaa] = await Promise.all([dohQuery(domain, 'A', config), dohQuery(domain, 'AAAA', config)]);
  }
  let mapping = {}; try { mapping = await getMapping(env); } catch {}
  return ok({ domain, A: a.filter(x => x.type === 1).map(x => x.data), AAAA: aaaa.filter(x => x.type === 28).map(x => x.data), TXT: txt.filter(x => x.type === 16).map(x => x.data), TXTTargets: txt.filter(x => x.type === 16).flatMap(x => parseTXTContent(x.data)), pool: mapping[domain] || '' });
}
async function handleCurrentStatus(url, config) {
  const idx = toInt(url.searchParams.get('target'), 0, 0, Math.max(0, config.targets.length - 1));
  const target = config.targets[idx];
  if (!target) return fail('NO_TARGET', '未配置目标域名');
  const txt = await cfListRecords(config, target.domain, 'TXT').catch(e => ({ error: e.message }));
  let a = [];
  if (config.enableARecords && target.mode !== 'TXT') a = await cfListRecords(config, target.domain, 'A').catch(e => ({ error: e.message }));
  return ok({ target, A: a, TXT: txt });
}
async function handleMappingGet(env) { return ok({ mapping: await getMapping(env) }); }
async function handleMappingSave(request, env) {
  const body = await readJson(request);
  if (!body || typeof body.mapping !== 'object' || Array.isArray(body.mapping)) return fail('BAD_MAPPING', 'mapping 必须是对象');
  const normalized = {};
  for (const [domain, pool] of Object.entries(body.mapping)) normalized[normalizeDomain(domain)] = normalizePoolKey(pool);
  await setMapping(env, normalized);
  return ok({ mapping: normalized });
}
async function handleLoadRemote(request, config) {
  if (!config.enableRemoteImport) return fail('REMOTE_IMPORT_DISABLED', '远程导入已关闭：当前版本按手动导入 IP 池设计，Cron 不会拉取远程源。', 403);
  const body = await readJson(request);
  if (!body?.url) return fail('MISSING_URL', '缺少 URL');
  let u; try { u = new URL(body.url); } catch { return fail('BAD_URL', 'URL 无效'); }
  if (!['http:', 'https:'].includes(u.protocol)) return fail('BAD_URL', '仅支持 http/https');
  const res = await fetchWithTimeout(u.toString(), { headers: { 'User-Agent': 'DDNS-Pro/12' } }, config.remoteTimeout);
  if (!res.ok) return fail('REMOTE_FAILED', `远程加载失败 HTTP ${res.status}`, 502);
  const length = Number(res.headers.get('Content-Length') || 0);
  if (length && length > config.maxRemoteBytes) return fail('REMOTE_TOO_LARGE', `远程内容过大：${length} bytes`, 413);
  const text = (await res.text()).slice(0, config.maxRemoteBytes);
  const port = String(body.port || body.defaultPort || '443');
  const country = String(body.cfCountry || body.country || '').trim().toUpperCase();
  const lines = extractRemoteTargets(text, { port, country, format: body.format || 'auto' });
  return ok({ ips: lines.join('\n'), count: lines.length });
}
function countryToken(value) {
  return String(value || '').trim().toUpperCase();
}
function lineMatchesCountry(line, country) {
  const token = countryToken(country);
  if (!token) return true;
  const s = String(line || '').toUpperCase();
  const comment = s.includes('#') ? s.slice(s.indexOf('#') + 1) : s;
  return new RegExp(`(^|[^A-Z0-9])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^A-Z0-9]|$)`).test(comment);
}
function extractRemoteTargets(text, options) {
  const format = String(options.format || 'auto').toLowerCase();
  if (format === 'csv' || (format === 'auto' && text.includes(',') && /ip|address|端口|port|colo|country/i.test(text.split(/\r?\n/)[0] || ''))) return extractCsvTargets(text, options);

  const out = [];
  const regex = /(\[[0-9a-fA-F:]+\]|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{2,}\b)(?::(\d{1,5}))?/g;
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!lineMatchesCountry(line, options.country)) continue;
    const main = splitComment(line).main;
    let m;
    regex.lastIndex = 0;
    while ((m = regex.exec(main))) {
      const host = stripBrackets(m[1]);
      if (!isIpHost(host)) continue;
      out.push(formatHostPort(host, m[2] || options.port || '443'));
    }
  }
  return unique(out);
}
function parseCsvLine(line) {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
    else if (ch === '"') q = !q;
    else if (ch === ',' && !q) { out.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  out.push(cur.trim()); return out;
}
function csvCountryMatches(value, country) {
  const token = countryToken(country);
  if (!token) return true;
  return lineMatchesCountry(`# ${String(value || '')}`, token);
}
function extractCsvTargets(text, options) {
  const rows = text.split(/\r?\n/).filter(Boolean).map(parseCsvLine);
  if (!rows.length) return [];
  const header = rows[0].map(h => h.toLowerCase());
  const ipIdx = header.findIndex(h => /^(ip|addr|address|proxyip|host)$/.test(h));
  const portIdx = header.findIndex(h => /port|端口/.test(h));
  const countryIdx = header.findIndex(h => /country|cfcolo|colo|国家|地区|region|地区/.test(h));
  const dataRows = ipIdx >= 0 ? rows.slice(1) : rows;
  const out = [];
  for (const row of dataRows) {
    if (options.country && countryIdx >= 0 && !csvCountryMatches(row[countryIdx], options.country)) continue;
    const host = stripBrackets(row[ipIdx >= 0 ? ipIdx : 0] || '');
    if (!isIpHost(host)) continue;
    const port = row[portIdx] || options.port || '443';
    if (!isValidPortValue(port)) continue;
    out.push(formatHostPort(host, port));
  }
  return unique(out);
}
async function handleAddRecord(request, config) {
  const body = await readJson(request);
  const target = config.targets[toInt(body?.targetIndex, 0, 0, Math.max(0, config.targets.length - 1))];
  if (!target) return fail('NO_TARGET', '未配置目标域名');
  const addr = normalizeAddr(body?.ip || '', target.port, { requireIp: true });
  if (!addr) return fail('MISSING_IP', '缺少有效 IP');
  const { host } = parseHostPort(addr);
  if (target.mode !== 'A' || !config.enableARecords) {
    const records = await cfListRecords(config, target.domain, 'TXT');
    const managed = managedTxtRecords(records);
    const primary = managed[0]?.record || null;
    const list = managed.length ? unique(managed.flatMap(x => x.addrs)) : [];
    if (!list.includes(addr)) list.push(addr);
    const content = txtContentFromList(fitTxtList(list, config));
    const r = primary ? await cfUpdateRecord(config, primary.id, { type: 'TXT', name: target.domain, content }) : await cfCreateRecord(config, { type: 'TXT', name: target.domain, content });
    return r.ok ? ok({ added: addr, mode: 'TXT' }) : fail('CF_ERROR', cfError(r), 502, r);
  }
  if (!isIPv4(host)) return fail('BAD_IP_VERSION', 'A 记录只能添加 IPv4；IPv6 请使用 TXT 模式');
  const r = await cfCreateRecord(config, { type: 'A', name: target.domain, content: host });
  return r.ok ? ok({ added: host, mode: 'A' }) : fail('CF_ERROR', cfError(r), 502, r);
}
async function handleDeleteRecord(url, config) {
  const id = url.searchParams.get('id') || '';
  if (!id) return fail('MISSING_ID', '缺少记录 ID');
  const r = await cfDeleteRecord(config, id);
  return r.ok ? ok({ deleted: id }) : fail('CF_ERROR', cfError(r), 502, r);
}
async function handleMaintain(url, env, config) { return ok(await maintainAllDomains(env, url.searchParams.get('manual') === 'true', config)); }

function plainText(text, status = 200, headers = {}) {
  return new Response(String(text || ''), { status, headers: { 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'public, max-age=60', ...headers } });
}
async function handlePublicTxt(url, config) {
  if (!config.publicTxtEndpoint) return fail('PUBLIC_TXT_DISABLED', '公开 TXT 输出未启用', 404);
  let domain = normalizeDomain(url.searchParams.get('domain') || '');
  const targetIdx = toInt(url.searchParams.get('target'), 0, 0, Math.max(0, config.targets.length - 1));
  if (!domain) domain = config.targets[targetIdx]?.domain || '';
  if (!domain) return plainText('', 404);

  const configured = new Set(config.targets.map(t => t.domain));
  if (!config.publicTxtAllowAny && !configured.has(domain)) return plainText('domain not allowed', 403);

  let targets = [];
  try { targets = await resolveTarget(`txt@${domain}`, config); }
  catch { targets = []; }

  const format = String(url.searchParams.get('format') || '').toLowerCase();
  if (format === 'json') return json({ success: true, domain, targets, count: targets.length }, 200, { 'Cache-Control': 'public, max-age=60' });
  if (format === 'csv') return plainText(targets.join(','));
  return plainText(targets.join('\n'));
}

const ROUTES = {
  '/api/version': (url, req, env, config) => handleVersion(env, config),
  '/api/health': (url, req, env, config) => handleHealth(env, config),
  '/api/config': (url, req, env, config) => handleConfig(env, config),
  '/api/auth/me': () => ok({ authenticated: true }),
  '/api/auth/login': (url, req, env, config) => handleAuthLogin(req, config),
  '/api/auth/logout': () => handleAuthLogout(),
  '/api/pools': (url, req, env) => handlePools(env),
  '/api/get-pool': (url, req, env) => handleGetPool(url, env),
  '/api/save-pool': (url, req, env, config) => handleSavePool(req, env, config),
  '/api/create-pool': (url, req, env) => handleCreatePool(req, env),
  '/api/delete-pool': (url, req, env) => handleDeletePool(url, env),
  '/api/clear-trash': (url, req, env) => handleClearTrash(env),
  '/api/restore-from-trash': (url, req, env) => handleRestoreTrash(req, env),
  '/api/load-remote-url': (url, req, env, config) => handleLoadRemote(req, config),
  '/api/resolve': (url, req, env, config) => handleResolve(url, config),
  '/api/resolve-batch': (url, req, env, config) => handleResolveBatch(req, config),
  '/api/check-ip': (url, req, env, config) => handleCheckIP(url, config),
  '/api/check': (url, req, env, config) => handleCheckBatch(req, config),
  '/api/lookup-domain': (url, req, env, config) => handleLookupDomain(url, config),
  '/api/domain/status': (url, req, env, config) => handleDomainStatus(url, env, config),
  '/api/current-status': (url, req, env, config) => handleCurrentStatus(url, config),
  '/api/get-domain-pool-mapping': (url, req, env) => handleMappingGet(env),
  '/api/save-domain-pool-mapping': (url, req, env) => handleMappingSave(req, env),
  '/api/add-a-record': (url, req, env, config) => handleAddRecord(req, config),
  '/api/delete-record': (url, req, env, config) => handleDeleteRecord(url, config),
  '/api/maintain': (url, req, env, config) => handleMaintain(url, env, config),
};
const POST_ONLY = new Set(['/api/auth/login','/api/auth/logout','/api/save-pool','/api/create-pool','/api/delete-pool','/api/clear-trash','/api/restore-from-trash','/api/load-remote-url','/api/resolve-batch','/api/check','/api/save-domain-pool-mapping','/api/add-a-record','/api/delete-record','/api/maintain']);
async function handleApi(request, env, config) {
  const url = new URL(request.url);
  const handler = ROUTES[url.pathname];
  if (!handler) return fail('NOT_FOUND', '接口不存在', 404);
  if (POST_ONLY.has(url.pathname) && request.method !== 'POST') return fail('METHOD_NOT_ALLOWED', 'Method Not Allowed', 405);
  try { return await handler(url, request, env, config); }
  catch (e) { console.error('API error', url.pathname, e); return fail('INTERNAL_ERROR', e.message || '内部错误', 500); }
}

export default {
  async fetch(request, env, ctx) {
    const config = createConfig(env, request);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return corsPreflight(request, env, config);
    if (url.protocol === 'http:') return Response.redirect(url.href.replace(/^http:/, 'https:'), 301);
    if (url.pathname === '/favicon.ico') return new Response(null, { status: 204 });
    if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });

    if (['/proxyip', '/txt', '/raw', '/pool.txt'].includes(url.pathname)) {
      return await handlePublicTxt(url, config);
    }

    // Worker 同源入口：前端静态文件部署在 GitHub Pages/Pages，Worker 只做轻量反代，不内嵌 HTML/CSS/JS。
    if (url.pathname === '/') return localRedirect('/admin/');

    if (url.pathname === '/logout') {
      return new Response('重定向中...', {
        status: 302,
        headers: {
          'Location': '/login',
          'Set-Cookie': 'ddns_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'
        }
      });
    }

    if (url.pathname === '/login' || url.pathname === '/login/' || url.pathname === '/login.html') {
      const auth = await checkAuth(request, url, config);
      if (request.method === 'POST') return await handleAuthLogin(request, config);
      if (auth.enabled && auth.ok) return localRedirect('/admin/');
      return await fetchAdminStatic(request, config);
    }

    if (url.pathname === '/admin') return localRedirect('/admin/' + url.search);
    if (url.pathname.startsWith('/admin/')) {
      const auth = await checkAuth(request, url, config);
      const key = String(url.searchParams.get('key') || '').trim();
      if (auth.enabled && key && key === config.authKey) {
        const token = await sessionToken(request, config);
        return redirectWithoutKey(url, authCookie(token));
      }
      if (auth.enabled && !auth.ok) return localRedirect('/login');
      return await fetchAdminStatic(request, config);
    }

    if (!url.pathname.startsWith('/api/')) {
      return withCors(fail('NOT_FOUND', '接口不存在', 404), request, env, config);
    }

    const publicApi = url.pathname === '/api/auth/login' || url.pathname === '/api/version' || url.pathname === '/api/health';
    if (!publicApi) {
      const auth = await checkAuth(request, url, config);
      if (auth.enabled && !auth.ok) {
        return withCors(fail('UNAUTHORIZED', '未登录或登录已过期', 401), request, env, config);
      }
      const response = await handleApi(request, env, config);
      const headers = new Headers(response.headers);
      if (auth.setCookie) headers.set('Set-Cookie', authCookie(auth.token));
      return withCors(new Response(response.body, { status: response.status, statusText: response.statusText, headers }), request, env, config);
    }

    return withCors(await handleApi(request, env, config), request, env, config);
  },
  async scheduled(event, env, ctx) {
    // Cron 只维护 KV 中已有的手动 IP 池，并写回 TXT；不会自动拉取任何远程源。
    const config = createConfig(env);
    ctx.waitUntil(maintainAllDomains(env, false, config).catch(e => console.error('scheduled maintain failed', e)));
  }
};
