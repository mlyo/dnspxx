/**
 * DDNS Pro v12 · Refactored DNS Maintenance System
 * Cloudflare Worker / Pages Advanced Mode compatible.
 */

const VERSION = '12.0.0-refactor';
const JSON_TYPE = 'application/json; charset=UTF-8';
const HTML_TYPE = 'text/html; charset=UTF-8';
const CHECK_CACHE_KEY = 'check_cache_v2';
const CHECK_FAIL_KEY = 'check_fail_v2';
const MAINTAIN_CURSOR_KEY = 'maintain_cursor_v2';

const DEFAULTS = Object.freeze({
  checkApi: 'https://cf.090227.xyz/check?proxyip=',
  checkApiBackup: 'https://api.090227.xyz/check?proxyip=',
  dohApi: 'https://cloudflare-dns.com/dns-query',
  adminOrigin: '',
  homeMode: 'nginx',
  dnsTtl: 60,
  proxied: false,
  defaultMinActive: 3,
  checkConcurrency: 5,
  checkTimeout: 5000,
  dohTimeout: 5000,
  cfTimeout: 10000,
  remoteTimeout: 8000,
  maxCheckPerDomain: 40,
  checkBatchSize: 2,
  maintainMaxDomains: 5,
  maxPoolLines: 5000,
  maxRemoteBytes: 1024 * 1024,
  maxTrashSize: 1000,
  failThreshold: 3,
});

const SYSTEM_POOLS = new Set(['pool', 'pool_trash']);
const MODE_LABELS = { A: 'A记录', TXT: 'TXT记录', ALL: 'A+TXT' };

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

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
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
    homeMode: envText(env, 'HOME_MODE', DEFAULTS.homeMode).toLowerCase(),
    homeUrl: envText(env, 'HOME_URL'),
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
    checkCacheEnabled: toBool(env?.CHECK_CACHE_ENABLED, false),
    checkCacheTtlMinutes: toInt(env?.CHECK_CACHE_TTL_MINUTES, 360, 1, 10080),
    ipInfoEnabled: toBool(env?.IP_INFO_ENABLED, false),
    ipInfoApi: envText(env, 'IP_INFO_API', 'http://ip-api.com/json'),
    allowedOrigins: envText(env, 'ALLOWED_ORIGINS'),
    targets: parseTargets(envText(env, 'CF_DOMAIN'), toInt(env?.DEFAULT_MIN_ACTIVE, DEFAULTS.defaultMinActive, 1, 200)),
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

function getAllowedOrigins(env, config) {
  const raw = config?.allowedOrigins || envText(env, 'ALLOWED_ORIGINS');
  if (raw) return raw.split(',').map(s => s.trim()).filter(Boolean);
  return config?.adminOrigin ? [config.adminOrigin] : [];
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

function htmlLogin() {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DDNS Pro 登录</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(420px,calc(100vw - 32px));background:#111827;border:1px solid #334155;border-radius:18px;padding:24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 8px}.hint{color:#94a3b8;line-height:1.7}input,button{width:100%;box-sizing:border-box;border-radius:12px;padding:12px 14px;font:inherit}input{background:#020617;color:#e5e7eb;border:1px solid #475569}button{margin-top:12px;border:0;background:#2563eb;color:white;font-weight:700;cursor:pointer}.err{min-height:22px;color:#fca5a5;margin-top:10px}</style></head><body><form class="card" id="form"><h1>DDNS Pro</h1><p class="hint">输入 Worker 环境变量 AUTH_KEY 登录后台。</p><input id="password" name="password" type="password" autocomplete="current-password" placeholder="AUTH_KEY" autofocus><button>登录</button><div class="err" id="err"></div></form><script>document.getElementById('form').addEventListener('submit',async e=>{e.preventDefault();const err=document.getElementById('err');err.textContent='';const password=document.getElementById('password').value;const res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({password})});if(res.ok)location.href='/admin/';else err.textContent='登录失败，请检查 AUTH_KEY';});</script></body></html>`;
}
function htmlNginxPage() {
  return `<!doctype html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}@media(max-width:720px){body{width:auto;margin:24px}}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>`;
}
async function handleHome(request, config) {
  if (config.homeMode === 'blank') return new Response('', { status: 204, headers: { 'Cache-Control': 'no-store' } });
  if (config.homeMode === '404') return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
  if (config.homeMode === 'redirect' && config.homeUrl) return Response.redirect(config.homeUrl, 302);
  return new Response(htmlNginxPage(), { headers: { 'Content-Type': HTML_TYPE, 'Cache-Control': 'no-store' } });
}
async function handleLogin(request, config) {
  if (!config.authKey) return new Response(htmlLogin().replace('输入 Worker 环境变量 AUTH_KEY 登录后台。', 'AUTH_KEY 未配置，后台处于开放模式。'), { headers: { 'Content-Type': HTML_TYPE, 'Cache-Control': 'no-store' } });
  if (request.method !== 'POST') return new Response(htmlLogin(), { headers: { 'Content-Type': HTML_TYPE, 'Cache-Control': 'no-store' } });
  let password = '';
  const type = request.headers.get('Content-Type') || '';
  if (type.includes('application/json')) {
    const body = await readJson(request);
    password = String(body?.password || body?.key || '').trim();
  } else {
    password = String(new URLSearchParams(await request.text()).get('password') || '').trim();
  }
  if (password !== config.authKey) return fail('BAD_AUTH', 'AUTH_KEY 错误', 401);
  const token = await sessionToken(request, config);
  return json({ success: true, data: { redirect: '/admin/' } }, 200, { 'Set-Cookie': authCookie(token) });
}

async function serveAsset(request, env, config) {
  const url = new URL(request.url);
  let path = url.pathname;
  if (path === '/admin') return Response.redirect(url.origin + '/admin/', 302);
  if (path === '/admin/' || path === '/admin') path = '/admin.html';
  else path = path.replace(/^\/admin\//, '/');

  if (env?.ASSETS?.fetch) {
    const assetUrl = new URL(request.url);
    assetUrl.pathname = path;
    const assetReq = new Request(assetUrl.toString(), request);
    const res = await env.ASSETS.fetch(assetReq);
    if (res.status !== 404) {
      const headers = new Headers(res.headers);
      headers.set('Cache-Control', path === '/admin.html' ? 'no-store' : 'public, max-age=300');
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    }
  }

  if (config.adminOrigin) {
    const upstream = await fetchWithTimeout(config.adminOrigin + path + url.search, { cf: { cacheTtl: path === '/admin.html' ? 0 : 300 } }, 8000);
    if (upstream.ok) return upstream;
  }
  return new Response('Admin asset not found. Deploy this project with Pages assets or set ADMIN_ORIGIN.', { status: 404 });
}

function parseTargets(raw, defaultMinActive) {
  return String(raw || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean).map((entry, index) => {
    let text = entry.split('#')[0].trim();
    let minActive = defaultMinActive;
    const minMatch = text.match(/&([0-9]{1,4})$/);
    if (minMatch) {
      minActive = Math.max(1, Number(minMatch[1]));
      text = text.replace(/&[0-9]{1,4}$/, '').trim();
    }
    let mode = 'A';
    if (/^txt@/i.test(text)) { mode = 'TXT'; text = text.replace(/^txt@/i, ''); }
    else if (/^all@/i.test(text)) { mode = 'ALL'; text = text.replace(/^all@/i, ''); }
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
function isIPv4(host) {
  const parts = String(host || '').split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}
function isIPv6(host) {
  const h = stripBrackets(host);
  return /^[0-9a-fA-F:]+$/.test(h) && h.includes(':');
}
function formatHostPort(host, port = '443') {
  const h = stripBrackets(host);
  return isIPv6(h) ? `[${h}]:${port}` : `${h}:${port}`;
}
function parseHostPort(input, defaultPort = '443') {
  let text = String(input || '').split('#')[0].trim();
  if (!text) return { host: '', port: String(defaultPort) };
  if (/^https?:\/\//i.test(text)) {
    try {
      const u = new URL(text);
      return { host: u.hostname, port: u.port || String(defaultPort) };
    } catch {}
  }
  let port = String(defaultPort);
  if (text.startsWith('[')) {
    const idx = text.lastIndexOf(']:');
    if (idx !== -1) {
      const p = Number(text.slice(idx + 2));
      if (Number.isInteger(p) && p >= 1 && p <= 65535) { port = String(p); text = text.slice(0, idx + 1); }
    }
    return { host: stripBrackets(text), port };
  }
  const colonCount = (text.match(/:/g) || []).length;
  if (colonCount === 1) {
    const idx = text.lastIndexOf(':');
    const p = Number(text.slice(idx + 1));
    if (Number.isInteger(p) && p >= 1 && p <= 65535) { port = String(p); text = text.slice(0, idx); }
  }
  return { host: stripBrackets(text), port };
}
function normalizeAddr(input, defaultPort = '443') {
  const p = parseHostPort(input, defaultPort);
  return p.host ? formatHostPort(p.host, p.port) : '';
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
    const addr = normalizeAddr(main);
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
    const addr = normalizeAddr(entry.addr || entry.line || entry);
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    const comment = entry.comment ? ` ${String(entry.comment).trim().startsWith('#') ? entry.comment.trim() : '#' + entry.comment.trim()}` : '';
    lines.push(`${addr}${comment}`);
  }
  return lines.join('\n');
}
function normalizeInputList(value) {
  const arr = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
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
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  return s.replace(/\\"/g, '"');
}
function parseTXTContent(content) {
  return unique(normalizeTxtValue(content).split(',').map(v => normalizeAddr(v)).filter(Boolean));
}
async function resolveTarget(input, config) {
  let raw = String(input || '').trim();
  let forceTxt = false;
  if (/^txt@/i.test(raw)) { forceTxt = true; raw = raw.replace(/^txt@/i, ''); }
  const { host, port } = parseHostPort(raw);
  if (!host) throw new Error('目标为空');
  if (isIPv4(host) || isIPv6(host)) return [formatHostPort(host, port)];
  if (forceTxt) {
    const txt = await dohQuery(host, 'TXT', config);
    const out = [];
    for (const record of txt.filter(x => x.type === 16)) out.push(...parseTXTContent(record.data));
    if (!out.length) throw new Error('TXT 记录为空或无法解析');
    return unique(out);
  }
  const [a, aaaa] = await Promise.all([dohQuery(host, 'A', config), dohQuery(host, 'AAAA', config)]);
  const out = [];
  for (const r of a.filter(x => x.type === 1 && x.data)) out.push(formatHostPort(r.data, port));
  for (const r of aaaa.filter(x => x.type === 28 && x.data)) out.push(formatHostPort(r.data, port));
  if (!out.length) throw new Error('域名无 A/AAAA 解析结果');
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
    return { ok: cfOk, status: res.status, result: data.result, errors: data.errors || [], messages: data.messages || [], raw: data };
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
  const q = `/zones/${config.zoneId}/dns_records?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}&per_page=100`;
  const r = await fetchCF(config, q);
  if (!r.ok) throw new Error(cfError(r));
  return Array.isArray(r.result) ? r.result : [];
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
  const probe = row?.probe_results || {};
  const exit = probe.ipv4?.exit || probe.ipv6?.exit || {};
  return {
    candidate,
    success: row?.success === true,
    source,
    colo: String(row?.colo || row?.checkColo || exit.colo || ''),
    responseTime: Number(row?.responseTime || row?.time || ms || 0),
    proxyIP: String(row?.proxyIP || row?.proxyip || candidate || ''),
    message: String(row?.message || row?.error || ''),
    exitIP: String(exit.ip || row?.ip || ''),
    country: String(exit.country || row?.country || ''),
    city: String(exit.city || row?.city || ''),
    asn: exit.asn ?? row?.asn ?? null,
    org: String(exit.asOrganization || exit.org || row?.asOrganization || row?.org || ''),
    raw: row || null,
  };
}
function buildCheckUrl(apiUrl, targets, token = '') {
  const base = String(apiUrl || '').trim();
  if (!base) return '';
  const joined = targets.map(v => normalizeAddr(v)).filter(Boolean).join(',');
  const sep = base.includes('?') && !/[?&]proxyip=$/i.test(base) ? (base.endsWith('&') || base.endsWith('?') ? '' : '&') : '';
  let url = base.endsWith('=') ? base + encodeURIComponent(joined) : base + sep + 'proxyip=' + encodeURIComponent(joined);
  if (token) url += (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
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
    const raw = safeJSONParse(await res.text(), {});
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
  for (let i = 0; i < list.length; i += chunkSize) {
    const chunk = list.slice(i, i + chunkSize);
    let rows = [];
    if (useBackupOnly) {
      rows = config.checkBatchApiBackup
        ? await checkPostBatch(chunk, config.checkBatchApiBackup, config.checkApiBackupToken, 'backup-batch', config)
        : await checkApiOnce(chunk, config.checkApiBackup, config.checkApiBackupToken, 'backup', config);
    } else {
      rows = config.checkBatchApi
        ? await checkPostBatch(chunk, config.checkBatchApi, config.checkApiToken, 'main-batch', config)
        : await checkApiOnce(chunk, config.checkApi, config.checkApiToken, 'main', config);
      if (!rows.some(r => r.success) && (config.checkApiBackup || config.checkBatchApiBackup)) {
        const backup = config.checkBatchApiBackup
          ? await checkPostBatch(chunk, config.checkBatchApiBackup, config.checkApiBackupToken, 'backup-batch', config)
          : await checkApiOnce(chunk, config.checkApiBackup, config.checkApiBackupToken, 'backup', config);
        if (backup.some(r => r.success)) rows = backup;
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
      if (row.success) state.cache[normalizeAddr(row.candidate)] = { ...row, time: Date.now() };
      out.push(row);
    }
  }
  return out;
}
function updateFailState(state, addr, check, config) {
  const key = normalizeAddr(addr);
  if (!key) return { failCount: 0, shouldTrash: false };
  if (check?.success === true) {
    delete state.failCount[key];
    return { failCount: 0, shouldTrash: false };
  }
  const prev = state.failCount[key] || { count: 0 };
  const count = config.removeFailedImmediately ? config.failThreshold : Number(prev.count || 0) + 1;
  state.failCount[key] = { count, lastFailureAt: nowISO(), message: check?.message || '检测失败' };
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
  key = key.replace(/[^\w\u4e00-\u9fa5-]/g, '_');
  return key.startsWith('pool_') ? key : `pool_${key}`;
}

async function getPoolCandidates(env, poolKey, target, config) {
  const entries = parsePool(await requireKV(env).get(poolKey) || '');
  const out = [];
  for (const entry of entries) {
    if (out.length >= config.maxCheckPerDomain) break;
    if (String(entry.port) !== String(target.port)) continue;
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
  const existing = new Set(activeAddrs.map(v => parseHostPort(v).host));
  const candidates = (await getPoolCandidates(env, poolKey, target, config)).filter(addr => !existing.has(parseHostPort(addr).host));
  if (!candidates.length) {
    report.poolExhausted = true;
    addReportLog(report, `⚠️ ${poolKey} 没有可用于 ${target.port} 端口的候选`);
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
  const current = records.map(r => ({ id: r.id, host: r.content, addr: formatHostPort(r.content, target.port), record: r }));
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
      updateFailState(state, item.addr, row, config);
      if (row.success) {
        active.push(item);
        addReportLog(report, `  ✅ ${item.addr} 活跃 ${row.colo || ''} ${row.responseTime || 0}ms`);
      } else {
        inactive.push({ ...item, reason: row.message || '检测失败' });
        addReportLog(report, `  ❌ ${item.addr} 失效：${row.message || 'success=false'}`);
      }
    }
  }
  report.beforeActive = active.length;

  const need = Math.max(0, target.minActive - active.length);
  const replacements = need > 0 ? await collectReplacementCandidates(env, poolKey, target, need, current.map(x => x.addr), state, config, report) : [];

  const addedHosts = [];
  for (const row of replacements) {
    const { host } = parseHostPort(row.candidate);
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
  const canDelete = inactive.length && (projectedActive >= target.minActive || config.removeUnhealthyWithoutReplacement || active.length > 0 || addedHosts.length > 0);
  if (canDelete) {
    for (const item of inactive) {
      const r = await cfDeleteRecord(config, item.id);
      if (r.ok) {
        report.removed.push({ ip: item.addr, reason: item.reason });
        addReportLog(report, `  🧹 已删除失效 A ${item.host}`);
      } else {
        report.keptFailed.push({ ip: item.addr, reason: `删除失败：${cfError(r)}` });
        addReportLog(report, `  ⚠️ 删除 A ${item.host} 失败：${cfError(r)}`);
      }
    }
  } else if (inactive.length) {
    report.keptFailed.push(...inactive.map(x => ({ ip: x.addr, reason: '安全保护：没有可用替换，暂不删除全部失效记录' })));
    addReportLog(report, `🛡️ 安全保护：没有足够替换，暂不删除 ${inactive.length} 条失效 A 记录`);
  }

  report.afterActive = projectedActive;
  report.status = report.configError ? 'failed' : (projectedActive >= target.minActive ? 'success' : (projectedActive > 0 ? 'partial' : 'failed'));
  addReportLog(report, `📊 A 维护完成：${report.afterActive}/${target.minActive}，新增 ${report.added.length}，移除 ${report.removed.length}`);
  return report;
}

async function maintainTXT(env, target, poolKey, state, config) {
  const report = newReport({ ...target, mode: 'TXT' }, poolKey);
  addReportLog(report, `🚀 维护 TXT: ${target.domain}，最小活跃 ${target.minActive}`);
  let records;
  try { records = await cfListRecords(config, target.domain, 'TXT'); }
  catch (e) { report.configError = true; report.status = 'failed'; addReportLog(report, `❌ 获取 TXT 失败：${e.message}`); return report; }
  const primary = records[0] || null;
  const original = parseTXTContent(primary?.content || '');
  report.currentCount = original.length;
  if (!primary) addReportLog(report, '当前没有 TXT 记录，需要创建');
  else addReportLog(report, `当前 TXT 包含 ${original.length} 个目标`);

  const active = [];
  const inactive = [];
  if (original.length) {
    addReportLog(report, `🔎 检测当前 TXT 目标 ${original.length} 个`);
    const rows = await checkWithState(original, config, state);
    const m = resultMap(rows);
    report.checkedCount += original.length;
    for (const addr of original) {
      const row = m.get(addr) || { success: false, candidate: addr, message: '未返回检测结果' };
      updateFailState(state, addr, row, config);
      if (row.success) {
        active.push(addr);
        addReportLog(report, `  ✅ ${addr} 活跃 ${row.colo || ''} ${row.responseTime || 0}ms`);
      } else {
        inactive.push({ addr, reason: row.message || '检测失败' });
        addReportLog(report, `  ❌ ${addr} 失效：${row.message || 'success=false'}`);
      }
    }
  }
  report.beforeActive = active.length;
  const need = Math.max(0, target.minActive - active.length);
  const replacements = need > 0 ? await collectReplacementCandidates(env, poolKey, target, need, active, state, config, report) : [];
  const added = replacements.map(r => normalizeAddr(r.candidate)).filter(Boolean);
  const final = unique([...active, ...added]);
  const changed = final.join(',') !== original.join(',');

  for (const r of replacements) report.added.push({ ip: normalizeAddr(r.candidate), colo: r.colo, time: r.responseTime });
  report.removed.push(...inactive.map(x => ({ ip: x.addr, reason: x.reason })));

  if (changed) {
    if (final.length === 0 && original.length > 0 && !config.deleteEmptyTxt && !config.removeUnhealthyWithoutReplacement) {
      report.keptFailed.push(...inactive.map(x => ({ ip: x.addr, reason: '安全保护：全部失败且无替换，未清空 TXT' })));
      report.removed = [];
      addReportLog(report, '🛡️ 安全保护：全部失败且无替换，未清空 TXT');
    } else if (final.length === 0 && primary) {
      const r = await cfDeleteRecord(config, primary.id);
      if (r.ok) addReportLog(report, '🧹 TXT 已删除（最终列表为空）');
      else addReportLog(report, `⚠️ TXT 删除失败：${cfError(r)}`);
    } else if (final.length > 0) {
      const content = `"${final.join(',')}"`;
      const r = primary
        ? await cfUpdateRecord(config, primary.id, { type: 'TXT', name: target.domain, content })
        : await cfCreateRecord(config, { type: 'TXT', name: target.domain, content });
      if (r.ok) addReportLog(report, primary ? '📝 TXT 已更新' : '📝 TXT 已创建');
      else addReportLog(report, `⚠️ TXT 写入失败：${cfError(r)}`);
    }
  } else {
    addReportLog(report, '✨ TXT 无需变更');
  }

  report.afterActive = final.length;
  report.status = report.configError ? 'failed' : (final.length >= target.minActive ? 'success' : (final.length > 0 ? 'partial' : 'failed'));
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
  if (target.mode === 'A') return await maintainA(env, target, poolKey, state, config);
  if (target.mode === 'TXT') return await maintainTXT(env, target, poolKey, state, config);
  const a = await maintainA(env, { ...target, mode: 'A' }, poolKey, state, config);
  const txt = await maintainTXT(env, { ...target, mode: 'TXT' }, poolKey, state, config);
  return summarizeModeReport(target, [a, txt]);
}
async function maintainAllDomains(env, isManual, config) {
  const start = Date.now();
  const store = requireKV(env);
  const targets = config.targets || [];
  const mapping = await getMapping(env);
  const state = { cache: await loadJsonKV(env, CHECK_CACHE_KEY, {}), failCount: await loadJsonKV(env, CHECK_FAIL_KEY, {}) };
  const reports = [];
  let cursor = toInt(await store.get(MAINTAIN_CURSOR_KEY), 0, 0, Math.max(0, targets.length - 1));
  const max = Math.min(config.maintainMaxDomains, targets.length || 0);
  for (let i = 0; i < max; i++) {
    const idx = (cursor + i) % targets.length;
    const target = targets[idx];
    reports.push(await maintainTarget(env, target, mapping, state, config));
  }
  if (targets.length) await store.put(MAINTAIN_CURSOR_KEY, String((cursor + max) % targets.length));
  await saveJsonKV(env, CHECK_CACHE_KEY, state.cache);
  await saveJsonKV(env, CHECK_FAIL_KEY, state.failCount);
  const notify = isManual || reports.some(r => r.added?.length || r.removed?.length || r.status !== 'success');
  const tgStatus = notify ? await sendTelegram(reports, config, isManual) : { sent: false, reason: 'no_need' };
  return { processedTargets: reports.length, totalTargets: targets.length, nextCursor: targets.length ? (cursor + max) % targets.length : 0, reports, notified: tgStatus.sent, tgStatus, processingTime: Date.now() - start };
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
  return ok({ version: VERSION, targets: config.targets, settings: { checkConcurrency: config.checkConcurrency, checkBatchSize: config.checkBatchSize, maxCheckPerDomain: config.maxCheckPerDomain, failThreshold: config.failThreshold, removeFailedImmediately: config.removeFailedImmediately, removeUnhealthyWithoutReplacement: config.removeUnhealthyWithoutReplacement }, authEnabled: !!config.authKey });
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
  if (/^txt@/i.test(domain)) return ok({ type: 'TXT', domain: domain.replace(/^txt@/i, ''), targets: await resolveTarget(domain, config) });
  const { host, port } = parseHostPort(domain);
  return ok({ type: 'A/AAAA', domain: host, port, targets: await resolveTarget(domain, config) });
}
async function handleDomainStatus(url, env, config) {
  const domain = normalizeDomain(url.searchParams.get('domain') || '');
  if (!domain) return fail('MISSING_DOMAIN', '缺少 domain 参数');
  const [a, aaaa, txt] = await Promise.all([dohQuery(domain, 'A', config), dohQuery(domain, 'AAAA', config), dohQuery(domain, 'TXT', config)]);
  let mapping = {}; try { mapping = await getMapping(env); } catch {}
  return ok({ domain, A: a.filter(x => x.type === 1).map(x => x.data), AAAA: aaaa.filter(x => x.type === 28).map(x => x.data), TXT: txt.filter(x => x.type === 16).map(x => x.data), pool: mapping[domain] || '' });
}
async function handleCurrentStatus(url, config) {
  const idx = toInt(url.searchParams.get('target'), 0, 0, Math.max(0, config.targets.length - 1));
  const target = config.targets[idx];
  if (!target) return fail('NO_TARGET', '未配置目标域名');
  const [a, txt] = await Promise.all([
    target.mode !== 'TXT' ? cfListRecords(config, target.domain, 'A').catch(e => ({ error: e.message })) : [],
    target.mode !== 'A' ? cfListRecords(config, target.domain, 'TXT').catch(e => ({ error: e.message })) : [],
  ]);
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
  const body = await readJson(request);
  if (!body?.url) return fail('MISSING_URL', '缺少 URL');
  let u; try { u = new URL(body.url); } catch { return fail('BAD_URL', 'URL 无效'); }
  if (!['http:', 'https:'].includes(u.protocol)) return fail('BAD_URL', '仅支持 http/https');
  const res = await fetchWithTimeout(u.toString(), { headers: { 'User-Agent': 'DDNS-Pro/12' } }, config.remoteTimeout);
  if (!res.ok) return fail('REMOTE_FAILED', `远程加载失败 HTTP ${res.status}`, 502);
  const text = (await res.text()).slice(0, config.maxRemoteBytes);
  const port = String(body.port || body.defaultPort || '443');
  const country = String(body.cfCountry || body.country || '').trim().toUpperCase();
  const lines = extractRemoteTargets(text, { port, country, format: body.format || 'auto' });
  return ok({ ips: lines.join('\n'), count: lines.length });
}
function extractRemoteTargets(text, options) {
  const format = String(options.format || 'auto').toLowerCase();
  if (format === 'csv' || (format === 'auto' && text.includes(',') && /ip|address|端口|port|colo|country/i.test(text.split(/\r?\n/)[0] || ''))) return extractCsvTargets(text, options);
  const regex = /(\[[0-9a-fA-F:]+\]|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{2,}\b)(?::(\d{1,5}))?/g;
  const out = [];
  let m;
  while ((m = regex.exec(text))) {
    const host = stripBrackets(m[1]);
    if (!isIPv4(host) && !isIPv6(host)) continue;
    out.push(formatHostPort(host, m[2] || options.port || '443'));
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
function extractCsvTargets(text, options) {
  const rows = text.split(/\r?\n/).filter(Boolean).map(parseCsvLine);
  if (!rows.length) return [];
  const header = rows[0].map(h => h.toLowerCase());
  const ipIdx = header.findIndex(h => /^(ip|addr|address|proxyip|host)$/.test(h));
  const portIdx = header.findIndex(h => /port|端口/.test(h));
  const countryIdx = header.findIndex(h => /country|cfcolo|colo|国家|地区/.test(h));
  const dataRows = ipIdx >= 0 ? rows.slice(1) : rows;
  const out = [];
  for (const row of dataRows) {
    if (options.country && countryIdx >= 0 && String(row[countryIdx] || '').toUpperCase() !== options.country) continue;
    const host = stripBrackets(row[ipIdx >= 0 ? ipIdx : 0] || '');
    if (!isIPv4(host) && !isIPv6(host)) continue;
    out.push(formatHostPort(host, row[portIdx] || options.port || '443'));
  }
  return unique(out);
}
async function handleAddRecord(request, config) {
  const body = await readJson(request);
  const target = config.targets[toInt(body?.targetIndex, 0, 0, Math.max(0, config.targets.length - 1))];
  if (!target) return fail('NO_TARGET', '未配置目标域名');
  const addr = normalizeAddr(body?.ip || '', target.port);
  if (!addr) return fail('MISSING_IP', '缺少 IP');
  const { host } = parseHostPort(addr);
  if (target.mode === 'TXT') {
    const records = await cfListRecords(config, target.domain, 'TXT');
    const primary = records[0] || null;
    const list = primary ? parseTXTContent(primary.content) : [];
    if (!list.includes(addr)) list.push(addr);
    const content = `"${list.join(',')}"`;
    const r = primary ? await cfUpdateRecord(config, primary.id, { type: 'TXT', name: target.domain, content }) : await cfCreateRecord(config, { type: 'TXT', name: target.domain, content });
    return r.ok ? ok({ added: addr, mode: 'TXT' }) : fail('CF_ERROR', cfError(r), 502, r);
  }
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

const ROUTES = {
  '/api/version': (url, req, env, config) => handleVersion(env, config),
  '/api/health': (url, req, env, config) => handleHealth(env, config),
  '/api/config': (url, req, env, config) => handleConfig(env, config),
  '/api/auth/me': () => ok({ authenticated: true }),
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
const POST_ONLY = new Set(['/api/save-pool','/api/create-pool','/api/delete-pool','/api/clear-trash','/api/restore-from-trash','/api/load-remote-url','/api/resolve-batch','/api/check','/api/save-domain-pool-mapping','/api/add-a-record','/api/delete-record','/api/maintain']);
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
    if (url.pathname === '/') return handleHome(request, config);
    if (url.pathname === '/login') return handleLogin(request, config);
    if (url.pathname === '/logout') return new Response('退出成功', { status: 302, headers: { Location: '/login', 'Set-Cookie': 'ddns_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict' } });

    const needsAuth = url.pathname.startsWith('/api/') || url.pathname === '/admin' || url.pathname.startsWith('/admin/');
    if (needsAuth) {
      const auth = await checkAuth(request, url, config);
      if (auth.enabled && !auth.ok) {
        if (url.pathname.startsWith('/api/')) return withCors(fail('UNAUTHORIZED', '未登录或登录已过期', 401), request, env, config);
        return Response.redirect(url.origin + '/login', 302);
      }
      const response = url.pathname.startsWith('/api/') ? await handleApi(request, env, config) : await serveAsset(request, env, config);
      const headers = new Headers(response.headers);
      if (auth.setCookie) headers.set('Set-Cookie', authCookie(auth.token));
      return withCors(new Response(response.body, { status: response.status, statusText: response.statusText, headers }), request, env, config);
    }

    return new Response('Not Found', { status: 404 });
  },
  async scheduled(event, env, ctx) {
    const config = createConfig(env);
    ctx.waitUntil(maintainAllDomains(env, false, config).catch(e => console.error('scheduled maintain failed', e)));
  }
};
