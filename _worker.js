/**
 * DDNS Pro & Proxy IP Manager v8.1 Resource Optimized
 */

// ==================== 默认配置（环境变量未设置时使用） ====================
const DEFAULT_CONFIG = {
    // 目标维护域名的Cloudflare 配置
    apiKey: '',              // CF_KEY: Cloudflare API Token
    zoneId: '',              // CF_ZONEID: Cloudflare Zone ID
    
    // 目标维护域名的配置
    targets: [],             // CF_DOMAIN: 域名配置（解析后的目标列表）
    
    // Telegram 通知配置
    tgToken: '',             // TG_TOKEN: Telegram Bot Token
    tgId: '',                // TG_ID: Telegram Chat ID
    
    // 检测 API 配置
    checkApi: 'https://cf.090227.xyz/check?proxyip=',  // CHECK_API: 主 ProxyIP 检测接口
    checkApiToken: '',       // CHECK_API_TOKEN: 检测接口认证Token
    checkApiBackup: 'https://api.090227.xyz/check?proxyip=',      // CHECK_API_BACKUP: 备用 ProxyIP 检测接口
    checkApiBackupToken: '', // CHECK_API_BACKUP_TOKEN: 备用检测接口认证Token
    
    // DNS 配置
    dohApi: 'https://cloudflare-dns.com/dns-query',  // DOH_API: DNS over HTTPS 接口
    
    // IP 归属地查询配置
    ipInfoEnabled: false,    // IP_INFO_ENABLED: 是否启用IP归属地查询
    ipInfoApi: 'http://ip-api.com/json',  // IP_INFO_API: IP归属地查询接口
    
    // 访问控制配置
    authKey: '',             // AUTH_KEY: 面板访问密钥
    
    // 运行时配置（非环境变量）
    projectUrl: ''           // 项目URL（自动获取）
};
// ==================== 默认配置结束 ====================

const GLOBAL_SETTINGS = {
    // ── IP 检测 ──
    CONCURRENT_CHECKS: 2,        // 维护任务推荐低并发；前端批量检测也不宜过高
    CHECK_TIMEOUT: 5000,         // 单次 ProxyIP 检测超时(ms)
    MAX_CHECK_PER_DOMAIN: 10,    // 每个域名单轮最多检测多少个候选，够用即停
    CHECK_CACHE_TTL_MINUTES: 360,// success=true 结果缓存分钟数，减少外部检测请求
    CHECK_FAIL_THRESHOLD: 3,     // 连续失败多少次后才移入垃圾桶
    REMOVE_FAILED_IMMEDIATELY: false,

    // ── 网络超时 ──
    REMOTE_LOAD_TIMEOUT: 5000,   // 远程 URL 加载超时(ms)
    IP_INFO_TIMEOUT: 3000,       // IP 归属地查询超时(ms)
    DOH_TIMEOUT: 5000,           // DNS over HTTPS 查询超时(ms)

    // ── 数据限制 ──
    DEFAULT_MIN_ACTIVE: 3,       // 默认最小活跃 IP 数
    MAX_TRASH_SIZE: 1000,        // 垃圾桶最大条目数
    MAX_POOL_NAME_LENGTH: 50,    // IP池名称最大长度
    MAX_IPS_PER_DOMAIN: 50,      // 域名解析最多取多少个 IP
};

function safeJSONParse(str, defaultValue = null) {
    try { return str ? JSON.parse(str) : defaultValue; }
    catch { return defaultValue; }
}

const parsePoolList = raw => (raw || '').split('\n').filter(l => l.trim());

const parseTXTContent = content => content ? content.replace(/^"|"$/g, '').split(',').map(ip => ip.trim()).filter(Boolean) : [];

const extractIPKey = line => {
    if (!line) return '';
    const idx = line.indexOf('#');
    return idx >= 0 ? line.substring(0, idx).trim() : line.trim();
};

function splitComment(line) {
    if (!line) return { main: '', comment: '' };
    const idx = line.indexOf('#');
    if (idx >= 0) return { main: line.substring(0, idx).trim(), comment: line.substring(idx) };
    return { main: line.trim(), comment: '' };
}

const POOL_DISPLAY_NAMES = { pool: '通用池', pool_trash: '🗑️ 垃圾桶', domain_pool_mapping: '系统数据' };
const getPoolDisplayName = poolKey => POOL_DISPLAY_NAMES[poolKey] || poolKey.replace('pool_', '') + '池';

const formatLogMessage = msg => `[${new Date().toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' })}] ${msg}`;

const JSON_CONTENT_TYPE = 'application/json; charset=UTF-8';
const CF_ERROR_MSG = 'CF配置错误或API调用失败';
const DEFAULT_ADMIN_ORIGIN = 'https://mlyo.github.io';

function getKVBinding(env) {
    const candidates = [
        ['IP_DATA', env.IP_DATA],
        ['KV', env.KV],
        ['IPDATA', env.IPDATA],
        ['KV_DATA', env.KV_DATA],
    ];
    for (const [name, store] of candidates) {
        if (store && typeof store.get === 'function' && typeof store.put === 'function') {
            return { name, store };
        }
    }
    return { name: 'missing', store: null };
}

function getKV(env) {
    return getKVBinding(env).store;
}

function hasKV(env) {
    return !!getKV(env);
}

function requireKV(env) {
    const { store } = getKVBinding(env);
    if (!store) {
        throw new Error('KV 未绑定：请在 Worker 变量/绑定中绑定 KV Namespace，推荐变量名 IP_DATA。');
    }
    return store;
}

function getAdminOrigin(env) {
    return (env.ADMIN_ORIGIN || DEFAULT_ADMIN_ORIGIN).replace(/\/$/, '');
}

function getAllowedOrigins(env) {
    const raw = (env.ALLOWED_ORIGINS || '').trim();
    if (!raw) return [getAdminOrigin(env)];
    return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function getCorsOrigin(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = getAllowedOrigins(env);
    if (!origin) return '';
    if (allowed.includes('*')) return '*';
    return allowed.includes(origin) ? origin : '';
}

function corsPreflight(request, env) {
    const origin = getCorsOrigin(request, env);
    const headers = new Headers();
    if (origin) {
        headers.set('Access-Control-Allow-Origin', origin);
        headers.set('Vary', 'Origin');
    }
    headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Key');
    headers.set('Access-Control-Max-Age', '86400');
    return new Response(null, { status: 204, headers });
}

function withCors(response, request, env) {
    const origin = getCorsOrigin(request, env);
    const headers = new Headers(response.headers);
    if (origin) {
        headers.set('Access-Control-Allow-Origin', origin);
        headers.set('Vary', 'Origin');
    }
    headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Key');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function jsonResponse(data, status = 200, extraHeaders = undefined) {
    const headers = new Headers({ 'Content-Type': JSON_CONTENT_TYPE });
    if (extraHeaders) {
        const h = extraHeaders instanceof Headers ? extraHeaders : new Headers(extraHeaders);
        h.forEach((v, k) => headers.set(k, v));
    }
    return new Response(JSON.stringify(data), { status, headers });
}

const badRequest = data => jsonResponse(data, 400);
const serverError = data => jsonResponse(data, 500);
const readJsonBody = async req => { try { return await req.json(); } catch { return null; } };

function parseCookieHeader(cookieHeader) {
    const out = {};
    if (!cookieHeader) return out;
    cookieHeader.split(';').forEach(part => {
        const idx = part.indexOf('=');
        if (idx === -1) return;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (k) { try { out[k] = decodeURIComponent(v); } catch { out[k] = v; } }
    });
    return out;
}

function getAuthCandidateFromRequest(request, url) {
    const authHeader = request.headers.get('Authorization') ?? '';
    const bearer = authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : '';
    const xAuth = (request.headers.get('X-Auth-Key') ?? '').trim();
    const qKey = (url.searchParams.get('key') ?? '').trim();
    const cookies = parseCookieHeader(request.headers.get('Cookie') ?? '');
    const cKey = (cookies.ddns_auth ?? '').trim();
    return { bearer, xAuth, qKey, cKey };
}

async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function getSessionSecret(env) {
    return (env.SESSION_SECRET || env.AUTH_SECRET || env.AUTH_KEY || '').trim();
}

async function createSessionToken(request, env) {
    const requiredKey = (env.AUTH_KEY || '').trim();
    const userAgent = request.headers.get('User-Agent') || '';
    return await sha256Hex(`${requiredKey}:${userAgent}:${getSessionSecret(env)}`);
}

async function checkRequestAuth(request, url, env) {
    const requiredKey = (env.AUTH_KEY || '').trim();
    if (!requiredKey) {
        return { enabled: false, ok: true, shouldSetCookie: false };
    }

    const { bearer, xAuth, qKey, cKey } = getAuthCandidateFromRequest(request, url);
    const sessionToken = await createSessionToken(request, env);
    const directOk = bearer === requiredKey || xAuth === requiredKey || qKey === requiredKey;
    const cookieOk = cKey === sessionToken || cKey === requiredKey;
    const ok = directOk || cookieOk;
    const shouldSetCookie = ok && (directOk || cKey === requiredKey || cKey !== sessionToken);
    return { enabled: true, ok, shouldSetCookie };
}

function unauthorizedResponse(url) {
    const isApi = url.pathname.startsWith('/api/');
    if (isApi) {
        return jsonResponse({
            success: false,
            error: {
                code: 'UNAUTHORIZED',
                message: '未登录或登录已过期'
            }
        }, 401);
    }
    // 页面：给出最小可理解指引
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DDNS Pro - 未授权</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b0b0f;color:#eaeaf2;margin:0;padding:40px}
    .card{max-width:760px;margin:0 auto;background:#151523;border:1px solid #2a2a40;border-radius:16px;padding:24px}
    code{background:#0f0f1a;padding:2px 6px;border-radius:8px}
    a{color:#7aa2ff}
  </style>
</head>
<body>
  <div class="card">
    <h2>未授权</h2>
    <p>该面板已开启访问保护（配置了 <code>AUTH_KEY</code>）。</p>
    <p>打开方式示例：<code>/?key=你的AUTH_KEY</code>（首次访问会写入 Cookie，后续可直接打开）。</p>
  </div>
</body>
</html>`;
    return new Response(html, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}


function htmlNginxPage(hostname = '') {
    return `<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

async function handleHomePage(request, env) {
    const url = new URL(request.url);
    const mode = (env.HOME_MODE || 'nginx').toLowerCase();
    if (mode === 'blank') return new Response('', { status: 204, headers: { 'Cache-Control': 'no-store' } });
    if (mode === '404') return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Cache-Control': 'no-store' } });
    if (mode === 'redirect' && env.HOME_URL) return Response.redirect(env.HOME_URL, 302);
    if (mode === 'proxy' && env.HOME_URL) {
        try {
            const target = new URL(env.HOME_URL);
            const headers = new Headers(request.headers);
            headers.set('Host', target.host);
            return await fetch(target.origin + url.pathname + url.search, { method: request.method, headers, body: request.body });
        } catch (e) {}
    }
    return new Response(htmlNginxPage(url.hostname), { status: 200, headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' } });
}

function htmlLoginPage() {
    return new Response(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>DDNS Pro - Login</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    .card{width:min(420px,calc(100vw - 32px));background:#111827;border:1px solid #334155;border-radius:18px;padding:24px;box-shadow:0 16px 48px rgba(0,0,0,.28)}
    h1{margin:0 0 8px;font-size:24px}.hint{color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 18px}
    input{width:100%;box-sizing:border-box;border:1px solid #475569;border-radius:12px;background:#020617;color:#e5e7eb;padding:12px 14px;outline:none}
    button{margin-top:12px;width:100%;border:0;border-radius:12px;background:#2563eb;color:white;font-weight:700;padding:12px 14px;cursor:pointer}
    .err{color:#fca5a5;min-height:20px;margin-top:12px;font-size:14px}
  </style>
</head>
<body>
  <form class="card" id="form">
    <h1>DDNS Pro</h1>
    <p class="hint">输入 Worker 环境变量 AUTH_KEY，登录后进入 /admin/。</p>
    <input id="password" name="password" type="password" placeholder="AUTH_KEY" autofocus />
    <button type="submit">登录</button>
    <div class="err" id="err"></div>
  </form>
<script>
  document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('password').value;
    const err = document.getElementById('err');
    err.textContent = '';
    const res = await fetch('/login', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({ password }) });
    if (res.ok) location.href = '/admin/';
    else err.textContent = '登录失败，请检查 AUTH_KEY';
  });
</script>
</body>
</html>`, { status: 200, headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' } });
}

async function handleLogin(request, env) {
    const requiredKey = (env.AUTH_KEY || '').trim();
    if (!requiredKey) {
        return new Response('AUTH_KEY 未配置', { status: 500, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
    }
    if (request.method === 'POST') {
        let password = '';
        const contentType = request.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
            const body = await readJsonBody(request);
            password = (body?.password || body?.key || '').trim();
        } else {
            const text = await request.text();
            password = (new URLSearchParams(text).get('password') || '').trim();
        }
        if (password === requiredKey) {
            const headers = new Headers({ 'Content-Type': 'application/json;charset=UTF-8' });
            const token = await createSessionToken(request, env);
            headers.set('Set-Cookie', `ddns_auth=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
            return new Response(JSON.stringify({ success: true, data: { redirect: '/admin/' } }), { status: 200, headers });
        }
        return jsonResponse({ success: false, error: 'AUTH_KEY 错误' }, 401);
    }

    try {
        const upstream = await fetch(getAdminOrigin(env) + '/login.html', { cf: { cacheTtl: 60 } });
        if (upstream.ok) {
            const headers = new Headers(upstream.headers);
            headers.set('Cache-Control', 'no-store');
            return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers });
        }
    } catch {}
    return htmlLoginPage();
}

function redirect(location, headers = {}) {
    return new Response('重定向中...', { status: 302, headers: { Location: location, ...headers } });
}

async function handleAdminAssets(request, env) {
    const url = new URL(request.url);
    const origin = getAdminOrigin(env);
    let assetPath = url.pathname.replace(/^\/admin\/?/, '/');
    if (!assetPath || assetPath === '/') assetPath = '/admin.html';

    let upstream = await fetch(origin + assetPath + url.search, {
        headers: { 'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0' },
        cf: { cacheTtl: assetPath === '/admin.html' ? 0 : 300 }
    });

    if (upstream.status === 404 && !assetPath.includes('.')) {
        upstream = await fetch(origin + '/admin.html', { cf: { cacheTtl: 0 } });
    }

    const headers = new Headers(upstream.headers);
    if (assetPath === '/admin.html') headers.set('Cache-Control', 'no-store');
    else headers.set('Cache-Control', 'public, max-age=300');
    headers.delete('Content-Security-Policy');
    headers.delete('X-Frame-Options');

    return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers
    });
}

export default {
    async fetch(request, env, ctx) {
        const requestStart = Date.now();
        const config = createConfig(env, request);
        const url = new URL(request.url);

        if (request.method === 'OPTIONS') {
            return corsPreflight(request, env);
        }

        const buildAuthCookie = async () => `ddns_auth=${encodeURIComponent(await createSessionToken(request, env))}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;

        if (url.protocol === 'http:') {
            return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
        }

        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        if (url.pathname === '/robots.txt') {
            return new Response('User-agent: *\nDisallow: /\n', { status: 200, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        }

        if (url.pathname === '/') {
            return await handleHomePage(request, env);
        }

        if (url.pathname === '/logout') {
            return redirect('/login', { 'Set-Cookie': 'ddns_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict' });
        }

        if (url.pathname === '/login') {
            return await handleLogin(request, env);
        }

        const isAdminPath = url.pathname === '/admin' || url.pathname.startsWith('/admin/');
        const isApiPath = url.pathname.startsWith('/api/');

        const auth = await checkRequestAuth(request, url, env);

        if (isAdminPath) {
            if (auth.enabled && !auth.ok) return redirect('/login');
            const adminResponse = await handleAdminAssets(request, env);
            if (auth.shouldSetCookie) {
                const headers = new Headers(adminResponse.headers);
                headers.set('Set-Cookie', await buildAuthCookie());
                return new Response(adminResponse.body, { status: adminResponse.status, statusText: adminResponse.statusText, headers });
            }
            return adminResponse;
        }

        if (!isApiPath) {
            return jsonResponse({ success: false, error: 'Not Found', message: '请访问 /admin/ 或 /api/*' }, 404);
        }

        if (auth.enabled && !auth.ok) {
            return withCors(unauthorizedResponse(url), request, env);
        }

        try {
            const apiStart = Date.now();
            const response = await handleAPIRequest(url, request, env, config);
            console.log(`🔧 API请求 ${url.pathname} 处理耗时: ${Date.now() - apiStart}ms`);

            // 添加性能头信息
            const headers = new Headers(response.headers);
            headers.set('X-Processing-Time', `${Date.now() - requestStart}ms`);
            if (url.pathname.startsWith('/api/') && !headers.has('Content-Type')) {
                headers.set('Content-Type', 'application/json; charset=UTF-8');
            }
            // API 响应不缓存，确保数据实时性
            if (url.pathname.startsWith('/api/')) {
                headers.set('Cache-Control', 'no-store');
            }
            if (auth.shouldSetCookie) {
                headers.set('Set-Cookie', await buildAuthCookie());
            }

            return withCors(new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers
            }), request, env);
        } catch (e) {
            console.error(`❌ 请求处理失败 ${url.pathname}:`, e);
            return withCors(serverError({
                error: '内部服务器错误',
                message: '请稍后重试'
            }), request, env);
        }
    },

    async scheduled(event, env, ctx) {
        console.log('⏰ 定时任务开始执行');
        const startTime = Date.now();

        try {
            const config = createConfig(env);
            ctx.waitUntil((async () => {
                await scheduledMaintainWithConditionalRemoteUpdate(env, config);
                console.log(`✅ 定时任务完成，总耗时: ${Date.now() - startTime}ms`);
            })());
        } catch (e) {
            console.error('❌ 定时任务失败:', e);
        }
    }
};

const API_ROUTES = {
    '/api/version': (url, req, env, config) => handleVersion(env, config),
    '/api/health': (url, req, env, config) => handleHealth(env, config),
    '/api/auth/me': (url, req, env, config) => jsonResponse({ success: true, data: { authenticated: true } }),
    '/api/pools': (url, req, env, config) => handleListPools(env),
    '/api/pool': (url, req, env, config) => req.method === 'GET' ? handleGetPool(url, env) : handleSavePool(req, env, config),
    '/api/get-pool': (url, req, env, config) => handleGetPool(url, env),
    '/api/save-pool': (url, req, env, config) => handleSavePool(req, env, config),
    '/api/load-remote-url': (url, req, env, config) => handleLoadRemoteUrl(req),
    '/api/current-status': (url, req, env, config) => handleCurrentStatus(url, config),
    '/api/lookup-domain': (url, req, env, config) => handleLookupDomain(url, config),
    '/api/check-ip': (url, req, env, config) => handleCheckIP(url, config),
    '/api/check': (url, req, env, config) => handleCheckBatch(req, env, config),
    '/api/resolve': (url, req, env, config) => handleResolve(url, config),
    '/api/resolve-batch': (url, req, env, config) => handleResolveBatch(req, config),
    '/api/domain/status': (url, req, env, config) => handleDomainDnsStatus(url, env, config),
    '/api/ip-info': (url, req, env, config) => handleIPInfo(url, config),
    '/api/delete-record': (url, req, env, config) => handleDeleteRecord(url, config),
    '/api/add-a-record': (url, req, env, config) => handleAddARecord(req, config),
    '/api/maintain': (url, req, env, config) => handleMaintain(url, env, config),
    '/api/get-domain-pool-mapping': (url, req, env, config) => handleGetDomainPoolMapping(env),
    '/api/save-domain-pool-mapping': (url, req, env, config) => handleSaveDomainPoolMapping(req, env),
    '/api/create-pool': (url, req, env, config) => handleCreatePool(req, env),
    '/api/delete-pool': (url, req, env, config) => handleDeletePool(url, env),
    '/api/clear-trash': (url, req, env, config) => handleClearTrash(env),
    '/api/restore-from-trash': (url, req, env, config) => handleRestoreFromTrash(req, env)
};

const POST_ONLY_ROUTES = new Set([
    '/api/save-pool', '/api/load-remote-url', '/api/add-a-record',
    '/api/save-domain-pool-mapping', '/api/create-pool', '/api/clear-trash',
    '/api/restore-from-trash',
    '/api/delete-record',
    '/api/delete-pool', 
    '/api/maintain', '/api/check', '/api/resolve-batch'
]);

async function handleAPIRequest(url, request, env, config) {
    if (POST_ONLY_ROUTES.has(url.pathname) && request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    const handler = API_ROUTES[url.pathname];
    return handler ? await handler(url, request, env, config) : new Response('Not Found', { status: 404 });
}

function handleVersion(env, config) {
    return jsonResponse({
        success: true,
        data: {
            name: 'DDNS Pro',
            version: '8.1-resource-optimized',
            homeMode: (env.HOME_MODE || 'nginx'),
            authEnabled: !!(env.AUTH_KEY || '').trim(),
            hasKv: hasKV(env)
        }
    });
}

async function handleHealth(env, config) {
    let kv = false;
    let kvBinding = 'missing';
    try {
        const binding = getKVBinding(env);
        const store = binding.store;
        kvBinding = binding.name;
        if (store && typeof store.get === 'function') {
            // 不传 cacheTtl，避免部分 Workers KV 环境因 cacheTtl 参数限制导致误判异常。
            await store.get('pool');
            kv = true;
        }
    } catch (e) {
        kvBinding = e?.message || 'error';
    }
    return jsonResponse({
        success: true,
        data: {
            ok: true,
            kv,
            kvBinding,
            auth: !!(env.AUTH_KEY || '').trim(),
            targets: Array.isArray(config.targets) ? config.targets.length : 0,
            timestamp: new Date().toISOString()
        }
    });
}


function normalizePoolKey(input, fallback = 'pool') {
    let name = String(input || '').trim();
    if (!name) return fallback;
    if (name === 'pool' || name === 'pool_trash') return name;
    name = name.replace(/[^\u4e00-\u9fa5a-zA-Z0-9_-]/g, '_');
    return name.startsWith('pool_') ? name : `pool_${name}`;
}

async function handleListPools(env) {
    const store = requireKV(env);
    const listed = await store.list({ prefix: 'pool' });
    const set = new Set(['pool', 'pool_trash']);
    for (const item of listed.keys || []) {
        if (item.name === 'pool' || item.name === 'pool_trash' || item.name.startsWith('pool_')) set.add(item.name);
    }
    const pools = Array.from(set).sort((a, b) => {
        const order = { pool: 0, pool_trash: 2 };
        return (order[a] ?? 1) - (order[b] ?? 1) || a.localeCompare(b, 'zh-CN');
    });
    return jsonResponse({ success: true, data: { pools, defaultPool: 'pool' } });
}

async function handleResolve(url, config) {
    const target = url.searchParams.get('target') || url.searchParams.get('proxyip') || url.searchParams.get('domain');
    if (!target) return badRequest({ success: false, error: { code: 'MISSING_TARGET', message: '缺少 target 参数' } });
    const targets = await resolveTarget(target, config);
    return jsonResponse({ success: true, data: { input: target, targets } });
}

async function handleResolveBatch(request, config) {
    const body = await readJsonBody(request);
    if (!body) return badRequest({ success: false, error: { code: 'INVALID_JSON', message: '请求体不是有效 JSON' } });
    const inputs = normalizeTargetInput(body.targets || body.proxyips || body.text || '');
    if (!inputs.length) return badRequest({ success: false, error: { code: 'MISSING_TARGETS', message: '缺少 targets' } });
    if (inputs.length > 50) return badRequest({ success: false, error: { code: 'TOO_MANY_TARGETS', message: '一次最多解析 50 条' } });
    const results = await Promise.all(inputs.map(async input => {
        try { return { input, targets: await resolveTarget(input, config) }; }
        catch (e) { return { input, targets: [], error: e.message || '解析失败' }; }
    }));
    return jsonResponse({ success: true, data: { results } });
}

async function handleCheckBatch(request, env, config) {
    const body = await readJsonBody(request);
    if (!body) return badRequest({ success: false, error: { code: 'INVALID_JSON', message: '请求体不是有效 JSON' } });
    const inputs = normalizeTargetInput(body.targets || body.text || body.ip || '');
    if (!inputs.length) return badRequest({ success: false, error: { code: 'MISSING_TARGETS', message: '缺少检测目标' } });
    if (inputs.length > 50) return badRequest({ success: false, error: { code: 'TOO_MANY_TARGETS', message: '一次最多检测 50 条' } });

    const shouldResolve = body.resolve !== false;
    const useBackupOnly = body.useBackup === true;
    const candidates = [];
    const resolved = [];
    for (const input of inputs) {
        try {
            const targets = shouldResolve ? await resolveTarget(input, config) : [normalizeCheckAddr(input)];
            resolved.push({ input, targets });
            for (const target of targets) if (!candidates.includes(target)) candidates.push(target);
        } catch (e) {
            resolved.push({ input, targets: [], error: e.message || '解析失败' });
        }
    }

    const results = [];
    for (const candidate of candidates.slice(0, 80)) {
        const result = useBackupOnly && config.checkApiBackup
            ? await checkProxyIPOnce(normalizeCheckAddr(candidate), config.checkApiBackup, config.checkApiBackupToken, 'backup')
            : await checkProxyIP(candidate, config);
        results.push(toLightCheckResult(result, candidate));
    }
    return jsonResponse({ success: true, data: { resolved, results, successCount: results.filter(r => r.success).length } });
}

async function handleDomainDnsStatus(url, env, config) {
    const domain = (url.searchParams.get('domain') || '').trim();
    if (!domain) return badRequest({ success: false, error: { code: 'MISSING_DOMAIN', message: '缺少 domain 参数' } });
    const clean = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const [a, aaaa, txt] = await Promise.all([dohQuery(clean, 'A', config), dohQuery(clean, 'AAAA', config), dohQuery(clean, 'TXT', config)]);
    let mapping = {};
    try { mapping = safeJSONParse(await requireKV(env).get('domain_pool_mapping') || '{}', {}); } catch {}
    return jsonResponse({ success: true, data: {
        domain: clean,
        A: a.filter(x => x.type === 1).map(x => x.data),
        AAAA: aaaa.filter(x => x.type === 28).map(x => x.data),
        TXT: txt.filter(x => x.type === 16).map(x => normalizeTxtValue(x.data)),
        pool: mapping[clean] || mapping[domain] || ''
    } });
}

function normalizeTargetInput(value) {
    const arr = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/);
    const seen = new Set();
    const out = [];
    for (const item of arr) {
        const v = String(item || '').split('#')[0].trim();
        if (!v || seen.has(v)) continue;
        seen.add(v); out.push(v);
    }
    return out;
}

function normalizeTxtValue(value) {
    const text = String(value ?? '').trim();
    if (text.startsWith('"') && text.endsWith('"')) return text.slice(1, -1).replace(/\\"/g, '"');
    return text.replace(/\\"/g, '"');
}

function parseResolveTarget(input) {
    let host = String(input || '').split('#')[0].trim();
    let port = 443;
    if (!host) return { host: '', port };
    if (host.startsWith('[')) {
        const idx = host.lastIndexOf(']:');
        if (idx !== -1) {
            const p = Number(host.slice(idx + 2));
            if (Number.isInteger(p) && p >= 1 && p <= 65535) { port = p; host = host.slice(0, idx + 1); }
        }
        return { host, port };
    }
    const colonCount = (host.match(/:/g) || []).length;
    if (colonCount === 1) {
        const idx = host.lastIndexOf(':');
        const p = Number(host.slice(idx + 1));
        if (Number.isInteger(p) && p >= 1 && p <= 65535) { port = p; host = host.slice(0, idx); }
    }
    const tp = host.toLowerCase().match(/\.tp(\d{1,5})\./);
    if (tp) {
        const p = Number(tp[1]);
        if (p >= 1 && p <= 65535) port = p;
    }
    return { host, port };
}

function isIPv4Literal(value) {
    const parts = String(value || '').split('.');
    return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6Literal(value) {
    const v = String(value || '').replace(/^\[|\]$/g, '');
    return v.includes(':') && /^[0-9a-fA-F:]+$/.test(v);
}

async function dohQuery(name, type, config) {
    try {
        const endpoint = config?.dohApi || DEFAULT_CONFIG.dohApi;
        const r = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
            headers: { accept: 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        if (!r.ok) return [];
        const data = await r.json();
        return Array.isArray(data.Answer) ? data.Answer : [];
    } catch { return []; }
}

async function resolveTarget(input, config) {
    let { host, port } = parseResolveTarget(input);
    if (!host) return [];
    const bracketedIPv6 = host.startsWith('[') && host.endsWith(']');
    if (isIPv4Literal(host)) return [`${host}:${port}`];
    if (bracketedIPv6 || isIPv6Literal(host)) {
        const clean = host.replace(/^\[|\]$/g, '');
        return [`[${clean}]:${port}`];
    }
    if (host.toLowerCase().includes('.william.') || host.toLowerCase().startsWith('txt@')) {
        const txtHost = host.toLowerCase().startsWith('txt@') ? host.slice(4) : host;
        const txtAnswers = await dohQuery(txtHost, 'TXT', config);
        const targets = [];
        for (const record of txtAnswers) {
            const value = normalizeTxtValue(record.data);
            for (const part of value.split(',')) {
                const candidate = part.trim();
                if (candidate) targets.push(normalizeCheckAddr(candidate));
            }
        }
        if (targets.length) return Array.from(new Set(targets));
    }
    const [a, aaaa] = await Promise.all([dohQuery(host, 'A', config), dohQuery(host, 'AAAA', config)]);
    const out = [];
    for (const record of a) if (record.type === 1 && record.data) out.push(`${record.data}:${port}`);
    for (const record of aaaa) if (record.type === 28 && record.data) out.push(`[${record.data}]:${port}`);
    if (!out.length) throw new Error('域名没有解析到 A/AAAA 记录');
    return Array.from(new Set(out));
}

function toLightCheckResult(result, fallbackCandidate = '') {
    const r = result || buildCheckFailure(fallbackCandidate);
    return {
        candidate: r.candidate || fallbackCandidate,
        success: r.success === true,
        source: r.source || 'main',
        ip: r.ip || r.proxyIP || '',
        ipType: r.ipType || (String(r.proxyIP || r.ip || '').includes(':') ? 'ipv6' : 'ipv4'),
        proxyIP: r.proxyIP || r.ip || '',
        portRemote: r.portRemote || 443,
        colo: r.colo || '',
        asn: r.asn ?? null,
        asOrganization: r.asOrganization || r.org || '',
        country: r.country || '',
        region: r.region || r.regionCode || '',
        city: r.city || '',
        responseTime: r.responseTime || 0,
        message: r.message || ''
    };
}

async function handleGetPool(url, env) {

    const poolKey = normalizePoolKey(url.searchParams.get('poolKey') || url.searchParams.get('name') || 'pool');
    const onlyCount = url.searchParams.get('onlyCount') === 'true';
    
    const pool = await requireKV(env).get(poolKey) || '';
    const count = pool.trim() ? pool.trim().split('\n').length : 0;
    
    if (onlyCount) {
        return jsonResponse({ count });
    }
    return jsonResponse({ pool, count });
}

async function handleSavePool(request, env, config) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const poolKey = normalizePoolKey(body.poolKey || body.name || 'pool');
    const mode = body.mode || 'append'; // append: 追加, replace: 覆盖, remove: 删除
    const newIPs = await cleanIPListAsync(body.pool || '', false, config);

    if (!newIPs && mode !== 'remove') {
        return badRequest({ success: false, error: '没有有效IP' });
    }

    const existingPool = await requireKV(env).get(poolKey) || '';
    const existingMap = new Map();

    // 先加载现有IP
    parsePoolList(existingPool).forEach(line => {
        const key = extractIPKey(line);
        if (key) existingMap.set(key, line);
    });

    const existingCount = existingMap.size;
    let responseData;

    if (mode === 'replace') {
        // 覆盖模式：清空现有，只保留新IP
        existingMap.clear();
        parsePoolList(newIPs).forEach(line => {
            const key = extractIPKey(line);
            if (key) existingMap.set(key, line);
        });

        responseData = {
            success: true,
            count: existingMap.size,
            replaced: existingCount,
            message: `已覆盖，原有 ${existingCount} 个IP，现有 ${existingMap.size} 个IP`
        };
    } else if (mode === 'remove') {
        // 删除模式：从池中删除指定IP
        const toRemove = new Set();
        parsePoolList(newIPs || body.pool || '').forEach(line => {
            const key = extractIPKey(line);
            if (key) toRemove.add(key);
        });

        let removed = 0;
        for (const key of toRemove) {
            if (existingMap.has(key)) {
                existingMap.delete(key);
                removed++;
            }
        }

        responseData = {
            success: true,
            count: existingMap.size,
            removed,
            message: `已删除 ${removed} 个IP，剩余 ${existingMap.size} 个IP`
        };
    } else {
        // 追加模式
        parsePoolList(newIPs).forEach(line => {
            const key = extractIPKey(line);
            if (key) existingMap.set(key, line);
        });

        responseData = {
            success: true,
            count: existingMap.size,
            added: existingMap.size - existingCount
        };
    }

    const finalPool = Array.from(existingMap.values()).join('\n');
    await requireKV(env).put(poolKey, finalPool);

    return jsonResponse(responseData);
}

async function handleLoadRemoteUrl(request) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const url = body.url;
    if (!url) {
        return badRequest({ success: false, error: '缺少URL' });
    }

    const options = {
        cfCountry: body.cfCountry || body.country || '',
        port: body.port || body.remotePort || body.defaultPort || '443',
        defaultPort: body.defaultPort || body.port || '443',
        format: body.format || body.type || 'auto',
        ipColumn: body.ipColumn || body.ipField || '',
        portColumn: body.portColumn || body.portField || '',
        countryColumn: body.countryColumn || body.countryField || ''
    };

    const ips = await loadFromRemoteUrl(url, options);
    return jsonResponse({ 
        success: true, 
        ips,
        count: ips ? ips.split('\n').filter(Boolean).length : 0,
        source: url,
        filter: { cfCountry: options.cfCountry || '', port: options.port || '' }
    });
}

async function handleCurrentStatus(url, config) {
    const targetIndex = parseInt(url.searchParams.get('target') || '0');
    const target = config.targets[targetIndex];
    if (!target) {
        return badRequest({ error: '无效的目标' });
    }
    const status = await getDomainStatus(target, config);
    return jsonResponse(status);
}

async function handleLookupDomain(url, config) {
    const input = url.searchParams.get('domain');
    if (!input) return badRequest({ error: '缺少domain参数' });

    if (input.startsWith('txt@')) {
        const domain = input.substring(4);
        const txtData = await resolveTXTRecord(domain, config);
        return jsonResponse({
            type: 'TXT',
            domain,
            ips: txtData.ips,
            raw: txtData.raw
        });
    }

    const { domain, port } = parseDomainPort(input);
    const ips = await resolveDomain(domain, config);
    return jsonResponse({
        type: 'A',
        ips,
        port,
        domain
    });
}

async function handleCheckIP(url, config) {
    const target = url.searchParams.get('ip');
    if (!target) return badRequest({ error: '缺少ip参数' });

    // useBackup=true 表示手动只测备用接口；默认行为是主接口失败后自动切备用。
    const useBackupOnly = url.searchParams.get('useBackup') === 'true';
    if (useBackupOnly && config.checkApiBackup) {
        const addr = normalizeCheckAddr(target);
        const result = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken, 'backup');
        return jsonResponse(result ?? buildCheckFailure(addr, '备用检测接口无响应', 'backup'));
    }

    const res = await checkProxyIP(target, config);
    return jsonResponse(res);
}

async function handleIPInfo(url, config) {
    const ip = url.searchParams.get('ip');
    if (!ip) {
        return badRequest({ error: '缺少IP参数' });
    }
    const info = await getIPInfo(ip, config);
    return jsonResponse(info ?? { error: '查询失败' });
}

async function handleDeleteRecord(url, config) {
    const id = url.searchParams.get('id');
    if (!id) return badRequest({ error: '缺少id参数' });
    const ip = url.searchParams.get('ip');
    const isTxt = url.searchParams.get('isTxt') === 'true';

    if (isTxt && ip) {
        // TXT记录删除单个IP
        const record = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`);
        if (!record) {
            return badRequest({ success: false, error: '获取记录失败' });
        }

        let ips = parseTXTContent(record.content);

        // 移除指定IP
        ips = ips.filter(i => i !== ip);

        if (ips.length === 0) {
            // 如果没有IP了，删除整个TXT记录
            const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
            if (result === null) {
                return jsonResponse({ success: false, error: 'CF API 删除失败' });
            }
        } else {
            // 更新TXT记录
            const newContent = `"${ips.join(',')}"`;
            const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'PUT', {
                type: 'TXT',
                name: record.name,
                content: newContent,
                ttl: 60
            });
            if (result === null) {
                return jsonResponse({ success: false, error: 'CF API 更新失败' });
            }
        }

        return jsonResponse({ success: true });
    }
    
    // A记录删除
    const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
    if (result === null) {
        return jsonResponse({ success: false, error: 'CF API 删除失败' });
    }
    return jsonResponse({ success: true });
}

async function handleAddARecord(request, config) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const ip = body.ip;
    const targetIndex = body.targetIndex || 0;
    const target = config.targets[targetIndex];

    if (!ip || !target) {
        return badRequest({ success: false, error: '参数错误' });
    }

    // 格式化IP:PORT
    const addr = ip.includes(':') ? ip : `${ip}:${target.port}`;

    const check = await checkProxyIP(addr, config);
    if (!check.success) {
        return jsonResponse({ success: false, error: 'IP检测失败' });
    }

    // TXT模式：追加到TXT记录
    if (target.mode === 'TXT') {
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);

        if (records === null) {
            return jsonResponse({ success: false, error: CF_ERROR_MSG });
        }

        let currentIPs = [];
        let recordId = null;

        if (records?.length > 0) {
            recordId = records[0].id;
            currentIPs = parseTXTContent(records[0].content);
        }

        // 检查是否已存在
        if (currentIPs.includes(addr)) {
            return jsonResponse({ success: false, error: 'IP已存在于TXT记录' });
        }

        // 追加新IP
        currentIPs.push(addr);
        const newContent = `"${currentIPs.join(',')}"`;

        if (recordId) {
            const putResult = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'PUT', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
            if (putResult === null) {
                return jsonResponse({ success: false, error: 'CF API 更新TXT记录失败' });
            }
        } else {
            const postResult = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
                type: 'TXT',
                name: target.domain,
                content: newContent,
                ttl: 60
            });
            if (postResult === null) {
                return jsonResponse({ success: false, error: 'CF API 创建TXT记录失败' });
            }
        }

        return jsonResponse({
            success: true,
            colo: check.colo,
            time: check.responseTime,
            mode: 'TXT'
        });
    }

    // A记录模式
    const result = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
        type: 'A',
        name: target.domain,
        content: ip.split(':')[0], // A记录只需要IP部分
        ttl: 60,
        proxied: false
    });

    return jsonResponse({
        success: !!result,
        colo: check.colo,
        time: check.responseTime,
        mode: 'A'
    });
}

async function handleMaintain(url, env, config) {
    const isManual = url.searchParams.get('manual') === 'true';

    // 手动维护也必须先建立国家域名映射，否则会回退到默认 pool。
    // 例如 us.cail.qzz.io -> pool_US，kr.cail.qzz.io -> pool_KR。
    await ensureCountryDomainPoolMapping(env, config);

    const res = await maintainAllDomains(env, isManual, config);

    // 将日志包含在响应中
    return jsonResponse({
        ...res,
        // 确保所有日志都返回给前端
        allLogs: res.reports.flatMap(r => r.logs)
    });
}

async function handleGetDomainPoolMapping(env) {
    const mappingJson = await requireKV(env).get('domain_pool_mapping') || '{}';
    const mapping = safeJSONParse(mappingJson, {});
    
    const allKeys = await requireKV(env).list();
    const pools = allKeys.keys
        .filter(k => k.name.startsWith('pool'))
        .map(k => k.name);
    
    if (!pools.includes('pool')) {
        pools.unshift('pool');
    }
    
    return jsonResponse({ mapping, pools });
}

async function handleSaveDomainPoolMapping(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    await requireKV(env).put('domain_pool_mapping', JSON.stringify(body.mapping));
    return jsonResponse({ success: true });
}

async function handleCreatePool(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const poolKey = normalizePoolKey(body.poolKey || body.name);
    
    if (!poolKey || poolKey === 'pool' || poolKey === 'pool_trash') {
        return badRequest({ success: false, error: '请输入自定义池名' });
    }
    
    // 支持中文、字母、数字、下划线、横杠
    if (poolKey.length > GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH || !/^pool_[\u4e00-\u9fa5a-zA-Z0-9_-]+$/.test(poolKey)) {
        return badRequest({ success: false, error: `池名称只能包含中文、字母、数字、下划线、横杠，最长${GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH}字符` });
    }
    
    const existing = await requireKV(env).get(poolKey);
    if (existing !== null) {
        return badRequest({ success: false, error: '池已存在' });
    }
    
    await requireKV(env).put(poolKey, '');
    return jsonResponse({ success: true });
}

async function handleDeletePool(url, env) {
    const poolKey = normalizePoolKey(url.searchParams.get('poolKey') || url.searchParams.get('name') || '');
    
    if (!poolKey) {
        return badRequest({ success: false, error: '缺少poolKey参数' });
    }
    
    // 保护系统池
    const protectedPools = ['pool', 'domain_pool_mapping', 'pool_trash'];
    if (protectedPools.includes(poolKey)) {
        return badRequest({ success: false, error: `不能删除${getPoolDisplayName(poolKey)}` });
    }
    
    try {
        await requireKV(env).delete(poolKey);
        return jsonResponse({ success: true });
    } catch (e) {
        console.error('删除池失败:', e);
        return jsonResponse({ success: false, error: '删除池失败' });
    }
}

async function handleClearTrash(env) {
    await requireKV(env).put('pool_trash', '');
    return jsonResponse({ success: true, message: '垃圾桶已清空' });
}

async function handleRestoreFromTrash(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const ipsToRestore = body.ips || [];
    const restoreToSource = body.restoreToSource === true;
    const targetPool = body.targetPool || 'pool';
    
    if (ipsToRestore.length === 0) {
        return badRequest({ success: false, error: '没有选择IP' });
    }
    
    // 获取垃圾桶
    let trashList = parsePoolList(await requireKV(env).get('pool_trash'));
    
    let restored = 0;
    const restoredByPool = {};

    // 读取/写入多个池：按需懒加载
    const poolCache = new Map(); // poolKey -> { list: string[], set: Set<string> }
    async function loadPool(poolKey) {
        if (poolCache.has(poolKey)) return poolCache.get(poolKey);
        const list = parsePoolList(await requireKV(env).get(poolKey));
        const set = new Set(list.map(p => extractIPKey(p)));
        const obj = { list, set };
        poolCache.set(poolKey, obj);
        return obj;
    }

    // 从垃圾桶条目中提取来源池
    function pickTargetPoolFromTrashEntry(trashEntry) {
        if (!restoreToSource) return targetPool;
        // trashEntry 格式：`${ipAddr} # ${reason} ${timestamp} 来自 ${poolKey}`
        // 例如：`1.2.3.4:443 # 洗库失效 2024-01-01T00:00:00.000Z 来自 pool_a`
        const idx = trashEntry.lastIndexOf(' 来自 ');
        if (idx !== -1) {
            const sourcePool = trashEntry.slice(idx + 4).trim();
            // 直接返回来源池名（如 pool_a），不需要通过域名映射
            if (sourcePool && sourcePool.startsWith('pool')) {
                return sourcePool;
            }
        }
        return 'pool';
    }
    
    // 建立垃圾桶索引，避免循环内反复遍历
    const trashMap = new Map();
    trashList.forEach(t => trashMap.set(extractIPKey(t), t));

    // 恢复IP
    for (const ip of ipsToRestore) {
        const trashEntry = trashMap.get(ip);

        if (trashEntry) {
            trashMap.delete(ip);

            const toPool = pickTargetPoolFromTrashEntry(trashEntry);
            const poolObj = await loadPool(toPool);

            // 添加到目标池（如果不存在）- 只恢复纯净的IP:PORT，不携带垃圾桶注释
            if (!poolObj.set.has(ip)) {
                poolObj.list.push(ip);
                poolObj.set.add(ip);
                restored++;
                restoredByPool[toPool] = (restoredByPool[toPool] || 0) + 1;
            }
        }
    }

    // 保存
    await requireKV(env).put('pool_trash', Array.from(trashMap.values()).join('\n'));
    for (const [poolKey, poolObj] of poolCache.entries()) {
        await requireKV(env).put(poolKey, poolObj.list.join('\n'));
    }
    
    return jsonResponse({ 
        success: true, 
        restored,
        restoredByPool,
        message: restoreToSource
            ? `已恢复 ${restored} 个IP到源IP库`
            : `已恢复 ${restored} 个IP到 ${targetPool}`
    });
}

function parseDomainPort(input, defaultPort = '443') {
    if (!input) return { domain: '', port: defaultPort };
    const parts = input.trim().split(':');
    return {
        domain: parts[0],
        port: parts[1] || defaultPort
    };
}

function parseTarget(input) {
    if (!input) return null;
    
    input = input.trim();
    
    // 解析最小活跃数（&后面的数字）
    let minActive = GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE;
    const minActiveMatch = input.match(/&(\d+)$/);
    if (minActiveMatch) {
        minActive = parseInt(minActiveMatch[1]);
        input = input.replace(/&\d+$/, ''); // 移除&数字部分
    }
    
    // TXT模式
    if (input.startsWith('txt@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'TXT', domain, port, minActive };
    }
    
    // ALL模式
    if (input.startsWith('all@')) {
        const rest = input.substring(4);
        const { domain, port } = parseDomainPort(rest);
        return { mode: 'ALL', domain, port, minActive };
    }
    
    // A模式（默认）
    const { domain, port } = parseDomainPort(input);
    return { mode: 'A', domain, port, minActive };
}

function clampInt(value, min, max, fallback) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.floor(n)));
}

function createConfig(env, request = null) {
    const config = { ...DEFAULT_CONFIG };

    config.apiKey = env.CF_KEY || DEFAULT_CONFIG.apiKey;
    config.zoneId = env.CF_ZONEID || DEFAULT_CONFIG.zoneId;
    config.authKey = env.AUTH_KEY || DEFAULT_CONFIG.authKey;

    const domainsInput = env.CF_DOMAIN || '';
    if (domainsInput) {
        const parts = domainsInput.split(',').map(s => s.trim()).filter(s => s);
        config.targets = parts.map(parseTarget).filter(t => t !== null);
    }

    if (config.targets.length === 0) {
        config.targets = [{ mode: 'A', domain: '', port: '443', minActive: GLOBAL_SETTINGS.DEFAULT_MIN_ACTIVE }];
    }

    config.tgToken = env.TG_TOKEN || DEFAULT_CONFIG.tgToken;
    config.tgId = env.TG_ID || DEFAULT_CONFIG.tgId;
    config.checkApi = env.CHECK_API || DEFAULT_CONFIG.checkApi;
    config.checkApiToken = env.CHECK_API_TOKEN || DEFAULT_CONFIG.checkApiToken;
    config.checkApiBackup = env.CHECK_API_BACKUP || DEFAULT_CONFIG.checkApiBackup;
    config.checkApiBackupToken = env.CHECK_API_BACKUP_TOKEN || DEFAULT_CONFIG.checkApiBackupToken;
    config.dohApi = env.DOH_API || DEFAULT_CONFIG.dohApi;
    config.ipInfoEnabled = env.IP_INFO_ENABLED === 'true';
    config.ipInfoApi = env.IP_INFO_API || DEFAULT_CONFIG.ipInfoApi;

    config.maxCheckPerDomain = clampInt(env.MAX_CHECK_PER_DOMAIN, 1, 50, GLOBAL_SETTINGS.MAX_CHECK_PER_DOMAIN);
    config.checkConcurrency = clampInt(env.CHECK_CONCURRENCY, 1, 5, GLOBAL_SETTINGS.CONCURRENT_CHECKS);
    config.checkCacheTtlMinutes = clampInt(env.CHECK_CACHE_TTL_MINUTES, 0, 1440, GLOBAL_SETTINGS.CHECK_CACHE_TTL_MINUTES);
    config.checkFailThreshold = clampInt(env.CHECK_FAIL_THRESHOLD, 1, 20, GLOBAL_SETTINGS.CHECK_FAIL_THRESHOLD);
    config.removeFailedImmediately = String(env.REMOVE_FAILED_IMMEDIATELY || '').toLowerCase() === 'true';
    config.remoteUpdateAlways = String(env.REMOTE_UPDATE_ALWAYS || '').toLowerCase() === 'true';

    if (request) {
        const url = new URL(request.url);
        config.projectUrl = `${url.protocol}//${url.host}`;
    }

    return Object.freeze(config);
}

async function batchAddToTrash(env, entries) {
    if (!entries || entries.length === 0) return;
    const trashKey = 'pool_trash';
    let trashList = parsePoolList(await requireKV(env).get(trashKey));
    const trashIPSet = new Set(trashList.map(t => extractIPKey(t)));
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    for (const { ipAddr, reason, poolKey } of entries) {
        if (!trashIPSet.has(ipAddr)) {
            const trashEntry = `${ipAddr} # ${reason} ${timestamp}${poolKey ? ' 来自 ' + poolKey : ''}`;
            trashList.push(trashEntry);
            trashIPSet.add(ipAddr);
        }
    }

    if (trashList.length > GLOBAL_SETTINGS.MAX_TRASH_SIZE) {
        trashList = trashList.slice(-GLOBAL_SETTINGS.MAX_TRASH_SIZE);
    }

    await requireKV(env).put(trashKey, trashList.join('\n'));
}

function parseIPLine(line) {
    line = line.trim();
    if (!line || line.startsWith('#')) return null;

    // 分离注释部分
    const { main: mainPart, comment } = splitComment(line);

    const isValidIP = ip => ip.split('.').every(o => { const n = Number(o); return n >= 0 && n <= 255; });
    const isValidPort = p => { const n = Number(p); return n >= 1 && n <= 65535; };

    // IP:PORT 格式
    let match = mainPart.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
    if (match && isValidIP(match[1]) && isValidPort(match[2])) return `${match[1]}:${match[2]}${comment}`;

    // IP：PORT 格式（中文冒号）
    match = mainPart.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})：(\d+)$/);
    if (match && isValidIP(match[1]) && isValidPort(match[2])) return `${match[1]}:${match[2]}${comment}`;

    // IP 空格/Tab PORT
    const parts = mainPart.split(/\s+/);
    if (parts.length === 2) {
        const ip = parts[0].trim();
        const port = parts[1].trim();
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) && /^\d+$/.test(port) && isValidIP(ip) && isValidPort(port)) {
            return `${ip}:${port}${comment}`;
        }
    }

    // 纯IP（默认443端口）
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(mainPart) && isValidIP(mainPart)) {
        return `${mainPart}:443${comment}`;
    }

    // 复杂格式
    const complexMatch = mainPart.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D+(\d+)/);
    if (complexMatch && isValidIP(complexMatch[1]) && isValidPort(complexMatch[2])) return `${complexMatch[1]}:${complexMatch[2]}${comment}`;

    return null;
}

async function cleanIPListAsync(text, resolveDomains = true, config = null) {
    if (!text) return '';
    const map = new Map();
    const lines = text.split('\n');

    for (let line of lines) {
        line = line.trim();
        if (!line || line.startsWith('#')) continue;

        // 分离注释
        const { main: mainPart, comment } = splitComment(line);

        // 检测域名格式
        const domainMatch = mainPart.match(/^([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}):?(\d+)?$/);
        if (domainMatch) {
            // 如果不解析域名或没有config，跳过域名格式的行
            if (!resolveDomains || !config) continue;

            const domain = domainMatch[1];
            const port = domainMatch[2] || '443';

            if (domain.length > 253) continue;

            try {
                const ips = await resolveDomain(domain, config);
                if (ips && ips.length > 0) {
                    ips.slice(0, GLOBAL_SETTINGS.MAX_IPS_PER_DOMAIN).forEach(ip => {
                        const fullFormat = `${ip}:${port}${comment}`;
                        const key = `${ip}:${port}`;
                        map.set(key, fullFormat);
                    });
                }
                continue;
            } catch (e) {
                console.error(`❌ 域名解析失败 ${domain}:`, e);
                continue;
            }
        }

        // IP格式
        const parsed = parseIPLine(line);
        if (parsed) {
            const key = extractIPKey(parsed);
            map.set(key, parsed);
        }
    }

    return Array.from(map.values()).join('\n');
}

function normalizeRemoteCSVText(text) {
    // 兼容少数 CSV 被复制/压缩成“表头 + 空格 + 数据行”的情况。
    return String(text || '')
        .replace(/^\uFEFF/, '')
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .replace(/(IP\s*,\s*cf-meta-ip\s*,\s*端口\s*,[^\n]*?TLS延迟\(ms\))\s+(?=\d{1,3}(?:\.\d{1,3}){3}\s*,)/i, '$1\n')
        .replace(/(\d+(?:\.\d+)?)\s+(?=\d{1,3}(?:\.\d{1,3}){3}\s*,)/g, '$1\n');
}

function cleanCSVCell(value) {
    let v = String(value ?? '')
        .replace(/^\uFEFF/, '')
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1).trim();
    }
    return v;
}

function parseCSVRows(text) {
    const rows = [];
    let row = [];
    let cur = '';
    let quoted = false;
    const input = normalizeRemoteCSVText(text);

    for (let i = 0; i < input.length; i++) {
        const ch = input[i];
        if (ch === '"') {
            if (quoted && input[i + 1] === '"') {
                cur += '"';
                i++;
            } else {
                quoted = !quoted;
            }
        } else if (ch === ',' && !quoted) {
            row.push(cleanCSVCell(cur));
            cur = '';
        } else if (ch === '\n' && !quoted) {
            row.push(cleanCSVCell(cur));
            cur = '';
            if (row.some(v => v !== '')) rows.push(row);
            row = [];
        } else {
            cur += ch;
        }
    }

    row.push(cleanCSVCell(cur));
    if (row.some(v => v !== '')) rows.push(row);
    return rows;
}

function parseCSVLine(line) {
    return parseCSVRows(line)[0] || [];
}

function normalizeCSVHeader(name) {
    return cleanCSVCell(name).toLowerCase().replace(/[\s_\uFEFF\-]+/g, '');
}

function normalizeCountryCode(value) {
    return cleanCSVCell(value).toUpperCase();
}

function pickCSVColumn(headers, aliases) {
    const normalized = headers.map(normalizeCSVHeader);
    const aliasSet = new Set(aliases.map(normalizeCSVHeader));
    return normalized.findIndex(h => aliasSet.has(h));
}

function isIPv4(ip) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(ip || '').trim()) &&
        String(ip).split('.').every(o => { const n = Number(o); return n >= 0 && n <= 255; });
}

function normalizePort(port, defaultPort = '443') {
    const raw = cleanCSVCell(port);
    if (/^\d{1,5}$/.test(raw)) {
        const n = Number(raw);
        if (n >= 1 && n <= 65535) return raw;
    }
    return String(defaultPort || '443');
}

function pickConfiguredCSVColumn(headers, selector, aliases, fallbackIndex = -1) {
    const cleanSelector = cleanCSVCell(selector);
    if (cleanSelector) {
        if (/^\d+$/.test(cleanSelector)) {
            const idx = Number(cleanSelector);
            if (idx >= 0 && idx < headers.length) return idx;
        }
        const normalizedSelector = normalizeCSVHeader(cleanSelector);
        const normalized = headers.map(normalizeCSVHeader);
        const exact = normalized.findIndex(h => h === normalizedSelector);
        if (exact !== -1) return exact;
    }
    const picked = pickCSVColumn(headers, aliases);
    return picked !== -1 ? picked : fallbackIndex;
}

function normalizeRemoteFormat(value) {
    const v = cleanCSVCell(value).toLowerCase();
    if (['csv', 'txt', 'text', 'plain'].includes(v)) return v === 'text' || v === 'plain' ? 'txt' : v;
    return 'auto';
}

function extractRemoteTextIPs(text, options = {}) {
    const expectedPort = normalizePort(options.port || options.remotePort || options.defaultPort || '443', '443');
    const defaultPort = normalizePort(options.defaultPort || expectedPort || '443', '443');
    const result = new Map();
    const lines = String(text || '')
        .replace(/^\uFEFF/, '')
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .split('\n');

    for (let rawLine of lines) {
        let line = String(rawLine || '').trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) continue;

        const commentMatch = line.match(/\s+#\s*(.+)$/);
        const comment = commentMatch ? ` # ${commentMatch[1].trim()}` : '';
        line = line.replace(/\s+#.*$/, '').trim();

        const match = line.match(/(\d{1,3}(?:\.\d{1,3}){3})(?:\s*(?:[:：,|\s])\s*(\d{1,5}))?/);
        if (!match) continue;

        const ip = match[1];
        if (!isIPv4(ip)) continue;

        const port = match[2] ? normalizePort(match[2], defaultPort) : defaultPort;
        if (expectedPort && port !== expectedPort) continue;

        const key = `${ip}:${port}`;
        result.set(key, `${key}${comment}`);
    }

    return Array.from(result.values()).join('\n');
}

function extractRemoteCSVIPs(text, options = {}) {
    const expectedCountry = normalizeCountryCode(options.cfCountry || options.country || '');
    const expectedPort = normalizePort(options.port || options.remotePort || options.defaultPort || '443', '443');
    const defaultPort = normalizePort(options.defaultPort || expectedPort || '443', '443');
    const rows = parseCSVRows(text);
    if (!rows.length) return '';

    const headers = rows[0];
    let ipIdx = pickConfiguredCSVColumn(headers, options.ipColumn, ['IP', 'ip', 'address', '地址', 'IP地址'], -1);
    let portIdx = pickConfiguredCSVColumn(headers, options.portColumn, ['端口', 'port'], -1);
    let countryIdx = pickConfiguredCSVColumn(headers, options.countryColumn, ['CF归属国', 'cf归属国', 'CF国家', 'cfCountry', 'country', '归属国', '国家'], -1);
    const hasHeader = ipIdx !== -1 || portIdx !== -1 || countryIdx !== -1;

    // 兼容 xgonce/Cloudflare_IP 的固定 schema：IP,cf-meta-ip,端口,速度(Mbps),CF归属国,机房,...
    if (hasHeader) {
        if (ipIdx === -1) ipIdx = 0;
        if (portIdx === -1) portIdx = 2;
        if (countryIdx === -1) countryIdx = 4;
    } else {
        ipIdx = 0;
        portIdx = 2;
        countryIdx = 4;
    }

    const dataRows = hasHeader ? rows.slice(1) : rows;
    const result = new Map();

    for (const row of dataRows) {
        const ip = cleanCSVCell(row[ipIdx]);
        const port = normalizePort(row[portIdx], defaultPort);
        const country = normalizeCountryCode(row[countryIdx]);

        if (!isIPv4(ip)) continue;
        if (expectedCountry && country !== expectedCountry) continue;
        if (expectedPort && port !== expectedPort) continue;

        const key = `${ip}:${port}`;
        const suffix = country ? ` # CF归属国 ${country}` : '';
        result.set(key, `${key}${suffix}`);
    }

    return Array.from(result.values()).join('\n');
}

async function loadFromRemoteUrl(url, options = {}) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
        const hostname = parsed.hostname.toLowerCase();
        if (hostname === 'localhost' ||
            hostname.startsWith('127.') ||
            hostname.startsWith('10.') ||
            hostname.startsWith('192.168.') ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
            hostname.startsWith('169.254.') ||
            hostname.startsWith('100.64.') ||
            hostname === 'metadata.google.internal' ||
            hostname === '0.0.0.0' ||
            hostname === '::1' ||
            hostname === '[::1]' ||
            hostname.startsWith('fc00:') ||
            hostname.startsWith('fe80:') ||
            hostname.startsWith('[fc00:') ||
            hostname.startsWith('[fe80:')) return '';
    } catch { return ''; }

    try {
        const r = await fetch(url, {
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.REMOTE_LOAD_TIMEOUT)
        });
        if (r.ok) {
            const text = await r.text();
            const path = new URL(url).pathname.toLowerCase();
            const contentType = (r.headers.get('content-type') || '').toLowerCase();
            const format = normalizeRemoteFormat(options.format || options.type || 'auto');

            if (format === 'csv') return extractRemoteCSVIPs(text, options);
            if (format === 'txt') return extractRemoteTextIPs(text, options);

            // auto：优先依据扩展名/Content-Type；否则先尝试 TXT 行提取，失败再尝试 CSV。
            if (path.endsWith('.csv') || contentType.includes('csv')) {
                const csv = extractRemoteCSVIPs(text, options);
                return csv || extractRemoteTextIPs(text, options);
            }
            const txt = extractRemoteTextIPs(text, options);
            return txt || extractRemoteCSVIPs(text, options);
        }
    } catch (e) {
        console.error(`❌ 远程加载失败 ${url}:`, e);
    }
    return '';
}

async function resolveDomain(domain, config) {
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=A`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        const d = await r.json();
        return d.Answer?.filter(a => a.type === 1).map(a => a.data) ?? [];
    } catch (e) {
        console.error('❌ DNS A记录解析失败:', e);
        return [];
    }
}

async function resolveTXTRecord(domain, config) {
    try {
        const r = await fetch(`${config.dohApi}?name=${encodeURIComponent(domain)}&type=TXT`, {
            headers: { 'accept': 'application/dns-json' },
            signal: AbortSignal.timeout(GLOBAL_SETTINGS.DOH_TIMEOUT)
        });
        const d = await r.json();

        if (!d.Answer?.length) {
            return { raw: '', ips: [] };
        }

        // 去掉DNS返回的引号
        const rawData = d.Answer[0].data;
        const ips = parseTXTContent(rawData);
        const raw = rawData.replace(/^"|"$/g, '');

        return { raw, ips };
    } catch (e) {
        console.error('❌ DNS TXT记录解析失败:', e);
        return { raw: '', ips: [] };
    }
}

async function getIPInfo(ip, config) {
    if (!config.ipInfoEnabled) return null;

    try {
        const cleanIP = ip.replace(/[\[\]]/g, '');
        const r = await fetch(
            `${config.ipInfoApi}/${cleanIP}?fields=status,country,countryCode,city,isp,as,asname&lang=zh-CN`,
            { signal: AbortSignal.timeout(GLOBAL_SETTINGS.IP_INFO_TIMEOUT) }
        );

        const data = await r.json();

        if (data.status === 'success') {
            return {
                country: data.country || '未知',
                countryCode: data.countryCode || '',
                city: data.city || '',
                isp: data.isp || '未知',
                asn: data.as || '',
                asname: data.asname || ''
            };
        }
    } catch (e) {
        console.error(`❌ IP信息查询失败 ${ip}:`, e);
    }

    return null;
}

// 批量检测IP列表，可选查询归属地
async function batchCheckIPs(ipList, checkFn, config, useBackupApi = false) {
    if (!ipList || ipList.length === 0) return [];

    // 垃圾桶复检时使用备用接口（如有）独立验证
    const effectiveCheckFn = (useBackupApi && config.checkApiBackup)
        ? (addr) => {
            const normalized = normalizeCheckAddr(addr);
            return checkProxyIPOnce(normalized, config.checkApiBackup, config.checkApiBackupToken)
                .then(r => r ?? { success: false });
        }
        : checkFn;

    const checkSettled = await Promise.allSettled(ipList.map(addr => effectiveCheckFn(addr)));
    const checkResults = checkSettled.map(r => r.status === 'fulfilled' ? r.value : { success: false });

    const ipInfoMap = new Map();
    if (config.ipInfoEnabled) {
        await Promise.allSettled(ipList.map(async (addr) => {
            const ipOnly = addr.split(':')[0];
            const info = await getIPInfo(ipOnly, config);
            if (info) ipInfoMap.set(ipOnly, info);
        }));
    }

    return checkResults.map((result, i) => ({
        address: ipList[i],
        success: result.success,
        colo: result.colo || 'N/A',
        time: result.responseTime || '-',
        ipInfo: config.ipInfoEnabled ? (ipInfoMap.get(ipList[i].split(':')[0]) || null) : null
    }));
}

async function getDomainStatus(target, config) {
    const result = {
        mode: target.mode,
        domain: target.domain,
        port: target.port,
        aRecords: [],
        txtRecords: [],
        error: null
    };

    if (target.mode === 'A' || target.mode === 'ALL') {
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=A`);
        if (!records) {
            result.error = CF_ERROR_MSG;
            return result;
        }
        // 使用批量检测流程
        const ipList = records.map(r => `${r.content}:${target.port}`);
        const checkResults = await batchCheckIPs(ipList, (addr) => checkProxyIP(addr, config), config);

        result.aRecords = records.map((r, i) => ({
            id: r.id,
            ip: r.content,
            port: target.port,
            success: checkResults[i].success,
            colo: checkResults[i].colo,
            time: checkResults[i].time,
            ipInfo: checkResults[i].ipInfo
        }));
    }

    if (target.mode === 'TXT' || target.mode === 'ALL') {
        const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);
        if (!records) {
            result.error = CF_ERROR_MSG;
            return result;
        }
        if (records.length > 0) {
            const ips = parseTXTContent(records[0].content);

            // 使用批量检测流程
            const checkResults = await batchCheckIPs(ips, (addr) => checkProxyIP(addr, config), config);

            const txtChecks = checkResults.map(result => ({
                ip: result.address,
                success: result.success,
                colo: result.colo,
                time: result.time,
                ipInfo: result.ipInfo
            }));

            result.txtRecords = [{
                id: records[0].id,
                ips: txtChecks
            }];
        }
    }

    return result;
}

// 单次检测 IP。检测接口返回字段统一为：
// candidate, success, proxyIP, portRemote, responseTime, colo, message, probe_results。
async function checkProxyIPOnce(addr, apiUrl, token, source = 'main') {
    try {
        let requestUrl = `${apiUrl}${encodeURIComponent(addr)}`;
        if (token) {
            requestUrl += `${requestUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`;
        }

        const startedAt = Date.now();
        const r = await fetch(requestUrl, { signal: AbortSignal.timeout(GLOBAL_SETTINGS.CHECK_TIMEOUT) });
        if (!r.ok) return buildCheckFailure(addr, `检测接口 HTTP ${r.status}`, source, Date.now() - startedAt);

        const data = safeJSONParse(await r.text(), null);
        if (!data || typeof data !== 'object') return buildCheckFailure(addr, '检测接口返回不是有效 JSON', source, Date.now() - startedAt);

        return normalizeCheckResult(data, addr, source, Date.now() - startedAt);
    } catch (e) {
        return buildCheckFailure(addr, e?.name === 'TimeoutError' ? '检测接口超时' : (e?.message || '检测接口请求失败'), source);
    }
}

function buildCheckFailure(addr, message = '检测失败', source = 'main', responseTime = 0) {
    const parsed = splitHostPort(addr);
    return {
        candidate: addr,
        success: false,
        proxyIP: parsed.host,
        portRemote: parsed.port,
        responseTime,
        colo: '',
        message,
        probe_results: {},
        source
    };
}

function normalizeCheckResult(data, addr, source = 'main', fallbackTime = 0) {
    const parsed = splitHostPort(addr);
    const responseTime = Number(data.responseTime ?? data.time ?? data.elapsed ?? fallbackTime ?? 0);
    // 外部检测接口是唯一标准：只有 success === true 才判定可用于 DNS 更新。
    const success = data.success === true;

    return {
        ...data,
        candidate: String(data.candidate || addr),
        success,
        proxyIP: String(data.proxyIP || parsed.host || data.ip || ''),
        portRemote: Number(data.portRemote ?? data.port ?? parsed.port ?? 443),
        responseTime: Number.isFinite(responseTime) ? responseTime : 0,
        colo: String(data.colo || data.coloCode || data.cfColo || ''),
        message: data.message || data.error || (success ? '' : '检测未通过'),
        probe_results: data.probe_results && typeof data.probe_results === 'object' ? data.probe_results : {},
        source
    };
}

function splitHostPort(addr) {
    const value = String(addr || '').trim();
    if (!value) return { host: '', port: 443 };

    const ipv6 = value.match(/^\[([^\]]+)\]:(\d+)$/);
    if (ipv6) return { host: ipv6[1], port: Number(ipv6[2]) || 443 };

    const ipv4OrDomain = value.match(/^(.+):(\d+)$/);
    if (ipv4OrDomain && !ipv4OrDomain[1].includes(':')) {
        return { host: ipv4OrDomain[1], port: Number(ipv4OrDomain[2]) || 443 };
    }

    return { host: value.replace(/^\[|\]$/g, ''), port: 443 };
}

// 地址格式化：智能添加默认端口443，处理IPv6方括号
function normalizeCheckAddr(input) {
    let addr = input.trim();
    if (addr.startsWith('[')) {
        if (!addr.includes(']:')) {
            addr = addr.endsWith(']') ? `${addr}:443` : `${addr}]:443`;
        }
    } else if (!addr.includes(':') || (addr.match(/:/g) || []).length > 1) {
        if ((addr.match(/:/g) || []).length > 1) {
            addr = `[${addr}]:443`;
        } else {
            addr = `${addr}:443`;
        }
    }
    return addr;
}

async function checkProxyIP(input, config) {
    const addr = normalizeCheckAddr(input);

    // 主接口优先：主接口不可用或判定失败时，自动切备用接口。
    const primary = await checkProxyIPOnce(addr, config.checkApi, config.checkApiToken, 'main');
    if (primary?.success) return primary;

    if (config.checkApiBackup) {
        const backup = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken, 'backup');
        if (backup?.success) return backup;

        return {
            ...(backup || primary || buildCheckFailure(addr)),
            success: false,
            message: backup?.message || primary?.message || '主备检测接口均未通过',
            primary_result: primary || null,
            backup_result: backup || null
        };
    }

    return primary || buildCheckFailure(addr);
}

async function fetchCF(config, path, method = 'GET', body = null) {
    if (!config.apiKey || !config.zoneId) {
        console.error('❌ Cloudflare配置不完整:', {
            apiKey: !!config.apiKey,
            zoneId: !!config.zoneId
        });
        return null;
    }

    const headers = {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json'
    };
    const init = { method, headers };
    if (body) init.body = JSON.stringify(body);

    try {
        const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, init);
        const d = await r.json();

        if (!d.success) {
            console.error('❌ Cloudflare API错误:', {
                path,
                method,
                errors: d.errors,
                messages: d.messages
            });
            return null;
        }

        return d.result;
    } catch (e) {
        console.error('❌ Cloudflare API请求失败:', {
            path,
            method,
            error: e.message
        });
        return null;
    }
}

async function getCandidateIPs(env, target, addLog, poolKey) {
    const pool = await requireKV(env).get(poolKey) || '';
    
    if (!pool) {
        addLog(`⚠️ ${poolKey} 为空`);
        return [];
    }
    
    let candidates = parsePoolList(pool);
    
    // TXT模式不过滤端口，A模式才过滤
    if (target.mode === 'A') {
        candidates = candidates.filter(l => {
            // 提取IP:PORT部分（去除注释）
            const ipPort = extractIPKey(l);
            const parts = ipPort.split(':');
            if (parts.length >= 2) {
                return parts[1] === target.port;
            }
            return false;
        });
    }
    
    addLog(`📦 使用 ${poolKey}: ${candidates.length} 个候选IP`);
    return candidates;
}

const CHECK_CACHE_KEY = 'check_cache_v1';
const CHECK_FAIL_KEY = 'check_fail_count_v1';

async function loadJsonFromKV(env, key, fallback) {
    try { return safeJSONParse(await requireKV(env).get(key) || '', fallback); }
    catch { return fallback; }
}

async function saveJsonToKV(env, key, value) {
    await requireKV(env).put(key, JSON.stringify(value || {}, null, 2));
}

function isFreshSuccessCache(item, ttlMinutes) {
    if (!item || item.success !== true) return false;
    const ttl = Number(ttlMinutes || 0);
    if (ttl <= 0) return false;
    const checkedAt = Number(item.checkedAt || 0);
    return checkedAt > 0 && (Date.now() - checkedAt) <= ttl * 60 * 1000;
}

function toCachedCheckResult(candidate, item) {
    const parsed = splitHostPort(candidate);
    return {
        candidate,
        success: true,
        proxyIP: item.proxyIP || parsed.host,
        portRemote: item.portRemote || parsed.port,
        responseTime: item.responseTime || 0,
        colo: item.colo || '',
        message: '缓存命中',
        probe_results: item.probe_results || {},
        source: item.source || 'cache',
        cacheHit: true
    };
}

function updateCheckStateAfterResult(state, candidate, result, config) {
    const key = normalizeCheckAddr(candidate);
    if (!state.cache || typeof state.cache !== 'object') state.cache = {};
    if (!state.failCount || typeof state.failCount !== 'object') state.failCount = {};

    if (result && result.success === true) {
        const parsed = splitHostPort(key);
        state.cache[key] = {
            success: true,
            checkedAt: Date.now(),
            proxyIP: result.proxyIP || parsed.host,
            portRemote: result.portRemote || parsed.port,
            responseTime: result.responseTime || 0,
            colo: result.colo || '',
            source: result.source || 'main',
            probe_results: result.probe_results || {}
        };
        delete state.failCount[key];
        return { failCount: 0, shouldTrash: false };
    }

    const next = (Number(state.failCount[key] || 0) || 0) + 1;
    state.failCount[key] = next;
    return {
        failCount: next,
        shouldTrash: config.removeFailedImmediately === true || next >= Number(config.checkFailThreshold || 3)
    };
}

async function maybeMoveFailedToTrash({ env, poolKey, poolList, ipAddr, reason, checkResult, state, config, addLog }) {
    const status = updateCheckStateAfterResult(state, ipAddr, checkResult, config);
    const threshold = Number(config.checkFailThreshold || 3);

    if (!status.shouldTrash) {
        addLog(`  ❌ ${ipAddr} - 外部检测 success=false，本轮不用于 DNS 更新，失败次数 ${status.failCount}/${threshold}`);
        return { poolList, removed: false };
    }

    const nextPool = poolList.filter(p => extractIPKey(p) !== ipAddr);
    await batchAddToTrash(env, [{ ipAddr, reason: `${reason}，连续失败 ${status.failCount}/${threshold}`, poolKey }]);
    addLog(`  🗑️ ${ipAddr} - 连续失败 ${status.failCount}/${threshold}，移入垃圾桶`);
    return { poolList: nextPool, removed: nextPool.length !== poolList.length };
}

async function maintainRecordsCommon(options) {
    const {
        env, target, addLog, report, poolKey, checkFn,
        getCurrentIPs, deleteRecord, addRecord, shouldSkipCandidate,
        checkState, config
    } = options;

    const currentIPs = getCurrentIPs();
    let poolList = parsePoolList(await requireKV(env).get(poolKey));
    report.poolKeyUsed = poolKey;

    let validIPs = [];
    let poolModified = false;
    let checkedCount = 0;
    let cacheHitCount = 0;
    const maxChecks = Number(config.maxCheckPerDomain || GLOBAL_SETTINGS.MAX_CHECK_PER_DOMAIN);

    // 先检查当前 DNS 记录。失败会从 DNS 中移除，但不立即污染 IP 池。
    for (const item of currentIPs) {
        const checkResult = await checkFn(item.addr);
        if (checkResult?.cacheHit) cacheHitCount++; else checkedCount++;
        updateCheckStateAfterResult(checkState, item.addr, checkResult, config);

        report.checkDetails.push({
            ip: item.addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-'
        });

        if (checkResult.success === true) {
            validIPs.push(item.ip);
            addLog(`  ${checkResult.cacheHit ? '⏭️' : '✅'} ${item.addr} - ${checkResult.cacheHit ? '缓存命中' : (checkResult.colo || 'OK')} (${checkResult.responseTime || 0}ms)`);
        } else {
            report.removed.push({ ip: item.addr, reason: '外部检测 success=false' });
            await deleteRecord(item.id);
            addLog(`  ❌ ${item.addr} - 外部检测 success=false，已从 DNS 移除，本轮不用于 DNS 更新`);
        }
    }

    report.beforeActive = validIPs.length;

    // 补充 IP：够用即停，并限制单域名单轮检测数量。
    if (validIPs.length < target.minActive) {
        addLog(`需补充: ${target.minActive - validIPs.length} 个，单轮最多检测 ${maxChecks} 个候选`);
        const candidates = await getCandidateIPs(env, target, addLog, poolKey);

        for (const item of candidates) {
            if (validIPs.length >= target.minActive) break;
            if (checkedCount >= maxChecks) {
                addLog(`⏹️ 已达到单轮检测上限 ${maxChecks}，停止继续检测以节省资源`);
                break;
            }

            const ipPort = extractIPKey(item);
            if (!ipPort || shouldSkipCandidate(ipPort, validIPs)) continue;

            const checkResult = await checkFn(ipPort);
            if (checkResult?.cacheHit) cacheHitCount++; else checkedCount++;

            if (checkResult && checkResult.success === true) {
                updateCheckStateAfterResult(checkState, ipPort, checkResult, config);
                const ip = ipPort.split(':')[0];
                await addRecord(ip);
                validIPs.push(ip);
                report.added.push({ ip: ipPort, colo: checkResult.colo || 'N/A', time: checkResult.responseTime || '-' });
                addLog(`  ${checkResult.cacheHit ? '⏭️' : '✅'} ${ipPort} - ${checkResult.cacheHit ? '缓存命中' : (checkResult.colo || 'OK')} (${checkResult.responseTime || 0}ms)，用于 DNS 更新`);
            } else {
                const moved = await maybeMoveFailedToTrash({ env, poolKey, poolList, ipAddr: ipPort, reason: '补充检测失败', checkResult, state: checkState, config, addLog });
                poolList = moved.poolList;
                if (moved.removed) {
                    report.poolRemoved++;
                    poolModified = true;
                }
            }
        }

        if (validIPs.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${poolKey} 本轮未补足目标数量：${validIPs.length}/${target.minActive}`);
        }
    }

    if (poolModified) {
        await requireKV(env).put(poolKey, poolList.join('\n'));
    }

    report.cacheHitCount = cacheHitCount;
    report.checkedCount = checkedCount;
    report.poolAfterCount = poolList.length;
    report.afterActive = validIPs.length;
    addLog(`📊 摘要：缓存命中 ${cacheHitCount}，本轮外部检测 ${checkedCount}，可用 ${validIPs.length}/${target.minActive}`);
}

async function maintainARecords(env, target, addLog, report, poolKey, checkFn, config, checkState) {
    addLog(`📋 维护A记录: ${target.domain}:${target.port} (最小活跃数: ${target.minActive})`);

    const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=A`);

    if (records === null) {
        addLog(`❌ 无法获取A记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    addLog(`当前A记录: ${records.length} 条`);

    // 使用通用维护逻辑
    await maintainRecordsCommon({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs: () => records.map(({ id, content }) => ({ id, addr: `${content}:${target.port}`, ip: content })),
        deleteRecord: async (id) => {
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${id}`, 'DELETE');
            if (r === null) addLog(`  ⚠️ 删除A记录失败: ${id}`);
        },
        addRecord: async (ip) => {
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
                type: 'A',
                name: target.domain,
                content: ip,
                ttl: 60,
                proxied: false
            });
            if (r === null) addLog(`  ⚠️ 添加A记录失败: ${ip}`);
        },
        shouldSkipCandidate: (ipPort, activeList) => {
            const [ip, port] = ipPort.split(':');
            return port !== target.port || activeList.includes(ip);
        },
        checkState,
        config
    });
}

async function maintainTXTRecords(env, target, addLog, report, poolKey, checkFn, config, checkState) {
    addLog(`📝 维护TXT: ${target.domain} (最小活跃数: ${target.minActive})`);

    const records = await fetchCF(config, `/zones/${config.zoneId}/dns_records?name=${target.domain}&type=TXT`);

    if (records === null) {
        addLog(`❌ 无法获取TXT记录 - 请检查CF配置`);
        report.configError = true;
        return;
    }

    let currentIPs = [];
    let recordId = null;

    if (records?.length > 0) {
        recordId = records[0].id;
        currentIPs = parseTXTContent(records[0].content);
        addLog(`当前TXT: ${currentIPs.length} 个IP`);
    }

    // 记录原始内容用于后续比较
    const originalIPs = [...currentIPs];

    // 使用通用维护逻辑（TXT模式：deleteRecord/addRecord 为空操作，最后统一更新）
    await maintainRecordsCommon({
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs: () => currentIPs.map(addr => ({ id: recordId, addr, ip: addr })),
        deleteRecord: async () => { /* TXT模式延迟到最后统一更新 */ },
        addRecord: async () => { /* TXT模式延迟到最后统一更新 */ },
        shouldSkipCandidate: (ipPort, activeList) => activeList.includes(ipPort),
        checkState,
        config
    });

    // 从report中提取最终有效IP列表
    // 现有IP中有效的 = 原始IP - 被移除的IP
    const removedSet = new Set(report.removed.map(r => r.ip));
    const survivedIPs = originalIPs.filter(ip => !removedSet.has(ip));
    // 新增的IP
    const addedIPs = report.added.map(a => a.ip);
    // 最终有效IP列表
    const finalValidIPs = [...survivedIPs, ...addedIPs];

    // TXT记录特殊处理：统一更新
    const newContent = finalValidIPs.length > 0 ? `"${finalValidIPs.join(',')}"` : '';
    const currentContent = originalIPs.length > 0 ? `"${originalIPs.join(',')}"` : '';

    if (newContent !== currentContent) {
        if (newContent === '' && recordId) {
            const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'DELETE');
            addLog(r !== null ? `📝 TXT记录已删除（所有IP失效）` : `⚠️ TXT记录删除失败`);
        } else if (newContent !== '') {
            if (recordId) {
                const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records/${recordId}`, 'PUT', {
                    type: 'TXT', name: target.domain, content: newContent, ttl: 60
                });
                addLog(r !== null ? `📝 TXT已更新` : `⚠️ TXT更新失败`);
            } else {
                const r = await fetchCF(config, `/zones/${config.zoneId}/dns_records`, 'POST', {
                    type: 'TXT', name: target.domain, content: newContent, ttl: 60
                });
                addLog(r !== null ? `📝 TXT已创建` : `⚠️ TXT创建失败`);
            }
        }
        report.txtUpdated = true;
    }
}

function normalizeTargetDomainName(domain) {
    return String(domain || '')
        .trim()
        .replace(/^(txt@|all@)/i, '')
        .split('&')[0]
        .split(':')[0]
        .toLowerCase();
}

function inferCountryFromDomain(domain) {
    const first = normalizeTargetDomainName(domain).split('.')[0] || '';
    return /^[a-z]{2}$/i.test(first) ? first.toUpperCase() : '';
}

function parseCountryDomainMap(env, config) {
    const raw = (env.REMOTE_COUNTRY_DOMAIN_MAP || env.COUNTRY_DOMAIN_MAP || '').trim();
    const map = new Map();

    if (raw) {
        raw.split(',').map(s => s.trim()).filter(Boolean).forEach(pair => {
            const parts = pair.split('=');
            if (parts.length < 2) return;
            const country = normalizeCountryCode(parts.shift());
            const domain = normalizeTargetDomainName(parts.join('='));
            if (country && domain) map.set(domain, country);
        });
    }

    // 未显式配置时，从域名前缀自动推断：US.xxx.xx -> US，KR.xxx.xx -> KR。
    if (map.size === 0) {
        for (const target of config.targets || []) {
            const domain = normalizeTargetDomainName(target.domain);
            const country = inferCountryFromDomain(domain);
            if (domain && country) map.set(domain, country);
        }
    }

    return map;
}

async function savePoolText(env, poolKey, poolText, mode = 'replace') {
    const lines = parsePoolList(poolText || '');
    const incoming = new Map();
    lines.forEach(line => {
        const key = extractIPKey(line);
        if (key) incoming.set(key, line);
    });

    if (mode === 'append') {
        const existing = new Map();
        parsePoolList(await requireKV(env).get(poolKey) || '').forEach(line => {
            const key = extractIPKey(line);
            if (key) existing.set(key, line);
        });
        incoming.forEach((line, key) => existing.set(key, line));
        await requireKV(env).put(poolKey, Array.from(existing.values()).join('\n'));
        return existing.size;
    }

    await requireKV(env).put(poolKey, Array.from(incoming.values()).join('\n'));
    return incoming.size;
}

function parseRemoteSourceObjectMap(raw) {
    const map = new Map();
    if (!raw) return map;
    try {
        const parsed = JSON.parse(raw);
        const items = Array.isArray(parsed)
            ? parsed
            : Object.entries(parsed).map(([domain, cfg]) => ({ domain, ...(typeof cfg === 'string' ? { url: cfg } : cfg) }));
        for (const item of items) {
            if (!item || typeof item !== 'object') continue;
            const domain = normalizeTargetDomainName(item.domain || item.host || item.name);
            const url = cleanCSVCell(item.url || item.source || item.href);
            if (!domain || !url) continue;
            map.set(domain, item);
        }
    } catch { }
    return map;
}

function parseRemoteDomainSources(env, config) {
    const raw = String(env.REMOTE_DOMAIN_SOURCES || env.REMOTE_DOMAIN_SOURCE || '').trim();
    const jsonRaw = String(env.REMOTE_DOMAIN_SOURCES_JSON || '').trim();
    const explicit = parseRemoteSourceObjectMap(jsonRaw || (raw.startsWith('[') || raw.startsWith('{') ? raw : ''));

    if (raw && explicit.size === 0) {
        // 行格式：domain|country|port|format|url
        // 多条可用换行或分号分隔。TXT 只有 IP 时会自动补 port。
        raw.split(/[;\n]+/).map(s => s.trim()).filter(Boolean).forEach(line => {
            const parts = line.split('|').map(v => v.trim());
            if (parts.length < 2) return;
            const domain = normalizeTargetDomainName(parts[0]);
            const url = parts.length >= 5 ? parts.slice(4).join('|') : parts[1];
            if (!domain || !url) return;
            explicit.set(domain, {
                domain,
                url,
                country: parts.length >= 5 ? parts[1] : '',
                port: parts.length >= 5 ? parts[2] : '',
                format: parts.length >= 5 ? parts[3] : 'auto'
            });
        });
    }

    const countryDomainMap = parseCountryDomainMap(env, config);
    const defaultUrl = env.REMOTE_IP_URL || 'https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv';
    const defaultPort = String(env.REMOTE_PORT || '443').trim() || '443';
    const sources = new Map();

    for (const target of config.targets || []) {
        const domain = normalizeTargetDomainName(target.domain);
        if (!domain) continue;
        const explicitCfg = explicit.get(domain) || {};
        const country = normalizeCountryCode(explicitCfg.country || explicitCfg.cfCountry || countryDomainMap.get(domain) || inferCountryFromDomain(domain));
        const port = String(explicitCfg.port || explicitCfg.remotePort || target.port || defaultPort).trim() || defaultPort;
        const url = cleanCSVCell(explicitCfg.url || explicitCfg.source || defaultUrl);
        const poolKey = cleanCSVCell(explicitCfg.poolKey || explicitCfg.pool || (country ? `pool_${country}` : 'pool'));
        sources.set(domain, {
            domain,
            url,
            country,
            cfCountry: country,
            port,
            defaultPort: String(explicitCfg.defaultPort || port || defaultPort).trim() || defaultPort,
            format: explicitCfg.format || explicitCfg.type || 'auto',
            ipColumn: explicitCfg.ipColumn || explicitCfg.ipField || '',
            portColumn: explicitCfg.portColumn || explicitCfg.portField || '',
            countryColumn: explicitCfg.countryColumn || explicitCfg.countryField || '',
            poolKey
        });
    }

    return sources;
}

function getDomainsNeedingRemoteUpdate(result) {
    const domains = new Set();
    if (!result || !Array.isArray(result.reports)) return domains;
    for (const report of result.reports) {
        if (!report || report.configError) continue;
        const afterActive = Number(report.afterActive || 0);
        const minActive = Number(report.minActive || 0);
        if (report.poolExhausted === true && afterActive < minActive) {
            const domain = normalizeTargetDomainName(report.domain || report.target?.domain);
            if (domain) domains.add(domain);
        }
    }
    return domains;
}

async function autoUpdateCountryPools(env, config, onlyDomains = null) {
    const enabledRaw = String(env.REMOTE_UPDATE_ENABLED || '').trim().toLowerCase();
    const sourceMap = parseRemoteDomainSources(env, config);
    const autoEnabled = enabledRaw ? ['1', 'true', 'yes', 'on'].includes(enabledRaw) : sourceMap.size > 0;
    if (!autoEnabled || sourceMap.size === 0) return { success: false, skipped: true, reason: 'not_enabled_or_no_sources' };

    const mode = String(env.REMOTE_UPDATE_MODE || 'replace').trim().toLowerCase() === 'append' ? 'append' : 'replace';
    const mappingJson = await requireKV(env).get('domain_pool_mapping') || '{}';
    const domainPoolMapping = safeJSONParse(mappingJson, {});
    const reports = [];
    const sourceCache = new Map();

    for (const [domain, source] of sourceMap.entries()) {
        if (onlyDomains && onlyDomains.size > 0 && !onlyDomains.has(domain)) continue;
        const poolKey = source.poolKey || (source.country ? `pool_${source.country}` : 'pool');
        const cacheKey = JSON.stringify({
            url: source.url,
            country: source.country || '',
            port: source.port || '',
            defaultPort: source.defaultPort || '',
            format: source.format || 'auto',
            ipColumn: source.ipColumn || '',
            portColumn: source.portColumn || '',
            countryColumn: source.countryColumn || ''
        });
        if (!sourceCache.has(cacheKey)) {
            const ips = await loadFromRemoteUrl(source.url, source);
            sourceCache.set(cacheKey, ips);
        }

        const ips = sourceCache.get(cacheKey) || '';
        const count = await savePoolText(env, poolKey, ips, mode);
        domainPoolMapping[domain] = poolKey;
        reports.push({ domain, country: source.country || '', poolKey, count, port: source.port, format: source.format || 'auto', source: source.url });
        console.log('🌐 远程IP池已更新: ' + domain + ' <= ' + (source.country || '-') + ', ' + poolKey + ', ' + count + '条, ' + source.url);
    }

    await requireKV(env).put('domain_pool_mapping', JSON.stringify(domainPoolMapping, null, 2));
    return { success: true, reports };
}


function scheduledReportNeedsRemoteUpdate(result) {
    if (!result || !Array.isArray(result.reports)) return false;
    return result.reports.some(report => {
        if (!report || report.configError) return false;
        const afterActive = Number(report.afterActive || 0);
        const minActive = Number(report.minActive || 0);
        return report.poolExhausted === true && afterActive < minActive;
    });
}

async function ensureCountryDomainPoolMapping(env, config) {
    const sourceMap = parseRemoteDomainSources(env, config);
    if (sourceMap.size === 0) return { updated: false, mapping: {} };

    const mappingJson = await requireKV(env).get('domain_pool_mapping') || '{}';
    const domainPoolMapping = safeJSONParse(mappingJson, {});
    let changed = false;

    for (const [domain, source] of sourceMap.entries()) {
        const poolKey = source.poolKey || (source.country ? `pool_${source.country}` : 'pool');
        if (domainPoolMapping[domain] !== poolKey) {
            domainPoolMapping[domain] = poolKey;
            changed = true;
        }
    }

    if (changed) {
        await requireKV(env).put('domain_pool_mapping', JSON.stringify(domainPoolMapping, null, 2));
    }

    return { updated: changed, mapping: domainPoolMapping };
}


async function scheduledMaintainWithConditionalRemoteUpdate(env, config) {
    // 先确保 US.xxx.xx / KR.xxx.xx 这类域名能自动映射到 pool_US / pool_KR。
    await ensureCountryDomainPoolMapping(env, config);

    // 默认只用当前 KV IP 池；只有不足时才拉远程源。REMOTE_UPDATE_ALWAYS=true 可强制每轮先刷新。
    const firstResult = config.remoteUpdateAlways ? { reports: [] } : await maintainAllDomains(env, false, config);

    if (!config.remoteUpdateAlways && !scheduledReportNeedsRemoteUpdate(firstResult)) {
        console.log('📦 本地IP池仍可用，跳过远程源更新');
        return firstResult;
    }

    const needDomains = config.remoteUpdateAlways ? new Set(config.targets.map(t => normalizeTargetDomainName(t.domain))) : getDomainsNeedingRemoteUpdate(firstResult);
    console.log('📦 本地IP池无可用候选或无法补足目标数量，开始按域名远程源更新: ' + Array.from(needDomains).join(', '));
    const updateResult = await autoUpdateCountryPools(env, config, needDomains);

    if (!updateResult || updateResult.skipped || !updateResult.reports || updateResult.reports.length === 0) {
        console.log('⚠️ 远程更新被跳过: ' + (updateResult?.reason || 'unknown'));
        return firstResult;
    }

    // 拉取远程源后再维护一次，让新池子立即参与补充。
    return await maintainAllDomains(env, false, config);
}

async function maintainAllDomains(env, isManual = false, config) {
    const allReports = [];
    const startTime = Date.now();

    const poolStats = new Map();
    // 内联 loadDomainPoolMapping
    const mappingJson = await requireKV(env).get('domain_pool_mapping') || '{}';
    const domainPoolMapping = safeJSONParse(mappingJson, {});

    // 跨轮次缓存 success=true 的检测结果，减少外部检测接口请求。
    const checkState = {
        cache: await loadJsonFromKV(env, CHECK_CACHE_KEY, {}),
        failCount: await loadJsonFromKV(env, CHECK_FAIL_KEY, {})
    };
    const checkCache = new Map();
    const checkProxyIPCached = async (addr) => {
        const key = normalizeCheckAddr((addr || '').trim());
        if (!key) return { success: false, message: 'empty candidate' };

        const persisted = checkState.cache?.[key];
        if (isFreshSuccessCache(persisted, config.checkCacheTtlMinutes)) {
            return toCachedCheckResult(key, persisted);
        }

        if (checkCache.has(key)) {
            const cached = checkCache.get(key);
            return cached && typeof cached.then === 'function' ? await cached : cached;
        }
        const p = checkProxyIP(key, config);
        checkCache.set(key, p);
        const res = await p;
        checkCache.set(key, res);
        return res;
    };

    const allKeys = await requireKV(env).list();
    const poolSettled = await Promise.allSettled(
        allKeys.keys.filter(k => k.name.startsWith('pool')).map(async k => {
            const raw = await requireKV(env).get(k.name) || '';
            return [k.name, parsePoolList(raw).length];
        })
    );
    const poolEntries = poolSettled
        .map(r => r.status === 'fulfilled' ? r.value : null)
        .filter(e => e !== null);
    poolEntries.forEach(([name, count]) => poolStats.set(name, { before: count, after: count }));

    for (let i = 0; i < config.targets.length; i++) {
        const target = config.targets[i];
        const { domain, mode, port, minActive } = target;

        const report = {
            target,
            domain,
            mode,
            port,
            minActive,
            beforeActive: 0,
            afterActive: 0,
            added: [],
            removed: [],
            poolRemoved: 0,
            poolExhausted: false,
            configError: false,
            checkDetails: [],
            logs: []
        };
        
        const addLog = (m) => {
            const formattedMsg = formatLogMessage(m);
            report.logs.push(formattedMsg);
            console.log(formattedMsg);
        };
        
        addLog(`🚀 开始维护: ${target.domain}`);
        // 域名到 IP 池映射：优先使用规范化域名，避免大小写/前缀导致命中失败。
        const normalizedDomain = normalizeTargetDomainName(target.domain);
        const poolKey = domainPoolMapping?.[normalizedDomain] ?? domainPoolMapping?.[target.domain] ?? 'pool';

        if (target.mode === 'A') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config, checkState);
        } else if (target.mode === 'TXT') {
            await maintainTXTRecords(env, target, addLog, report, poolKey, checkProxyIPCached, config, checkState);
        } else if (target.mode === 'ALL') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config, checkState);

            const txtTarget = {
                ...target,
                mode: 'TXT'
            };

            const txtReport = {
                ...report,
                beforeActive: 0,
                afterActive: 0,
                added: [],
                removed: [],
                checkDetails: [],
                logs: [],
                poolRemoved: 0,
                poolExhausted: false,
                configError: false
            };
            const addTxtLog = (m) => {
                const formattedMsg = formatLogMessage(m);
                txtReport.logs.push(formattedMsg);
                console.log(formattedMsg);
            };
            await maintainTXTRecords(env, txtTarget, addTxtLog, txtReport, poolKey, checkProxyIPCached, config, checkState);
            
            report.txtLogs = txtReport.logs;
            report.txtAdded = txtReport.added;
            report.txtRemoved = txtReport.removed;
            report.txtActive = txtReport.afterActive;
            report.poolRemoved += txtReport.poolRemoved;
            if (txtReport.poolExhausted) {
                report.poolExhausted = true;
            }
            if (txtReport.configError) {
                report.configError = true;
            }
        }
        
        addLog(`✅ 完成: ${report.afterActive}/${target.minActive}`);
        allReports.push(report);
    }

    // 更新池统计（无需再次遍历 KV 读取：直接使用维护过程中已知的最终池长度）
    for (const r of allReports) {
        if (r && r.poolKeyUsed && typeof r.poolAfterCount === 'number' && poolStats.has(r.poolKeyUsed)) {
            poolStats.get(r.poolKeyUsed).after = r.poolAfterCount;
        }
    }

    // 重新读取垃圾桶的实际数量（维护过程中 batchAddToTrash 直接写入 KV，不经过 report）
    if (poolStats.has('pool_trash')) {
        const trashRaw = await requireKV(env).get('pool_trash') || '';
        poolStats.get('pool_trash').after = parsePoolList(trashRaw).length;
    }
     
    // 维护结束后批量写入检测缓存/失败次数，避免每个候选单独写 KV。
    await saveJsonToKV(env, CHECK_CACHE_KEY, checkState.cache || {});
    await saveJsonToKV(env, CHECK_FAIL_KEY, checkState.failCount || {});

    // 1. 检查是否有IP变化（删除或新增）
    const hasIPChanges = allReports.some(r => 
        r.added.length > 0 || 
        r.removed.length > 0 || 
        (r.txtAdded && r.txtAdded.length > 0) || 
        (r.txtRemoved && r.txtRemoved.length > 0)
    );
    
    // 2. 检查是否有配置错误
    const hasConfigError = allReports.some(r => r.configError);

    // 3. 检查是否有域名活跃数不足且无法补充IP
    // 注：poolExhausted 表示候选IP不足（包括池枯竭、端口不匹配等情况）
    const hasInsufficientActive = allReports.some(r => 
        r.afterActive < r.minActive && r.poolExhausted
    );
    
    // 通知条件：手动执行 OR IP变化 OR 活跃数不足 OR 配置错误
    // 注：移除了 hasPoolExhausted，因为 hasInsufficientActive 已涵盖"无法补充IP"的场景
    const shouldNotify = isManual || hasIPChanges || hasInsufficientActive || hasConfigError;

    let tgResult = { sent: false, reason: 'no_need' };
    if (shouldNotify) {
        tgResult = await sendTG(allReports, poolStats, isManual, config);
    }

    console.log(`✅ 维护任务完成，总耗时: ${Date.now() - startTime}ms，处理域名: ${config.targets.length}个`);
    
    return {
        success: true,
        reports: allReports,
        poolStats: Object.fromEntries(poolStats),
        notified: tgResult.sent,
        tgStatus: tgResult,
        processingTime: Date.now() - startTime
    };
}

function formatIPInfoStr(ipInfoMap, ip) {
    const ipOnly = ip.split(':')[0];
    const info = ipInfoMap.get(ipOnly);
    if (!info) return '';
    let s = ` · ${info.country}`;
    if (info.asn) s += ` · ${info.asn}`;
    if (info.isp) s += ` · ${info.isp}`;
    return s;
}

function formatIPChanges(added, removed, ipInfoMap, port = '', minActive = 0, afterActive = 0) {
    let msg = '';
    if (added && added.length > 0) {
        msg += `📈 新增 ${added.length} 个IP\n`;
        added.forEach(item => {
            const displayIP = item.ip.includes(':') ? item.ip : `${item.ip}:${port}`;
            msg += `   ✅ <code>${displayIP}</code>\n`;
            msg += `      ${item.colo} · ${item.time}ms${formatIPInfoStr(ipInfoMap, item.ip)}\n`;
        });
    }
    if (removed && removed.length > 0) {
        msg += `📉 移除 ${removed.length} 个IP\n`;
        removed.forEach(item => {
            msg += `   ❌ <code>${item.ip}</code>\n`;
            msg += `      原因: ${item.reason}\n`;
        });
    }
    if ((!added || added.length === 0) && (!removed || removed.length === 0)) {
        msg += `✨ 所有IP正常，无变化\n`;
    }
    msg += `✅ 完成: ${afterActive}/${minActive}\n`;
    return msg;
}

async function sendTG(reports, poolStats, isManual, config) {
    if (!config.tgToken || !config.tgId) {
        console.log('📱 TG未配置，跳过通知');
        return { sent: false, reason: 'not_configured', message: 'TG未配置' };
    }

    const modeLabel = { 'A': 'A记录', 'TXT': 'TXT记录', 'ALL': '双模式' };
    const timestamp = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });

    let msg = isManual ? `🔧 <b>DDNS 手动维护报告</b>\n` : `⚙️ <b>DDNS 自动维护报告</b>\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n⏰ ${timestamp}\n\n`;

    const hasConfigError = reports.some(r => r.configError);
    if (hasConfigError) {
        msg += `⚠️ <b>警告: 检测到配置错误</b>\n请检查 CF_KEY, CF_ZONEID 是否正确配置\n\n`;
    }

    // 收集所有IP用于批量查询归属地
    const allIPsForInfo = new Set();
    reports.forEach(r => {
        (r.checkDetails || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
        (r.added || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
        (r.txtAdded || []).forEach(d => allIPsForInfo.add(d.ip.split(':')[0]));
    });

    const ipInfoMap = new Map();
    if (config.ipInfoEnabled && allIPsForInfo.size > 0) {
        await Promise.all(Array.from(allIPsForInfo).map(async ip => {
            const info = await getIPInfo(ip, config);
            if (info) ipInfoMap.set(ip, info);
        }));
    }

    reports.forEach((report, index) => {
        if (index > 0) msg += `\n`;
        msg += `━━ <code>${report.domain}</code> ━━\n`;
        msg += `${modeLabel[report.mode]}`;
        if (report.mode === 'A' || report.mode === 'ALL') msg += ` · 端口 ${report.port}`;
        msg += ` · 最小活跃数 ${report.minActive}\n\n`;

        if (report.configError) {
            msg += `❌ <b>配置错误，无法获取记录</b>\n`;
            return;
        }

        // 检测详情
        if (report.checkDetails && report.checkDetails.length > 0) {
            report.checkDetails.forEach(d => {
                const icon = d.status.includes('✅') ? '✅' : '❌';
                msg += `${icon} <code>${d.ip}</code>\n   ${d.colo} · ${d.time}ms${formatIPInfoStr(ipInfoMap, d.ip)}\n`;
            });
            msg += `\n`;
        }

        // A记录或ALL模式的A记录部分
        if (report.mode === 'A' || report.mode === 'ALL') {
            msg += formatIPChanges(report.added, report.removed, ipInfoMap, report.port, report.minActive, report.afterActive);
        }

        // ALL模式的TXT记录部分
        if (report.mode === 'ALL' && report.txtActive !== undefined) {
            msg += `\n<b>📝 TXT记录</b>\n`;
            msg += formatIPChanges(report.txtAdded, report.txtRemoved, ipInfoMap, '', report.minActive, report.txtActive);
        }

        // 纯TXT模式
        if (report.mode === 'TXT') {
            msg += formatIPChanges(report.added, report.removed, ipInfoMap, '', report.minActive, report.afterActive);
        }
    });

    msg += `\n━━━━━━━━━━━━━━━━━━\n`;
    msg += `📦 <b>IP池库存统计</b>\n`;

    for (const [poolKey, stats] of poolStats) {
        const displayName = getPoolDisplayName(poolKey);
        msg += `\n<b>${displayName}</b>\n`;
        msg += `   维护前: ${stats.before} 个\n`;
        msg += `   维护后: ${stats.after} 个\n`;

        const change = stats.after - stats.before;
        if (change !== 0) {
            const changeSymbol = change > 0 ? '📈' : '📉';
            msg += `   ${changeSymbol} 变化: ${change > 0 ? '+' : ''}${change}\n`;
        }

        // 垃圾桶/系统数据池不参与枯竭或低库存告警
        if (poolKey !== 'pool_trash' && poolKey !== 'domain_pool_mapping') {
            if (stats.after === 0 && stats.before > 0) {
                msg += `   ⚠️ <b>警告：${displayName}已枯竭！</b>\n`;
            } else if (stats.after < 10) {
                msg += `   ⚠️ 库存较低\n`;
            }
        }
    }

    if (isManual && config.projectUrl) {
        msg += `\n🔗 <a href="${config.projectUrl}">打开管理面板</a>\n`;
    }

    try {
        const response = await fetch(`https://api.telegram.org/bot${config.tgToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: config.tgId,
                text: msg,
                parse_mode: 'HTML',
                disable_web_page_preview: true
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error('❌ TG配置错误，发送失败。请检查TG_TOKEN和TG_ID是否正确:', errorData);
            return {
                sent: false,
                reason: 'config_error',
                message: 'TG配置错误，请检查TG_TOKEN和TG_ID',
                detail: errorData.description || '未知错误'
            };
        } else {
            console.log('✅ TG通知发送成功');
            return { sent: true, reason: 'success', message: 'TG通知发送成功' };
        }
    } catch (e) {
        console.error('❌ TG发送失败，网络错误:', e.message);
        return {
            sent: false,
            reason: 'network_error',
            message: 'TG发送失败，网络错误',
            detail: e.message
        };
    }
}

