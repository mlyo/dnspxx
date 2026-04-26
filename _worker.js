/**
 * DDNS Pro & Proxy IP Manager v7.0
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
    checkApi: 'https://check.proxyip.cmliussss.net/check?proxyip=',  // CHECK_API: ProxyIP 检测接口
    checkApiToken: '',       // CHECK_API_TOKEN: 检测接口认证Token
    checkApiBackup: 'https://check.proxyip.cmliussss.net/check?proxyip=',      // CHECK_API_BACKUP: 备用检测接口
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
    CONCURRENT_CHECKS: 15,       // 前端批量检测并发数
    CHECK_TIMEOUT: 3000,         // 单次 ProxyIP 检测超时(ms)

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

function checkRequestAuth(request, url, env) {
    const requiredKey = (env.AUTH_KEY || '').trim();
    if (!requiredKey) {
        return { enabled: false, ok: true, shouldSetCookie: false };
    }

    const { bearer, xAuth, qKey, cKey } = getAuthCandidateFromRequest(request, url);
    const ok = bearer === requiredKey || xAuth === requiredKey || qKey === requiredKey || cKey === requiredKey;
    const shouldSetCookie = ok && qKey === requiredKey && cKey !== requiredKey;
    return { enabled: true, ok, shouldSetCookie };
}

function unauthorizedResponse(url) {
    const isApi = url.pathname.startsWith('/api/');
    if (isApi) {
        return jsonResponse({
            success: false,
            error: '未授权',
            message: '需要提供 AUTH_KEY'
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
            headers.set('Set-Cookie', `ddns_auth=${encodeURIComponent(requiredKey)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`);
            return new Response(JSON.stringify({ success: true }), { status: 200, headers });
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
    if (!assetPath || assetPath === '/') assetPath = '/index.html';

    let upstream = await fetch(origin + assetPath + url.search, {
        headers: { 'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0' },
        cf: { cacheTtl: assetPath === '/index.html' ? 0 : 300 }
    });

    if (upstream.status === 404 && !assetPath.includes('.')) {
        upstream = await fetch(origin + '/index.html', { cf: { cacheTtl: 0 } });
    }

    const headers = new Headers(upstream.headers);
    if (assetPath === '/index.html') headers.set('Cache-Control', 'no-store');
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

        const buildAuthCookie = () => `ddns_auth=${encodeURIComponent((env.AUTH_KEY || '').trim())}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;

        if (url.protocol === 'http:') {
            return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
        }

        if (url.pathname === '/favicon.ico') {
            return new Response(null, { status: 204 });
        }

        if (url.pathname === '/') {
            return redirect('/admin/');
        }

        if (url.pathname === '/logout') {
            return redirect('/login', { 'Set-Cookie': 'ddns_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' });
        }

        if (url.pathname === '/login') {
            return await handleLogin(request, env);
        }

        const isAdminPath = url.pathname === '/admin' || url.pathname.startsWith('/admin/');
        const isApiPath = url.pathname.startsWith('/api/');

        const auth = checkRequestAuth(request, url, env);

        if (isAdminPath) {
            if (auth.enabled && !auth.ok) return redirect('/login');
            const adminResponse = await handleAdminAssets(request, env);
            if (auth.shouldSetCookie) {
                const headers = new Headers(adminResponse.headers);
                headers.set('Set-Cookie', buildAuthCookie());
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
                headers.set('Set-Cookie', buildAuthCookie());
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
                await maintainAllDomains(env, false, config);
                console.log(`✅ 定时任务完成，总耗时: ${Date.now() - startTime}ms`);
            })());
        } catch (e) {
            console.error('❌ 定时任务失败:', e);
        }
    }
};

const API_ROUTES = {
    '/api/get-pool': (url, req, env, config) => handleGetPool(url, env),
    '/api/save-pool': (url, req, env, config) => handleSavePool(req, env, config),
    '/api/load-remote-url': (url, req, env, config) => handleLoadRemoteUrl(req),
    '/api/current-status': (url, req, env, config) => handleCurrentStatus(url, config),
    '/api/lookup-domain': (url, req, env, config) => handleLookupDomain(url, config),
    '/api/check-ip': (url, req, env, config) => handleCheckIP(url, config),
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
    '/api/maintain'
]);

async function handleAPIRequest(url, request, env, config) {
    if (POST_ONLY_ROUTES.has(url.pathname) && request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    const handler = API_ROUTES[url.pathname];
    return handler ? await handler(url, request, env, config) : new Response('Not Found', { status: 404 });
}

async function handleGetPool(url, env) {
    const poolKey = url.searchParams.get('poolKey') || 'pool';
    const onlyCount = url.searchParams.get('onlyCount') === 'true';
    
    const pool = await env.IP_DATA.get(poolKey) || '';
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
    const poolKey = body.poolKey || 'pool';
    const mode = body.mode || 'append'; // append: 追加, replace: 覆盖, remove: 删除
    const newIPs = await cleanIPListAsync(body.pool || '', false, config);

    if (!newIPs && mode !== 'remove') {
        return badRequest({ success: false, error: '没有有效IP' });
    }

    const existingPool = await env.IP_DATA.get(poolKey) || '';
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
    await env.IP_DATA.put(poolKey, finalPool);

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
        defaultPort: body.defaultPort || '443'
    };

    const ips = await loadFromRemoteUrl(url, options);
    return jsonResponse({ 
        success: true, 
        ips,
        count: ips ? ips.split('\n').filter(Boolean).length : 0,
        source: url,
        filter: options.cfCountry ? { cfCountry: options.cfCountry } : null
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
    const useBackup = url.searchParams.get('useBackup') === 'true';
    if (useBackup && config.checkApiBackup) {
        const addr = normalizeCheckAddr(target);
        const result = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken);
        return jsonResponse(result ?? { success: false });
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
    const res = await maintainAllDomains(env, isManual, config);

    // 将日志包含在响应中
    return jsonResponse({
        ...res,
        // 确保所有日志都返回给前端
        allLogs: res.reports.flatMap(r => r.logs)
    });
}

async function handleGetDomainPoolMapping(env) {
    const mappingJson = await env.IP_DATA.get('domain_pool_mapping') || '{}';
    const mapping = safeJSONParse(mappingJson, {});
    
    const allKeys = await env.IP_DATA.list();
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
    await env.IP_DATA.put('domain_pool_mapping', JSON.stringify(body.mapping));
    return jsonResponse({ success: true });
}

async function handleCreatePool(request, env) {
    const body = await readJsonBody(request);
    if (!body) {
        return badRequest({ success: false, error: '请求体不是有效JSON' });
    }
    const poolKey = body.poolKey;
    
    if (!poolKey || !poolKey.startsWith('pool_')) {
        return badRequest({ success: false, error: '池名称必须以pool_开头' });
    }
    
    // 支持中文、字母、数字、下划线、横杠
    if (poolKey.length > GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH || !/^pool_[\u4e00-\u9fa5a-zA-Z0-9_-]+$/.test(poolKey)) {
        return badRequest({ success: false, error: `池名称只能包含中文、字母、数字、下划线、横杠，最长${GLOBAL_SETTINGS.MAX_POOL_NAME_LENGTH}字符` });
    }
    
    const existing = await env.IP_DATA.get(poolKey);
    if (existing !== null) {
        return badRequest({ success: false, error: '池已存在' });
    }
    
    await env.IP_DATA.put(poolKey, '');
    return jsonResponse({ success: true });
}

async function handleDeletePool(url, env) {
    const poolKey = url.searchParams.get('poolKey');
    
    if (!poolKey) {
        return badRequest({ success: false, error: '缺少poolKey参数' });
    }
    
    // 保护系统池
    const protectedPools = ['pool', 'domain_pool_mapping', 'pool_trash'];
    if (protectedPools.includes(poolKey)) {
        return badRequest({ success: false, error: `不能删除${getPoolDisplayName(poolKey)}` });
    }
    
    try {
        await env.IP_DATA.delete(poolKey);
        return jsonResponse({ success: true });
    } catch (e) {
        console.error('删除池失败:', e);
        return jsonResponse({ success: false, error: '删除池失败' });
    }
}

async function handleClearTrash(env) {
    await env.IP_DATA.put('pool_trash', '');
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
    let trashList = parsePoolList(await env.IP_DATA.get('pool_trash'));
    
    let restored = 0;
    const restoredByPool = {};

    // 读取/写入多个池：按需懒加载
    const poolCache = new Map(); // poolKey -> { list: string[], set: Set<string> }
    async function loadPool(poolKey) {
        if (poolCache.has(poolKey)) return poolCache.get(poolKey);
        const list = parsePoolList(await env.IP_DATA.get(poolKey));
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
    await env.IP_DATA.put('pool_trash', Array.from(trashMap.values()).join('\n'));
    for (const [poolKey, poolObj] of poolCache.entries()) {
        await env.IP_DATA.put(poolKey, poolObj.list.join('\n'));
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

    if (request) {
        const url = new URL(request.url);
        config.projectUrl = `${url.protocol}//${url.host}`;
    }

    return Object.freeze(config);
}

async function batchAddToTrash(env, entries) {
    if (!entries || entries.length === 0) return;
    const trashKey = 'pool_trash';
    let trashList = parsePoolList(await env.IP_DATA.get(trashKey));
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

    await env.IP_DATA.put(trashKey, trashList.join('\n'));
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

function extractRemoteCSVIPs(text, options = {}) {
    const expectedCountry = normalizeCountryCode(options.cfCountry || '');
    const defaultPort = String(options.defaultPort || '443');
    const rows = parseCSVRows(text);
    if (!rows.length) return '';

    const headers = rows[0];
    let ipIdx = pickCSVColumn(headers, ['IP', 'ip', 'address', '地址', 'IP地址']);
    let portIdx = pickCSVColumn(headers, ['端口', 'port']);
    let countryIdx = pickCSVColumn(headers, ['CF归属国', 'cf归属国', 'CF国家', 'cfCountry', 'country', '归属国', '国家']);
    const hasHeader = ipIdx !== -1 || portIdx !== -1 || countryIdx !== -1;

    // 兼容该 result.csv 的固定 schema：IP,cf-meta-ip,端口,速度(Mbps),CF归属国,机房,...
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
        // 关键：严格按“CF归属国”列过滤；比如 expectedCountry=US 时，CA 行必须被过滤掉。
        if (expectedCountry && country !== expectedCountry) continue;

        const key = `${ip}:${port}`;
        result.set(key, `${key} # CF归属国 ${country || '-'}`);
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
            hostname.startsWith('169.254.') ||   // 链路本地地址 (AWS/GCP 元数据服务等)
            hostname.startsWith('100.64.') ||    // 运营商级 NAT (RFC 6598)
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
            const contentType = r.headers.get('content-type') || '';
            if (path.endsWith('.csv') || contentType.includes('csv')) {
                return extractRemoteCSVIPs(text, options);
            }
            return await cleanIPListAsync(text, false); // 不解析域名，只清洗IP格式
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

// 单次检测IP（不带重试）
async function checkProxyIPOnce(addr, apiUrl, token) {
    try {
        let url = `${apiUrl}${encodeURIComponent(addr)}`;
        if (token) {
            url += `${url.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`;
        }

        const r = await fetch(url, { signal: AbortSignal.timeout(GLOBAL_SETTINGS.CHECK_TIMEOUT) });
        if (!r.ok) return null;

        const data = safeJSONParse(await r.text(), null);
        return data && typeof data === 'object' ? data : null;
    } catch {
        return null;
    }
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

    // 主接口检测
    const result = await checkProxyIPOnce(addr, config.checkApi, config.checkApiToken);
    if (result !== null) return result;

    // 备用接口检测
    if (config.checkApiBackup) {
        const backup = await checkProxyIPOnce(addr, config.checkApiBackup, config.checkApiBackupToken);
        if (backup !== null) return backup;
    }

    return { success: false };
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
    const pool = await env.IP_DATA.get(poolKey) || '';
    
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

async function maintainRecordsCommon(options) {
    const {
        env,
        target,
        addLog,
        report,
        poolKey,
        checkFn,
        getCurrentIPs,
        deleteRecord,
        addRecord,
        shouldSkipCandidate
    } = options;

    const currentIPs = getCurrentIPs();
    let poolList = parsePoolList(await env.IP_DATA.get(poolKey));
    report.poolKeyUsed = poolKey;

    let validIPs = [];
    let poolModified = false;
    const trashBatch = [];

    // 并行检测所有现有IP
    const checkSettled = await Promise.allSettled(
        currentIPs.map(item => checkFn(item.addr).then(
            r => ({ item, result: r }),
            () => ({ item, result: { success: false } })
        ))
    );
    const checkResults = checkSettled.map(r =>
        r.status === 'fulfilled' ? r.value : { item: currentIPs[0], result: { success: false } }
    );
    // 串行处理结果（删除操作需要顺序执行）
    for (const { item, result: checkResult } of checkResults) {
        report.checkDetails.push({
            ip: item.addr,
            status: checkResult.success ? '✅ 活跃' : '❌ 失效',
            colo: checkResult.colo || 'N/A',
            time: checkResult.responseTime || '-'
        });

        if (checkResult.success) {
            validIPs.push(item.ip);
            addLog(`  ✅ ${item.addr} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
        } else {
            report.removed.push({ ip: item.addr, reason: '检测失效' });
            await deleteRecord(item.id);

            poolList = poolList.filter(p => extractIPKey(p) !== item.addr);
            report.poolRemoved++;
            poolModified = true;

            trashBatch.push({ ipAddr: item.addr, reason: '维护失效', poolKey });
            addLog(`  ❌ ${item.addr} - 失效已删除，已放入垃圾桶`);
        }
    }

    report.beforeActive = validIPs.length;

    // 补充IP
    if (validIPs.length < target.minActive) {
        addLog(`需补充: ${target.minActive - validIPs.length} 个`);
        const candidates = await getCandidateIPs(env, target, addLog, poolKey);

        for (const item of candidates) {
            if (validIPs.length >= target.minActive) break;
            const ipPort = extractIPKey(item);
            if (!ipPort || shouldSkipCandidate(ipPort, validIPs)) continue;

            const checkResult = await checkFn(ipPort);
            if (checkResult && checkResult.success) {
                const ip = ipPort.split(':')[0];
                await addRecord(ip);
                validIPs.push(ip);
                report.added.push({ ip: ipPort, colo: checkResult.colo || 'N/A', time: checkResult.responseTime || '-' });
                addLog(`  ✅ ${ipPort} - ${checkResult.colo} (${checkResult.responseTime}ms)`);
            } else {
                poolList = poolList.filter(p => extractIPKey(p) !== ipPort);
                report.poolRemoved++;
                poolModified = true;
                trashBatch.push({ ipAddr: ipPort, reason: '补充检测失败', poolKey });
                addLog(`  ❌ ${ipPort} - 检测失败，从池中移除并放入垃圾桶`);
            }
        }

        if (validIPs.length < target.minActive) {
            report.poolExhausted = true;
            addLog(`⚠️ ${poolKey} 库存不足，无法达到最小活跃数 ${target.minActive}`);
        }
    }

    // 批量写入垃圾桶
    if (trashBatch.length > 0) {
        await batchAddToTrash(env, trashBatch);
    }

    if (poolModified) {
        await env.IP_DATA.put(poolKey, poolList.join('\n'));
    }

    report.poolAfterCount = poolList.length;
    report.afterActive = validIPs.length;
}

async function maintainARecords(env, target, addLog, report, poolKey, checkFn, config) {
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
        }
    });
}

async function maintainTXTRecords(env, target, addLog, report, poolKey, checkFn, config) {
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
        shouldSkipCandidate: (ipPort, activeList) => activeList.includes(ipPort)
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

async function maintainAllDomains(env, isManual = false, config) {
    const allReports = [];
    const startTime = Date.now();

    const poolStats = new Map();
    // 内联 loadDomainPoolMapping
    const mappingJson = await env.IP_DATA.get('domain_pool_mapping') || '{}';
    const domainPoolMapping = safeJSONParse(mappingJson, {});

    // 单次维护任务内缓存 proxyip 检测结果，减少重复外部请求（不改变结果，仅减少请求次数）
    const checkCache = new Map();
    const checkProxyIPCached = async (addr) => {
        const key = (addr || '').trim();
        if (!key) return { success: false };
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

    const allKeys = await env.IP_DATA.list();
    const poolSettled = await Promise.allSettled(
        allKeys.keys.filter(k => k.name.startsWith('pool')).map(async k => {
            const raw = await env.IP_DATA.get(k.name) || '';
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
        // 内联 getPoolKeyForDomain
        const poolKey = domainPoolMapping?.[target.domain] ?? 'pool';

        if (target.mode === 'A') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);
        } else if (target.mode === 'TXT') {
            await maintainTXTRecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);
        } else if (target.mode === 'ALL') {
            await maintainARecords(env, target, addLog, report, poolKey, checkProxyIPCached, config);

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
            await maintainTXTRecords(env, txtTarget, addTxtLog, txtReport, poolKey, checkProxyIPCached, config);
            
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
        const trashRaw = await env.IP_DATA.get('pool_trash') || '';
        poolStats.get('pool_trash').after = parsePoolList(trashRaw).length;
    }
     
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

