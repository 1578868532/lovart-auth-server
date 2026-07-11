const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const { createOtpState } = require('./lib/otp-state');
const { createImapOtpWorker } = require('./lib/imap-otp-worker');

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// In production ADMIN_SECRET must be set via environment variable; the fallback only works in local dev.
const ADMIN_SECRET = process.env.ADMIN_SECRET || (IS_PRODUCTION ? '' : 'dev-local-only-not-for-production');
const OTP_RATE_LIMIT = Number(process.env.OTP_RATE_LIMIT || 120);
const OTP_RATE_WINDOW_MS = 60 * 1000;
const OTP_SESSION_TTL_MS = Number(process.env.OTP_SESSION_TTL_MS || 5 * 60 * 1000);
const OTP_BUFFER_MAX_AGE_MS = Number(process.env.OTP_BUFFER_MAX_AGE_MS || 10 * 60 * 1000);
const OTP_BUFFER_MAX_SIZE = Number(process.env.OTP_BUFFER_MAX_SIZE || 200);

// Worker 层凭证（仅存在于此文件，不暴露到 API 层）
const WORKER_EMAIL = String(process.env.OTP_EMAIL || '').trim();
const WORKER_PASS = String(process.env.OTP_PASS || '').trim();
const OTP_IMAP_USE_PROXY = String(process.env.OTP_IMAP_USE_PROXY || 'false').toLowerCase() === 'true';
const OTP_IMAP_PROXY_SERVER = String(process.env.OTP_IMAP_PROXY_SERVER || '').trim();

// === 抗并发 OTP 系统 ===
// OTP Session Store: sessionKey → { email, machineId, requestId, code, createdAt, used, status }
// Inbox Buffer: [{ to, text, code, timestamp, messageId, used }]
// Processing Lock: `${email}_${machineId}` → { time }
// Rate limiting
const otpRateBuckets = new Map();
// IMAP Worker state

function createEmptyDB() {
    return { licenses: [], sessions: [] };
}

function loadDB() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify(createEmptyDB(), null, 2), 'utf8');
    }

    try {
        const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        return {
            licenses: Array.isArray(db.licenses) ? db.licenses : [],
            sessions: Array.isArray(db.sessions) ? db.sessions : []
        };
    } catch (error) {
        throw new Error(`db.json is invalid: ${error.message}`);
    }
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function now() {
    return Date.now();
}

function refreshDateKey(time = Date.now()) {
    return new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Asia/Shanghai',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(new Date(time));
}

function createToken() {
    return crypto.randomBytes(32).toString('hex');
}

function createLicenseKey() {
    return `LV-${crypto.randomBytes(10).toString('hex').toUpperCase()}`;
}

const LICENSE_PRIVATE_KEY = process.env.LICENSE_PRIVATE_KEY
    ? crypto.createPrivateKey(process.env.LICENSE_PRIVATE_KEY.replace(/\\n/g, '\n'))
    : null;
const LICENSE_PUBLIC_KEY = crypto.createPublicKey(
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJVmR7Yrj3zh/GDV9txERvI/v/9UI7w/4k/pR7n/tHlc=\n-----END PUBLIC KEY-----'
);

function createLV3LicenseKey(plan, expireAt) {
    if (!LICENSE_PRIVATE_KEY) throw new Error('LICENSE_PRIVATE_KEY not set');
    const payload = {
        kid: crypto.randomBytes(4).toString('hex'),
        machineId: 'UNBOUND',
        expire: expireAt,
        plan: plan,
        hasGift: plan === 'permanent'
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.sign(null, Buffer.from(payloadB64), LICENSE_PRIVATE_KEY);
    return 'LV3.' + payloadB64 + '.' + sig.toString('base64url');
}

function requireAdmin(req, res) {
    if (!ADMIN_SECRET) {
        res.status(503).json({ success: false, message: 'ADMIN_SECRET is not configured' });
        return false;
    }

    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
        res.status(403).json({ success: false, message: '管理员密钥错误' });
        return false;
    }
    return true;
}

function getLicenseForSession(req) {
    const body = req.body || {};

    // 支持 Electron 本地卡密模式（LV2/LV3，无 sessionToken）
    if (body.licenseMode === 'local-lv2') {
        const licenseKey = String(body.licenseKey || '').trim();
        const machineId = String(body.machineId || '').trim();
        if (!licenseKey || !machineId) return { error: '缺少授权信息' };
        if (!licenseKey.startsWith('LV2.') && !licenseKey.startsWith('LV3.')) return { error: 'license_invalid' };

        try {
            const parts = licenseKey.split('.');
            if (parts.length !== 3) return { error: 'license_invalid' };

            // Ed25519 签名验证
            const payloadB64 = parts[1];
            const sig = Buffer.from(parts[2], 'base64url');
            const payloadBytes = Buffer.from(Buffer.from(payloadB64, 'base64url').toString('utf8'), 'utf8');
            const valid = crypto.verify(null, payloadBytes, LICENSE_PUBLIC_KEY, sig) ||
                crypto.verify(null, Buffer.from(payloadB64), LICENSE_PUBLIC_KEY, sig);
            if (!valid) return { error: 'license_invalid' };

            const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

            if (String(payload.machineId) !== machineId) return { error: 'license_invalid' };
            if (!Number.isFinite(Number(payload.expire)) || Number(payload.expire) <= now()) {
                return { error: 'license_invalid' };
            }

            return {
                licenseMode: 'local-lv2',
                machineId,
                licenseKey,
                rateLimitKey: machineId,
                expire_at: Number(payload.expire)
            };
        } catch (e) {
            return { error: 'license_invalid' };
        }
    }

    // 原有 session 模式
    const authorization = String(req.headers.authorization || '');
    const sessionToken = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
    const machineId = String(req.headers['x-machine-id'] || '').trim();
    if (!sessionToken || !machineId) return { error: '缺少授权信息' };

    const db = loadDB();
    const session = db.sessions.find(item => item.sessionToken === sessionToken);
    if (!session || session.machineId !== machineId) return { error: '授权会话无效' };

    const license = db.licenses.find(item => item.licenseKey === session.licenseKey);
    if (!license || license.status !== 'active') return { error: '授权已失效' };
    if (now() > Number(license.expire_at) || now() > Number(session.expire_at)) return { error: '授权已过期' };
    return { db, session, license, sessionToken, machineId, rateLimitKey: sessionToken };
}

function requireLicenseSession(req, res) {
    try {
        const auth = getLicenseForSession(req);
        if (auth.error) {
            res.status(401).json({ success: false, error: auth.error });
            return null;
        }
        return auth;
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
        return null;
    }
}

function allowOtpRequest(key) {
    const currentTime = now();
    const recent = (otpRateBuckets.get(key) || []).filter(timestamp => currentTime - timestamp < OTP_RATE_WINDOW_MS);
    if (recent.length >= OTP_RATE_LIMIT) return false;
    recent.push(currentTime);
    otpRateBuckets.set(key, recent);
    return true;
}

function normalizeTargetEmail(value) {
    const email = String(value || '').trim().toLowerCase();
    if (!email) return '';
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
    return email;
}

const IMAP_ERROR_CODES = new Set(['imap_auth_failed', 'imap_proxy_failed', 'imap_network_failed']);

function stableImapErrorCode(value) {
    const code = typeof value === 'string' ? value : value && value.code;
    return IMAP_ERROR_CODES.has(code) ? code : 'imap_network_failed';
}

function normalizeCandidateRecipient(value) {
    const match = String(value || '').match(/[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+/);
    return match ? normalizeTargetEmail(match[0]) : null;
}


function createApp({ otpWorker, otpState, now: appNow = now } = {}) {
  if (!otpWorker || !otpState) throw new TypeError('otpWorker and otpState are required');
  const app = express();
  const trackedSessions = new Map();

  app.use(cors());
  app.use(express.json({ limit: '32kb' }));

app.use((req, res, next) => {
  console.log('[REQ]', req.method, req.path, req.query || {});
  next();
});

app.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'auth server running', time: now() });
});

app.get('/api/otp/status', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const workerStatus = typeof otpWorker.getStatus === 'function' ? otpWorker.getStatus() : {};
    const stateStatus = typeof otpState.getStatus === 'function' ? otpState.getStatus() : {};
    const latestErrorCode = workerStatus.lastErrorCode || (stateStatus.lastError && stateStatus.lastError.code);
    let pendingSessions = 0;
    for (const [key, request] of trackedSessions) {
        const session = typeof otpState.getSession === 'function' ? otpState.getSession(request) : null;
        if (!session || session.status !== 'pending') {
            trackedSessions.delete(key);
        } else {
            pendingSessions += 1;
        }
    }

    res.json({
        success: true,
        worker: {
            connected: Boolean(workerStatus.connected),
            idling: Boolean(workerStatus.idling),
            lastEventAt: Number.isFinite(workerStatus.lastEventAt) ? workerStatus.lastEventAt : null,
            reconnectCount: Number(workerStatus.reconnectCount) || 0,
            lastErrorCode: latestErrorCode ? stableImapErrorCode(latestErrorCode) : null,
            proxyEnabled: OTP_IMAP_USE_PROXY
        },
        pendingSessions,
        metrics: {
            lastScanDurationMs: Number(workerStatus.lastScanDurationMs) || 0,
            lastScanScanned: Number(workerStatus.lastScanScanned) || 0,
            lastScanCandidates: Number(workerStatus.lastScanCandidates) || 0,
            totalScanScanned: Number(workerStatus.totalScanScanned) || 0,
            totalScanCandidates: Number(workerStatus.totalScanCandidates) || 0
        }
    });
});

app.post('/api/admin/create-license', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const days = Math.min(Number(req.body && req.body.days || 30), 365);
    const maxSlots = Number(req.body && req.body.maxSlots || 3);
    const maxAccounts = Number(req.body && req.body.maxAccounts || 100);
    const plan = String(req.body && req.body.plan || 'monthly').trim() || 'monthly';
    if (!Number.isFinite(days) || days <= 0 || !Number.isFinite(maxSlots) || maxSlots <= 0 || !Number.isFinite(maxAccounts) || maxAccounts <= 0) {
        return res.status(400).json({ success: false, message: '授权参数无效' });
    }

    const db = loadDB();
    let licenseKey;
    const expireAt = now() + days * 86400000;
    if (LICENSE_PRIVATE_KEY) {
        licenseKey = createLV3LicenseKey(plan, expireAt);
    } else {
        licenseKey = createLicenseKey();
        while (db.licenses.some(l => l.licenseKey === licenseKey)) licenseKey = createLicenseKey();
    }
    const license = {
        licenseKey,
        plan,
        expire_at: now() + days * 24 * 60 * 60 * 1000,
        status: 'active',
        bound_machine_id: null,
        maxSlots: Math.floor(maxSlots),
        maxAccounts: Math.floor(maxAccounts),
        created_at: now()
    };
    db.licenses.push(license);
    saveDB(db);
    res.json({ success: true, license });
});

app.get('/api/admin/licenses', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const db = loadDB();
    res.json({ success: true, total: db.licenses.length, licenses: db.licenses });
});

app.post('/api/admin/block-license', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const db = loadDB();
    const license = db.licenses.find(item => item.licenseKey === String(req.body && req.body.licenseKey || '').trim());
    if (!license) return res.status(404).json({ success: false, message: '卡密不存在' });
    license.status = 'blocked';
    db.sessions = db.sessions.filter(session => session.licenseKey !== license.licenseKey);
    saveDB(db);
    res.json({ success: true, message: '已封禁', license });
});

app.post('/api/admin/unbind-license', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const db = loadDB();
    const license = db.licenses.find(item => item.licenseKey === String(req.body && req.body.licenseKey || '').trim());
    if (!license) return res.status(404).json({ success: false, message: '卡密不存在' });
    license.bound_machine_id = null;
    license.activated_at = null;
    db.sessions = db.sessions.filter(session => session.licenseKey !== license.licenseKey);
    saveDB(db);
    res.json({ success: true, message: '已解绑', license });
});

app.post('/api/activate', (req, res) => {
    const licenseKey = String(req.body && req.body.licenseKey || '').trim();
    const machineId = String(req.body && req.body.machineId || '').trim();
    if (!licenseKey || !machineId) return res.status(400).json({ success: false, message: '缺少卡密或机器码' });

    const db = loadDB();
    const license = db.licenses.find(item => item.licenseKey === licenseKey);
    if (!license) return res.status(404).json({ success: false, message: '卡密不存在' });
    if (license.status !== 'active') return res.status(403).json({ success: false, message: '卡密已被封禁' });
    if (now() > Number(license.expire_at)) return res.status(403).json({ success: false, message: '卡密已过期' });
    if (license.bound_machine_id && license.bound_machine_id !== machineId) {
        return res.status(409).json({ success: false, message: '该卡密已绑定其他设备' });
    }

    if (!license.bound_machine_id) {
        license.bound_machine_id = machineId;
        license.activated_at = now();
    }
    db.sessions = db.sessions.filter(session => !(session.licenseKey === licenseKey && session.machineId === machineId));
    const sessionToken = createToken();
    db.sessions.push({
        sessionToken,
        licenseKey,
        machineId,
        expire_at: license.expire_at,
        created_at: now()
    });
    saveDB(db);
    res.json({
        success: true,
        sessionToken,
        expire: license.expire_at,
        plan: license.plan,
        maxSlots: license.maxSlots,
        maxAccounts: license.maxAccounts,
        serverTime: now()
    });
});

app.post('/api/verify', (req, res) => {
    const sessionToken = String(req.body && req.body.sessionToken || '').trim();
    const machineId = String(req.body && req.body.machineId || '').trim();
    if (!sessionToken || !machineId) return res.status(400).json({ success: false, message: '缺少授权信息' });

    try {
        const db = loadDB();
        const session = db.sessions.find(item => item.sessionToken === sessionToken);
        if (!session || session.machineId !== machineId) return res.status(401).json({ success: false, message: '授权会话无效' });
        const license = db.licenses.find(item => item.licenseKey === session.licenseKey);
        if (!license || license.status !== 'active') return res.status(403).json({ success: false, message: '授权已失效' });
        if (now() > Number(license.expire_at) || now() > Number(session.expire_at)) {
            return res.status(403).json({ success: false, message: '授权已到期' });
        }
        res.json({
            success: true,
            expire: license.expire_at,
            plan: license.plan,
            maxSlots: license.maxSlots,
            maxAccounts: license.maxAccounts,
            serverTime: now(),
            forceUpdate: false
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== 公共工具：生成账号批次 ====================
const DOMAIN_POOL = 'yxd.ccwu.cc, haitai.cc.cd, shupianduizhang.cc.cd, ylian.ccwu.cc'.split(/[\n,]+/).map(d => d.trim()).filter(d => d.length > 0);

function generateAccountBatch(count) {
    const accounts = [];
    for (let i = 0; i < count; i++) {
        const prefix = Date.now().toString(36) + crypto.randomBytes(2).toString('hex');
        const randomDomain = DOMAIN_POOL[Math.floor(Math.random() * DOMAIN_POOL.length)];
        accounts.push({ email: prefix + '@' + randomDomain, password: '' });
    }
    return accounts;
}

// ==================== 接口 3: 客户端账号拉取/刷新 ====================
app.post('/api', (req, res, next) => {
    const action = req.query.action;

    // --- 自动拉取（激活时首次下发） ---
    if (action === 'auto_fetch') {
        const licenseKey = String(req.body && req.body.licenseKey || '').trim();
        const machineId = String(req.body && req.body.machineId || '').trim();

        if (!licenseKey || (!licenseKey.startsWith('LV2.') && !licenseKey.startsWith('LV3.'))) {
            return res.status(400).json({ success: false, message: '无效的卡密' });
        }

        let payload = {};
        try {
            const parts = licenseKey.split('.');
            if (parts.length === 2) { // LV2
                payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            } else if (parts.length === 3) { // LV3
                payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
            }
        } catch (e) {
            return res.status(400).json({ success: false, message: '卡密解析失败' });
        }

        const db = loadDB();
        const license = db.licenses.find(item => item.licenseKey === licenseKey);
        if (!license || license.status !== 'active') {
            return res.status(403).json({ success: false, message: '卡密无效或已被封禁' });
        }
        if (now() > Number(license.expire_at)) {
            return res.status(403).json({ success: false, message: '卡密已过期' });
        }

        let count = payload.plan === 'permanent' ? 0 : (payload.plan === 'monthly' ? 50 : 10);
        if (count <= 0) return res.json({ success: true, count: 0, accounts: [], message: '永久卡不携带云端账号，请手动导入账号' });
        const accounts = generateAccountBatch(count);

        // 记录配额
        db.refresh_records = db.refresh_records || [];
        db.refresh_records.push({ licenseKey, machineId, date: new Date().toISOString().split('T')[0], count, type: 'initial' });
        saveDB(db);

        console.log('[auto-fetch] license=' + licenseKey.substring(0, 12) + '... plan=' + payload.plan + ' count=' + count);
        return res.json({ success: true, count, accounts });
    }

    // --- 每日刷新（补满配额） ---
    if (action === 'refresh_accounts') {
        const licenseKey = String(req.body && req.body.licenseKey || '').trim();
        const machineId = String(req.body && req.body.machineId || '').trim();
        const deletedCount = parseInt(req.body && req.body.deletedCount, 10) || 0;

        const db = loadDB();

        // 验证卡密
        let payload = {};
        try {
            const parts = licenseKey.split('.');
            if (licenseKey.startsWith('LV2.') && parts.length === 2) {
                payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
            } else if (licenseKey.startsWith('LV3.') && parts.length === 3) {
                payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
            }
        } catch (e) {}

        const license = db.licenses.find(item => item.licenseKey === licenseKey);
        if (!license || license.status !== 'active') {
            return res.status(403).json({ success: false, message: '卡密无效或已被封禁' });
        }
        if (now() > Number(license.expire_at)) {
            return res.status(403).json({ success: false, message: '卡密已过期' });
        }

        // 严格限制：同一卡密同设备按北京时间自然日只能手动刷新一次
        db.refresh_records = db.refresh_records || [];
        const today = refreshDateKey();
        const todayRefreshes = db.refresh_records.filter(r => r.licenseKey === licenseKey && r.machineId === machineId && r.date === today && r.type === 'refresh');
        if (todayRefreshes.length > 0) {
            return res.status(429).json({ success: false, message: '今日已补号，请明天 00:00 后再试', refreshUsedToday: true });
        }

        // 总配额限制：累计下发不超过套餐上限
        const plan = payload.plan || license.plan || 'trial';
        if (plan === 'permanent') return res.status(403).json({ success: false, message: '永久卡不支持云端补号，请手动导入账号' });
        const quota = plan === 'monthly' ? 50 : 10;
        const totalSent = db.refresh_records.filter(r => r.licenseKey === licenseKey && r.machineId === machineId).reduce((sum, r) => sum + (r.count || 0), 0);
        const remaining = Math.max(0, quota - totalSent);

        if (remaining <= 0) {
            return res.status(429).json({ success: false, message: '已达到套餐总配额上限（' + quota + ' 个），无法继续补号' });
        }

        // 补号数量 = min(删除数, 剩余配额)
        const fillCount = Math.min(Math.max(deletedCount, 1), remaining);
        const accounts = generateAccountBatch(fillCount);

        db.refresh_records.push({ licenseKey, machineId, date: today, count: fillCount, type: 'refresh', createdAt: now() });
        saveDB(db);

        console.log('[refresh-accounts] license=' + licenseKey.substring(0, 12) + '... filled=' + fillCount + ' remaining=' + (remaining - fillCount));
        return res.json({ success: true, count: fillCount, accounts });
    }

    // 其他 action 透传
    return next();
});

app.post('/api/otp/mark-baseline', async (req, res) => {
    const auth = requireLicenseSession(req, res);
    if (!auth) return;
    if (!allowOtpRequest(auth.rateLimitKey)) return res.status(429).json({ success: false, status: 'error', error: '请求过于频繁' });
    const targetEmail = normalizeTargetEmail(req.body && req.body.targetEmail);
    if (targetEmail === null) return res.status(400).json({ success: false, status: 'error', error: '目标邮箱格式无效' });

    try {
        const snapshot = await otpWorker.snapshotBaseline();
        otpState.establishBaseline({ targetEmail, machineId: auth.machineId, ...snapshot });
        return res.json({ success: true, baselineReady: true });
    } catch (error) {
        const code = stableImapErrorCode(error);
        otpState.setWorkerError({ code, at: appNow() });
        return res.status(502).json({ success: false, status: 'error', error: code });
    }
});

app.post('/api/otp/get', async (req, res) => {
    const auth = requireLicenseSession(req, res);
    if (!auth) return;
    if (!allowOtpRequest(auth.rateLimitKey)) return res.status(429).json({ success: false, status: 'error', error: '请求过于频繁' });
    const targetEmail = normalizeTargetEmail(req.body && req.body.targetEmail);
    if (targetEmail === null) return res.status(400).json({ success: false, status: 'error', error: '目标邮箱格式无效' });

    const request = {
        targetEmail,
        machineId: auth.machineId,
        requestId: String(req.body && req.body.requestId || crypto.randomUUID()).trim()
    };
    otpState.expireSessions();
    const session = otpState.createOrGetSession(request);
    trackedSessions.set(session.key, request);

    if (session.status === 'success' && session.code) {
        return res.json({ success: true, code: session.code });
    }

    const matched = otpState.matchAndConsume({ ...request, observedAfter: session.createdAt });
    if (matched) {
        otpState.completeSession(session, matched.code);
        return res.json({ success: true, code: matched.code });
    }

    const workerError = otpState.getStatus().lastError;
    if (workerError && Number(workerError.at) > session.createdAt) {
        const code = stableImapErrorCode(workerError);
        session.lastErrorCode = code;
        return res.status(502).json({ success: false, status: 'error', error: code });
    }

    return res.json({ success: false, status: 'waiting', error: 'waiting' });

});

app.use((error, req, res, next) => {
    if (error instanceof SyntaxError) return res.status(400).json({ success: false, message: 'Invalid JSON' });
    next(error);
});

  return app;
}

function createProductionOtpWorker(otpState) {
    const imapOptions = {
        host: process.env.OTP_IMAP_HOST || 'imap.163.com',
        port: Number(process.env.OTP_IMAP_PORT) || 993,
        secure: String(process.env.OTP_IMAP_SECURE || 'true').toLowerCase() !== 'false',
        auth: { user: WORKER_EMAIL, pass: WORKER_PASS },
        logger: false
    };
    if (OTP_IMAP_USE_PROXY && OTP_IMAP_PROXY_SERVER) imapOptions.proxy = OTP_IMAP_PROXY_SERVER;

    return createImapOtpWorker({
        createClient: () => new ImapFlow(imapOptions),
        parseMessage: simpleParser,
        onCandidate: candidate => {
            const targetEmail = normalizeCandidateRecipient(candidate.to);
            if (!targetEmail) return;
            otpState.addMessage({ ...candidate, to: targetEmail });
            console.log('[OTP IMAP] candidate accepted', JSON.stringify({ uid: candidate.uid }));
        },
        onError: error => {
            console.error('[OTP IMAP] error', stableImapErrorCode(error));
            otpState.setWorkerError({
                code: stableImapErrorCode(error),
                at: Number.isFinite(error && error.at) ? error.at : now()
            });
        },
        getMinimumPendingBaseline: () => null,
        hasPendingWork: () => otpState.hasPendingSessions(),
        config: { fallbackIntervalMs: 2_000 },
        now
    });
}

const defaultOtpState = createOtpState({
    now,
    sessionTtlMs: OTP_SESSION_TTL_MS,
    bufferMaxAgeMs: OTP_BUFFER_MAX_AGE_MS,
    bufferMaxSize: OTP_BUFFER_MAX_SIZE
});
const defaultOtpWorker = createProductionOtpWorker(defaultOtpState);
const app = createApp({ otpWorker: defaultOtpWorker, otpState: defaultOtpState, now });

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    const server = app.listen(PORT, () => {
        console.log(`auth server running on port ${PORT}`);
        defaultOtpWorker.start().catch(error => {
            defaultOtpState.setWorkerError({ code: stableImapErrorCode(error), at: now() });
        });
    });

    let stopping = false;
    const stopServer = async () => {
        if (stopping) return;
        stopping = true;
        await defaultOtpWorker.stop().catch(() => {});
        server.close(() => process.exit(0));
    };
    process.once('SIGINT', stopServer);
    process.once('SIGTERM', stopServer);
}

module.exports = { app, createApp, loadDB, saveDB };
