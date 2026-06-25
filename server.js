const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

const app = express();
app.use(cors());
app.use(express.json({ limit: '32kb' }));

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// In production ADMIN_SECRET must be set via environment variable; the fallback only works in local dev.
const ADMIN_SECRET = process.env.ADMIN_SECRET || (IS_PRODUCTION ? '' : 'dev-local-only-not-for-production');
const OTP_RATE_LIMIT = 60;
const OTP_RATE_WINDOW_MS = 60 * 1000;
const OTP_SESSION_TTL_MS = 2 * 60 * 1000;
const OTP_BUFFER_MAX_AGE_MS = 5 * 60 * 1000;
const OTP_BUFFER_MAX_SIZE = 50;
const IMAP_POLL_INTERVAL_MS = 5000;
const LOCK_TTL_MS = 3000;

// Worker 层凭证（仅存在于此文件，不暴露到 API 层）
const WORKER_EMAIL = String(process.env.OTP_EMAIL || '').trim();
const WORKER_PASS = String(process.env.OTP_PASS || '').trim();

// === 抗并发 OTP 系统 ===
// OTP Session Store: sessionKey → { email, machineId, requestId, code, createdAt, used, status }
const otpStore = new Map();
// Inbox Buffer: [{ to, text, code, timestamp, messageId, used }]
const inboxBuffer = [];
// Processing Lock: `${email}_${machineId}` → { time }
const processingLock = new Map();
// Rate limiting
const otpRateBuckets = new Map();
// IMAP Worker state
let imapWorkerRunning = false;
let imapWorkerTimer = null;

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

function collectMessageText(parsed) {
    const headers = [];
    try {
        for (const [key, value] of parsed.headers || []) {
            headers.push(`${key}: ${Array.isArray(value) ? value.join(',') : value}`);
        }
    } catch (error) {}

    return [
        parsed.subject || '',
        parsed.from && parsed.from.text ? parsed.from.text : '',
        parsed.sender && parsed.sender.text ? parsed.sender.text : '',
        parsed.to && parsed.to.text ? parsed.to.text : '',
        parsed.cc && parsed.cc.text ? parsed.cc.text : '',
        parsed.text || '',
        parsed.html || '',
        headers.join(' ')
    ].join(' ');
}

function isLovartOtpEmail(parsed) {
    const content = collectMessageText(parsed).toLowerCase();
    const sender = parsed.from && parsed.from.text ? parsed.from.text.toLowerCase() : '';
    const subject = String(parsed.subject || '').toLowerCase();
    const fromLovart = sender.includes('lovart') || sender.includes('lovart.ai');
    const looksLikeOtp = subject.includes('welcome to lovart')
        || subject.includes('lovart')
        || content.includes('enter this code')
        || content.includes('the lovart team');
    return fromLovart && looksLikeOtp;
}

function messageTargetsEmail(parsed, targetEmail) {
    return !targetEmail || collectMessageText(parsed).toLowerCase().includes(targetEmail);
}

function getMessageId(parsed, sequence) {
    return parsed.messageId || (parsed.date ? String(parsed.date.getTime()) : String(sequence));
}

function extractOtpCode(parsed) {
    const content = collectMessageText(parsed);
    const contextual = content.match(/(?:code|verification)[\s\S]{0,300}?(\b\d{6}\b)/i);
    if (contextual && contextual[1] !== '000000') return contextual[1];
    return (content.match(/\b\d{6}\b/g) || []).find(code => code !== '000000') || null;
}

async function openOtpMailbox() {
    if (!WORKER_EMAIL || !WORKER_PASS) throw new Error('worker credentials not configured');
    const client = new ImapFlow({
        host: process.env.OTP_IMAP_HOST || 'imap.163.com',
        port: Number(process.env.OTP_IMAP_PORT) || 993,
        secure: String(process.env.OTP_IMAP_SECURE || 'true').toLowerCase() !== 'false',
        auth: { user: WORKER_EMAIL, pass: WORKER_PASS },
        logger: false
    });
    await client.connect();
    await client.mailboxOpen('INBOX');
    return client;
}

// === IMAP Worker：后台轮询新邮件，填充 inboxBuffer ===

function extractTargetEmailFromMessage(parsed) {
    const toText = parsed.to && parsed.to.text ? parsed.to.text.toLowerCase() : '';
    const match = toText.match(/([^\s@]+@[^\s@]+\.[^\s@]+)/);
    return match ? match[1] : '';
}

async function imapPollWorker() {
    if (imapWorkerRunning) return;

    // 只在有 pending session 时才轮询 IMAP（节省资源）
    const hasPending = Array.from(otpStore.values()).some(s => s.status === 'pending');
    if (!hasPending) return;

    imapWorkerRunning = true;
    let client;

    try {
        client = await openOtpMailbox();
        const exists = client.mailbox && Number(client.mailbox.exists) || 0;
        const scanLimit = 15; // 只扫最近 15 封
        const start = Math.max(1, exists - scanLimit);
        const fiveMinAgo = now() - OTP_BUFFER_MAX_AGE_MS;

        for (let sequence = exists; sequence >= start; sequence--) {
            const message = await client.fetchOne(String(sequence), { source: true });
            if (!message || !message.source) continue;

            const parsed = await simpleParser(message.source);

            // 时间过滤：跳过超过 5 分钟的邮件
            if (parsed.date && parsed.date.getTime() < fiveMinAgo) continue;

            // 只处理 Lovart OTP 邮件
            if (!isLovartOtpEmail(parsed)) continue;

            const messageId = getMessageId(parsed, sequence);

            // 去重：已在 buffer 中则跳过
            if (inboxBuffer.some(item => item.messageId === messageId)) continue;

            const code = extractOtpCode(parsed);
            if (!code) continue;

            const targetEmail = extractTargetEmailFromMessage(parsed);
            const text = collectMessageText(parsed).toLowerCase();

            inboxBuffer.push({
                to: targetEmail,
                text,
                code,
                timestamp: parsed.date ? parsed.date.getTime() : Date.now(),
                messageId,
                used: false
            });

            console.log('[IMAP Worker] new OTP email for:', targetEmail, 'code:', code, 'seq:', sequence);
        }

        // 清理过期和已消费的 buffer 条目
        const cutoff = now() - OTP_BUFFER_MAX_AGE_MS;
        for (let i = inboxBuffer.length - 1; i >= 0; i--) {
            if (inboxBuffer[i].timestamp < cutoff || inboxBuffer[i].used) {
                inboxBuffer.splice(i, 1);
            }
        }
        while (inboxBuffer.length > OTP_BUFFER_MAX_SIZE) inboxBuffer.shift();

    } catch (error) {
        console.error('[IMAP Worker] error:', error.message);
    } finally {
        if (client) {
            try { await client.logout(); } catch (e) {}
        }
        imapWorkerRunning = false;
    }
}

function startImapWorker() {
    if (imapWorkerTimer) return;
    imapWorkerTimer = setInterval(() => {
        imapPollWorker().catch(err => console.error('[IMAP Worker] unhandled:', err));
    }, IMAP_POLL_INTERVAL_MS);
    console.log('[IMAP Worker] started, polling every', IMAP_POLL_INTERVAL_MS / 1000, 'seconds');
}

// === OTP 匹配与消费 ===

function matchOTP(email) {
    const fiveMinAgo = now() - OTP_BUFFER_MAX_AGE_MS;

    // 从最新往旧找，返回第一个未使用的匹配项
    for (let i = inboxBuffer.length - 1; i >= 0; i--) {
        const item = inboxBuffer[i];
        if (item.used) continue;
        if (item.timestamp < fiveMinAgo) continue;

        // 优先用 To 字段精确匹配
        if (email && item.to === email) return item;

        // 回退：检查邮件正文是否包含目标邮箱
        if (email && item.text.includes(email)) return item;

        // 无 email 参数时返回任意未使用项
        if (!email) return item;
    }
    return null;
}

function consumeOTP(item) {
    item.used = true;
    const idx = inboxBuffer.indexOf(item);
    if (idx >= 0) inboxBuffer.splice(idx, 1);
}

// === TTL 清理 ===

function cleanupOtpStore() {
    const expired = now() - OTP_SESSION_TTL_MS;
    for (const [key, session] of otpStore) {
        if (session.createdAt < expired) {
            otpStore.delete(key);
        }
    }
}

// === 并发锁 ===

function acquireLock(key) {
    const currentTime = now();
    if (processingLock.has(key)) {
        const lock = processingLock.get(key);
        if (currentTime - lock.time < LOCK_TTL_MS) return false;
    }
    processingLock.set(key, { time: currentTime });
    return true;
}

app.use((req, res, next) => {
  console.log('[REQ]', req.method, req.path, req.query || {});
  next();
});

app.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'auth server running', time: now() });
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

        let count = payload.plan === 'monthly' ? 50 : (payload.plan === 'permanent' ? 100 : 10);
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
        const quota = plan === 'monthly' ? 50 : (plan === 'permanent' ? 100 : 10);
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
        // 触发一次 IMAP 轮询，捕获当前邮件状态
        await imapPollWorker();

        // 将当前 buffer 中该邮箱的所有验证码标记为已使用（建立基线）
        for (const item of inboxBuffer) {
            if (!item.used && (item.to === targetEmail || (targetEmail && item.text.includes(targetEmail)))) {
                item.used = true;
            }
        }

        console.log('[OTP] baseline marked for:', targetEmail);
        res.json({ success: true });
    } catch (error) {
        res.status(502).json({ success: false, status: 'error', error: error.message });
    }
});

app.post('/api/otp/get', async (req, res) => {
    const auth = requireLicenseSession(req, res);
    if (!auth) return;
    if (!allowOtpRequest(auth.rateLimitKey)) return res.status(429).json({ success: false, status: 'error', error: '请求过于频繁' });
    const targetEmail = normalizeTargetEmail(req.body && req.body.targetEmail);
    if (targetEmail === null) return res.status(400).json({ success: false, status: 'error', error: '目标邮箱格式无效' });

    // 生成 requestId 和 sessionKey
    const requestId = String(req.body && req.body.requestId || crypto.randomUUID()).trim();
    const machineId = auth.machineId;
    const sessionKey = `${targetEmail || 'global'}_${machineId}_${requestId}`;

    // 并发锁：同一 email+machineId 3 秒内只允许 1 次
    const lockKey = `${targetEmail || 'global'}_${machineId}`;
    if (!acquireLock(lockKey)) {
        return res.json({ success: false, status: 'waiting', error: 'waiting' });
    }

    // 定期清理过期 session
    cleanupOtpStore();

    // 检查已有 session
    const existingSession = otpStore.get(sessionKey);
    if (existingSession) {
        if (existingSession.status === 'success' && existingSession.code) {
            console.log('[OTP] session hit:', sessionKey, 'code:', existingSession.code);
            return res.json({ success: true, code: existingSession.code });
        }
        if (existingSession.status === 'expired') {
            return res.json({ success: false, status: 'expired', error: 'not_found' });
        }
        // session 仍在 pending，继续尝试匹配
    } else {
        // 创建新 session
        otpStore.set(sessionKey, {
            email: targetEmail,
            machineId,
            requestId,
            code: null,
            createdAt: now(),
            used: false,
            status: 'pending'
        });

        // TTL: 2 分钟后自动过期
        setTimeout(() => {
            const session = otpStore.get(sessionKey);
            if (session && session.status === 'pending') {
                session.status = 'expired';
                otpStore.delete(sessionKey);
                console.log('[OTP] session expired:', sessionKey);
            }
        }, OTP_SESSION_TTL_MS);

        console.log('[OTP] new session:', sessionKey);
    }

    // 从 inboxBuffer 匹配验证码
    const matched = matchOTP(targetEmail);
    if (matched) {
        consumeOTP(matched);
        const session = otpStore.get(sessionKey);
        if (session) {
            session.status = 'success';
            session.code = matched.code;
            session.used = true;
        }
        console.log('[OTP] match success:', sessionKey, 'code:', matched.code);
        return res.json({ success: true, code: matched.code });
    }

    // 未匹配到，触发 IMAP 轮询并返回 waiting
    imapPollWorker().catch(() => {});

    console.log('[OTP] waiting:', sessionKey);
    return res.json({ success: false, status: 'waiting', error: 'waiting' });
});

app.use((error, req, res, next) => {
    if (error instanceof SyntaxError) return res.status(400).json({ success: false, message: 'Invalid JSON' });
    next(error);
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`auth server running on port ${PORT}`);
        startImapWorker();
    });
}

module.exports = { app, loadDB, saveDB };
