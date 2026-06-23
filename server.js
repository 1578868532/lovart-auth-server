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
const OTP_EMAIL = String(process.env.OTP_EMAIL || '').trim();
const OTP_PASS = String(process.env.OTP_PASS || '').trim();
const OTP_RATE_LIMIT = 60;
const OTP_RATE_WINDOW_MS = 60 * 1000;

const otpRateBuckets = new Map();
const otpBaselines = new Map();
const otpUsedMessageIds = new Map();
const otpFetchLocks = new Map();

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

function createToken() {
    return crypto.randomBytes(32).toString('hex');
}

function createLicenseKey() {
    return `LV-${crypto.randomBytes(10).toString('hex').toUpperCase()}`;
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

    // 支持 local-lv2 模式（Electron 本地卡密，无 sessionToken）
    if (body.licenseMode === 'local-lv2') {
        const licenseKey = String(body.licenseKey || '').trim();
        const machineId = String(body.machineId || '').trim();
        if (!licenseKey || !machineId) return { error: '缺少授权信息' };
        if (!licenseKey.startsWith('LV2.')) return { error: 'license_invalid' };

        try {
            const parts = licenseKey.split('.');
            if (parts.length !== 3) return { error: 'license_invalid' };

            // base64url decode payload（不验证签名，仅解析）
            const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
            const payloadBytes = Buffer.from(padded, 'base64');
            const payload = JSON.parse(payloadBytes.toString('utf8'));

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
    if (!OTP_EMAIL || !OTP_PASS) throw new Error('OTP_EMAIL or OTP_PASS is not configured');
    const client = new ImapFlow({
        host: process.env.OTP_IMAP_HOST || 'imap.163.com',
        port: Number(process.env.OTP_IMAP_PORT) || 993,
        secure: String(process.env.OTP_IMAP_SECURE || 'true').toLowerCase() !== 'false',
        auth: { user: OTP_EMAIL, pass: OTP_PASS },
        logger: false
    });
    await client.connect();
    await client.mailboxOpen('INBOX');
    return client;
}

async function findLatestLovartMessage(client, targetEmail, options = {}) {
    const exists = client.mailbox && Number(client.mailbox.exists) || 0;
    const start = Math.max(1, exists - (options.scanLimit || 120));
    const usedIds = otpUsedMessageIds.get(targetEmail || 'global') || new Set();
    const baseline = otpBaselines.get(targetEmail || 'global') || '';

    for (let sequence = exists; sequence >= start; sequence--) {
        const message = await client.fetchOne(String(sequence), { source: true });
        if (!message || !message.source) continue;
        const parsed = await simpleParser(message.source);
        if (!isLovartOtpEmail(parsed) || !messageTargetsEmail(parsed, targetEmail)) continue;

        const messageId = getMessageId(parsed, sequence);
        if (options.baselineOnly) return { messageId };
        if (messageId === baseline) break;
        if (usedIds.has(messageId)) continue;
        if (parsed.date && now() - parsed.date.getTime() > 10 * 60 * 1000) continue;

        const code = extractOtpCode(parsed);
        if (code) return { messageId, code };
    }
    return null;
}

async function markOtpBaseline(targetEmail) {
    let client;
    try {
        client = await openOtpMailbox();
        const found = await findLatestLovartMessage(client, targetEmail, { baselineOnly: true, scanLimit: 80 });
        if (found) otpBaselines.set(targetEmail || 'global', found.messageId);
    } finally {
        if (client) {
            try { await client.logout(); } catch (error) {}
        }
    }
}

async function fetchLatestOtp(targetEmail) {
    const lockKey = targetEmail || 'global';
    if (otpFetchLocks.has(lockKey)) return otpFetchLocks.get(lockKey);

    const request = (async () => {
        let client;
        try {
            client = await openOtpMailbox();
            const found = await findLatestLovartMessage(client, targetEmail);
            if (!found) return null;

            const usedIds = otpUsedMessageIds.get(lockKey) || new Set();
            usedIds.add(found.messageId);
            while (usedIds.size > 200) usedIds.delete(usedIds.values().next().value);
            otpUsedMessageIds.set(lockKey, usedIds);
            otpBaselines.set(lockKey, found.messageId);
            return found.code;
        } finally {
            if (client) {
                try { await client.logout(); } catch (error) {}
            }
        }
    })();

    otpFetchLocks.set(lockKey, request);
    try { return await request; }
    finally { otpFetchLocks.delete(lockKey); }
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
    const days = Number(req.body && req.body.days || 30);
    const maxSlots = Number(req.body && req.body.maxSlots || 3);
    const maxAccounts = Number(req.body && req.body.maxAccounts || 100);
    const plan = String(req.body && req.body.plan || 'monthly').trim() || 'monthly';
    if (!Number.isFinite(days) || days <= 0 || !Number.isFinite(maxSlots) || maxSlots <= 0 || !Number.isFinite(maxAccounts) || maxAccounts <= 0) {
        return res.status(400).json({ success: false, message: '授权参数无效' });
    }

    const db = loadDB();
    let licenseKey = createLicenseKey();
    while (db.licenses.some(license => license.licenseKey === licenseKey)) licenseKey = createLicenseKey();
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

app.post('/api/otp/mark-baseline', async (req, res) => {
    const auth = requireLicenseSession(req, res);
    if (!auth) return;
    if (!allowOtpRequest(auth.rateLimitKey)) return res.status(429).json({ success: false, error: '请求过于频繁' });
    const targetEmail = normalizeTargetEmail(req.body && req.body.targetEmail);
    if (targetEmail === null) return res.status(400).json({ success: false, error: '目标邮箱格式无效' });

    try {
        await markOtpBaseline(targetEmail);
        res.json({ success: true });
    } catch (error) {
        res.status(502).json({ success: false, error: error.message });
    }
});

app.post('/api/otp/get', async (req, res) => {
    const auth = requireLicenseSession(req, res);
    if (!auth) return;
    if (!allowOtpRequest(auth.rateLimitKey)) return res.status(429).json({ success: false, error: '请求过于频繁' });
    const targetEmail = normalizeTargetEmail(req.body && req.body.targetEmail);
    if (targetEmail === null) return res.status(400).json({ success: false, error: '目标邮箱格式无效' });

    try {
        const code = await fetchLatestOtp(targetEmail);
        if (!code) return res.json({ success: false, error: 'not_found' });
        res.json({ success: true, code });
    } catch (error) {
        res.status(502).json({ success: false, error: error.message });
    }
});

app.use((error, req, res, next) => {
    if (error instanceof SyntaxError) return res.status(400).json({ success: false, message: 'Invalid JSON' });
    next(error);
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => console.log(`auth server running on port ${PORT}`));
}

module.exports = { app, loadDB, saveDB };
