const crypto = require('crypto');
const fs = require('fs');
let neon = null;
try { neon = require('@neondatabase/serverless').neon; } catch (e) {}

// Account import codes must remain compatible with the encryption key embedded
// in every currently released desktop client. A server-only override makes the
// generated code impossible for those clients to decrypt.
const DATA_KEY_TEXT = 'LOVART_DATA_SECURE_KEY';
const ENCRYPT_KEY = crypto.scryptSync(DATA_KEY_TEXT, 'salt', 32);
const IV = Buffer.alloc(16, 0);
const LICENSE_PRIVATE_KEY_TEXT = process.env.LOVART_LICENSE_PRIVATE_KEY || process.env.LICENSE_PRIVATE_KEY || '';
const LICENSE_PRIVATE_KEY = normalizePrivateKey(LICENSE_PRIVATE_KEY_TEXT);
const DEFAULT_LICENSE_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJVmR7Yrj3zh/GDV9txERvI/v/9UI7w/4k/pR7n/tHlc=\n-----END PUBLIC KEY-----';
const LICENSE_PUBLIC_KEY_TEXT = process.env.LOVART_LICENSE_PUBLIC_KEY || process.env.LICENSE_PUBLIC_KEY || DEFAULT_LICENSE_PUBLIC_KEY;
const LICENSE_PUBLIC_KEY = createPublicKeySafe(normalizePublicKey(LICENSE_PUBLIC_KEY_TEXT));
const LICENSE_SIGNING_PRIVATE_KEY = createPrivateKeySafe(LICENSE_PRIVATE_KEY);
const SECURELINK_LICENSE_PRIVATE_KEY_DER = process.env.SECURELINK_LICENSE_PRIVATE_KEY_DER || 'MC4CAQAwBQYDK2VwBCIEIEJHnMdGJVKjTnSVuAR4mbDLC9YhL+Ns2YFtq5YsfydF';
const ADMIN_SECRET = String(process.env.ADMIN_SECRET || '').trim();
const BUILD_SHA = process.env.RENDER_GIT_COMMIT || process.env.VERCEL_GIT_COMMIT_SHA || process.env.GIT_COMMIT_SHA || 'development';

const ISSUE_TOKENS_FILE = '/tmp/lovart_issue_tokens.json';
const BLACKLIST_FILE = '/tmp/lovart_blacklist.json';
const QUOTA_FILE = '/tmp/lovart_quota.json';
const ACTIVATIONS_FILE = '/tmp/lovart_activations.json';
const TRIAL_CLAIMS_FILE = '/tmp/lovart_trial_claims.json';
const SETTINGS_FILE = '/tmp/lovart_settings.json';
const ACTIVATION_GRANTS_FILE = '/tmp/lovart_activation_grants.json';
const ISSUED_LICENSES_FILE = '/tmp/lovart_issued_licenses.json';
const LICENSE_ACCOUNT_AUTHORIZATIONS_FILE = '/tmp/lovart_license_account_authorizations.json';
const CLIENT_ACCOUNT_SNAPSHOTS_FILE = '/tmp/lovart_client_account_snapshots.json';
const ACCOUNT_COMMANDS_FILE = '/tmp/lovart_account_commands.json';
const ACCOUNT_CLOUD_STATUS_FILE = '/tmp/lovart_account_cloud_status.json';
const ACTIVE_CLIENTS_FILE = '/tmp/lovart_active_clients.json';
const ACCOUNT_POOLS_FILE = '/tmp/lovart_account_pools.json';
const DOMAIN_POOL = 'yxd.ccwu.cc,haitai.cc.cd,shupianduizhang.cc.cd,ylian.ccwu.cc';
const CLOUDFLARE_DOMAIN_POOL = '115765814.cc.cd,1xxcdeh.ccwu.cc,fxasf.cc.cd,gyjfgh.ccwu.cc';
const TRIAL_HOURS = 1;
const TRIAL_ACCOUNT_COUNT = 10;
const BUILTIN_TRIAL_REPEAT_WHITELIST = ['6146e7a1400c83010d43'];
const TRIAL_REPEAT_WHITELIST = new Set(
  BUILTIN_TRIAL_REPEAT_WHITELIST
    .concat(String(process.env.TRIAL_REPEAT_WHITELIST || '').split(','))
    .map(x => String(x || '').trim().toLowerCase())
    .filter(Boolean)
);

const issueTokens = loadJSON(ISSUE_TOKENS_FILE, []);
const blacklist = loadJSON(BLACKLIST_FILE, []);
const quotaStore = loadJSON(QUOTA_FILE, {});
const activationStore = loadJSON(ACTIVATIONS_FILE, []);
const trialClaims = loadJSON(TRIAL_CLAIMS_FILE, []);
const settingsStore = loadJSON(SETTINGS_FILE, {});
const activationGrants = loadJSON(ACTIVATION_GRANTS_FILE, {});
const issuedLicenses = loadJSON(ISSUED_LICENSES_FILE, []);
const licenseAccountAuthorizations = loadJSON(LICENSE_ACCOUNT_AUTHORIZATIONS_FILE, {});
const clientAccountSnapshots = loadJSON(CLIENT_ACCOUNT_SNAPSHOTS_FILE, {});
const accountCommands = loadJSON(ACCOUNT_COMMANDS_FILE, []);
const accountCloudStatus = loadJSON(ACCOUNT_CLOUD_STATUS_FILE, {});
const activeClients = loadJSON(ACTIVE_CLIENTS_FILE, {});
const accountPools = loadJSON(ACCOUNT_POOLS_FILE, []);
const { buildReservationCommand, normalizeEmails, decideReservationAck, RESERVATION_TTL_MS } = require('./account-reservation');
const channel = require('./channel-core');
const ACTIVE_CLIENT_TIMEOUT_MS = 90 * 1000;
const claimRate = {};
const DATABASE_URL = String(
  process.env.CHANNEL_DATABASE_URL ||
  process.env.CHANNEL_POSTGRES_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  ''
).trim();
const sql = DATABASE_URL && neon ? neon(DATABASE_URL) : null;
let dbReady = false;
let dbInitPromise = null;

function normalizePrivateKey(value) {
  let key = String(value || '').trim();
  key = key.replace(/^LOVART_LICENSE_PRIVATE_KEY\s*=\s*/i, '').replace(/^LICENSE_PRIVATE_KEY\s*=\s*/i, '').trim();
  if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) key = key.slice(1, -1);
  return key.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n').trim();
}
function normalizePublicKey(value) {
  let key = String(value || '').trim();
  key = key.replace(/^LOVART_LICENSE_PUBLIC_KEY\s*=\s*/i, '').replace(/^LICENSE_PUBLIC_KEY\s*=\s*/i, '').trim();
  if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) key = key.slice(1, -1);
  return key.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n').trim();
}
function createPublicKeySafe(value) {
  try { return value ? crypto.createPublicKey(value) : null; } catch (e) { return null; }
}
function createPrivateKeySafe(value) {
  try { return value ? crypto.createPrivateKey(value) : null; } catch (e) { return null; }
}
function loadJSON(file, fallback) {
  try { return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback; } catch (e) { return fallback; }
}
function saveJSON(file, data) { try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); } catch (e) {} }
async function ensureDb() {
  if (!sql) return false;
  if (dbReady) return true;
  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS activations (
        machine_id TEXT NOT NULL,
        product TEXT NOT NULL,
        plan TEXT NOT NULL,
        expire BIGINT NOT NULL DEFAULT 0,
        account_count INTEGER NOT NULL DEFAULT 0,
        license_hash TEXT,
        reported_account_count INTEGER,
        last_seen_at BIGINT,
        activated_at BIGINT NOT NULL,
        activation_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (machine_id, product)
      )`;
      await sql`ALTER TABLE activations ADD COLUMN IF NOT EXISTS license_hash TEXT`;
      await sql`ALTER TABLE activations ADD COLUMN IF NOT EXISTS reported_account_count INTEGER`;
      await sql`ALTER TABLE activations ADD COLUMN IF NOT EXISTS last_seen_at BIGINT`;
      await sql`CREATE TABLE IF NOT EXISTS blacklist (
        machine_id TEXT PRIMARY KEY,
        reason TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE
      )`;
      await sql`CREATE TABLE IF NOT EXISTS refresh_quota (
        license_hash TEXT PRIMARY KEY,
        last_date TEXT NOT NULL,
        refresh_count INTEGER NOT NULL DEFAULT 0
      )`;
      await sql`CREATE TABLE IF NOT EXISTS issue_tokens (
        token TEXT PRIMARY KEY,
        plan TEXT NOT NULL,
        account_count INTEGER NOT NULL,
        days INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        used BOOLEAN NOT NULL DEFAULT FALSE,
        used_by TEXT,
        used_at BIGINT
      )`;
      await sql`ALTER TABLE issue_tokens ADD COLUMN IF NOT EXISTS order_id TEXT`;
      await sql`ALTER TABLE issue_tokens ADD COLUMN IF NOT EXISTS expires_at BIGINT`;
      await sql`ALTER TABLE issue_tokens ADD COLUMN IF NOT EXISTS cancelled BOOLEAN NOT NULL DEFAULT FALSE`;
      await sql`CREATE TABLE IF NOT EXISTS reseller_accounts (
        reseller_id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        balance_cents BIGINT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS reseller_sessions (
        token_hash TEXT PRIMARY KEY,
        reseller_id TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        last_seen_at BIGINT NOT NULL
      )`;
      await sql`CREATE INDEX IF NOT EXISTS reseller_sessions_reseller_idx ON reseller_sessions(reseller_id)`;
      await sql`CREATE INDEX IF NOT EXISTS reseller_sessions_expire_idx ON reseller_sessions(expires_at)`;
      await sql`CREATE TABLE IF NOT EXISTS channel_products (
        product_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'monthly',
        days INTEGER NOT NULL DEFAULT 30,
        account_count INTEGER NOT NULL DEFAULT 30,
        retail_price_cents BIGINT NOT NULL DEFAULT 0,
        reseller_price_cents BIGINT NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS channel_orders (
        order_id TEXT PRIMARY KEY,
        reseller_id TEXT,
        product_id TEXT NOT NULL,
        order_type TEXT NOT NULL DEFAULT 'reseller_claim',
        status TEXT NOT NULL DEFAULT 'created',
        amount_cents BIGINT NOT NULL DEFAULT 0,
        platform_order_no TEXT,
        claim_token TEXT UNIQUE,
        public_secret_hash TEXT,
        machine_id TEXT,
        license_hash TEXT,
        previous_expire BIGINT,
        new_expire BIGINT,
        created_at BIGINT NOT NULL,
        paid_at BIGINT,
        claimed_at BIGINT,
        cancelled_at BIGINT
      )`;
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS channel_orders_reseller_platform_idx ON channel_orders(reseller_id,platform_order_no) WHERE platform_order_no IS NOT NULL`;
      await sql`CREATE INDEX IF NOT EXISTS channel_orders_reseller_created_idx ON channel_orders(reseller_id,created_at DESC)`;
      await sql`CREATE INDEX IF NOT EXISTS channel_orders_status_idx ON channel_orders(status)`;
      await sql`CREATE TABLE IF NOT EXISTS reseller_wallet_ledger (
        ledger_id TEXT PRIMARY KEY,
        reseller_id TEXT NOT NULL,
        entry_type TEXT NOT NULL,
        amount_cents BIGINT NOT NULL,
        balance_after_cents BIGINT NOT NULL,
        order_id TEXT,
        note TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL
      )`;
      await sql`CREATE INDEX IF NOT EXISTS reseller_wallet_ledger_reseller_idx ON reseller_wallet_ledger(reseller_id,created_at DESC)`;
      await sql`CREATE TABLE IF NOT EXISTS payment_transactions (
        payment_id TEXT PRIMARY KEY,
        order_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_trade_no TEXT,
        amount_cents BIGINT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        raw_notify_hash TEXT,
        created_at BIGINT NOT NULL,
        paid_at BIGINT,
        UNIQUE(provider,provider_trade_no)
      )`;
      await sql`CREATE TABLE IF NOT EXISTS trial_claims (
        machine_id TEXT PRIMARY KEY,
        license_hash TEXT,
        claimed_at BIGINT NOT NULL,
        expire BIGINT NOT NULL,
        account_count INTEGER NOT NULL DEFAULT 10
      )`;
      await sql`CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS activation_account_grants (
        license_hash TEXT PRIMARY KEY,
        machine_id TEXT NOT NULL,
        granted_at BIGINT NOT NULL,
        account_count INTEGER NOT NULL DEFAULT 0,
        accounts_json TEXT NOT NULL DEFAULT '[]'
      )`;
      await sql`CREATE TABLE IF NOT EXISTS license_account_authorizations (
        license_hash TEXT NOT NULL,
        machine_id TEXT NOT NULL,
        email TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'cloud_grant',
        authorized_at BIGINT NOT NULL,
        PRIMARY KEY (license_hash, email)
      )`;
      await sql`CREATE INDEX IF NOT EXISTS license_account_authorizations_machine_idx ON license_account_authorizations(machine_id)`;
      await sql`CREATE TABLE IF NOT EXISTS issued_licenses (
        license_hash TEXT PRIMARY KEY,
        machine_id TEXT NOT NULL,
        product TEXT NOT NULL,
        plan TEXT NOT NULL,
        expire BIGINT NOT NULL DEFAULT 0,
        account_count INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'admin',
        token TEXT,
        issued_at BIGINT NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoke_reason TEXT NOT NULL DEFAULT '',
        revoked_at BIGINT
      )`;
      await sql`ALTER TABLE issued_licenses ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE`;
      await sql`ALTER TABLE issued_licenses ADD COLUMN IF NOT EXISTS revoke_reason TEXT NOT NULL DEFAULT ''`;
      await sql`ALTER TABLE issued_licenses ADD COLUMN IF NOT EXISTS revoked_at BIGINT`;
      await sql`CREATE TABLE IF NOT EXISTS client_account_snapshots (
        machine_id TEXT PRIMARY KEY,
        product TEXT NOT NULL DEFAULT 'lovart-modern',
        license_hash TEXT,
        account_count INTEGER NOT NULL DEFAULT 0,
        accounts_json TEXT NOT NULL DEFAULT '[]',
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS account_commands (
        command_id TEXT PRIMARY KEY,
        machine_id TEXT NOT NULL,
        product TEXT NOT NULL DEFAULT 'lovart-modern',
        license_hash TEXT,
        command_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        result_json TEXT,
        created_at BIGINT NOT NULL,
        delivered_at BIGINT,
        completed_at BIGINT,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NOT NULL DEFAULT ''
      )`;
      await sql`ALTER TABLE account_commands ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0`;
      await sql`ALTER TABLE account_commands ADD COLUMN IF NOT EXISTS last_error TEXT`;
      await sql`ALTER TABLE account_commands ADD COLUMN IF NOT EXISTS delivered_at BIGINT`;
      await sql`ALTER TABLE account_commands ADD COLUMN IF NOT EXISTS completed_at BIGINT`;
      await sql`CREATE TABLE IF NOT EXISTS account_cloud_status (
        email TEXT PRIMARY KEY,
        machine_id TEXT NOT NULL,
        status_json TEXT NOT NULL DEFAULT '{}',
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS client_active_sessions (
        machine_id TEXT PRIMARY KEY,
        pool_id TEXT,
        product TEXT NOT NULL DEFAULT 'lovart-modern',
        account_count INTEGER NOT NULL DEFAULT 0,
        accounts_json TEXT NOT NULL DEFAULT '[]',
        last_seen_at BIGINT NOT NULL
      )`;
      await sql`ALTER TABLE client_active_sessions ADD COLUMN IF NOT EXISTS pool_id TEXT`;
      await sql`CREATE TABLE IF NOT EXISTS account_pools (
        pool_id TEXT PRIMARY KEY,
        name TEXT NOT NULL DEFAULT '',
        machine_ids_json TEXT NOT NULL DEFAULT '[]',
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      )`;
      await sql`CREATE TABLE IF NOT EXISTS account_pool_inventory (
        id TEXT PRIMARY KEY,
        pool_id TEXT NOT NULL,
        normalized_email TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'available',
        reserved_command_id TEXT,
        reserved_machine_id TEXT,
        reserved_at BIGINT,
        reservation_expires_at BIGINT,
        assigned_machine_id TEXT,
        assigned_at BIGINT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(pool_id, normalized_email)
      )`;
      await sql`CREATE INDEX IF NOT EXISTS account_pool_inventory_pool_status_idx ON account_pool_inventory(pool_id,status)`;
      await sql`CREATE INDEX IF NOT EXISTS account_pool_inventory_reservation_expiry_idx ON account_pool_inventory(reservation_expires_at)`;
      await sql`CREATE INDEX IF NOT EXISTS account_pool_inventory_command_idx ON account_pool_inventory(reserved_command_id)`;
      await sql`CREATE INDEX IF NOT EXISTS account_pool_inventory_machine_idx ON account_pool_inventory(assigned_machine_id)`;
      dbReady = true;
      return true;
    })().catch(error => {
      console.error('[db] init failed:', error.message);
      dbInitPromise = null;
      return false;
    });
  }
  return dbInitPromise;
}
function b64url(input) { return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function decodePayload(part) { return JSON.parse(Buffer.from(part, 'base64').toString('utf8')); }
function parseLicensePayload(key) {
  try {
    if (!key || typeof key !== 'string') return null;
    const parts = key.split('.');
    if ((key.startsWith('LV2.') || key.startsWith('LV3.')) && parts.length >= 2) return decodePayload(parts[1]);
    return null;
  } catch (e) { return null; }
}
function verifySignedLicense(key) {
  if (!LICENSE_PUBLIC_KEY) return null;
  const parts = String(key || '').split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadB64 = parts[1];
    const sig = Buffer.from(parts[2], 'base64url');
    const rawPayload = Buffer.from(Buffer.from(payloadB64, 'base64').toString('utf8'), 'utf8');
    const ok = crypto.verify(null, rawPayload, LICENSE_PUBLIC_KEY, sig) || crypto.verify(null, Buffer.from(payloadB64), LICENSE_PUBLIC_KEY, sig);
    return ok ? decodePayload(payloadB64) : null;
  } catch (e) { return null; }
}
function getLicenseProductField(raw) {
  if (!raw || typeof raw !== 'object') return '';
  const v = raw.product !== undefined ? raw.product : raw.Product;
  return typeof v === 'string' ? v : '';
}
function isSecureLinkKey(key) {
  if (!key || typeof key !== 'string') return false;
  if (key.startsWith('LV3.')) return false;
  const payload = parseLicensePayload(key);
  const product = getLicenseProductField(payload);
  return Boolean(product && product.toLowerCase() === 'securelink');
}
function verifySecureLinkLicense(key) {
  if (!SECURELINK_LICENSE_PRIVATE_KEY_DER) return null;
  const parts = String(key || '').split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadB64 = parts[1];
    const sig = Buffer.from(parts[2], 'base64url');
    const privateKeyObj = crypto.createPrivateKey({
      key: Buffer.from(SECURELINK_LICENSE_PRIVATE_KEY_DER, 'base64'),
      format: 'der',
      type: 'pkcs8'
    });
    const publicKeyObj = crypto.createPublicKey(privateKeyObj);
    const rawBytes = Buffer.from(payloadB64, 'base64');
    const b64StrBytes = Buffer.from(payloadB64, 'utf8');
    // 兼容两种签名方式：原始字节 或 base64url 字符串字节
    const ok = crypto.verify(null, rawBytes, publicKeyObj, sig) || crypto.verify(null, b64StrBytes, publicKeyObj, sig);
    return ok ? decodePayload(payloadB64) : null;
  } catch (e) { return null; }
}
function readValidLicensePayload(key) {
  const raw = parseLicensePayload(key);
  if (!raw) return { payload: null, message: '卡密无效' };
  if (String(key || '').startsWith('LV3.')) {
    if (!LICENSE_PUBLIC_KEY) return { payload: null, message: '服务器缺少有效的 LV3 验签公钥' };
    const verified = verifySignedLicense(key);
    if (!verified) return { payload: null, message: 'LV3 卡密签名无效' };
    return { payload: verified };
  }
  if (String(key || '').startsWith('LV2.')) {
    const product = getLicenseProductField(raw);
    if (product && product.toLowerCase() === 'securelink') {
      const verified = verifySecureLinkLicense(key);
      if (!verified) return { payload: null, message: 'SecureLink 卡密签名无效' };
      return { payload: verified };
    }
    return { payload: raw };
  }
  return { payload: raw };
}
function signLicense(payload, prefix, product) {
  let key;
  if (product === 'securelink') {
    key = crypto.createPrivateKey({ key: Buffer.from(SECURELINK_LICENSE_PRIVATE_KEY_DER, 'base64'), format: 'der', type: 'pkcs8' });
    payload.product = 'securelink';
    delete payload.Product;
  } else {
    if (!LICENSE_SIGNING_PRIVATE_KEY) throw new Error('Lovart 发卡私钥未配置或格式不正确：请设置有效的 LOVART_LICENSE_PRIVATE_KEY 或 LICENSE_PRIVATE_KEY');
    key = LICENSE_SIGNING_PRIVATE_KEY;
  }
  const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  const sig = crypto.sign(null, payloadBytes, key);
  return prefix + '.' + b64url(payloadBytes) + '.' + b64url(sig);
}
function readBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => body += c.toString());
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch (e) { resolve({}); } });
  });
}
function checkAdmin(req) { return Boolean(ADMIN_SECRET) && req.headers['x-admin-secret'] === ADMIN_SECRET; }
function isBlacklisted(machineId) { return blacklist.some(x => x.machineId === machineId && !x.revoked); }
function hashLicenseKey(key) { return crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 16); }
function isTrialRepeatWhitelisted(machineId) { return TRIAL_REPEAT_WHITELIST.has(String(machineId || '').trim().toLowerCase()); }
async function recordIssuedLicense({ licenseKey, machineId, product, plan, expire, accountCount, source, token }) {
  const item = {
    licenseHash: hashLicenseKey(licenseKey),
    machineId: String(machineId || '').trim(),
    product: product || 'lovart-modern',
    plan: plan || 'monthly',
    expire: Number(expire) || 0,
    accountCount: Number(accountCount) || 0,
    source: source || 'admin',
    token: token || '',
    issuedAt: Date.now()
  };
  if (!item.machineId || !licenseKey) return;
  if (await ensureDb()) {
    await sql`INSERT INTO issued_licenses
      (license_hash,machine_id,product,plan,expire,account_count,source,token,issued_at)
      VALUES (${item.licenseHash},${item.machineId},${item.product},${item.plan},${item.expire},${item.accountCount},${item.source},${item.token || null},${item.issuedAt})
      ON CONFLICT (license_hash) DO UPDATE SET
        machine_id=EXCLUDED.machine_id,
        product=EXCLUDED.product,
        plan=EXCLUDED.plan,
        expire=EXCLUDED.expire,
        account_count=EXCLUDED.account_count,
        source=EXCLUDED.source,
        token=COALESCE(EXCLUDED.token, issued_licenses.token),
        issued_at=EXCLUDED.issued_at`;
    return;
  }
  const i = issuedLicenses.findIndex(x => x.licenseHash === item.licenseHash);
  if (i >= 0) issuedLicenses[i] = { ...issuedLicenses[i], ...item };
  else issuedLicenses.push(item);
  saveJSON(ISSUED_LICENSES_FILE, issuedLicenses);
}
async function listIssuedLicenses() {
  if (await ensureDb()) {
    const rows = await sql`SELECT license_hash,machine_id,product,plan,expire,account_count,source,token,issued_at,revoked,revoke_reason,revoked_at
      FROM issued_licenses ORDER BY issued_at DESC LIMIT 500`;
    return rows.map(r => ({
      licenseHash: r.license_hash,
      machineId: r.machine_id,
      product: r.product,
      plan: r.plan,
      expire: Number(r.expire),
      accountCount: Number(r.account_count),
      source: r.source,
      token: r.token || '',
      issuedAt: Number(r.issued_at),
      revoked: Boolean(r.revoked),
      revokeReason: r.revoke_reason || '',
      revokedAt: r.revoked_at ? Number(r.revoked_at) : null
    }));
  }
  return issuedLicenses.slice().sort((a, b) => Number(b.issuedAt || 0) - Number(a.issuedAt || 0));
}
async function getLicenseRevocation(licenseKey) {
  const licenseHash = hashLicenseKey(licenseKey);
  if (await ensureDb()) {
    const rows = await sql`SELECT revoked,revoke_reason,revoked_at FROM issued_licenses WHERE license_hash=${licenseHash} LIMIT 1`;
    const item = rows[0];
    return {
      revoked: Boolean(item && item.revoked),
      reason: item ? item.revoke_reason || '' : '',
      revokedAt: item && item.revoked_at ? Number(item.revoked_at) : null
    };
  }
  const item = issuedLicenses.find(x => x.licenseHash === licenseHash);
  return {
    revoked: Boolean(item && item.revoked),
    reason: item ? item.revokeReason || '' : '',
    revokedAt: item && item.revokedAt ? Number(item.revokedAt) : null
  };
}
async function setLicenseRevocation(licenseHash, revoked, reason) {
  const normalizedHash = String(licenseHash || '').trim().toLowerCase();
  if (!/^[a-f0-9]{16}$/.test(normalizedHash)) return false;
  const revokedAt = revoked ? Date.now() : null;
  const revokeReason = revoked ? String(reason || '').trim().slice(0, 300) : '';
  if (await ensureDb()) {
    const rows = await sql`UPDATE issued_licenses
      SET revoked=${Boolean(revoked)},revoke_reason=${revokeReason},revoked_at=${revokedAt}
      WHERE license_hash=${normalizedHash}
      RETURNING license_hash`;
    return rows.length > 0;
  }
  const item = issuedLicenses.find(x => String(x.licenseHash || '').toLowerCase() === normalizedHash);
  if (!item) return false;
  item.revoked = Boolean(revoked);
  item.revokeReason = revokeReason;
  item.revokedAt = revokedAt;
  saveJSON(ISSUED_LICENSES_FILE, issuedLicenses);
  return true;
}
function normalizeBoolSetting(value, defaultValue) {
  if (value === undefined || value === null || value === '') return Boolean(defaultValue);
  if (typeof value === 'boolean') return value;
  const text = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled', '开启'].includes(text)) return true;
  if (['0', 'false', 'no', 'off', 'disabled', '关闭'].includes(text)) return false;
  return Boolean(defaultValue);
}
async function getSetting(key, defaultValue) {
  if (await ensureDb()) {
    const rows = await sql`SELECT value FROM app_settings WHERE key=${key} LIMIT 1`;
    return rows[0] ? rows[0].value : defaultValue;
  }
  return Object.prototype.hasOwnProperty.call(settingsStore, key) ? settingsStore[key] : defaultValue;
}
async function setSetting(key, value) {
  const text = String(value);
  if (await ensureDb()) {
    await sql`INSERT INTO app_settings (key,value,updated_at)
      VALUES (${key},${text},${Date.now()})
      ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at`;
    return;
  }
  settingsStore[key] = text;
  saveJSON(SETTINGS_FILE, settingsStore);
}
async function isRefreshAccountsEnabled() {
  return normalizeBoolSetting(await getSetting('refresh_accounts_enabled', 'true'), true);
}
async function isTrialActivationAccountsEnabled() {
  return normalizeBoolSetting(await getSetting('trial_activation_accounts_enabled', 'false'), false);
}
function normalizeMachineList(value) {
  return String(value || '').split(/\r?\n|,/).map(x => x.trim()).filter(Boolean).slice(0, 10);
}
function resolvePoolMachineIds(value) {
  return String(value || '')
    .split(/\r?\n|,|;|\s+/)
    .map(x => x.trim())
    .filter(Boolean)
    .map(token => {
      const checked = readValidLicensePayload(token);
      const payload = checked && checked.payload;
      return String((payload && (payload.machineId || payload.MachineId)) || token).trim();
    })
    .filter(Boolean)
    .slice(0, 10);
}
function makePoolId(machineIds) {
  return 'POOL-' + crypto.createHash('sha256').update(normalizeMachineList(machineIds).sort().join('|')).digest('hex').slice(0, 16).toUpperCase();
}
async function findAccountPoolByMachine(machineId) {
  const mid = String(machineId || '').trim();
  if (!mid) return null;
  if (await ensureDb()) {
    const rows = await sql`SELECT pool_id,name,machine_ids_json,created_at,updated_at FROM account_pools ORDER BY updated_at DESC LIMIT 500`;
    for (const r of rows) {
      let machineIds = [];
      try { machineIds = JSON.parse(r.machine_ids_json || '[]'); } catch(e) {}
      if (machineIds.includes(mid)) return { poolId: r.pool_id, name: r.name || '', machineIds, createdAt: Number(r.created_at || 0), updatedAt: Number(r.updated_at || 0) };
    }
    return null;
  }
  return accountPools.find(p => Array.isArray(p.machineIds) && p.machineIds.includes(mid)) || null;
}
async function syncGrantAccountsToInventory(machineId, accounts) {
  if (!(await ensureDb())) return;
  const pool = await findAccountPoolByMachine(machineId);
  if (!pool || !Array.isArray(accounts)) return;
  const now = Date.now();
  for (const account of accounts) {
    const email = String(account && account.email || '').trim();
    const normalized = email.toLowerCase();
    if (!email || !normalized || !account.password) continue;
    const id = crypto.createHash('sha256').update(`${pool.poolId}:${normalized}`).digest('hex').slice(0, 32);
    await sql`INSERT INTO account_pool_inventory (id,pool_id,normalized_email,email,password,status,created_at,updated_at)
      VALUES (${id},${pool.poolId},${normalized},${email},${String(account.password)},'available',${now},${now})
      ON CONFLICT (pool_id,normalized_email) DO NOTHING`;
  }
}
async function upsertAccountPool(name, machineIds) {
  const ids = Array.from(new Set(normalizeMachineList(machineIds)));
  if (ids.length < 2) throw new Error('至少填写 2 个卡密或机器码');
  const now = Date.now();
  const poolId = makePoolId(ids);
  const item = { poolId, name: String(name || '').trim() || ids.join(' / '), machineIds: ids, createdAt: now, updatedAt: now };
  if (await ensureDb()) {
    await sql`INSERT INTO account_pools (pool_id,name,machine_ids_json,created_at,updated_at)
      VALUES (${item.poolId},${item.name},${JSON.stringify(item.machineIds)},${item.createdAt},${item.updatedAt})
      ON CONFLICT (pool_id) DO UPDATE SET
        name=EXCLUDED.name,
        machine_ids_json=EXCLUDED.machine_ids_json,
        updated_at=EXCLUDED.updated_at`;
    await migrateAccountGrantsToPool(item);
    return item;
  }
  const i = accountPools.findIndex(p => p.poolId === poolId);
  if (i >= 0) accountPools[i] = { ...accountPools[i], ...item, createdAt: accountPools[i].createdAt || now };
  else accountPools.push(item);
  saveJSON(ACCOUNT_POOLS_FILE, accountPools);
  await migrateAccountGrantsToPool(item);
  return item;
}
async function migrateAccountGrantsToPool(pool) {
  if (!pool || !pool.poolId || !Array.isArray(pool.machineIds) || !pool.machineIds.length) return;
  const poolKey = 'POOL:' + pool.poolId;
  const mergeAccounts = (lists) => {
    const seen = new Set();
    const merged = [];
    for (const list of lists) {
      for (const a of (Array.isArray(list) ? list : [])) {
        const email = String(a && a.email || '').trim();
        if (!email) continue;
        const key = email.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        merged.push({ email, password: String(a.password || '') });
      }
    }
    return merged.slice(0, 500);
  };
  if (await ensureDb()) {
    const rows = await sql`SELECT accounts_json FROM activation_account_grants WHERE license_hash=${poolKey} OR machine_id = ANY(${pool.machineIds})`;
    const accounts = mergeAccounts(rows.map(r => {
      try { return JSON.parse(r.accounts_json || '[]'); } catch(e) { return []; }
    }));
    if (!accounts.length) return;
    await sql`INSERT INTO activation_account_grants (license_hash,machine_id,granted_at,account_count,accounts_json)
      VALUES (${poolKey},${pool.machineIds[0] || ''},${Date.now()},${accounts.length},${JSON.stringify(accounts)})
      ON CONFLICT (license_hash) DO UPDATE SET
        machine_id=EXCLUDED.machine_id,
        account_count=EXCLUDED.account_count,
        accounts_json=EXCLUDED.accounts_json`;
    return;
  }
  const lists = [];
  if (activationGrants[poolKey] && Array.isArray(activationGrants[poolKey].accounts)) lists.push(activationGrants[poolKey].accounts);
  for (const grant of Object.values(activationGrants)) {
    if (grant && pool.machineIds.includes(grant.machineId) && Array.isArray(grant.accounts)) lists.push(grant.accounts);
  }
  const accounts = mergeAccounts(lists);
  if (!accounts.length) return;
  activationGrants[poolKey] = { machineId: pool.machineIds[0] || '', grantedAt: Date.now(), accountCount: accounts.length, accounts };
  saveJSON(ACTIVATION_GRANTS_FILE, activationGrants);
}
async function listAccountPools() {
  if (await ensureDb()) {
    const rows = await sql`SELECT pool_id,name,machine_ids_json,created_at,updated_at FROM account_pools ORDER BY updated_at DESC LIMIT 500`;
    return rows.map(r => {
      let machineIds = [];
      try { machineIds = JSON.parse(r.machine_ids_json || '[]'); } catch(e) {}
      return { poolId: r.pool_id, name: r.name || '', machineIds, createdAt: Number(r.created_at || 0), updatedAt: Number(r.updated_at || 0) };
    });
  }
  return accountPools.slice().sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
}
async function removeAccountPool(poolId) {
  const id = String(poolId || '').trim();
  if (!id) return;
  if (await ensureDb()) {
    await sql`DELETE FROM account_pools WHERE pool_id=${id}`;
    return;
  }
  const i = accountPools.findIndex(p => p.poolId === id);
  if (i >= 0) {
    accountPools.splice(i, 1);
    saveJSON(ACCOUNT_POOLS_FILE, accountPools);
  }
}
async function accountGrantKey(licenseKey, machineId, accountPool) {
  const pool = await findAccountPoolByMachine(machineId);
  const baseKey = pool ? 'POOL:' + pool.poolId : hashLicenseKey(licenseKey);
  return accountPool === 'cloudflare' ? baseKey + ':cloudflare' : baseKey;
}
async function getOrCreateActivationGrant(licenseKey, machineId, count, options = {}) {
  const accountPool = wantsCloudflareAccounts(options) ? 'cloudflare' : 'legacy';
  const domains = accountPool === 'cloudflare' ? CLOUDFLARE_DOMAIN_POOL : DOMAIN_POOL;
  const licenseHash = await accountGrantKey(licenseKey, machineId, accountPool);
  const targetCount = Math.max(0, Math.min(Math.floor(Number(count) || 0), 500));
  if (await ensureDb()) {
    const rows = await sql`SELECT accounts_json FROM activation_account_grants WHERE license_hash=${licenseHash} LIMIT 1`;
    if (rows[0]) {
      try {
        const existing = JSON.parse(rows[0].accounts_json || '[]');
        if (Array.isArray(existing) && existing.length >= targetCount) { await syncGrantAccountsToInventory(machineId, existing); return existing; }
        const accounts = Array.isArray(existing) ? existing.slice() : [];
        accounts.push(...makeAccounts(targetCount - accounts.length, domains));
        await sql`UPDATE activation_account_grants
          SET machine_id=${machineId}, account_count=${accounts.length}, accounts_json=${JSON.stringify(accounts)}
          WHERE license_hash=${licenseHash}`;
        await syncGrantAccountsToInventory(machineId, accounts);
        return accounts;
      } catch (e) { return []; }
    }
    const accounts = makeAccounts(targetCount, domains);
    try {
      await sql`INSERT INTO activation_account_grants (license_hash,machine_id,granted_at,account_count,accounts_json)
        VALUES (${licenseHash},${machineId},${Date.now()},${accounts.length},${JSON.stringify(accounts)})`;
    } catch (e) {
      const retryRows = await sql`SELECT accounts_json FROM activation_account_grants WHERE license_hash=${licenseHash} LIMIT 1`;
      if (retryRows[0]) {
        try { return JSON.parse(retryRows[0].accounts_json || '[]'); } catch (parseError) {}
      }
      throw e;
    }
    await syncGrantAccountsToInventory(machineId, accounts);
    return accounts;
  }
  if (activationGrants[licenseHash]) {
    const accounts = Array.isArray(activationGrants[licenseHash].accounts) ? activationGrants[licenseHash].accounts : [];
    if (accounts.length < targetCount) {
      accounts.push(...makeAccounts(targetCount - accounts.length, domains));
      activationGrants[licenseHash] = { ...activationGrants[licenseHash], machineId, accountCount: accounts.length, accounts };
      saveJSON(ACTIVATION_GRANTS_FILE, activationGrants);
    }
    return accounts;
  }
  const accounts = makeAccounts(targetCount, domains);
  activationGrants[licenseHash] = { machineId, grantedAt: Date.now(), accountCount: accounts.length, accounts };
  saveJSON(ACTIVATION_GRANTS_FILE, activationGrants);
  return accounts;
}
function canRefreshToday(key) { const h = hashLicenseKey(key), d = new Date().toISOString().slice(0, 10); return !quotaStore[h] || quotaStore[h].lastDate !== d; }
function markRefresh(key, count = 1) { const h = hashLicenseKey(key), d = new Date().toISOString().slice(0, 10), n = Math.max(1, parseInt(count, 10) || 1); quotaStore[h] = quotaStore[h] || { refreshCount: 0, lastDate: d }; quotaStore[h].refreshCount = quotaStore[h].lastDate === d ? (quotaStore[h].refreshCount || 0) + n : n; quotaStore[h].lastDate = d; saveJSON(QUOTA_FILE, quotaStore); }
async function isBlacklistedDb(machineId) {
  if (await ensureDb()) {
    const rows = await sql`SELECT reason FROM blacklist WHERE machine_id=${machineId} AND revoked=FALSE LIMIT 1`;
    return { blocked: rows.length > 0, reason: rows[0] ? rows[0].reason : '' };
  }
  const item = blacklist.find(x => x.machineId === machineId && !x.revoked);
  return { blocked: Boolean(item), reason: item ? item.reason || '已拉黑' : '' };
}
async function authorizeCloudLicense(licenseKey, machineId) {
  const key = String(licenseKey || '').trim();
  const claimedMachineId = String(machineId || '').trim().slice(0, 80);
  const checked = readValidLicensePayload(key);
  const payload = checked.payload;
  if (!payload) return { ok: false, status: 400, message: checked.message || '卡密无效' };

  // Lovart LV2 did not verify signatures. It may still be decoded locally for
  // compatibility, but it must never authorize cloud account resources.
  const hasServerVerifiedSignature = key.startsWith('LV3.') || (key.startsWith('LV2.') && isSecureLinkKey(key));
  if (!hasServerVerifiedSignature) return { ok: false, status: 403, message: '旧版卡密不能访问云端账号资源，请联系管理员升级卡密' };
  if (!claimedMachineId) return { ok: false, status: 400, message: '缺少机器码' };

  const boundMachineId = String(payload.machineId || payload.MachineId || '').trim();
  if (!boundMachineId || boundMachineId !== claimedMachineId) {
    return { ok: false, status: 403, message: '卡密与本机不匹配' };
  }
  const expire = Number(payload.expire !== undefined ? payload.expire : payload.Expire);
  if (Number.isFinite(expire) && expire > 0 && expire <= Date.now()) {
    return { ok: false, status: 403, message: '卡密已过期' };
  }

  const blocked = await isBlacklistedDb(claimedMachineId);
  if (blocked.blocked) return { ok: false, status: 403, message: blocked.reason ? '该机器已被拉黑：' + blocked.reason : '该机器已被拉黑' };
  const revocation = await getLicenseRevocation(key);
  if (revocation.revoked) return { ok: false, status: 403, message: revocation.reason ? '该卡密已被撤销：' + revocation.reason : '该卡密已被撤销' };

  return { ok: true, key, machineId: claimedMachineId, payload };
}
async function canRefreshTodayDb(key) {
  const h = hashLicenseKey(key), d = new Date().toISOString().slice(0, 10);
  if (await ensureDb()) {
    const rows = await sql`SELECT last_date FROM refresh_quota WHERE license_hash=${h} LIMIT 1`;
    return !rows[0] || rows[0].last_date !== d;
  }
  return !quotaStore[h] || quotaStore[h].lastDate !== d;
}
async function markRefreshDb(key, count = 1) {
  const h = hashLicenseKey(key), d = new Date().toISOString().slice(0, 10);
  const n = Math.max(1, parseInt(count, 10) || 1);
  if (await ensureDb()) {
    await sql`INSERT INTO refresh_quota (license_hash,last_date,refresh_count)
      VALUES (${h},${d},${n})
      ON CONFLICT (license_hash) DO UPDATE SET
        refresh_count = CASE WHEN refresh_quota.last_date = EXCLUDED.last_date THEN refresh_quota.refresh_count + EXCLUDED.refresh_count ELSE EXCLUDED.refresh_count END,
        last_date = EXCLUDED.last_date`;
    return;
  }
  markRefresh(key, n);
}
function normalizePlanDurationDays(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}
async function findActivationDurationDays(machineId, product) {
  if (!machineId) return null;
  if (await ensureDb()) {
    const rows = await sql`SELECT expire, activated_at FROM activations WHERE machine_id=${machineId} AND product=${product} LIMIT 1`;
    if (!rows[0]) return null;
    const duration = (Number(rows[0].expire || 0) - Number(rows[0].activated_at || 0)) / 86400000;
    return normalizePlanDurationDays(duration);
  }
  const item = activationStore.find(x => x.machineId === machineId && x.product === product);
  if (!item) return null;
  return normalizePlanDurationDays((Number(item.expire || 0) - Number(item.activatedAt || 0)) / 86400000);
}
async function canUseRefreshForLicense(payload, machineId, licenseKey) {
  if (!payload || payload.plan === 'permanent') return { allowed: false, reason: '永久卡不需要替换账号' };
  return { allowed: true, durationDays: normalizePlanDurationDays(payload.durationDays) };
}
function licenseAccountCount(payload) {
  if (!payload) return 0;
  const n = Number(payload.accountCount);
  if (Number.isFinite(n)) return Math.max(0, Math.min(Math.floor(n), 500));
  if (payload.plan === 'permanent') return 0;
  return payload.hasGift ? 100 : 0;
}
function parseAccountCount(value, fallback = 30) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(Math.floor(n), 500));
}
function createLovartModernLicense(machineId, plan, days, accountCount) {
  const normalizedPlan = plan === 'permanent' ? 'permanent' : 'monthly';
  const normalizedDays = Math.max(1, Math.min(parseInt(days, 10) || 30, 3650));
  const normalizedCount = parseAccountCount(accountCount, normalizedPlan === 'permanent' ? 0 : 30);
  const expireTime = normalizedPlan === 'permanent' ? 4070908800000 : Date.now() + normalizedDays * 86400000;
  const payload = {
    machineId,
    expire: expireTime,
    plan: normalizedPlan,
    hasGift: false,
    issuedAt: Date.now(),
    durationDays: normalizedPlan === 'permanent' ? 0 : normalizedDays,
    accountCount: normalizedCount
  };
  const licenseKey = signLicense(payload, 'LV3', 'original');
  return { licenseKey, plan: normalizedPlan, days: normalizedDays, expireTime, accountCount: normalizedCount };
}
async function recordActivation(machineId, plan, expire, accountCount, product, licenseKey) {
  const licenseHash = licenseKey ? hashLicenseKey(licenseKey) : null;
  if (await ensureDb()) {
    const activatedAt = Date.now();
    await sql`INSERT INTO activations (machine_id,product,plan,expire,account_count,license_hash,activated_at,activation_count)
      VALUES (${machineId},${product},${plan},${Number(expire) || 0},${Number(accountCount) || 0},${licenseHash},${activatedAt},1)
      ON CONFLICT (machine_id, product) DO UPDATE SET
        plan=EXCLUDED.plan,
        expire=EXCLUDED.expire,
        account_count=EXCLUDED.account_count,
        license_hash=COALESCE(EXCLUDED.license_hash, activations.license_hash),
        activated_at=EXCLUDED.activated_at,
        activation_count=activations.activation_count + 1`;
    return;
  }
  const item = activationStore.find(x => x.machineId === machineId && x.product === product);
  const activatedAt = Date.now();
  if (item) Object.assign(item, { plan, expire, accountCount, product, activatedAt, activationCount: (item.activationCount || 0) + 1 });
  else activationStore.push({ machineId, plan, expire, accountCount, product, activatedAt, activationCount: 1 });
  saveJSON(ACTIVATIONS_FILE, activationStore);
}
async function recordClientStatus(machineId, product, licenseKey, reportedAccountCount, licensePayload) {
  const licenseHash = licenseKey ? hashLicenseKey(licenseKey) : null;
  const lastSeenAt = Date.now();
  const plan = (licensePayload && licensePayload.plan) || 'monthly';
  const expire = Number(licensePayload && licensePayload.expire) || 0;
  const accountCount = licenseAccountCount(licensePayload);
  if (await ensureDb()) {
    await sql`INSERT INTO activations
      (machine_id,product,plan,expire,account_count,license_hash,reported_account_count,last_seen_at,activated_at,activation_count)
      VALUES
      (${machineId},${product},${plan},${expire},${accountCount},${licenseHash},${Number(reportedAccountCount) || 0},${lastSeenAt},${lastSeenAt},0)
      ON CONFLICT (machine_id, product) DO UPDATE SET
        plan=EXCLUDED.plan,
        expire=EXCLUDED.expire,
        account_count=EXCLUDED.account_count,
        reported_account_count=EXCLUDED.reported_account_count,
        last_seen_at=EXCLUDED.last_seen_at,
        license_hash=COALESCE(EXCLUDED.license_hash, activations.license_hash)`;
    return;
  }
  const item = activationStore.find(x => x.machineId === machineId && x.product === product);
  if (item) Object.assign(item, { reportedAccountCount: Number(reportedAccountCount) || 0, lastSeenAt, licenseHash });
  else activationStore.push({ machineId, product, plan, expire, accountCount, reportedAccountCount: Number(reportedAccountCount) || 0, lastSeenAt, activatedAt: lastSeenAt, activationCount: 0, licenseHash });
  saveJSON(ACTIVATIONS_FILE, activationStore);
}
function normalizeClientAccounts(accounts) {
  return Array.isArray(accounts) ? accounts.map(a => {
    const points = a && a.points && typeof a.points === 'object' ? a.points : {};
    const replace = a && a.replace && typeof a.replace === 'object' ? a.replace : {};
    return {
      email: String(a && a.email || '').trim(),
      source: String(a && a.source || ''),
      ...(a && a.loginDate ? { loginDate: String(a.loginDate) } : {}),
      ...(a && a.lastLoginAt ? { lastLoginAt: Number(a.lastLoginAt) || String(a.lastLoginAt) } : {}),
      points: {
        ...(points.date ? { date: String(points.date) } : {}),
        ...(points.status ? { status: String(points.status) } : {}),
        ...(Number.isFinite(Number(points.firstPoints)) ? { firstPoints: Number(points.firstPoints) } : {}),
        ...(Number.isFinite(Number(points.currentPoints)) ? { currentPoints: Number(points.currentPoints) } : {}),
        ...(points.currentDetectedAt ? { currentDetectedAt: Number(points.currentDetectedAt) || String(points.currentDetectedAt) } : {}),
        ...(points.lastCheckStatus ? { lastCheckStatus: String(points.lastCheckStatus) } : {})
      },
      replace: {
        needed: replace.needed === true,
        ...(replace.reason ? { reason: String(replace.reason) } : {}),
        ...(replace.date ? { date: String(replace.date) } : {})
      }
    };
  }).filter(a => a.email).slice(0, 500) : [];
}
async function saveClientAccountSnapshot(machineId, product, licenseKey, accounts) {
  const normalized = normalizeClientAccounts(accounts);
  const licenseHash = licenseKey ? hashLicenseKey(licenseKey) : null;
  const updatedAt = Date.now();
  if (await ensureDb()) {
    await sql`INSERT INTO client_account_snapshots
      (machine_id,product,license_hash,account_count,accounts_json,updated_at)
      VALUES (${machineId},${product},${licenseHash},${normalized.length},${JSON.stringify(normalized)},${updatedAt})
      ON CONFLICT (machine_id) DO UPDATE SET
        product=EXCLUDED.product,
        license_hash=EXCLUDED.license_hash,
        account_count=EXCLUDED.account_count,
        accounts_json=EXCLUDED.accounts_json,
        updated_at=EXCLUDED.updated_at`;
    return normalized;
  }
  clientAccountSnapshots[machineId] = { machineId, product, licenseHash, accountCount: normalized.length, accounts: normalized, updatedAt };
  saveJSON(CLIENT_ACCOUNT_SNAPSHOTS_FILE, clientAccountSnapshots);
  return normalized;
}
function accountStatusTimestamp(status) {
  if (!status || typeof status !== 'object') return 0;
  const points = status.points && typeof status.points === 'object' ? status.points : {};
  const replace = status.replace && typeof status.replace === 'object' ? status.replace : {};
  return Math.max(
    Number(status.updatedAt) || 0,
    Number(points.updatedAt) || 0,
    Number(points.currentDetectedAt) || 0,
    Number(points.firstDetectedAt) || 0,
    Number(replace.updatedAt) || 0,
    Number(replace.markedAt) || 0
  );
}
async function saveAccountCloudStatuses(machineId, accounts) {
  const normalized = normalizeClientAccounts(accounts);
  const now = Date.now();
  const rows = normalized
    .filter(a => a.email && (a.points || a.replace || (a.flags && a.flags.length)))
    .map(a => ({
      email: a.email.toLowerCase(),
      status: {
        email: a.email,
        points: a.points || null,
        replace: a.replace || null,
        flags: a.flags || [],
        machineId,
        updatedAt: Number(a.updatedAt) || now
      }
    }));
  if (!rows.length) return;
  if (await ensureDb()) {
    for (const row of rows) {
      const existingRows = await sql`SELECT status_json FROM account_cloud_status WHERE email=${row.email} LIMIT 1`;
      if (existingRows.length) {
        try {
          const existingStatus = JSON.parse(existingRows[0].status_json || '{}');
          if (accountStatusTimestamp(existingStatus) > accountStatusTimestamp(row.status)) continue;
        } catch(e) {}
      }
      await sql`INSERT INTO account_cloud_status (email,machine_id,status_json,updated_at)
        VALUES (${row.email},${machineId},${JSON.stringify(row.status)},${now})
        ON CONFLICT (email) DO UPDATE SET
          machine_id=EXCLUDED.machine_id,
          status_json=EXCLUDED.status_json,
          updated_at=EXCLUDED.updated_at`;
    }
    return;
  }
  for (const row of rows) {
    if (accountStatusTimestamp(accountCloudStatus[row.email]) > accountStatusTimestamp(row.status)) continue;
    accountCloudStatus[row.email] = row.status;
  }
  saveJSON(ACCOUNT_CLOUD_STATUS_FILE, accountCloudStatus);
}
async function getAccountCloudStatuses(emails) {
  const keys = Array.from(new Set((Array.isArray(emails) ? emails : [])
    .map(x => String(x || '').trim().toLowerCase())
    .filter(Boolean))).slice(0, 500);
  if (!keys.length) return {};
  if (await ensureDb()) {
    const rows = await sql`SELECT email,status_json FROM account_cloud_status WHERE email = ANY(${keys})`;
    const result = {};
    for (const row of rows) {
      try { result[row.email] = JSON.parse(row.status_json || '{}'); } catch(e) {}
    }
    return result;
  }
  const result = {};
  for (const key of keys) if (accountCloudStatus[key]) result[key] = accountCloudStatus[key];
  return result;
}
function accountEmailSet(accounts) {
  return new Set(normalizeClientAccounts(accounts).map(a => a.email.toLowerCase()).filter(Boolean));
}
function findAccountOverlap(setA, accountsB) {
  const overlap = [];
  for (const a of normalizeClientAccounts(accountsB)) {
    const key = a.email.toLowerCase();
    if (setA.has(key)) overlap.push(a.email);
    if (overlap.length >= 20) break;
  }
  return overlap;
}
async function checkAndTouchActiveClient(machineId, product, accounts) {
  const normalized = normalizeClientAccounts(accounts);
  const currentEmails = accountEmailSet(normalized);
  const pool = await findAccountPoolByMachine(machineId);
  const poolId = pool ? pool.poolId : '';
  const now = Date.now();
  const cutoff = now - ACTIVE_CLIENT_TIMEOUT_MS;
  if (await ensureDb()) {
    const rows = poolId
      ? await sql`SELECT machine_id,pool_id,accounts_json,last_seen_at FROM client_active_sessions
        WHERE machine_id<>${machineId} AND pool_id=${poolId} AND last_seen_at>${cutoff}
        ORDER BY last_seen_at DESC LIMIT 50`
      : currentEmails.size
        ? await sql`SELECT machine_id,pool_id,accounts_json,last_seen_at FROM client_active_sessions
          WHERE machine_id<>${machineId} AND last_seen_at>${cutoff}
          ORDER BY last_seen_at DESC LIMIT 50`
        : [];
      for (const r of rows) {
        let otherAccounts = [];
        try { otherAccounts = JSON.parse(r.accounts_json || '[]'); } catch(e) {}
        const overlap = findAccountOverlap(currentEmails, otherAccounts);
        if (poolId || overlap.length) {
          return { machineId: r.machine_id, lastSeenAt: Number(r.last_seen_at || 0), overlap };
        }
      }
    await sql`INSERT INTO client_active_sessions (machine_id,pool_id,product,account_count,accounts_json,last_seen_at)
        VALUES (${machineId},${poolId || null},${product || 'lovart-modern'},${normalized.length},${JSON.stringify(normalized)},${now})
        ON CONFLICT (machine_id) DO UPDATE SET
          pool_id=EXCLUDED.pool_id,
          product=EXCLUDED.product,
          account_count=EXCLUDED.account_count,
          accounts_json=EXCLUDED.accounts_json,
          last_seen_at=EXCLUDED.last_seen_at`;
    return null;
  }
  if (poolId) {
    for (const item of Object.values(activeClients)) {
      if (!item || item.machineId === machineId || Number(item.lastSeenAt || 0) <= cutoff) continue;
      if (item.poolId === poolId) return { machineId: item.machineId, lastSeenAt: Number(item.lastSeenAt || 0), overlap: [] };
    }
  } else if (currentEmails.size) {
    for (const item of Object.values(activeClients)) {
      if (!item || item.machineId === machineId || Number(item.lastSeenAt || 0) <= cutoff) continue;
      const overlap = findAccountOverlap(currentEmails, item.accounts || []);
      if (overlap.length) return { machineId: item.machineId, lastSeenAt: Number(item.lastSeenAt || 0), overlap };
    }
  }
  activeClients[machineId] = { machineId, poolId, product: product || 'lovart-modern', accountCount: normalized.length, accounts: normalized, lastSeenAt: now };
  saveJSON(ACTIVE_CLIENTS_FILE, activeClients);
  return null;
}
async function clearActiveClient(machineId) {
  const id = String(machineId || '').trim();
  if (!id) return;
  if (await ensureDb()) {
    await sql`DELETE FROM client_active_sessions WHERE machine_id=${id}`;
    return;
  }
  if (activeClients[id]) {
    delete activeClients[id];
    saveJSON(ACTIVE_CLIENTS_FILE, activeClients);
  }
}
async function getClientAccountSnapshot(machineId) {
  if (await ensureDb()) {
    const rows = await sql`SELECT machine_id,product,license_hash,account_count,accounts_json,updated_at FROM client_account_snapshots WHERE machine_id=${machineId} LIMIT 1`;
    const r = rows[0];
    if (!r) return null;
    let accounts = [];
    try { accounts = JSON.parse(r.accounts_json || '[]'); } catch(e) {}
    return { machineId: r.machine_id, product: r.product, licenseHash: r.license_hash || '', accountCount: Number(r.account_count || 0), accounts, updatedAt: Number(r.updated_at || 0) };
  }
  return clientAccountSnapshots[machineId] || null;
}
async function authorizeLicenseAccounts(licenseKey, machineId, accounts, source) {
  const normalizedAccounts = normalizeClientAccounts(accounts);
  if (!normalizedAccounts.length) return;
  const licenseHash = hashLicenseKey(licenseKey);
  const authorizedAt = Date.now();
  if (await ensureDb()) {
    for (const account of normalizedAccounts) {
      const email = String(account.email || '').trim().toLowerCase();
      if (!email) continue;
      await sql`INSERT INTO license_account_authorizations (license_hash,machine_id,email,source,authorized_at)
        VALUES (${licenseHash},${machineId},${email},${source || 'cloud_grant'},${authorizedAt})
        ON CONFLICT (license_hash,email) DO UPDATE SET
          machine_id=EXCLUDED.machine_id,source=EXCLUDED.source,authorized_at=EXCLUDED.authorized_at`;
    }
    return;
  }
  const list = Array.isArray(licenseAccountAuthorizations[licenseHash]) ? licenseAccountAuthorizations[licenseHash] : [];
  const byEmail = new Map(list.map(item => [String(item.email || '').toLowerCase(), item]));
  for (const account of normalizedAccounts) {
    const email = String(account.email || '').trim().toLowerCase();
    if (email) byEmail.set(email, { machineId, email, source: source || 'cloud_grant', authorizedAt });
  }
  licenseAccountAuthorizations[licenseHash] = Array.from(byEmail.values()).slice(-2000);
  saveJSON(LICENSE_ACCOUNT_AUTHORIZATIONS_FILE, licenseAccountAuthorizations);
}
async function listClientAccountSnapshots() {
  if (await ensureDb()) {
    const rows = await sql`SELECT machine_id,product,account_count,accounts_json,updated_at FROM client_account_snapshots ORDER BY updated_at DESC LIMIT 500`;
    return rows.map(r => {
      let accounts = [];
      try { accounts = JSON.parse(r.accounts_json || '[]'); } catch(e) {}
      return { machineId: r.machine_id, product: r.product, accountCount: Number(r.account_count || 0), accounts, updatedAt: Number(r.updated_at || 0) };
    });
  }
  return Object.values(clientAccountSnapshots).sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));
}
async function cleanupExpiredReservations() {
  if (!(await ensureDb())) return false;
  const now = Date.now();
  await sql.transaction(tx => [tx`WITH expired AS (
      SELECT i.id,i.reserved_command_id
      FROM account_pool_inventory i
      LEFT JOIN account_commands c ON c.command_id=i.reserved_command_id
      WHERE i.status='reserved' AND i.reservation_expires_at <= ${now} AND COALESCE(c.status,'') <> 'completed'
      FOR UPDATE OF i
    ), released AS (
      UPDATE account_pool_inventory i SET status='available',reserved_command_id=NULL,reserved_machine_id=NULL,reserved_at=NULL,reservation_expires_at=NULL,updated_at=${now}
      FROM expired e WHERE i.id=e.id RETURNING e.reserved_command_id
    ) UPDATE account_commands c SET status='failed',last_error='RESERVATION_EXPIRED',completed_at=${now}
      FROM released r WHERE c.command_id=r.reserved_command_id AND c.status <> 'completed'`]);
  return true;
}

async function createReservedAccountCommand({ machineId, product, licenseKey, command }) {
  if (!(await ensureDb())) {
    const error = new Error('DATABASE_REQUIRED_FOR_RESERVATION');
    error.code = 'DATABASE_REQUIRED_FOR_RESERVATION';
    throw error;
  }
  await cleanupExpiredReservations();
  const pool = await findAccountPoolByMachine(machineId);
  if (!pool) throw Object.assign(new Error('ACCOUNT_POOL_NOT_FOUND'), { code: 'ACCOUNT_POOL_NOT_FOUND' });
  const commandId = 'ACMD-' + crypto.randomBytes(12).toString('hex').toUpperCase();
  const now = Date.now();
  const expires = now + RESERVATION_TTL_MS;
  const replenishCount = Number(command.replenishCount || 0);
  const [rows] = await sql.transaction(tx => [tx`WITH selected AS (
      SELECT i.id,i.email,i.normalized_email
      FROM account_pool_inventory i
      WHERE i.pool_id=${pool.poolId} AND i.status='available'
        AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(COALESCE((SELECT accounts_json::jsonb FROM client_account_snapshots WHERE machine_id=${machineId} LIMIT 1),'[]'::jsonb)) a
          WHERE lower(trim(a->>'email'))=i.normalized_email
        )
      ORDER BY i.normalized_email ASC
      FOR UPDATE SKIP LOCKED LIMIT ${replenishCount}
    ), updated AS (
      UPDATE account_pool_inventory i SET status='reserved', reserved_command_id=${commandId}, reserved_machine_id=${machineId}, reserved_at=${now}, reservation_expires_at=${expires}, updated_at=${now}
      FROM selected s WHERE i.id=s.id RETURNING s.id,s.email,s.normalized_email
    ), inserted AS (
      INSERT INTO account_commands (command_id,machine_id,product,license_hash,command_json,status,result_json,created_at,delivered_at,completed_at,attempt_count,last_error)
      SELECT ${commandId},${machineId},${product || 'lovart-modern'},${licenseKey ? hashLicenseKey(licenseKey) : null},
        jsonb_build_object('type',${command.type || 'delete_replenish_accounts'},'deleteCount',${Number(command.deleteCount) || 0},'replenishCount',${replenishCount},'emails',${JSON.stringify(Array.isArray(command.emails) ? command.emails : [])}::jsonb,'selectionMode',${command.selectionMode || 'exact_emails'},'allowFallbackSelection',${command.allowFallbackSelection === true},'replacementAccountIds',(SELECT jsonb_agg(id ORDER BY normalized_email) FROM updated),'replacementEmails',(SELECT jsonb_agg(normalized_email ORDER BY normalized_email) FROM updated))::text,
        'pending',NULL,${now},NULL,NULL,0,''
      WHERE (SELECT count(*) FROM updated)=${replenishCount}
      RETURNING command_id,command_json
    ) SELECT * FROM inserted`]);
  if (!rows || !rows.length) throw Object.assign(new Error('INSUFFICIENT_POOL_INVENTORY'), { code: 'INSUFFICIENT_POOL_INVENTORY' });
  return { commandId, command: { ...JSON.parse(rows[0].command_json), commandId } };
}

async function createAccountCommand(machineId, product, licenseKey, command) {
  const commandId = 'ACMD-' + crypto.randomBytes(12).toString('hex').toUpperCase();
  const item = {
    commandId,
    machineId,
    product: product || 'lovart-modern',
    licenseHash: licenseKey ? hashLicenseKey(licenseKey) : null,
    command: { ...command, commandId },
    status: 'pending',
    result: null,
    createdAt: Date.now(),
    deliveredAt: null,
    completedAt: null
    ,attemptCount: 0
    ,lastError: ''
  };
  if (await ensureDb()) {
    await sql`INSERT INTO account_commands
      (command_id,machine_id,product,license_hash,command_json,status,result_json,created_at,delivered_at,completed_at,attempt_count,last_error)
      VALUES (${item.commandId},${item.machineId},${item.product},${item.licenseHash},${JSON.stringify(item.command)},${item.status},NULL,${item.createdAt},NULL,NULL,0,'')`;
    return item;
  }
  accountCommands.push(item);
  saveJSON(ACCOUNT_COMMANDS_FILE, accountCommands);
  return item;
}
async function takePendingAccountCommands(machineId, licenseKey) {
  const licenseHash = licenseKey ? hashLicenseKey(licenseKey) : null;
  const now = Date.now();
  if (await ensureDb()) {
    await cleanupExpiredReservations();
    await sql`UPDATE account_commands SET status='failed', last_error='DELIVERY_RETRY_EXHAUSTED', completed_at=${now}
      WHERE machine_id=${machineId} AND status IN ('pending','delivered') AND attempt_count >= 5 AND (status='pending' OR delivered_at < ${now - 120000})`;
    const rows = await sql`SELECT command_id,machine_id,command_json,attempt_count FROM account_commands
      WHERE machine_id=${machineId} AND (status='pending' OR (status='delivered' AND delivered_at < ${now - 120000})) AND (license_hash IS NULL OR license_hash=${licenseHash}) AND attempt_count < 5
      ORDER BY created_at ASC LIMIT 5`;
    for (const r of rows) {
      await sql`UPDATE account_commands SET status='delivered', delivered_at=${now}, attempt_count=attempt_count+1 WHERE command_id=${r.command_id}`;
    }
    const commands = [];
    for (const r of rows) {
      let command;
      try { command = JSON.parse(r.command_json || '{}'); } catch(e) { continue; }
      if (Array.isArray(command.replacementAccountIds) && command.replacementAccountIds.length) {
        const reservations = await sql`SELECT id,email,password,status,reservation_expires_at FROM account_pool_inventory
          WHERE reserved_command_id=${r.command_id} AND reserved_machine_id=${machineId} AND status='reserved' AND reservation_expires_at > ${now}`;
        const byId = new Map(reservations.map(item => [String(item.id), item]));
        const ordered = command.replacementAccountIds.map(id => byId.get(String(id))).filter(Boolean);
        if (ordered.length !== command.replacementAccountIds.length) continue;
        command.replacementAccounts = ordered.map(item => ({ email: item.email, password: item.password }));
      }
      commands.push(command);
    }
    return commands;
  }
  const commands = [];
  for (const item of accountCommands) {
    if (commands.length >= 5) break;
    if (item.machineId === machineId && (item.status === 'pending' || (item.status === 'delivered' && Number(item.deliveredAt || 0) < now - 120000)) && Number(item.attemptCount || 0) < 5 && (!item.licenseHash || item.licenseHash === licenseHash)) {
      item.status = 'delivered';
      item.deliveredAt = now;
      item.attemptCount = Number(item.attemptCount || 0) + 1;
      commands.push(item.command);
    }
  }
  if (commands.length) saveJSON(ACCOUNT_COMMANDS_FILE, accountCommands);
  return commands;
}
async function completeAccountCommand(machineId, commandId, result) {
  const now = Date.now();
  if (!commandId) return false;
  if (await ensureDb()) {
    await cleanupExpiredReservations();
    const addedEmails = normalizeEmails(result && result.addedEmails);
    const errorCode = String(result && (result.errorCode || result.message) || 'COMMAND_FAILED');
    const [updated] = await sql.transaction(tx => [tx`WITH locked AS (
      SELECT i.id,i.email,lower(trim(i.email)) AS normalized_email
      FROM account_pool_inventory i JOIN account_commands c ON c.command_id=i.reserved_command_id
      WHERE i.reserved_command_id=${commandId} AND i.reserved_machine_id=${machineId} AND c.machine_id=${machineId} AND c.status <> 'completed'
      FOR UPDATE
    ), mismatch AS (
      SELECT EXISTS (SELECT 1 FROM jsonb_array_elements_text(${JSON.stringify(addedEmails)}::jsonb) a WHERE NOT EXISTS (SELECT 1 FROM locked l WHERE l.normalized_email=a)) AS bad,
             (SELECT count(*) FROM locked) AS total,
             (SELECT count(*) FROM locked l WHERE l.normalized_email = ANY(${addedEmails})) AS added
    ), assigned AS (
      UPDATE account_pool_inventory i SET status='assigned',assigned_machine_id=${machineId},assigned_at=${now},reserved_command_id=NULL,reserved_machine_id=NULL,reserved_at=NULL,reservation_expires_at=NULL,updated_at=${now}
      FROM locked l,mismatch m WHERE i.id=l.id AND l.normalized_email=ANY(${addedEmails}) AND NOT m.bad RETURNING i.id
    ), released AS (
      UPDATE account_pool_inventory i SET status='available',reserved_command_id=NULL,reserved_machine_id=NULL,reserved_at=NULL,reservation_expires_at=NULL,updated_at=${now}
      FROM locked l,mismatch m WHERE i.id=l.id AND (l.normalized_email <> ALL(${addedEmails}) OR m.bad) RETURNING i.id
    ) UPDATE account_commands c SET status=CASE WHEN m.bad THEN 'failed' WHEN m.added=m.total AND ${result && result.success === true} THEN 'completed' WHEN m.added=0 THEN 'failed' ELSE 'partial' END,
      result_json=${JSON.stringify(result || {})},last_error=CASE WHEN m.bad THEN 'ACK_EMAIL_MISMATCH' WHEN m.added=m.total AND ${result && result.success === true} THEN '' WHEN m.added=0 THEN ${errorCode} ELSE 'PARTIAL_REPLACEMENT' END,completed_at=${now}
      FROM mismatch m WHERE c.command_id=${commandId} AND c.machine_id=${machineId} AND c.status <> 'completed' RETURNING c.command_id`]);
    return Array.isArray(updated) && updated.length > 0;
  }
  const item = accountCommands.find(x => x.commandId === commandId && x.machineId === machineId);
  if (item) {
    item.status = result && result.success === true ? 'completed' : 'failed';
    item.result = result || {};
    item.lastError = item.status === 'failed' ? String(result && (result.errorCode || result.message) || 'COMMAND_FAILED') : '';
    item.completedAt = now;
    saveJSON(ACCOUNT_COMMANDS_FILE, accountCommands);
    return true;
  }
  return false;
}
async function listAccountCommands(filters = {}) {
  const machineId = String(filters.machineId || '').trim();
  const status = String(filters.status || '').trim();
  if (await ensureDb()) {
    const rows = await sql`SELECT command_id,machine_id,command_json,status,result_json,created_at,delivered_at,completed_at,attempt_count,last_error FROM account_commands WHERE (${machineId}='' OR machine_id=${machineId}) AND (${status}='' OR status=${status}) ORDER BY created_at DESC LIMIT 500`;
    return rows.map(r => { let command = {}, result = null; try { command = JSON.parse(r.command_json || '{}'); } catch(e) {} try { result = r.result_json ? JSON.parse(r.result_json) : null; } catch(e) {} return { commandId: r.command_id, machineId: r.machine_id, type: command.type, deleteCount: command.deleteCount || 0, replenishCount: command.replenishCount || 0, emails: command.emails || [], status: r.status, attemptCount: Number(r.attempt_count || 0), result, createdAt: Number(r.created_at || 0), deliveredAt: r.delivered_at, completedAt: r.completed_at, lastError: r.last_error || '' }; });
  }
  return accountCommands.filter(item => (!machineId || item.machineId === machineId) && (!status || item.status === status)).map(item => ({ commandId: item.commandId, machineId: item.machineId, type: item.command.type, deleteCount: item.command.deleteCount || 0, replenishCount: item.command.replenishCount || 0, emails: item.command.emails || [], status: item.status, attemptCount: item.attemptCount || 0, result: item.result, createdAt: item.createdAt, deliveredAt: item.deliveredAt, completedAt: item.completedAt, lastError: item.lastError || '' }));
}
async function getActivationStats() {
  const nowTime = Date.now();
  if (await ensureDb()) {
    const rows = await sql`SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE plan='monthly' AND expire>${nowTime})::int AS active_monthly,
      COUNT(*) FILTER (WHERE plan='permanent')::int AS active_permanent,
      COUNT(*) FILTER (WHERE plan='monthly' AND expire<=${nowTime})::int AS expired,
      COUNT(*) FILTER (WHERE
        (activations.reported_account_count IS NOT NULL AND activations.reported_account_count > activations.account_count)
        OR (activations.plan='monthly' AND activations.expire<=${nowTime} AND activations.last_seen_at IS NOT NULL AND activations.last_seen_at > activations.expire)
      )::int AS risk
      FROM activations`;
    const r = rows[0] || {};
    return { total: r.total || 0, activeMonthly: r.active_monthly || 0, activePermanent: r.active_permanent || 0, expired: r.expired || 0, risk: r.risk || 0 };
  }
  const risk = (await listActivations()).filter(a => a.risk).length;
  return { total: activationStore.length, activeMonthly: activationStore.filter(a => a.plan === 'monthly' && a.expire > nowTime).length, activePermanent: activationStore.filter(a => a.plan === 'permanent').length, expired: activationStore.filter(a => a.plan === 'monthly' && a.expire <= nowTime).length, risk };
}
async function getStorageStats() {
  const tableNames = [
    'activations',
    'issued_licenses',
    'activation_account_grants',
    'client_account_snapshots',
    'account_cloud_status',
    'client_active_sessions',
    'account_pools',
    'account_commands',
    'trial_claims',
    'issue_tokens',
    'refresh_quota',
    'blacklist',
    'app_settings',
    'reseller_accounts',
    'reseller_sessions',
    'channel_products',
    'channel_orders',
    'reseller_wallet_ledger',
    'payment_transactions'
  ];
  if (await ensureDb()) {
    const dbRows = await sql`SELECT pg_database_size(current_database())::bigint AS bytes`;
    const tableRows = await sql`
      SELECT
        c.relname AS name,
        pg_total_relation_size(c.oid)::bigint AS bytes,
        COALESCE(s.n_live_tup, 0)::bigint AS estimated_rows
      FROM pg_class c
      LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
      WHERE c.relkind = 'r' AND c.relname = ANY(${tableNames})
      ORDER BY pg_total_relation_size(c.oid) DESC`;
    const tables = [];
    for (const row of tableRows) {
      let count = Number(row.estimated_rows || 0);
      try {
        const countRows = await sql`SELECT COUNT(*)::bigint AS count FROM ${sql.unsafe(row.name)}`;
        count = Number(countRows[0] && countRows[0].count || count);
      } catch(e) {}
      tables.push({ name: row.name, bytes: Number(row.bytes || 0), rows: count });
    }
    const totalBytes = Number(dbRows[0] && dbRows[0].bytes || 0);
    return {
      mode: 'database',
      database: true,
      totalBytes,
      totalMb: Math.round(totalBytes / 1024 / 1024 * 100) / 100,
      tables,
      checkedAt: Date.now()
    };
  }
  const files = [
    ISSUE_TOKENS_FILE,
    BLACKLIST_FILE,
    QUOTA_FILE,
    ACTIVATIONS_FILE,
    TRIAL_CLAIMS_FILE,
    SETTINGS_FILE,
    ACTIVATION_GRANTS_FILE,
    ISSUED_LICENSES_FILE,
    CLIENT_ACCOUNT_SNAPSHOTS_FILE,
    ACCOUNT_COMMANDS_FILE,
    ACCOUNT_CLOUD_STATUS_FILE,
    ACTIVE_CLIENTS_FILE,
    ACCOUNT_POOLS_FILE
  ].map(file => {
    try {
      const stat = fs.existsSync(file) ? fs.statSync(file) : null;
      return { name: file.replace(/^.*[\\/]/, ''), bytes: stat ? Number(stat.size || 0) : 0, rows: null };
    } catch(e) {
      return { name: file.replace(/^.*[\\/]/, ''), bytes: 0, rows: null };
    }
  });
  const totalBytes = files.reduce((sum, f) => sum + Number(f.bytes || 0), 0);
  return {
    mode: 'tmp_files',
    database: false,
    totalBytes,
    totalMb: Math.round(totalBytes / 1024 / 1024 * 100) / 100,
    tables: files.sort((a, b) => Number(b.bytes || 0) - Number(a.bytes || 0)),
    checkedAt: Date.now()
  };
}
async function listActivations() {
  const nowTime = Date.now();
  if (await ensureDb()) {
    const rows = await sql`SELECT a.machine_id, a.product, a.plan, a.expire, a.account_count, a.reported_account_count, a.last_seen_at, a.activated_at, a.activation_count
      FROM activations a
      ORDER BY a.activated_at DESC LIMIT 500`;
    return rows.map(a => {
      const reported = a.reported_account_count == null ? null : Number(a.reported_account_count);
      const expire = Number(a.expire);
      const risks = [];
      if (a.plan !== 'permanent' && reported != null && reported > Number(a.account_count || 0)) risks.push('本地账号超出套餐');
      if (a.plan === 'monthly' && expire <= nowTime && a.last_seen_at && Number(a.last_seen_at) > expire) risks.push('过期后仍在线');
      return {
        machineId: a.machine_id,
        product: a.product,
        plan: a.plan,
        expire,
        accountCount: a.account_count,
        reportedAccountCount: reported,
        todayRefreshCount: 0,
        lastSeenAt: a.last_seen_at ? Number(a.last_seen_at) : null,
        activatedAt: Number(a.activated_at),
        activationCount: a.activation_count,
        risk: risks.length ? risks.join('；') : '',
        status: risks.length ? 'risk' : (a.plan === 'permanent' || expire > nowTime ? 'active' : 'expired')
      };
    });
  }
  return activationStore.map(a => {
    const todayRefreshCount = a.licenseHash && quotaStore[a.licenseHash] && quotaStore[a.licenseHash].lastDate === today ? quotaStore[a.licenseHash].refreshCount || 0 : 0;
    const risks = [];
    if (a.plan === 'monthly' && todayRefreshCount > Number(a.accountCount || 0)) risks.push('今日替换数超过套餐账号数');
    if (a.plan !== 'permanent' && a.reportedAccountCount != null && a.reportedAccountCount > a.accountCount) risks.push('本地账号超出套餐');
    if (a.plan === 'monthly' && a.expire <= nowTime && a.lastSeenAt && a.lastSeenAt > a.expire) risks.push('过期后仍在线');
    return { ...a, todayRefreshCount, risk: risks.join('；'), status: risks.length ? 'risk' : (a.plan === 'permanent' || a.expire > nowTime ? 'active' : 'expired') };
  }).sort((a, b) => b.activatedAt - a.activatedAt);
}
async function getLatestActivation(machineId) {
  const id = String(machineId || '').trim();
  if (!id) return null;
  if (await ensureDb()) {
    const rows = await sql`SELECT machine_id,product,plan,expire,account_count,activated_at,last_seen_at
      FROM activations
      WHERE machine_id=${id}
      ORDER BY COALESCE(last_seen_at, activated_at) DESC
      LIMIT 1`;
    const r = rows[0];
    return r ? {
      machineId: r.machine_id,
      product: r.product || 'lovart-modern',
      plan: r.plan || 'monthly',
      expire: Number(r.expire || 0),
      accountCount: Number(r.account_count || 0),
      activatedAt: Number(r.activated_at || 0),
      lastSeenAt: Number(r.last_seen_at || 0)
    } : null;
  }
  const rows = activationStore
    .filter(a => a.machineId === id)
    .sort((a, b) => Number(b.lastSeenAt || b.activatedAt || 0) - Number(a.lastSeenAt || a.activatedAt || 0));
  return rows[0] || null;
}
function createLovartModernLicenseWithExpire(machineId, plan, expireTime, accountCount = 0) {
  const normalizedPlan = plan === 'permanent' ? 'permanent' : 'monthly';
  const expire = normalizedPlan === 'permanent' ? 4070908800000 : Number(expireTime || 0);
  if (normalizedPlan !== 'permanent' && (!Number.isFinite(expire) || expire <= Date.now())) {
    throw new Error('第一台电脑的卡密已过期，不能生成同期限绑定卡密');
  }
  const durationDays = normalizedPlan === 'permanent' ? 0 : Math.max(1, Math.ceil((expire - Date.now()) / 86400000));
  const count = Math.max(0, Math.min(Math.floor(Number(accountCount) || 0), 500));
  const payload = {
    machineId: String(machineId || '').trim(),
    expire,
    plan: normalizedPlan,
    hasGift: false,
    accountCount: count,
    issuedAt: Date.now(),
    durationDays
  };
  const licenseKey = signLicense(payload, 'LV3', 'original');
  return { licenseKey, plan: normalizedPlan, expireTime: expire, accountCount: count, durationDays };
}
async function createIssueToken(item) {
  if (await ensureDb()) {
    await sql`INSERT INTO issue_tokens (token,plan,account_count,days,created_at,used,used_by,used_at,order_id,expires_at,cancelled)
      VALUES (${item.token},${item.plan},${item.accountCount},${item.days},${item.createdAt},FALSE,NULL,NULL,${item.orderId || null},${item.expiresAt || null},FALSE)`;
    return;
  }
  issueTokens.push({ token: item.token, plan: item.plan, accountCount: item.accountCount, days: item.days, createdAt: item.createdAt, used: false, usedBy: null, orderId: item.orderId || null, expiresAt: item.expiresAt || null, cancelled: false });
  saveJSON(ISSUE_TOKENS_FILE, issueTokens);
}
async function findIssueToken(token) {
  if (await ensureDb()) {
    const rows = await sql`SELECT token,plan,account_count,days,created_at,used,used_by,used_at,order_id,expires_at,cancelled FROM issue_tokens WHERE token=${token} LIMIT 1`;
    const r = rows[0];
    return r ? { token: r.token, plan: r.plan, accountCount: Number(r.account_count), days: Number(r.days), createdAt: Number(r.created_at), used: r.used, usedBy: r.used_by, usedAt: r.used_at ? Number(r.used_at) : null, orderId: r.order_id || null, expiresAt: r.expires_at ? Number(r.expires_at) : null, cancelled: Boolean(r.cancelled) } : null;
  }
  return issueTokens.find(t => t.token === token) || null;
}
async function useIssueToken(token, machineId) {
  if (await ensureDb()) {
    const usedAt = Date.now();
    await sql`UPDATE issue_tokens SET used=TRUE, used_by=${machineId}, used_at=${usedAt} WHERE token=${token}`;
    return;
  }
  const item = issueTokens.find(t => t.token === token);
  if (item) {
    Object.assign(item, { used: true, usedAt: Date.now(), usedBy: machineId });
    saveJSON(ISSUE_TOKENS_FILE, issueTokens);
  }
}

async function consumeIssueTokenWithLicense({ token, machineId, licenseKey, plan, expireTime, accountCount, source }) {
  const licenseHash = hashLicenseKey(licenseKey);
  const usedAt = Date.now();
  if (await ensureDb()) {
    const rows = await sql`WITH claimed_token AS (
        UPDATE issue_tokens
        SET used=TRUE, used_by=${machineId}, used_at=${usedAt}
        WHERE token=${token}
          AND used=FALSE
          AND cancelled=FALSE
          AND (expires_at IS NULL OR expires_at > ${usedAt})
        RETURNING token,order_id
      ), issued AS (
        INSERT INTO issued_licenses
          (license_hash,machine_id,product,plan,expire,account_count,source,token,issued_at)
        SELECT ${licenseHash},${machineId},'lovart-modern',${plan},${expireTime},${accountCount},${source || 'issue_link'},token,${usedAt}
        FROM claimed_token
        ON CONFLICT (license_hash) DO UPDATE SET issued_at=EXCLUDED.issued_at
        RETURNING license_hash
      ), updated_order AS (
        UPDATE channel_orders o
        SET status='claimed',machine_id=${machineId},license_hash=${licenseHash},new_expire=${expireTime},claimed_at=${usedAt}
        FROM claimed_token c
        WHERE o.order_id=c.order_id
        RETURNING o.order_id
      )
      SELECT token,order_id FROM claimed_token`;
    return rows[0] || null;
  }
  const item = await findIssueToken(token);
  if (!item || item.used || item.cancelled || (item.expiresAt && item.expiresAt <= usedAt)) return null;
  await useIssueToken(token, machineId);
  await recordIssuedLicense({ licenseKey, machineId, product: 'lovart-modern', plan, expire: expireTime, accountCount, source: source || 'issue_link', token });
  return { token, order_id: item.orderId || null };
}

async function requireChannelDb() {
  if (!(await ensureDb())) {
    const error = new Error('经销商系统需要持久化数据库，请先配置 DATABASE_URL');
    error.statusCode = 503;
    throw error;
  }
}

function channelProductRow(row) {
  return {
    productId: row.product_id,
    name: row.name,
    plan: row.plan,
    days: Number(row.days),
    accountCount: Number(row.account_count),
    retailPriceCents: Number(row.retail_price_cents),
    resellerPriceCents: Number(row.reseller_price_cents),
    status: row.status,
    sortOrder: Number(row.sort_order || 0)
  };
}

async function listChannelProducts(includeDisabled = false) {
  await requireChannelDb();
  const rows = includeDisabled
    ? await sql`SELECT * FROM channel_products ORDER BY sort_order ASC,created_at ASC`
    : await sql`SELECT * FROM channel_products WHERE status='active' ORDER BY sort_order ASC,created_at ASC`;
  return rows.map(channelProductRow);
}

async function saveChannelProduct(data) {
  await requireChannelDb();
  const productId = String(data.productId || '').trim() || channel.randomId('PRD-', 8);
  const name = String(data.name || '').trim().slice(0, 80);
  if (!name) throw new Error('请输入套餐名称');
  const plan = data.plan === 'permanent' ? 'permanent' : 'monthly';
  const days = plan === 'permanent' ? 0 : Math.max(1, Math.min(parseInt(data.days, 10) || 30, 3650));
  const accountCount = parseAccountCount(data.accountCount, plan === 'permanent' ? 0 : 30);
  const retailPriceCents = channel.cents(data.retailPriceCents);
  const resellerPriceCents = channel.cents(data.resellerPriceCents);
  if (resellerPriceCents > retailPriceCents && retailPriceCents > 0) throw new Error('经销价不能高于零售价');
  const status = data.status === 'disabled' ? 'disabled' : 'active';
  const sortOrder = Math.max(-9999, Math.min(parseInt(data.sortOrder, 10) || 0, 9999));
  const now = Date.now();
  const rows = await sql`INSERT INTO channel_products
      (product_id,name,plan,days,account_count,retail_price_cents,reseller_price_cents,status,sort_order,created_at,updated_at)
    VALUES (${productId},${name},${plan},${days},${accountCount},${retailPriceCents},${resellerPriceCents},${status},${sortOrder},${now},${now})
    ON CONFLICT (product_id) DO UPDATE SET
      name=EXCLUDED.name,plan=EXCLUDED.plan,days=EXCLUDED.days,account_count=EXCLUDED.account_count,
      retail_price_cents=EXCLUDED.retail_price_cents,reseller_price_cents=EXCLUDED.reseller_price_cents,
      status=EXCLUDED.status,sort_order=EXCLUDED.sort_order,updated_at=EXCLUDED.updated_at
    RETURNING *`;
  return channelProductRow(rows[0]);
}

async function createResellerAccount(data) {
  await requireChannelDb();
  const username = channel.normalizeUsername(data.username);
  const displayName = String(data.displayName || username).trim().slice(0, 80) || username;
  const password = channel.createPasswordRecord(data.password);
  const resellerId = channel.randomId('RSL-', 8);
  const now = Date.now();
  const rows = await sql`INSERT INTO reseller_accounts
      (reseller_id,username,display_name,password_hash,password_salt,status,balance_cents,created_at,updated_at)
    VALUES (${resellerId},${username},${displayName},${password.passwordHash},${password.passwordSalt},'active',0,${now},${now})
    RETURNING reseller_id,username,display_name,status,balance_cents,created_at,updated_at`;
  return resellerPublicRow(rows[0]);
}

function resellerPublicRow(row) {
  return {
    resellerId: row.reseller_id,
    username: row.username,
    displayName: row.display_name,
    status: row.status,
    balanceCents: Number(row.balance_cents || 0),
    createdAt: Number(row.created_at || 0),
    updatedAt: Number(row.updated_at || 0)
  };
}

async function listResellerAccounts() {
  await requireChannelDb();
  const rows = await sql`SELECT reseller_id,username,display_name,status,balance_cents,created_at,updated_at FROM reseller_accounts ORDER BY created_at DESC`;
  return rows.map(resellerPublicRow);
}

async function adjustResellerBalance(resellerId, amountCents, note) {
  await requireChannelDb();
  const amount = Math.round(Number(amountCents) || 0);
  if (!amount) throw new Error('调整金额不能为 0');
  const ledgerId = channel.randomId('LED-', 10);
  const now = Date.now();
  const rows = await sql`WITH changed AS (
      UPDATE reseller_accounts
      SET balance_cents=balance_cents+${amount},updated_at=${now}
      WHERE reseller_id=${resellerId} AND balance_cents+${amount} >= 0
      RETURNING reseller_id,balance_cents
    ), ledger AS (
      INSERT INTO reseller_wallet_ledger
        (ledger_id,reseller_id,entry_type,amount_cents,balance_after_cents,order_id,note,created_at)
      SELECT ${ledgerId},reseller_id,${amount > 0 ? 'admin_credit' : 'admin_debit'},${amount},balance_cents,NULL,${String(note || '后台调整').slice(0, 200)},${now}
      FROM changed
    ) SELECT reseller_id,balance_cents FROM changed`;
  if (!rows[0]) throw new Error('经销商不存在或余额不足');
  return { resellerId: rows[0].reseller_id, balanceCents: Number(rows[0].balance_cents) };
}

async function loginReseller(usernameValue, password, req) {
  await requireChannelDb();
  let username;
  try { username = channel.normalizeUsername(usernameValue); } catch (error) { return null; }
  const rows = await sql`SELECT * FROM reseller_accounts WHERE username=${username} LIMIT 1`;
  const reseller = rows[0];
  if (!reseller || reseller.status !== 'active' || !channel.verifyPassword(password, reseller.password_hash, reseller.password_salt)) return null;
  const token = channel.randomId('', 32);
  const tokenHash = channel.hashToken(token);
  const now = Date.now();
  await sql`DELETE FROM reseller_sessions WHERE expires_at <= ${now}`;
  await sql`INSERT INTO reseller_sessions (token_hash,reseller_id,created_at,expires_at,last_seen_at)
    VALUES (${tokenHash},${reseller.reseller_id},${now},${now + channel.SESSION_TTL_MS},${now})`;
  return { token, reseller: resellerPublicRow(reseller) };
}

async function getResellerSession(req) {
  await requireChannelDb();
  const cookies = channel.parseCookies(req.headers.cookie);
  const token = cookies[channel.SESSION_COOKIE];
  if (!token) return null;
  const tokenHash = channel.hashToken(token);
  const now = Date.now();
  const rows = await sql`SELECT r.reseller_id,r.username,r.display_name,r.status,r.balance_cents,r.created_at,r.updated_at,s.expires_at
    FROM reseller_sessions s JOIN reseller_accounts r ON r.reseller_id=s.reseller_id
    WHERE s.token_hash=${tokenHash} AND s.expires_at>${now} AND r.status='active' LIMIT 1`;
  if (!rows[0]) return null;
  await sql`UPDATE reseller_sessions SET last_seen_at=${now} WHERE token_hash=${tokenHash}`;
  return { tokenHash, reseller: resellerPublicRow(rows[0]) };
}

async function createResellerClaimOrder(reseller, data, req) {
  await requireChannelDb();
  const productId = String(data.productId || '').trim();
  const platformOrderNo = String(data.platformOrderNo || '').trim().slice(0, 100) || null;
  const products = await sql`SELECT * FROM channel_products WHERE product_id=${productId} AND status='active' LIMIT 1`;
  const product = products[0];
  if (!product) throw new Error('套餐不存在或已下架');
  const amount = Number(product.reseller_price_cents || 0);
  if (amount <= 0) throw new Error('该套餐尚未设置经销价');
  const orderId = channel.randomId('ORD-', 10);
  const token = channel.randomId('LTK-', 16);
  const now = Date.now();
  const expiresAt = now + 30 * 24 * 60 * 60 * 1000;
  let rows;
  try {
    rows = await sql`WITH charged AS (
        UPDATE reseller_accounts
        SET balance_cents=balance_cents-${amount},updated_at=${now}
        WHERE reseller_id=${reseller.resellerId} AND status='active' AND balance_cents>=${amount}
        RETURNING reseller_id,balance_cents
      ), new_order AS (
        INSERT INTO channel_orders
          (order_id,reseller_id,product_id,order_type,status,amount_cents,platform_order_no,claim_token,created_at,paid_at)
        SELECT ${orderId},reseller_id,${productId},'reseller_claim','paid',${amount},${platformOrderNo},${token},${now},${now}
        FROM charged RETURNING order_id,reseller_id
      ), new_token AS (
        INSERT INTO issue_tokens
          (token,plan,account_count,days,created_at,used,order_id,expires_at,cancelled)
        SELECT ${token},${product.plan},${Number(product.account_count)},${Number(product.days)},${now},FALSE,order_id,${expiresAt},FALSE
        FROM new_order
      ), ledger AS (
        INSERT INTO reseller_wallet_ledger
          (ledger_id,reseller_id,entry_type,amount_cents,balance_after_cents,order_id,note,created_at)
        SELECT ${channel.randomId('LED-', 10)},reseller_id,'order_charge',${-amount},balance_cents,${orderId},${'发卡：' + product.name},${now}
        FROM charged
      ) SELECT reseller_id,balance_cents FROM charged`;
  } catch (error) {
    if (String(error.message || '').toLowerCase().includes('unique')) throw new Error('闲鱼订单号已经发过卡，请勿重复发货');
    throw error;
  }
  if (!rows[0]) throw new Error('余额不足');
  return {
    orderId,
    token,
    link: appUrl(req) + '/?action=claim&token=' + encodeURIComponent(token),
    expiresAt,
    balanceCents: Number(rows[0].balance_cents),
    product: channelProductRow(product)
  };
}

async function listResellerOrders(resellerId, limit = 100) {
  await requireChannelDb();
  const rows = await sql`SELECT o.order_id,o.product_id,o.status,o.amount_cents,o.platform_order_no,o.claim_token,o.machine_id,o.created_at,o.paid_at,o.claimed_at,o.cancelled_at,p.name AS product_name
    FROM channel_orders o LEFT JOIN channel_products p ON p.product_id=o.product_id
    WHERE o.reseller_id=${resellerId} ORDER BY o.created_at DESC LIMIT ${Math.max(1, Math.min(Number(limit) || 100, 500))}`;
  return rows.map(r => ({ orderId: r.order_id, productId: r.product_id, productName: r.product_name || r.product_id, status: r.status, amountCents: Number(r.amount_cents), platformOrderNo: r.platform_order_no || '', claimToken: r.claim_token || '', machineId: r.machine_id || '', createdAt: Number(r.created_at), paidAt: r.paid_at ? Number(r.paid_at) : null, claimedAt: r.claimed_at ? Number(r.claimed_at) : null, cancelledAt: r.cancelled_at ? Number(r.cancelled_at) : null }));
}

async function listAllChannelOrders(limit = 300) {
  await requireChannelDb();
  const rows = await sql`SELECT o.order_id,o.reseller_id,o.product_id,o.status,o.amount_cents,o.platform_order_no,o.machine_id,o.created_at,o.claimed_at,o.cancelled_at,p.name AS product_name,r.display_name AS reseller_name
    FROM channel_orders o
    LEFT JOIN channel_products p ON p.product_id=o.product_id
    LEFT JOIN reseller_accounts r ON r.reseller_id=o.reseller_id
    ORDER BY o.created_at DESC LIMIT ${Math.max(1, Math.min(Number(limit) || 300, 1000))}`;
  return rows.map(r => ({ orderId: r.order_id, resellerId: r.reseller_id || '', resellerName: r.reseller_name || '', productId: r.product_id, productName: r.product_name || r.product_id, status: r.status, amountCents: Number(r.amount_cents), platformOrderNo: r.platform_order_no || '', machineId: r.machine_id || '', createdAt: Number(r.created_at), claimedAt: r.claimed_at ? Number(r.claimed_at) : null, cancelledAt: r.cancelled_at ? Number(r.cancelled_at) : null }));
}

function hasValidRequestOrigin(req) {
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true;
  try {
    const originHost = new URL(origin).host.toLowerCase();
    const requestHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().toLowerCase();
    return Boolean(requestHost) && originHost === requestHost;
  } catch (error) {
    return false;
  }
}

async function cancelResellerOrder(reseller, orderId) {
  await requireChannelDb();
  const now = Date.now();
  const ledgerId = channel.randomId('LED-', 10);
  const rows = await sql`WITH cancelled AS (
      UPDATE channel_orders
      SET status='cancelled',cancelled_at=${now}
      WHERE order_id=${orderId} AND reseller_id=${reseller.resellerId} AND status='paid'
      RETURNING order_id,reseller_id,amount_cents,claim_token
    ), token_cancel AS (
      UPDATE issue_tokens t SET cancelled=TRUE
      FROM cancelled c WHERE t.token=c.claim_token AND t.used=FALSE
      RETURNING t.token
    ), refunded AS (
      UPDATE reseller_accounts r
      SET balance_cents=r.balance_cents+c.amount_cents,updated_at=${now}
      FROM cancelled c
      WHERE r.reseller_id=c.reseller_id AND EXISTS (SELECT 1 FROM token_cancel)
      RETURNING r.reseller_id,r.balance_cents,c.amount_cents,c.order_id
    ), ledger AS (
      INSERT INTO reseller_wallet_ledger
        (ledger_id,reseller_id,entry_type,amount_cents,balance_after_cents,order_id,note,created_at)
      SELECT ${ledgerId},reseller_id,'order_refund',amount_cents,balance_cents,order_id,'未领取订单撤销退款',${now} FROM refunded
    ) SELECT reseller_id,balance_cents FROM refunded`;
  if (!rows[0]) throw new Error('订单不存在、已经领取或已经撤销');
  return { success: true, balanceCents: Number(rows[0].balance_cents) };
}
async function findTrialClaim(machineId) {
  if (await ensureDb()) {
    const rows = await sql`SELECT machine_id,license_hash,claimed_at,expire,account_count FROM trial_claims WHERE machine_id=${machineId} LIMIT 1`;
    const r = rows[0];
    return r ? { machineId: r.machine_id, licenseHash: r.license_hash, claimedAt: Number(r.claimed_at), expire: Number(r.expire), accountCount: Number(r.account_count) } : null;
  }
  return trialClaims.find(x => x.machineId === machineId) || null;
}
async function recordTrialClaim(machineId, licenseKey, expire) {
  const item = { machineId, licenseHash: hashLicenseKey(licenseKey), claimedAt: Date.now(), expire, accountCount: TRIAL_ACCOUNT_COUNT };
  if (await ensureDb()) {
    const rows = await sql`INSERT INTO trial_claims (machine_id,license_hash,claimed_at,expire,account_count)
      VALUES (${item.machineId},${item.licenseHash},${item.claimedAt},${item.expire},${item.accountCount})
      ON CONFLICT (machine_id) DO NOTHING
      RETURNING machine_id`;
    return rows.length ? item : null;
  }
  if (trialClaims.find(x => x.machineId === machineId)) return null;
  trialClaims.push(item);
  saveJSON(TRIAL_CLAIMS_FILE, trialClaims);
  return item;
}
async function getTrialStats() {
  const nowTime = Date.now();
  const today = new Date().toISOString().slice(0, 10);
  if (await ensureDb()) {
    const rows = await sql`SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE to_timestamp(claimed_at / 1000)::date = ${today}::date)::int AS today_count,
      COUNT(*) FILTER (WHERE expire > ${nowTime})::int AS active,
      COUNT(*) FILTER (WHERE expire <= ${nowTime})::int AS expired,
      COUNT(*) FILTER (WHERE b.machine_id IS NOT NULL)::int AS blacklisted,
      COUNT(*) FILTER (WHERE converted.converted IS TRUE)::int AS converted
      FROM trial_claims t
      LEFT JOIN blacklist b ON b.machine_id = t.machine_id AND b.revoked = FALSE
      LEFT JOIN LATERAL (
        SELECT TRUE AS converted
        FROM activations a
        WHERE a.machine_id = t.machine_id
          AND a.license_hash IS NOT NULL
          AND t.license_hash IS NOT NULL
          AND a.license_hash <> t.license_hash
        LIMIT 1
      ) converted ON TRUE`;
    const r = rows[0] || {};
    return { total: r.total || 0, today: r.today_count || 0, active: r.active || 0, expired: r.expired || 0, blacklisted: r.blacklisted || 0, converted: r.converted || 0 };
  }
  const blacklistList = await listBlacklist();
  const convertedMachines = new Set(activationStore.filter(a => a.licenseHash).map(a => a.machineId));
  return {
    total: trialClaims.length,
    today: trialClaims.filter(t => new Date(t.claimedAt).toISOString().slice(0, 10) === today).length,
    active: trialClaims.filter(t => Number(t.expire) > nowTime).length,
    expired: trialClaims.filter(t => Number(t.expire) <= nowTime).length,
    blacklisted: trialClaims.filter(t => blacklistList.some(b => b.machineId === t.machineId && !b.revoked)).length,
    converted: trialClaims.filter(t => convertedMachines.has(t.machineId)).length
  };
}
async function listTrialClaims() {
  const nowTime = Date.now();
  if (await ensureDb()) {
    const rows = await sql`SELECT
      t.machine_id,
      t.claimed_at,
      t.expire,
      t.account_count,
      b.reason AS blacklist_reason,
      CASE WHEN converted.converted IS TRUE THEN TRUE ELSE FALSE END AS converted
      FROM trial_claims t
      LEFT JOIN blacklist b ON b.machine_id = t.machine_id AND b.revoked = FALSE
      LEFT JOIN LATERAL (
        SELECT TRUE AS converted
        FROM activations a
        WHERE a.machine_id = t.machine_id
          AND a.license_hash IS NOT NULL
          AND t.license_hash IS NOT NULL
          AND a.license_hash <> t.license_hash
        LIMIT 1
      ) converted ON TRUE
      ORDER BY t.claimed_at DESC LIMIT 500`;
    return rows.map(t => {
      const blacklisted = Boolean(t.blacklist_reason);
      const expired = Number(t.expire) <= nowTime;
      return {
        machineId: t.machine_id,
        claimedAt: Number(t.claimed_at),
        expire: Number(t.expire),
        accountCount: Number(t.account_count),
        converted: Boolean(t.converted),
        blacklistReason: t.blacklist_reason || '',
        status: blacklisted ? 'blacklisted' : (expired ? 'expired' : 'active')
      };
    });
  }
  const blacklistList = await listBlacklist();
  const convertedMachines = new Set(activationStore.filter(a => a.licenseHash).map(a => a.machineId));
  return trialClaims.map(t => {
    const blacklisted = blacklistList.find(b => b.machineId === t.machineId && !b.revoked);
    return {
      ...t,
      converted: convertedMachines.has(t.machineId),
      blacklistReason: blacklisted ? blacklisted.reason || '已拉黑' : '',
      status: blacklisted ? 'blacklisted' : (Number(t.expire) <= nowTime ? 'expired' : 'active')
    };
  }).sort((a, b) => b.claimedAt - a.claimedAt);
}
async function listBlacklist() {
  if (await ensureDb()) {
    const rows = await sql`SELECT machine_id, reason, created_at, revoked FROM blacklist ORDER BY created_at DESC LIMIT 500`;
    return rows.map(r => ({ machineId: r.machine_id, reason: r.reason, createdAt: Number(r.created_at), revoked: r.revoked }));
  }
  return blacklist;
}
async function addBlacklist(machineId, reason) {
  if (await ensureDb()) {
    await sql`INSERT INTO blacklist (machine_id,reason,created_at,revoked)
      VALUES (${machineId},${reason || ''},${Date.now()},FALSE)
      ON CONFLICT (machine_id) DO UPDATE SET reason=EXCLUDED.reason, created_at=EXCLUDED.created_at, revoked=FALSE`;
    return;
  }
  if (!isBlacklisted(machineId)) { blacklist.push({ machineId, reason: String(reason || ''), createdAt: Date.now(), revoked: false }); saveJSON(BLACKLIST_FILE, blacklist); }
}
async function removeBlacklist(machineId) {
  if (await ensureDb()) {
    await sql`DELETE FROM blacklist WHERE machine_id=${machineId}`;
    return;
  }
  const i = blacklist.findIndex(x => x.machineId === machineId);
  if (i >= 0) { blacklist.splice(i, 1); saveJSON(BLACKLIST_FILE, blacklist); }
}
function makeAccounts(count, domainsStr) {
  const domains = String(domainsStr || DOMAIN_POOL).split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
  const pool = domains.length ? domains : ['yxd.ccwu.cc'];
  return Array.from({ length: count }, () => ({ email: Date.now().toString(36) + crypto.randomBytes(2).toString('hex') + '@' + pool[Math.floor(Math.random() * pool.length)], password: '' }));
}
function makeCloudflareAccounts(count) {
  return makeAccounts(count, CLOUDFLARE_DOMAIN_POOL);
}
function wantsCloudflareAccounts(data) {
  if (!data || typeof data !== 'object') return false;
  const pool = String(data.accountPool || data.account_pool || '').trim().toLowerCase();
  return pool === 'cloudflare' || data.requireCloudflareAccounts === true || data.cloudflareAccounts === true;
}
function makeAccountsForRequest(count, data) {
  return wantsCloudflareAccounts(data) ? makeCloudflareAccounts(count) : makeAccounts(count, DOMAIN_POOL);
}
function accountPoolNameForRequest(data) {
  return wantsCloudflareAccounts(data) ? 'cloudflare' : 'legacy';
}
function encryptAccounts(accounts) { const c = crypto.createCipheriv('aes-256-cbc', ENCRYPT_KEY, IV); return c.update(JSON.stringify(accounts), 'utf8', 'hex') + c.final('hex'); }
function allowClaim(ip) { const now = Date.now(); claimRate[ip] = (claimRate[ip] || []).filter(t => now - t < 60000); if (claimRate[ip].length >= 3) return false; claimRate[ip].push(now); return true; }
function appUrl(req) { const host = req.headers['x-forwarded-host'] || req.headers.host || process.env.VERCEL_URL; return host ? 'https://' + String(host).replace(/^https?:\/\//, '') : 'http://localhost:3000'; }

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-secret');
  if (req.method === 'OPTIONS') return res.status(204).end();
  try {
    const action = req.query.action;
    if (action === 'health') {
      return res.json({ success: true, ok: true, service: 'lovart-card-api', buildSha: BUILD_SHA, database: Boolean(await ensureDb()), time: Date.now() });
    }
    if (req.method === 'GET' && action === 'channel_admin') {
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).send(channelAdminPage());
    }
    if (req.method === 'GET' && action === 'reseller') {
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).send(resellerPage());
    }
    if (req.method === 'POST' && action === 'channel_products') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listChannelProducts(true) });
    }
    if (req.method === 'POST' && action === 'save_channel_product') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, product: await saveChannelProduct(await readBody(req)) });
    }
    if (req.method === 'POST' && action === 'create_reseller') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, reseller: await createResellerAccount(await readBody(req)) });
    }
    if (req.method === 'POST' && action === 'list_resellers') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listResellerAccounts() });
    }
    if (req.method === 'POST' && action === 'adjust_reseller_balance') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      return res.json({ success: true, result: await adjustResellerBalance(String(data.resellerId || ''), Math.round(Number(data.amountYuan || 0) * 100), data.note) });
    }
    if (req.method === 'POST' && action === 'list_channel_orders') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listAllChannelOrders() });
    }
    if (req.method === 'POST' && action === 'reseller_login') {
      if (!hasValidRequestOrigin(req)) return res.status(403).json({ success: false, message: '请求来源无效' });
      const data = await readBody(req);
      const result = await loginReseller(data.username, data.password, req);
      if (!result) return res.status(401).json({ success: false, message: '账号或密码不正确' });
      res.setHeader('Set-Cookie', channel.sessionCookie(result.token));
      return res.json({ success: true, reseller: result.reseller });
    }
    if (req.method === 'POST' && action === 'reseller_logout') {
      if (!hasValidRequestOrigin(req)) return res.status(403).json({ success: false, message: '请求来源无效' });
      let session = null;
      try { session = await getResellerSession(req); } catch (error) {}
      if (session) await sql`DELETE FROM reseller_sessions WHERE token_hash=${session.tokenHash}`;
      res.setHeader('Set-Cookie', channel.clearSessionCookie());
      return res.json({ success: true });
    }
    if (req.method === 'POST' && action === 'reseller_dashboard') {
      const session = await getResellerSession(req);
      if (!session) return res.status(401).json({ success: false, message: '请先登录' });
      return res.json({ success: true, reseller: session.reseller, products: await listChannelProducts(false), orders: await listResellerOrders(session.reseller.resellerId) });
    }
    if (req.method === 'POST' && action === 'reseller_create_claim') {
      if (!hasValidRequestOrigin(req)) return res.status(403).json({ success: false, message: '请求来源无效' });
      const session = await getResellerSession(req);
      if (!session) return res.status(401).json({ success: false, message: '请先登录' });
      return res.json({ success: true, order: await createResellerClaimOrder(session.reseller, await readBody(req), req) });
    }
    if (req.method === 'POST' && action === 'reseller_cancel_order') {
      if (!hasValidRequestOrigin(req)) return res.status(403).json({ success: false, message: '请求来源无效' });
      const session = await getResellerSession(req);
      if (!session) return res.status(401).json({ success: false, message: '请先登录' });
      const data = await readBody(req);
      return res.json(await cancelResellerOrder(session.reseller, String(data.orderId || '')));
    }
    if (req.method === 'POST' && action === 'license') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim();
      if (!machineId) return res.status(400).json({ success: false, message: '请输入机器码' });
      const product = ['lovart-legacy', 'lovart-modern', 'securelink'].includes(data.product) ? data.product : 'lovart-legacy';
      const type = data.type || 'sub';
      const plan = type === 'perm' ? 'permanent' : 'monthly';
      const days = Math.max(1, Math.min(parseInt(data.days, 10) || 1, 3650));
      const accountCount = (product === 'lovart-legacy' || product === 'securelink')
        ? 0
        : parseAccountCount(data.accountCount, plan === 'permanent' ? 0 : 30);
      const expireTime = plan === 'permanent' ? 4070908800000 : Date.now() + days * 86400000;
      let payload;
      if (product === 'securelink') {
        payload = { MachineId: machineId, Expire: expireTime, Plan: plan, HasGift: false };
      } else {
        payload = { machineId, expire: expireTime, plan, hasGift: product === 'lovart-legacy' && plan === 'monthly', issuedAt: Date.now(), durationDays: plan === 'permanent' ? 0 : days };
        if (product !== 'lovart-legacy') payload.accountCount = accountCount;
      }
      const prefix = product === 'lovart-modern' ? 'LV3' : 'LV2';
      const signingProduct = product === 'securelink' ? 'securelink' : 'original';
      const licenseKey = signLicense(payload, prefix, signingProduct);
      await recordIssuedLicense({ licenseKey, machineId, product, plan, expire: expireTime, accountCount, source: 'admin' });
      const hasGift = product === 'lovart-legacy' && plan === 'monthly';
      return res.json({ success: true, licenseKey, product, plan, expireTime, accountCount, hasGift });
    }
    if (req.method === 'POST' && action === 'adjust_customer_accounts') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim();
      if (!machineId) return res.status(400).json({ success: false, message: '请输入机器码' });
      const plan = data.plan === 'permanent' ? 'permanent' : 'monthly';
      const days = Math.max(1, Math.min(parseInt(data.days, 10) || 30, 3650));
      const targetCount = parseAccountCount(data.targetCount, plan === 'permanent' ? 0 : 30);
      const currentCountRaw = Number(data.currentCount);
      const currentCount = Number.isFinite(currentCountRaw) ? Math.max(0, Math.min(Math.floor(currentCountRaw), 500)) : null;
      const generated = createLovartModernLicense(machineId, plan, days, targetCount);
      await recordIssuedLicense({
        licenseKey: generated.licenseKey,
        machineId,
        product: 'lovart-modern',
        plan: generated.plan,
        expire: generated.expireTime,
        accountCount: generated.accountCount,
        source: 'admin_adjust'
      });
      return res.json({
        success: true,
        licenseKey: generated.licenseKey,
        product: 'lovart-modern',
        plan: generated.plan,
        expireTime: generated.expireTime,
        accountCount: generated.accountCount,
        currentCount,
        addCount: currentCount == null ? null : Math.max(0, generated.accountCount - currentCount),
        removeCount: currentCount == null ? null : Math.max(0, currentCount - generated.accountCount),
        message: '已生成客户账号数调整卡密'
      });
    }
    if (req.method === 'POST' && action === 'accounts') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const count = Math.max(1, Math.min(parseInt(data.count, 10) || 50, 500));
      return res.json({ success: true, code: encryptAccounts(makeAccounts(count, data.domains)), count });
    }
    if (req.method === 'POST' && action === 'cloudflare_accounts') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const count = Math.max(1, Math.min(parseInt(data.count, 10) || 50, 500));
      return res.json({ success: true, code: encryptAccounts(makeCloudflareAccounts(count)), count, domains: CLOUDFLARE_DOMAIN_POOL });
    }
    if (req.method === 'POST' && action === 'auto_fetch') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const payload = auth.payload;
      const plan = payload.plan || 'monthly';
      if (plan === 'monthly') return res.json({ success: true, count: 0, accounts: [], plan, message: '已激活，请使用替换失效账号功能领取新账号。' });
      const count = Math.min(parseInt(payload.accountCount, 10) || 0, 200);
      return res.json({ success: true, count, accounts: makeAccountsForRequest(count, data), plan, accountPool: accountPoolNameForRequest(data) });
    }
    if (req.method === 'POST' && action === 'otp_access_check') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, allowed: false, message: auth.message });
      return res.json({ success: true, allowed: true });
    }
    if (action === 'blacklist_check') {
      const data = req.method === 'POST' ? await readBody(req) : {};
      const machineId = String(req.query.machineId || data.machineId || '').slice(0, 80);
      const blocked = await isBlacklistedDb(machineId);
      return res.json({ success: true, blocked: blocked.blocked, reason: blocked.reason || '' });
    }
    if (req.method === 'POST' && action === 'refresh_accounts') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const key = auth.key;
      const payload = auth.payload;
      if (!(await isRefreshAccountsEnabled())) return res.json({ success: false, message: '管理员已关闭替换失效账号，请联系客服处理' });
      const requestedCount = Math.max(0, Math.min(parseInt(data.replaceCount, 10) || parseInt(data.deletedCount, 10) || parseInt(data.count, 10) || parseInt(payload.accountCount, 10) || 0, 500));
      const maxCount = Math.min(parseInt(payload.accountCount, 10) || 0, 500);
      const count = Math.min(requestedCount, maxCount);
      if (count <= 0) return res.json({ success: true, count: 0, accounts: [], message: '该卡密不包含账号数量，请单独生成账号代码。' });
      await markRefreshDb(key, count);
      const accounts = makeAccountsForRequest(count, data);
      await authorizeLicenseAccounts(key, auth.machineId, accounts, 'refresh');
      // Default desktop replacement requests use the first legacy pool. The
      // Cloudflare-only desktop explicitly opts into its separate pool.
      return res.json({
        success: true,
        count,
        accounts,
        accountPool: accountPoolNameForRequest(data)
      });
    }
    if (req.method === 'POST' && action === 'activation_accounts') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const key = auth.key;
      const payload = auth.payload;
      const machineId = auth.machineId;
      if (!payload.trial) return res.json({ success: true, count: 0, accounts: [], message: '非体验卡不走首激发号' });
      if (!(await isTrialActivationAccountsEnabled())) return res.json({ success: true, count: 0, accounts: [], message: '体验卡首激发号已关闭' });
      const trialAccountCount = Number.isFinite(Number(payload.accountCount)) ? Number(payload.accountCount) : TRIAL_ACCOUNT_COUNT;
      const count = Math.max(0, Math.min(Math.floor(trialAccountCount), TRIAL_ACCOUNT_COUNT));
      if (count <= 0) return res.json({ success: true, count: 0, accounts: [] });
      const accounts = await getOrCreateActivationGrant(key, machineId, count, data);
      await authorizeLicenseAccounts(key, machineId, accounts, 'trial_activation');
      return res.json({ success: true, count: accounts.length, accounts, activationGrant: true, accountPool: accountPoolNameForRequest(data) });
    }
    if (req.method === 'POST' && action === 'plan_adjust') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const key = auth.key;
      const machineId = auth.machineId;
      const payload = auth.payload;

      const licenseLimit = licenseAccountCount(payload);
      const requestedTarget = parseInt(data.targetCount, 10);
      const requestedCurrent = parseInt(data.currentCount, 10);
      const targetCount = Math.max(0, Math.min(Number.isFinite(requestedTarget) ? requestedTarget : licenseLimit, licenseLimit));
      const currentCount = Math.max(0, Math.min(Number.isFinite(requestedCurrent) ? requestedCurrent : 0, targetCount));
      const count = Math.max(0, Math.min(targetCount - currentCount, 500));
      const grantAccounts = targetCount > 0 ? await getOrCreateActivationGrant(key, machineId, targetCount, data) : [];
      if (grantAccounts.length) await authorizeLicenseAccounts(key, machineId, grantAccounts, 'plan_adjust');
      const accounts = count > 0 ? grantAccounts.slice(currentCount, currentCount + count) : [];

      return res.json({
        success: true,
        count: accounts.length,
        targetCount,
        currentCount,
        accounts,
        activationGrant: true,
        accountPool: accountPoolNameForRequest(data)
      });
    }
    if (req.method === 'POST' && action === 'create_issue_token') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const plan = data.plan === 'permanent' ? 'permanent' : 'monthly';
      const days = Math.max(1, Math.min(parseInt(data.days, 10) || 1, 3650));
      const accountCount = parseAccountCount(data.accountCount, plan === 'permanent' ? 0 : 30);
      const token = 'LTK-' + crypto.randomBytes(16).toString('hex').toUpperCase();
      await createIssueToken({ token, plan, accountCount, days, createdAt: Date.now() });
      return res.json({ success: true, link: appUrl(req) + '/?action=claim&token=' + encodeURIComponent(token) + '&plan=' + plan + '&count=' + accountCount + '&days=' + days, token, plan, accountCount, days });
    }
    if (req.method === 'GET' && action === 'claim') {
      const token = String(req.query.token || '').trim();
      const item = await findIssueToken(token);
      return res.status(200).send(claimPage({ token, plan: item ? item.plan : (req.query.plan || 'monthly'), count: item ? item.accountCount : parseAccountCount(req.query.count, 30), days: item ? item.days : (parseInt(req.query.days, 10) || 1), unavailable: !item || item.used || item.cancelled || Boolean(item.expiresAt && item.expiresAt <= Date.now()) }));
    }
    if (req.method === 'GET' && action === 'trial') {
      return res.status(200).send(trialPage());
    }
    if (req.method === 'POST' && action === 'claim_trial') {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
      if (!allowClaim(ip)) return res.status(429).json({ success: false, message: '操作太频繁，请稍后再试' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim().slice(0, 80);
      if (!machineId) return res.status(400).json({ success: false, message: '缺少机器码' });
      if ((await isBlacklistedDb(machineId)).blocked) return res.status(403).json({ success: false, message: '该机器已被拉黑' });
      const repeatAllowed = isTrialRepeatWhitelisted(machineId);
      const existing = repeatAllowed ? null : await findTrialClaim(machineId);
      if (existing) return res.status(409).json({ success: false, message: '该机器码已经领取过体验版' });
      const expireTime = Date.now() + TRIAL_HOURS * 60 * 60 * 1000;
      const payload = { machineId, expire: expireTime, plan: 'monthly', accountCount: TRIAL_ACCOUNT_COUNT, trial: true, issuedAt: Date.now(), durationDays: TRIAL_HOURS / 24 };
      const licenseKey = signLicense(payload, 'LV3', 'original');
      await recordIssuedLicense({ licenseKey, machineId, product: 'lovart-modern', plan: 'monthly', expire: expireTime, accountCount: TRIAL_ACCOUNT_COUNT, source: 'trial' });
      if (!repeatAllowed) {
        const inserted = await recordTrialClaim(machineId, licenseKey, expireTime);
        if (!inserted) return res.status(409).json({ success: false, message: '该机器码已经领取过体验版' });
      }
      return res.json({ success: true, licenseKey, plan: 'monthly', expire: expireTime, accountCount: TRIAL_ACCOUNT_COUNT, trial: true, repeatAllowed });
    }
    if (req.method === 'POST' && action === 'claim') {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
      if (!allowClaim(ip)) return res.status(429).json({ success: false, message: '操作太频繁，请稍后再试' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim().slice(0, 80), token = String(data.token || '').trim();
      if (!machineId || !token) return res.status(400).json({ success: false, message: '缺少机器码或领取码' });
      if ((await isBlacklistedDb(machineId)).blocked) return res.status(403).json({ success: false, message: '该机器已被拉黑' });
      const item = await findIssueToken(token);
      if (!item) return res.status(404).json({ success: false, message: '领取链接无效' });
      if (item.used) return res.status(410).json({ success: false, message: '领取链接已被使用' });
      if (item.cancelled) return res.status(410).json({ success: false, message: '领取链接已撤销' });
      if (item.expiresAt && item.expiresAt <= Date.now()) return res.status(410).json({ success: false, message: '领取链接已过期' });
      const expireTime = item.plan === 'permanent' ? 4070908800000 : Date.now() + item.days * 86400000;
      const accountCount = licenseAccountCount(item);
      const payload = { machineId, expire: expireTime, plan: item.plan, hasGift: false, accountCount, issuedAt: Date.now(), durationDays: item.plan === 'permanent' ? 0 : item.days };
      const licenseKey = signLicense(payload, 'LV3', 'original');
      const consumed = await consumeIssueTokenWithLicense({ token, machineId, licenseKey, plan: item.plan, expireTime, accountCount, source: item.orderId ? 'reseller_link' : 'issue_link' });
      if (!consumed) return res.status(409).json({ success: false, message: '领取链接已被使用、撤销或过期' });
      return res.json({ success: true, licenseKey, plan: item.plan, expire: expireTime, accountCount });
    }
    if (req.method === 'POST' && action === 'record_activation') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const key = auth.key;
      const machineId = auth.machineId;
      const payload = auth.payload;
      const product = isSecureLinkKey(key) ? 'securelink' : (key.startsWith('LV3.') ? 'lovart-modern' : 'lovart-legacy');
      const accountCount = licenseAccountCount(payload);
      await recordActivation(machineId, payload.plan || 'monthly', Number(payload.expire) || 0, accountCount, product, key);
      return res.json({ success: true });
    }
    if (req.method === 'POST' && action === 'client_status') {
      const data = await readBody(req);
      const auth = await authorizeCloudLicense(data.licenseKey, data.machineId);
      if (!auth.ok) return res.status(auth.status).json({ success: false, message: auth.message });
      const key = auth.key;
      const machineId = auth.machineId;
      const payload = auth.payload;
      const product = isSecureLinkKey(key) ? 'securelink' : (key.startsWith('LV3.') ? 'lovart-modern' : 'lovart-legacy');
      await recordClientStatus(machineId, product, key, parseInt(data.accountCount, 10) || 0, payload);
      if (data.closing === true) {
        if (Array.isArray(data.accounts)) {
          await saveClientAccountSnapshot(machineId, product, key, data.accounts);
          await saveAccountCloudStatuses(machineId, data.accounts);
        }
        const acknowledgedCommandIds = [];
        if (Array.isArray(data.commandResults)) for (const r of data.commandResults) if (await completeAccountCommand(machineId, String(r && r.commandId || ''), r)) acknowledgedCommandIds.push(r.commandId);
        await clearActiveClient(machineId);
        const accountStatuses = await getAccountCloudStatuses((Array.isArray(data.accounts) ? data.accounts : []).map(a => a && a.email));
        return res.json({ success: true, closing: true, accountStatuses, acknowledgedCommandIds, buildSha: BUILD_SHA });
      }
      const activeConflict = await checkAndTouchActiveClient(machineId, product, data.accounts || []);
      if (activeConflict) {
        return res.json({
          success: true,
          activeDeviceConflict: true,
          conflictMachineId: activeConflict.machineId,
          conflictLastSeenAt: activeConflict.lastSeenAt,
          overlapCount: activeConflict.overlap.length,
          message: '同一批账号正在另一台电脑使用，请先关闭另一台电脑的软件'
        });
      }
      if (Array.isArray(data.accounts)) {
        await saveClientAccountSnapshot(machineId, product, key, data.accounts);
        await saveAccountCloudStatuses(machineId, data.accounts);
      }
      const acknowledgedCommandIds = [];
      if (Array.isArray(data.commandResults)) for (const r of data.commandResults) if (await completeAccountCommand(machineId, String(r && r.commandId || ''), r)) acknowledgedCommandIds.push(r.commandId);
      const commands = await takePendingAccountCommands(machineId, key);
      const accountStatuses = await getAccountCloudStatuses((Array.isArray(data.accounts) ? data.accounts : []).map(a => a && a.email));
      return res.json({ success: true, commands, accountStatuses, acknowledgedCommandIds, buildSha: BUILD_SHA });
    }
    if (req.method === 'POST' && action === 'activation_stats') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, stats: await getActivationStats() });
    }
    if (req.method === 'POST' && action === 'storage_stats') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, stats: await getStorageStats() });
    }
    if (req.method === 'POST' && action === 'list_activations') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listActivations() });
    }
    if (req.method === 'POST' && action === 'list_issued_licenses') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listIssuedLicenses() });
    }
    if (req.method === 'POST' && action === 'revoke_license') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const changed = await setLicenseRevocation(data.licenseHash, true, data.reason);
      if (!changed) return res.status(404).json({ success: false, message: '没有找到该卡密发放记录' });
      return res.json({ success: true, message: '卡密已撤销，云端接口将立即拒绝该卡密' });
    }
    if (req.method === 'POST' && action === 'restore_license') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const changed = await setLicenseRevocation(data.licenseHash, false, '');
      if (!changed) return res.status(404).json({ success: false, message: '没有找到该卡密发放记录' });
      return res.json({ success: true, message: '卡密已恢复' });
    }
    if (req.method === 'POST' && action === 'list_client_accounts') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim();
      if (machineId) return res.json({ success: true, snapshot: await getClientAccountSnapshot(machineId) });
      return res.json({ success: true, list: await listClientAccountSnapshots() });
    }
    if (req.method === 'POST' && action === 'list_account_commands') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      return res.json({ success: true, list: await listAccountCommands(data) });
    }
    if (req.method === 'POST' && action === 'remote_account_maintenance') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const machineId = String(data.machineId || '').trim();
      if (!machineId) return res.status(400).json({ success: false, message: '请输入机器码' });
      const snapshot = await getClientAccountSnapshot(machineId);
      const deleteCount = Math.max(0, Math.min(parseInt(data.deleteCount, 10) || 0, 200));
      const replenishCount = Math.max(0, Math.min(parseInt(data.replenishCount, 10) || 0, 200));
      if (replenishCount > 0 && !(await ensureDb())) {
        return res.status(503).json({ success: false, errorCode: 'DATABASE_REQUIRED_FOR_RESERVATION', message: '补号需要可用 PostgreSQL 数据库' });
      }
      const emails = String(data.emails || '').split(/\r?\n|,/).map(x => x.trim()).filter(Boolean).slice(0, 200);
      if (!deleteCount && !emails.length && !replenishCount) return res.status(400).json({ success: false, message: '请填写删除数量、指定邮箱或补充数量' });
      const exactMode = emails.length > 0;
      const selectionMode = exactMode ? 'exact_emails' : 'invalid_first_then_tail';
      const allowFallbackSelection = !exactMode;
      const commandInput = {
        type: 'delete_replenish_accounts',
        deleteCount,
        replenishCount,
        emails,
        selectionMode,
        allowFallbackSelection,
        priority: 'invalid_first',
        createdBy: 'admin'
      };
      const command = replenishCount > 0
        ? await createReservedAccountCommand({ machineId, product: snapshot && snapshot.product || 'lovart-modern', licenseKey: null, command: commandInput })
        : await createAccountCommand(machineId, snapshot && snapshot.product || 'lovart-modern', null, commandInput);
      console.log(JSON.stringify({ event: 'account_command_created', machineId, commandId: command.commandId, selectionMode, deleteCount, replenishCount, emailCount: emails.length }));
      return res.json({ success: true, commandId: command.commandId, command: command.command, buildSha: BUILD_SHA, message: '命令已下发，客户软件在线时会自动执行' });
    }
    if (req.method === 'POST' && action === 'list_account_pools') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listAccountPools() });
    }
    if (req.method === 'POST' && action === 'save_account_pool') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const item = await upsertAccountPool('', resolvePoolMachineIds(data.machineIds));
      return res.json({ success: true, item, message: '机器码绑定已保存' });
    }
    if (req.method === 'POST' && action === 'delete_account_pool') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      await removeAccountPool(String(data.poolId || ''));
      return res.json({ success: true, message: '绑定已删除' });
    }
    if (req.method === 'POST' && action === 'bind_secondary_license') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      const primaryMachineId = String(data.primaryMachineId || '').trim();
      const secondaryMachineId = String(data.secondaryMachineId || '').trim();
      if (!primaryMachineId || !secondaryMachineId) return res.status(400).json({ success: false, message: '请填写第一台和第二台电脑机器码' });
      if (primaryMachineId === secondaryMachineId) return res.status(400).json({ success: false, message: '两台电脑机器码不能相同' });
      const primary = await getLatestActivation(primaryMachineId);
      if (!primary) return res.status(404).json({ success: false, message: '没有找到第一台电脑的激活记录，请先确认第一台已经激活并在线上报过' });
      const generated = createLovartModernLicenseWithExpire(secondaryMachineId, primary.plan, primary.expire, 0);
      const pool = await upsertAccountPool('', [primaryMachineId, secondaryMachineId]);
      await recordIssuedLicense({
        licenseKey: generated.licenseKey,
        machineId: secondaryMachineId,
        product: 'lovart-modern',
        plan: generated.plan,
        expire: generated.expireTime,
        accountCount: 0,
        source: 'bound_secondary'
      });
      return res.json({
        success: true,
        licenseKey: generated.licenseKey,
        primaryMachineId,
        secondaryMachineId,
        plan: generated.plan,
        expireTime: generated.expireTime,
        accountCount: 0,
        pool,
        message: '已生成第二台电脑卡密，并绑定到同一账号池'
      });
    }
    if (req.method === 'POST' && action === 'trial_stats') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, stats: await getTrialStats() });
    }
    if (req.method === 'POST' && action === 'admin_settings') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({
        success: true,
        settings: {
          refreshAccountsEnabled: await isRefreshAccountsEnabled(),
          trialActivationAccountsEnabled: await isTrialActivationAccountsEnabled()
        }
      });
    }
    if (req.method === 'POST' && action === 'update_admin_settings') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      const data = await readBody(req);
      if (Object.prototype.hasOwnProperty.call(data, 'refreshAccountsEnabled')) {
        await setSetting('refresh_accounts_enabled', normalizeBoolSetting(data.refreshAccountsEnabled, true) ? 'true' : 'false');
      }
      if (Object.prototype.hasOwnProperty.call(data, 'trialActivationAccountsEnabled')) {
        await setSetting('trial_activation_accounts_enabled', normalizeBoolSetting(data.trialActivationAccountsEnabled, false) ? 'true' : 'false');
      }
      return res.json({
        success: true,
        settings: {
          refreshAccountsEnabled: await isRefreshAccountsEnabled(),
          trialActivationAccountsEnabled: await isTrialActivationAccountsEnabled()
        },
        message: '设置已保存'
      });
    }
    if (req.method === 'POST' && action === 'list_trial_claims') {
      if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' });
      return res.json({ success: true, list: await listTrialClaims() });
    }
    if (req.method === 'POST' && action === 'list_blacklist') { if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' }); return res.json({ success: true, list: await listBlacklist() }); }
    if (req.method === 'POST' && action === 'add_blacklist') { if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' }); const d = await readBody(req); const machineId = String(d.machineId || '').trim(); if (!machineId) return res.status(400).json({ success: false, message: '请输入机器码' }); await addBlacklist(machineId, String(d.reason || '')); return res.json({ success: true, message: '已拉黑' }); }
    if (req.method === 'POST' && action === 'remove_blacklist') { if (!checkAdmin(req)) return res.status(403).json({ success: false, message: '后台密钥不正确' }); const d = await readBody(req); await removeBlacklist(String(d.machineId || '').trim()); return res.json({ success: true, message: '已移除' }); }
    return res.status(200).send(adminPageV2());
  } catch (e) { return res.status(Number(e.statusCode) || 500).json({ success: false, message: e.message || 'server_error' }); }
};


function claimPage({ token, plan, count, days, unavailable }) {
  const planName = plan === 'permanent' ? '永久卡' : '月卡';
  const desc = plan === 'permanent' ? '永久' : days + ' 天';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>领取卡密</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;color:#c9d1d9;font-family:Arial,"Microsoft YaHei",sans-serif}.card{width:min(480px,92vw);background:#161b22;border:1px solid #30363d;border-radius:10px;padding:32px}.row{display:flex;justify-content:space-between;padding:5px 0}input,button{width:100%;box-sizing:border-box;border-radius:8px;font-size:15px}input{padding:13px;border:1px solid #30363d;background:#0d1117;color:#fff;margin:14px 0}button{border:0;padding:13px;background:#238636;color:white;font-weight:700}button:disabled{opacity:.55}.result{display:none;margin-top:16px;padding:14px;border-radius:8px;background:#0d1117;border:1px solid #238636;word-break:break-all}.error{border-color:#da3633;color:#f85149}.key{display:block;margin-top:10px;color:#58a6ff;font-family:Consolas,monospace}.notice{margin:16px 0;padding:12px;border:1px solid #da3633;border-radius:8px;color:#ff9b93;background:#2a1515}</style></head><body><div class="card"><h1>领取卡密</h1><div><div class="row"><span>类型</span><b>${planName}</b></div><div class="row"><span>有效期</span><b>${desc}</b></div><div class="row"><span>账号数</span><b>${count}</b></div></div>${unavailable ? '<div class="notice">这个领取链接无效、已使用、已撤销或已过期。</div>' : ''}<input id="machineId" placeholder="请输入客户机器码" ${unavailable ? 'disabled' : ''}><button id="claimBtn" onclick="doClaim()" ${unavailable ? 'disabled' : ''}>${unavailable ? '链接不可用' : '生成卡密'}</button><div id="result" class="result"><span id="msg"></span><span id="key" class="key"></span><button id="copyBtn" style="display:none;margin-top:12px;background:#1f6feb" onclick="copyKey()">复制卡密</button></div></div><script>async function doClaim(){var mid=document.getElementById('machineId').value.trim();if(!mid)return alert('请输入机器码');var btn=document.getElementById('claimBtn');btn.disabled=true;btn.innerText='正在生成...';try{var res=await fetch('/api?action=claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({machineId:mid,token:${JSON.stringify(token)}})});var data=await res.json();var box=document.getElementById('result');box.style.display='block';if(data.success){box.className='result';document.getElementById('msg').innerText='生成成功';document.getElementById('key').innerText=data.licenseKey;document.getElementById('copyBtn').style.display='block'}else{box.className='result error';document.getElementById('msg').innerText=data.message||'生成失败';document.getElementById('key').innerText='';document.getElementById('copyBtn').style.display='none'}}catch(e){alert('请求失败：'+e.message)}finally{btn.disabled=false;btn.innerText='生成卡密'}}function copyKey(){navigator.clipboard.writeText(document.getElementById('key').innerText).then(function(){alert('已复制')})}</script></body></html>`;
}

function trialPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>领取体验版</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d1117;color:#c9d1d9;font-family:Arial,"Microsoft YaHei",sans-serif}.card{width:min(480px,92vw);background:#161b22;border:1px solid #30363d;border-radius:10px;padding:32px}.row{display:flex;justify-content:space-between;padding:5px 0}input,button{width:100%;box-sizing:border-box;border-radius:8px;font-size:15px}input{padding:13px;border:1px solid #30363d;background:#0d1117;color:#fff;margin:14px 0}button{border:0;padding:13px;background:#238636;color:white;font-weight:700}.result{display:none;margin-top:16px;padding:14px;border-radius:8px;background:#0d1117;border:1px solid #238636;word-break:break-all}.error{border-color:#da3633;color:#f85149}.key{display:block;margin-top:10px;color:#58a6ff;font-family:Consolas,monospace}.muted{color:#8b949e;line-height:1.7}</style></head><body><div class="card"><h1>领取体验版</h1><p class="muted">每台电脑只能领取一次，体验 1 小时，固定 10 个账号。</p><div><div class="row"><span>有效期</span><b>${TRIAL_HOURS} 小时</b></div><div class="row"><span>账号数</span><b>${TRIAL_ACCOUNT_COUNT}</b></div></div><input id="machineId" placeholder="请输入客户机器码"><button id="claimBtn" onclick="doClaim()">领取体验卡密</button><div id="result" class="result"><span id="msg"></span><span id="key" class="key"></span><button id="copyBtn" style="display:none;margin-top:12px;background:#1f6feb" onclick="copyKey()">复制卡密</button></div></div><script>async function doClaim(){var mid=document.getElementById('machineId').value.trim();if(!mid)return alert('请输入机器码');var btn=document.getElementById('claimBtn');btn.disabled=true;btn.innerText='正在领取...';try{var res=await fetch('/api?action=claim_trial',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({machineId:mid})});var data=await res.json();var box=document.getElementById('result');box.style.display='block';if(data.success){box.className='result';document.getElementById('msg').innerText='领取成功';document.getElementById('key').innerText=data.licenseKey;document.getElementById('copyBtn').style.display='block'}else{box.className='result error';document.getElementById('msg').innerText=data.message||'领取失败';document.getElementById('key').innerText='';document.getElementById('copyBtn').style.display='none'}}catch(e){alert('请求失败：'+e.message)}finally{btn.disabled=false;btn.innerText='领取体验卡密'}}function copyKey(){navigator.clipboard.writeText(document.getElementById('key').innerText).then(function(){alert('已复制')})}</script></body></html>`;
}

function channelAdminPage() {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>渠道与经销商管理</title><style>
:root{color-scheme:dark;--bg:#0b0f14;--panel:#131923;--panel2:#192231;--line:#293548;--text:#f4f7fb;--muted:#8fa0b7;--brand:#7c5cff;--cyan:#21d4c2;--red:#ff6673;--gold:#ffc857}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#18213c 0,transparent 30%),var(--bg);color:var(--text);font:14px/1.55 Arial,"Microsoft YaHei",sans-serif}.wrap{max-width:1280px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:22px}.top h1{margin:0;font-size:28px}.top p{margin:5px 0 0;color:var(--muted)}a{color:#b8a9ff;text-decoration:none}.nav{display:flex;gap:10px;flex-wrap:wrap}.nav a{padding:9px 13px;border:1px solid var(--line);border-radius:9px;background:#121823}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{background:rgba(19,25,35,.96);border:1px solid var(--line);border-radius:14px;padding:20px}.full{grid-column:1/-1}.panel h2{margin:0 0 15px;font-size:18px}.form{display:grid;grid-template-columns:repeat(12,1fr);gap:10px;align-items:end}.field{grid-column:span 3;display:flex;flex-direction:column;gap:6px}.field.wide{grid-column:span 6}.field label{font-size:12px;color:var(--muted)}input,select,button{font:inherit;border-radius:9px;padding:11px 12px}input,select{width:100%;background:var(--panel2);border:1px solid #34435a;color:var(--text)}button{border:0;background:var(--brand);color:#fff;font-weight:700;cursor:pointer}button.secondary{background:#263247}button.danger{background:var(--red)}button.ok{background:var(--cyan);color:#08201d}button:disabled{opacity:.55}.hint,.muted{color:var(--muted)}.status{display:inline-flex;gap:7px;align-items:center;padding:7px 10px;border:1px solid var(--line);border-radius:999px}.dot{width:8px;height:8px;border-radius:50%;background:var(--gold)}.dot.ok{background:var(--cyan)}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;margin-top:14px}table{width:100%;border-collapse:collapse;min-width:760px}th,td{padding:11px;border-bottom:1px solid #253044;text-align:left;vertical-align:middle}th{color:var(--muted);font-weight:600;background:#101620}.money{font-variant-numeric:tabular-nums;color:#8ff3d9}.row-actions{display:flex;gap:7px;align-items:center}.row-actions input{width:100px}.empty{padding:20px;color:var(--muted)}.message{display:none;margin:0 0 18px;padding:12px 14px;border-radius:9px;background:#172c29;border:1px solid #286d63}.message.bad{background:#30191d;border-color:#74313a}@media(max-width:850px){.wrap{padding:16px}.grid{grid-template-columns:1fr}.full{grid-column:auto}.field,.field.wide{grid-column:span 12}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main class="wrap"><header class="top"><div><h1>渠道与经销商管理</h1><p>管理套餐、经销商余额和每一笔发卡订单</p></div><nav class="nav"><a href="/api">资源后台</a><a href="/api?action=reseller" target="_blank">经销商入口</a><span class="status"><span id="dbDot" class="dot"></span><span id="dbText">检查数据库</span></span></nav></header><div id="message" class="message"></div><div class="grid">
<section class="panel"><h2>新增或修改套餐</h2><div class="form"><div class="field wide"><label>套餐名称</label><input id="pName" placeholder="例如：30天 / 30账号"></div><div class="field"><label>类型</label><select id="pPlan"><option value="monthly">月卡</option><option value="permanent">永久卡</option></select></div><div class="field"><label>有效天数</label><input id="pDays" type="number" value="30"></div><div class="field"><label>账号数量</label><input id="pCount" type="number" value="30"></div><div class="field"><label>零售价（元）</label><input id="pRetail" type="number" min="0" step="0.01"></div><div class="field"><label>经销价（元）</label><input id="pReseller" type="number" min="0" step="0.01"></div><div class="field"><label>状态</label><select id="pStatus"><option value="active">上架</option><option value="disabled">下架</option></select></div><button onclick="saveProduct(this)">保存套餐</button></div><p class="hint">价格由服务器保存，经销商不能在浏览器里修改。经销价必须大于 0 才能发卡。</p></section>
<section class="panel"><h2>创建经销商</h2><div class="form"><div class="field"><label>登录账号</label><input id="rUsername" placeholder="dealer01"></div><div class="field wide"><label>显示名称</label><input id="rName" placeholder="闲鱼渠道 A"></div><div class="field"><label>初始密码</label><input id="rPassword" type="password" minlength="8" placeholder="至少 8 位"></div><button onclick="createReseller(this)">创建账号</button></div><p class="hint">创建后先充值余额，再把经销商入口和账号密码发给对方。</p></section>
<section class="panel full"><h2>销售套餐</h2><div id="productsBox" class="table-wrap"><div class="empty">读取中…</div></div></section>
<section class="panel full"><h2>经销商与余额</h2><div id="resellersBox" class="table-wrap"><div class="empty">读取中…</div></div></section>
<section class="panel full"><h2>最近订单</h2><div id="ordersBox" class="table-wrap"><div class="empty">读取中…</div></div></section>
</div></main><script>
var SECRET=localStorage.getItem('lovart_admin_secret')||'';function secret(){if(!SECRET){SECRET=prompt('请输入后台密钥')||'';if(SECRET)localStorage.setItem('lovart_admin_secret',SECRET)}return SECRET}function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}function yuan(c){return '¥'+(Number(c||0)/100).toFixed(2)}function time(v){return v?new Date(v).toLocaleString():'-'}function msg(text,bad){var el=document.getElementById('message');el.style.display='block';el.className='message'+(bad?' bad':'');el.textContent=text;setTimeout(function(){el.style.display='none'},3500)}async function post(action,body){var res=await fetch('/api?action='+action,{method:'POST',headers:{'Content-Type':'application/json','x-admin-secret':secret()},body:JSON.stringify(body||{})});var data=await res.json().catch(function(){return {success:false,message:'服务器响应异常'}});if(!data.success&&String(data.message||'').includes('后台密钥')){SECRET='';localStorage.removeItem('lovart_admin_secret')}return data}async function busy(btn,fn){btn.disabled=true;try{await fn()}finally{btn.disabled=false}}
async function health(){var d=await fetch('/api?action=health').then(function(r){return r.json()});document.getElementById('dbText').textContent=d.database?'数据库已连接':'数据库未连接';document.getElementById('dbDot').className='dot'+(d.database?' ok':'')}
async function saveProduct(btn){busy(btn,async function(){var d=await post('save_channel_product',{name:document.getElementById('pName').value,plan:document.getElementById('pPlan').value,days:Number(document.getElementById('pDays').value),accountCount:Number(document.getElementById('pCount').value),retailPriceCents:Math.round(Number(document.getElementById('pRetail').value)*100),resellerPriceCents:Math.round(Number(document.getElementById('pReseller').value)*100),status:document.getElementById('pStatus').value});if(!d.success)return msg(d.message||'保存失败',true);msg('套餐已保存');loadProducts()})}
async function createReseller(btn){busy(btn,async function(){var d=await post('create_reseller',{username:document.getElementById('rUsername').value,displayName:document.getElementById('rName').value,password:document.getElementById('rPassword').value});if(!d.success)return msg(d.message||'创建失败',true);document.getElementById('rPassword').value='';msg('经销商已创建');loadResellers()})}
async function loadProducts(){var d=await post('channel_products');var box=document.getElementById('productsBox');if(!d.success)return box.innerHTML='<div class="empty">'+esc(d.message)+'</div>';if(!d.list.length)return box.innerHTML='<div class="empty">还没有套餐，请先在上方创建。</div>';box.innerHTML='<table><thead><tr><th>套餐</th><th>类型</th><th>有效期</th><th>账号</th><th>零售价</th><th>经销价</th><th>状态</th></tr></thead><tbody>'+d.list.map(function(p){return '<tr><td>'+esc(p.name)+'</td><td>'+(p.plan==='permanent'?'永久':'月卡')+'</td><td>'+(p.plan==='permanent'?'永久':p.days+' 天')+'</td><td>'+p.accountCount+'</td><td>'+yuan(p.retailPriceCents)+'</td><td class="money">'+yuan(p.resellerPriceCents)+'</td><td>'+esc(p.status==='active'?'上架':'下架')+'</td></tr>'}).join('')+'</tbody></table>'}
async function adjust(id,sign){var input=document.getElementById('money-'+id);var amount=Number(input.value||0)*sign;if(!amount)return msg('请输入金额',true);var note=prompt('备注','后台充值')||'';var d=await post('adjust_reseller_balance',{resellerId:id,amountYuan:amount,note:note});if(!d.success)return msg(d.message||'调整失败',true);msg('余额已更新');loadResellers()}
async function loadResellers(){var d=await post('list_resellers');var box=document.getElementById('resellersBox');if(!d.success)return box.innerHTML='<div class="empty">'+esc(d.message)+'</div>';if(!d.list.length)return box.innerHTML='<div class="empty">暂无经销商。</div>';box.innerHTML='<table><thead><tr><th>名称</th><th>账号</th><th>余额</th><th>状态</th><th>创建时间</th><th>余额操作</th></tr></thead><tbody>'+d.list.map(function(r){return '<tr><td>'+esc(r.displayName)+'</td><td>'+esc(r.username)+'</td><td class="money">'+yuan(r.balanceCents)+'</td><td>'+esc(r.status)+'</td><td>'+time(r.createdAt)+'</td><td><div class="row-actions"><input id="money-'+esc(r.resellerId)+'" type="number" min="0" step="0.01" placeholder="金额"><button class="ok" onclick="adjust(&quot;'+esc(r.resellerId)+'&quot;,1)">充值</button><button class="danger" onclick="adjust(&quot;'+esc(r.resellerId)+'&quot;,-1)">扣减</button></div></td></tr>'}).join('')+'</tbody></table>'}
function statusName(v){return v==='paid'?'待领取':v==='claimed'?'已领取':v==='cancelled'?'已撤销':v==='pending_payment'?'待支付':v}
async function loadOrders(){var d=await post('list_channel_orders');var box=document.getElementById('ordersBox');if(!d.success)return box.innerHTML='<div class="empty">'+esc(d.message)+'</div>';if(!d.list.length)return box.innerHTML='<div class="empty">暂无订单。</div>';box.innerHTML='<table><thead><tr><th>时间</th><th>经销商</th><th>套餐</th><th>闲鱼订单号</th><th>金额</th><th>状态</th><th>机器码</th></tr></thead><tbody>'+d.list.map(function(o){return '<tr><td>'+time(o.createdAt)+'</td><td>'+esc(o.resellerName||'-')+'</td><td>'+esc(o.productName)+'</td><td>'+esc(o.platformOrderNo||'-')+'</td><td>'+yuan(o.amountCents)+'</td><td>'+esc(statusName(o.status))+'</td><td>'+esc(o.machineId||'-')+'</td></tr>'}).join('')+'</tbody></table>'}
health();loadProducts();loadResellers();loadOrders();setInterval(loadOrders,30000);
</script></body></html>`;
}

function resellerPage() {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>经销商发卡中心</title><style>
:root{color-scheme:dark;--bg:#090d12;--panel:#121924;--panel2:#182232;--line:#2a374a;--text:#f5f7fb;--muted:#8d9db2;--brand:#7d62ff;--green:#24d2ae;--red:#ff6673}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(145deg,#101932 0,#090d12 45%);color:var(--text);font:14px/1.55 Arial,"Microsoft YaHei",sans-serif}.shell{max-width:1120px;margin:auto;padding:28px}.brand{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.brand h1{margin:0;font-size:26px}.brand p{margin:4px 0;color:var(--muted)}.card{background:rgba(18,25,36,.96);border:1px solid var(--line);border-radius:15px;padding:20px}.login{max-width:420px;margin:10vh auto}.login h2{margin-top:0}.field{display:flex;flex-direction:column;gap:7px;margin-bottom:13px}.field label{font-size:12px;color:var(--muted)}input,select,button{font:inherit;border-radius:9px;padding:12px}input,select{width:100%;background:var(--panel2);border:1px solid #35445a;color:var(--text)}button{border:0;background:var(--brand);color:#fff;font-weight:700;cursor:pointer}button.secondary{background:#263247}button.danger{background:var(--red)}button.ok{background:var(--green);color:#06221c}button:disabled{opacity:.55}.hidden{display:none!important}.summary{display:grid;grid-template-columns:1.2fr .8fr;gap:18px;margin-bottom:18px}.balance b{display:block;font-size:34px;color:#8df5dc}.muted{color:var(--muted)}.products{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}.product{position:relative;border:1px solid var(--line);border-radius:12px;padding:15px;background:var(--panel2);cursor:pointer}.product.selected{border-color:var(--brand);box-shadow:0 0 0 1px var(--brand) inset}.product input{position:absolute;opacity:0}.product b{display:block;font-size:16px}.product strong{display:block;color:#8df5dc;font-size:22px;margin-top:8px}.issue-row{display:grid;grid-template-columns:1fr auto;gap:10px}.result{display:none;margin-top:14px;padding:14px;border:1px solid #2b7569;background:#102925;border-radius:10px}.result input{margin:10px 0}.message{display:none;margin-bottom:14px;padding:12px;border-radius:9px;background:#30191d;border:1px solid #74313a}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;margin-top:14px}table{width:100%;min-width:820px;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid #263247;text-align:left}th{color:var(--muted);background:#101620}.money{color:#8df5dc}.top-actions{display:flex;gap:10px;align-items:center}.top-actions button{padding:9px 12px}@media(max-width:780px){.shell{padding:16px}.summary{grid-template-columns:1fr}.products{grid-template-columns:1fr}.issue-row{grid-template-columns:1fr}.brand{align-items:flex-start}.brand h1{font-size:22px}}
</style></head><body><main class="shell"><div id="login" class="card login"><h2>经销商登录</h2><p class="muted">登录后可以按拿货价生成一次性客户领取链接。</p><div id="loginMsg" class="message"></div><div class="field"><label>账号</label><input id="username" autocomplete="username"></div><div class="field"><label>密码</label><input id="password" type="password" autocomplete="current-password"></div><button style="width:100%" onclick="login(this)">登录发卡中心</button></div>
<section id="dashboard" class="hidden"><header class="brand"><div><h1>经销商发卡中心</h1><p id="welcome"></p></div><div class="top-actions"><button class="secondary" onclick="refresh()">刷新</button><button class="secondary" onclick="logout()">退出</button></div></header><div id="dashMsg" class="message"></div><div class="summary"><section class="card balance"><span class="muted">可用余额</span><b id="balance">¥0.00</b><span class="muted">每笔发卡自动扣除对应经销价</span></section><section class="card"><b>发货规则</b><p class="muted">链接 30 天内有效，只能领取一次。客户领取前可以撤销并原路退回后台余额。</p></section></div><section class="card"><h2 style="margin-top:0">生成客户领取链接</h2><div id="products" class="products"></div><div class="issue-row"><input id="platformOrderNo" placeholder="闲鱼订单号（建议填写，防止重复发货）"><button onclick="issue(this)">扣款并生成链接</button></div><div id="issueResult" class="result"><b>领取链接已生成</b><input id="issueLink" readonly><button class="ok" onclick="copyLink()">复制发货话术</button></div></section><section class="card" style="margin-top:18px"><h2 style="margin-top:0">最近订单</h2><div id="orders" class="table-wrap"></div></section></section></main><script>
var state={products:[],selected:'',orders:[]};function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}function yuan(c){return '¥'+(Number(c||0)/100).toFixed(2)}function time(v){return v?new Date(v).toLocaleString():'-'}async function api(action,body){var r=await fetch('/api?action='+action,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body||{})});return r.json().catch(function(){return {success:false,message:'服务器响应异常'}})}function message(id,text){var el=document.getElementById(id);el.textContent=text;el.style.display='block';setTimeout(function(){el.style.display='none'},3500)}async function login(btn){btn.disabled=true;var d=await api('reseller_login',{username:document.getElementById('username').value,password:document.getElementById('password').value});btn.disabled=false;if(!d.success)return message('loginMsg',d.message||'登录失败');refresh()}async function logout(){await api('reseller_logout');document.getElementById('dashboard').classList.add('hidden');document.getElementById('login').classList.remove('hidden')}function selectProduct(id){state.selected=id;renderProducts()}
function renderProducts(){var box=document.getElementById('products');if(!state.products.length){box.innerHTML='<p class="muted">管理员还没有上架套餐。</p>';return}if(!state.selected)state.selected=state.products[0].productId;box.innerHTML=state.products.map(function(p){return '<label class="product '+(state.selected===p.productId?'selected':'')+'" onclick="selectProduct(&quot;'+esc(p.productId)+'&quot;)"><input type="radio" name="product"><b>'+esc(p.name)+'</b><span class="muted">'+(p.plan==='permanent'?'永久':p.days+' 天')+' · '+p.accountCount+' 个账号</span><strong>'+yuan(p.resellerPriceCents)+'</strong></label>'}).join('')}
function statusName(v){return v==='paid'?'待领取':v==='claimed'?'已领取':v==='cancelled'?'已撤销':v}function renderOrders(){var box=document.getElementById('orders');if(!state.orders.length){box.innerHTML='<p class="muted" style="padding:15px">暂无订单。</p>';return}box.innerHTML='<table><thead><tr><th>时间</th><th>闲鱼订单号</th><th>套餐</th><th>拿货价</th><th>状态</th><th>机器码</th><th>操作</th></tr></thead><tbody>'+state.orders.map(function(o){return '<tr><td>'+time(o.createdAt)+'</td><td>'+esc(o.platformOrderNo||'-')+'</td><td>'+esc(o.productName)+'</td><td class="money">'+yuan(o.amountCents)+'</td><td>'+esc(statusName(o.status))+'</td><td>'+esc(o.machineId||'-')+'</td><td>'+(o.status==='paid'?'<button class="danger" onclick="cancelOrder(&quot;'+esc(o.orderId)+'&quot;)">撤销退款</button>':'-')+'</td></tr>'}).join('')+'</tbody></table>'}
async function refresh(){var d=await api('reseller_dashboard');if(!d.success){document.getElementById('dashboard').classList.add('hidden');document.getElementById('login').classList.remove('hidden');if(d.message&&d.message!=='请先登录')message('loginMsg',d.message);return}document.getElementById('login').classList.add('hidden');document.getElementById('dashboard').classList.remove('hidden');document.getElementById('welcome').textContent='你好，'+d.reseller.displayName;document.getElementById('balance').textContent=yuan(d.reseller.balanceCents);state.products=d.products||[];state.orders=d.orders||[];renderProducts();renderOrders()}
async function issue(btn){if(!state.selected)return message('dashMsg','请选择套餐');btn.disabled=true;var d=await api('reseller_create_claim',{productId:state.selected,platformOrderNo:document.getElementById('platformOrderNo').value.trim()});btn.disabled=false;if(!d.success)return message('dashMsg',d.message||'生成失败');document.getElementById('issueResult').style.display='block';document.getElementById('issueLink').value=d.order.link;document.getElementById('platformOrderNo').value='';refresh()}function copyLink(){var link=document.getElementById('issueLink').value;var text='您的卡密领取链接：'+link+'\\n打开后填写软件中的机器码即可领取。链接仅限使用一次。';navigator.clipboard.writeText(text).then(function(){message('dashMsg','发货话术已复制')})}async function cancelOrder(id){if(!confirm('确认撤销这个未领取订单并退回余额吗？'))return;var d=await api('reseller_cancel_order',{orderId:id});if(!d.success)return message('dashMsg',d.message||'撤销失败');message('dashMsg','订单已撤销，余额已退回');refresh()}refresh();
</script></body></html>`;
}

function adminPageV2() {
  const lovartReady = LICENSE_SIGNING_PRIVATE_KEY ? '已配置' : '未配置';
  const lovartWarn = LICENSE_SIGNING_PRIVATE_KEY ? '' : '<div class="notice">Lovart 发卡私钥未配置或格式不正确：现有卡密仍可验签，但新卡密和领取链接会生成失败。</div>';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>资源后台</title><style>
:root{color-scheme:dark;--bg:#101113;--panel:#1b1c1f;--panel2:#222327;--line:#343842;--text:#f3f6fb;--muted:#9aa4b2;--accent:#a66cff;--accent2:#15d6c7;--danger:#ff5b67;--ok:#45d483}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,"Microsoft YaHei",sans-serif;font-size:14px}.wrap{max-width:1280px;margin:0 auto;padding:28px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:18px;border-bottom:1px solid var(--line);margin-bottom:22px}.top h1{margin:0;font-size:28px}.pill{border:1px solid var(--accent2);color:var(--accent2);border-radius:999px;padding:8px 12px;white-space:nowrap}.notice{border:1px solid #9a6700;background:#2b2110;color:#ffd98a;border-radius:8px;padding:12px;margin-bottom:16px}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px}.panel h2{font-size:18px;margin:0 0 16px;color:#c391ff}.form{display:grid;grid-template-columns:repeat(12,1fr);gap:12px;align-items:end}.field{display:flex;flex-direction:column;gap:7px}.field label,.label{color:var(--muted);font-size:12px}.col-2{grid-column:span 2}.col-3{grid-column:span 3}.col-4{grid-column:span 4}.col-5{grid-column:span 5}.col-6{grid-column:span 6}.col-8{grid-column:span 8}.col-12{grid-column:span 12}input,select,textarea{width:100%;background:var(--panel2);border:1px solid #454954;color:var(--text);border-radius:8px;padding:11px 12px;font:inherit}textarea{min-height:112px;font-family:Consolas,monospace;resize:vertical}button{border:0;border-radius:8px;background:var(--accent);color:#100f13;font-weight:700;padding:12px 16px;cursor:pointer;white-space:nowrap}button.secondary{background:#2d3036;color:var(--text);border:1px solid #474c58}button.danger{background:var(--danger);color:white}button.ok{background:var(--accent2)}button:disabled{opacity:.65;cursor:wait}.seg{display:flex;gap:10px;flex-wrap:wrap}.seg label{display:flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid #3c404a;border-radius:8px;padding:10px 12px;min-width:145px}.domains{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;background:var(--panel2);border:1px solid #454954;border-radius:8px;padding:12px}.domains label{display:flex;gap:8px;align-items:center}.hint{color:var(--muted);line-height:1.6;margin:12px 0 0}.result{display:none;margin-top:14px;background:#111316;border:1px solid #2c6b67;border-left:4px solid var(--accent2);border-radius:8px;padding:12px;word-break:break-all}.key{font-family:Consolas,monospace;color:var(--accent2);margin-top:8px}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}.stat{background:var(--panel2);border:1px solid #3a3e48;border-radius:8px;padding:10px 12px;min-width:110px}.stat.risk{border-color:#ff5b67;color:#ffd6d9}.table-tools{display:grid;grid-template-columns:2fr 1fr 1.2fr 1fr auto;gap:10px;margin:12px 0}.pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:10px;color:var(--muted)}.pager button{padding:8px 12px}.risk-row{background:rgba(255,91,103,.08)}.badge{display:inline-block;border-radius:999px;padding:4px 8px;font-size:12px;font-weight:700}.badge-ok{background:rgba(69,212,131,.16);color:#7bf0aa}.badge-risk{background:rgba(255,91,103,.18);color:#ff9aa2}.badge-muted{background:#2d3036;color:#b7c0cd}.stat b{font-size:20px;margin-right:4px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse;min-width:760px}th,td{border-bottom:1px solid #2d3038;padding:10px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600;background:#17191d}.muted{color:var(--muted)}.full{grid-column:1/-1}@media(max-width:920px){.grid{grid-template-columns:1fr}.col-2,.col-3,.col-4,.col-5,.col-6,.col-8{grid-column:span 12}.domains{grid-template-columns:1fr}.wrap{padding:16px}.top{align-items:flex-start;flex-direction:column}.table-tools{grid-template-columns:1fr}.pager{justify-content:flex-start;flex-wrap:wrap}}
.seg label{position:relative;justify-content:center;min-width:128px;min-height:48px;padding:12px 16px;color:#d9e4ff;font-weight:700;line-height:1.25;text-align:center;white-space:nowrap;cursor:pointer;transition:.16s}.seg label:hover,.domains label:hover{border-color:#75628f;background:#282a31}.seg label input,.domains label input{position:absolute;opacity:0;pointer-events:none}.seg label:has(input:checked),.domains label:has(input:checked){border-color:var(--accent);background:rgba(166,108,255,.18);box-shadow:0 0 0 1px rgba(166,108,255,.28) inset;color:#fff}.seg label:has(input:checked)::after,.domains label:has(input:checked)::after{content:'已选';position:absolute;right:8px;top:6px;color:var(--accent2);font-size:11px;font-weight:700}.domains{background:transparent;border:0;padding:0}.domains label{position:relative;justify-content:center;min-height:48px;background:var(--panel2);border:1px solid #454954;border-radius:8px;padding:12px 32px 12px 12px;font-weight:700;cursor:pointer;transition:.16s;text-align:center}.tabs{display:flex;gap:10px;margin:0 0 18px}.tab-btn{background:#20232a;color:#d9e4ff;border:1px solid #3c404a;padding:11px 18px}.tab-btn.active{background:rgba(166,108,255,.22);border-color:var(--accent);color:#fff;box-shadow:0 0 0 1px rgba(166,108,255,.28) inset}.tab-card{display:none}.tab-card.active{display:block}.grid>.panel:not(.full).tab-card.active{display:block}
</style></head><body><div class="wrap"><div class="top"><h1>资源后台</h1><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><a href="/api?action=channel_admin" style="color:#fff;border:1px solid var(--accent);border-radius:8px;padding:8px 12px;text-decoration:none">经销商系统</a><span class="pill">Lovart 私钥：${lovartReady}</span></div></div><div class="tabs"><button id="tabTools" class="tab-btn active" onclick="switchAdminTab('tools')">生成工具</button><button id="tabData" class="tab-btn" onclick="switchAdminTab('data')">数据看板</button></div>${lovartWarn}
<div class="grid">
<section class="panel tab-card active" data-tab="tools"><h2>生成卡密</h2><div class="form"><div class="col-12 seg"><label><input type="radio" name="licProduct" value="lovart-modern" checked onchange="updateLicenseProduct()">新版 Lovart LV3</label><label><input type="radio" name="licProduct" value="lovart-legacy" onchange="updateLicenseProduct()">旧版 Lovart LV2</label><label><input type="radio" name="licProduct" value="securelink" onchange="updateLicenseProduct()">SecureLink LV2</label></div><div class="col-12 seg"><label><input type="radio" name="licType" value="sub" checked onchange="toggleDays(true)">月卡</label><label><input type="radio" name="licType" value="perm" onchange="toggleDays(false)">永久卡</label></div><div class="field col-5"><label>客户机器码</label><input id="machineId" placeholder="粘贴客户机器码"></div><div class="field col-2"><label>有效期</label><select id="licenseDays"><option value="1" selected>1 天</option><option value="3">3 天</option><option value="7">7 天</option><option value="30">30 天</option><option value="90">90 天</option></select></div><div class="field col-2"><label>自定义天数</label><input id="licenseCustomDays" type="number" min="1" max="3650" placeholder="可选"></div><div class="field col-2"><label>账号数</label><input id="accountCount" type="number" value="30"></div><button class="col-1" onclick="genLicense(event)">生成</button></div><p class="hint">新版 Lovart 卡密会写入账号数；客户激活成功后会自动同步账号。旧版 Lovart 和 SecureLink 不包含账号数，需要单独生成账号代码。</p><div id="licenseResult" class="result"><b>卡密</b><div id="licenseCodeDisplay" class="key"></div><button class="ok" style="margin-top:10px" onclick="copyText('licenseCodeDisplay')">复制卡密</button></div></section>
<section class="panel tab-card active" data-tab="tools"><h2>生成账号代码</h2><div class="form"><div class="col-8 domains" id="domainGroup"><label><input type="checkbox" value="yxd.ccwu.cc" checked> yxd.ccwu.cc</label><label><input type="checkbox" value="haitai.cc.cd" checked> haitai.cc.cd</label><label><input type="checkbox" value="shupianduizhang.cc.cd" checked> shupianduizhang.cc.cd</label><label><input type="checkbox" value="ylian.ccwu.cc" checked> ylian.ccwu.cc</label></div><div class="field col-3"><label>数量</label><input id="count" type="number" value="50"></div><button class="col-1" onclick="genAccounts(event)">生成</button></div><div id="accountResult" class="result"><b>账号代码</b><textarea id="outputCode" readonly></textarea><button class="ok" onclick="copyInput('outputCode')">复制账号代码</button></div></section>
<section class="panel tab-card active" data-tab="tools"><h2>Cloudflare 邮箱账号代码</h2><div class="form"><div class="col-8 domains"><label>115765814.cc.cd</label><label>1xxcdeh.ccwu.cc</label><label>fxasf.cc.cd</label><label>gyjfgh.ccwu.cc</label></div><div class="field col-3"><label>数量</label><input id="cloudflareCount" type="number" value="50"></div><button class="col-1" onclick="genCloudflareAccounts(event)">生成</button></div><p class="hint">新增 Cloudflare 收码专用账号池；不会影响上面的旧 163 转发域名生成器。</p><div id="cloudflareAccountResult" class="result"><b>Cloudflare 账号代码</b><textarea id="cloudflareOutputCode" readonly></textarea><button class="ok" onclick="copyInput('cloudflareOutputCode')">复制账号代码</button></div></section>
<section id="adjustLicensePanel" class="panel tab-card active" data-tab="tools"><h2>调整客户账号数</h2><div class="form"><div class="field col-5"><label>客户机器码</label><input id="adjustMachineId" placeholder="粘贴客户机器码"></div><div class="field col-2"><label>当前账号数</label><input id="adjustCurrentCount" type="number" min="0" max="500" placeholder="可选"></div><div class="field col-2"><label>目标账号数</label><input id="adjustTargetCount" type="number" min="0" max="500" value="30"></div><div class="field col-2"><label>有效期</label><select id="adjustDays"><option value="1">1 天</option><option value="3">3 天</option><option value="7">7 天</option><option value="30" selected>30 天</option><option value="90">90 天</option></select></div><div class="field col-2"><label>自定义天数</label><input id="adjustCustomDays" type="number" min="1" max="3650" placeholder="可选"></div><button class="col-3" onclick="adjustCustomerAccounts(event)">生成调整卡密</button></div><p class="hint">已自动填入客户机器码和当前套餐账号数。修改“目标账号数”和有效期后生成新卡密，再发给客户切换套餐。</p><div id="adjustResult" class="result"><b>调整卡密</b><div id="adjustSummary" class="hint"></div><div id="adjustLicenseDisplay" class="key"></div><button class="ok" style="margin-top:10px" onclick="copyText('adjustLicenseDisplay')">复制调整卡密</button></div></section>
<section class="panel full tab-card active" data-tab="tools"><h2>设备账号运维</h2><div class="form"><div class="field col-5"><label>客户机器码</label><input id="opsMachineId" placeholder="粘贴客户机器码"></div><button class="secondary col-2" onclick="loadClientAccounts()">读取账号</button><div class="field col-2"><label>删除数量</label><input id="opsDeleteCount" type="number" min="0" max="200" value="10"></div><div class="field col-2"><label>补充数量</label><input id="opsReplenishCount" type="number" min="0" max="200" value="10"></div><button class="danger col-1" onclick="sendAccountMaintenance(event)">下发</button><div class="field col-12"><label>指定删除邮箱（可选，一行一个；不填则优先删除 0 积分 / 需替换账号）</label><textarea id="opsEmails" placeholder="user@example.com"></textarea></div></div><p class="hint">不会修改客户套餐上限。命令会在客户软件在线并上报状态时自动执行；如果指定邮箱为空，会优先删除 0 积分和需要替换的账号，再补新号。</p><div id="clientAccountsBox" style="margin-top:14px"></div><div id="accountCommandsBox" style="margin-top:14px"></div></section>
<section class="panel full tab-card active" data-tab="tools"><h2>机器码绑定生成</h2><div class="form"><div class="field col-5"><label>第一台电脑机器码</label><input id="bindPrimaryMachineId" placeholder="已激活的电脑 A 机器码"></div><div class="field col-5"><label>第二台电脑机器码</label><input id="bindSecondaryMachineId" placeholder="新电脑 B 机器码"></div><button class="ok col-2" onclick="genBoundSecondaryLicense(event)">生成 B 卡密</button></div><p class="hint">B 卡密会跟 A 当前卡密同到期时间，账号数写入 0。B 打开后不会自动带账号，需要客户从 A 导出账号文件，再到 B 手动导入。后台只负责绑定两台电脑、共享账号状态和限制同时在线。</p><div id="bindResult" class="result"><b>第二台电脑卡密</b><div id="bindSummary" class="hint"></div><div id="bindLicenseDisplay" class="key"></div><button class="ok" style="margin-top:10px" onclick="copyText('bindLicenseDisplay')">复制 B 卡密</button></div><div id="accountPoolsBox" style="margin-top:14px"></div></section>


<section class="panel full tab-card active" data-tab="tools"><h2>替换失效账号开关</h2><div class="stats"><div class="stat" id="refreshSwitchCard"><b id="refreshSwitchText">读取中</b>当前状态</div><button id="refreshSwitchBtn" class="secondary" onclick="toggleRefreshSwitch(event)">读取中</button></div><p class="hint">关闭后，本地软件点击“替换失效账号”会被云端拒绝，不能从资源服务器领取新账号；重新开启后恢复正常。</p></section>
<section class="panel full tab-card active" data-tab="tools"><h2>生成领取链接</h2><div class="form"><div class="col-3 seg"><label><input type="radio" name="issuePlan" value="monthly" checked onchange="toggleIssueDays(true)">月卡</label><label><input type="radio" name="issuePlan" value="permanent" onchange="toggleIssueDays(false)">永久卡</label></div><div class="field col-2"><label>有效期</label><select id="issueDays"><option value="1" selected>1 天</option><option value="3">3 天</option><option value="7">7 天</option><option value="30">30 天</option><option value="90">90 天</option></select></div><div class="field col-2"><label>自定义天数</label><input id="issueCustomDays" type="number" min="1" max="3650" placeholder="可选"></div><div class="field col-2"><label>账号数</label><input id="issueCount" type="number" value="30"></div><button class="col-3" onclick="genIssueLink(event)">生成链接</button><button class="secondary col-3" onclick="copyTrialLink()">复制体验链接</button></div><div class="stats" style="margin-top:14px"><div class="stat" id="trialActivationSwitchCard"><b id="trialActivationSwitchText">读取中</b>体验首激发号</div><button id="trialActivationSwitchBtn" class="secondary" onclick="toggleTrialActivationSwitch(event)">读取中</button></div><p class="hint">体验链接固定可长期使用：每台电脑限领一次，1 小时，10 个账号。开启“体验首激发号”后，体验卡在客户端首次激活时会从云端下发 10 个账号，不受替换失效账号开关影响，也不占用今日替换次数。</p><div id="issueResult" class="result"><input id="issueLinkDisplay" readonly><div class="hint">领取码：<span id="issueTokenDisplay"></span></div><button class="ok" style="margin-top:10px" onclick="copyInput('issueLinkDisplay')">复制链接</button></div></section>



<section class="panel full tab-card" data-tab="data"><h2>云空间占用</h2><div class="stats"><div class="stat"><b id="storageUsedMb">-</b>已用 MB</div><div class="stat"><b id="storageMode">-</b>存储模式</div><div class="stat"><b id="storageTableCount">0</b>数据表</div><div class="stat"><b id="storageCheckedAt">-</b>检查时间</div><button class="secondary" onclick="loadStorageStats()">刷新占用</button></div><p class="hint">这里显示数据库实际占用和主要业务表记录数，用来判断账号快照、积分状态、发卡记录是否快把云空间撑满。</p><div id="storageStatsBox" style="margin-top:14px"></div></section>
<section class="panel full tab-card" data-tab="data"><h2>真实激活记录</h2><div class="stats"><div class="stat"><b id="statTotal">0</b>总数</div><div class="stat"><b id="statMonthly">0</b>月卡</div><div class="stat"><b id="statPerm">0</b>永久卡</div><div class="stat"><b id="statExpired">0</b>已过期</div><div class="stat risk"><b id="statRisk">0</b>风险</div><button class="secondary" onclick="loadActivations()">刷新记录</button></div><div class="table-tools"><input id="activationSearch" placeholder="搜索机器码 / 时长 / 风险" oninput="setActivationPage(1)"><select id="activationProduct" onchange="setActivationPage(1)"><option value="">全部产品</option><option value="lovart-modern">新版 Lovart</option><option value="lovart-legacy">旧版 Lovart</option><option value="securelink">SecureLink</option></select><select id="activationStatus" onchange="setActivationPage(1)"><option value="">全部状态</option><option value="active">正常</option><option value="expired">已过期</option><option value="risk">重点检查</option></select><select id="activationSort" onchange="setActivationPage(1)"><option value="activatedAt">按最近激活</option><option value="lastSeenAt">按最后在线</option><option value="expire">按到期时间</option><option value="accountCount">按套餐账号</option><option value="todayRefreshCount">按今日替换数</option></select><select id="activationOrder" onchange="setActivationPage(1)"><option value="desc">倒序</option><option value="asc">正序</option></select><button class="secondary" onclick="resetActivationFilters()">重置</button></div><div class="table-wrap"><div id="activationTable"><p class="muted" style="padding:12px">加载中...</p></div></div><div class="pager" id="activationPager"></div></section>
<section class="panel full tab-card" data-tab="data"><h2>授权发放记录</h2><div class="stats"><div class="stat"><b id="issuedTotal">0</b>总发放</div><button class="secondary" onclick="loadIssuedLicenses()">刷新发放</button></div><div class="table-tools"><input id="issuedSearch" placeholder="搜索机器码 / 来源 / 激活时长 / 卡密哈希" oninput="setIssuedPage(1)"><select id="issuedProduct" onchange="setIssuedPage(1)"><option value="">全部产品</option><option value="lovart-modern">新版 Lovart</option><option value="lovart-legacy">旧版 Lovart</option><option value="securelink">SecureLink</option></select><button class="secondary" onclick="resetIssuedFilters()">重置</button></div><div class="table-wrap"><div id="issuedTable"><p class="muted" style="padding:12px">加载中...</p></div></div><div class="pager" id="issuedPager"></div></section>
<section class="panel full tab-card" data-tab="data"><h2>体验卡统计</h2><div class="stats"><div class="stat"><b id="trialTotal">0</b>总领取</div><div class="stat"><b id="trialToday">0</b>今日领取</div><div class="stat"><b id="trialActive">0</b>正常</div><div class="stat"><b id="trialExpired">0</b>已过期</div><div class="stat risk"><b id="trialBlacklisted">0</b>拉黑</div><div class="stat"><b id="trialConverted">0</b>已转正式</div><button class="secondary" onclick="loadTrials()">刷新体验</button></div><div class="table-tools"><input id="trialSearch" placeholder="搜索机器码 / 拉黑原因" oninput="setTrialPage(1)"><select id="trialStatus" onchange="setTrialPage(1)"><option value="">全部状态</option><option value="active">正常</option><option value="expired">已过期</option><option value="blacklisted">拉黑</option><option value="converted">已转正式</option><option value="notConverted">未转正式</option></select><select id="trialSort" onchange="setTrialPage(1)"><option value="claimedAt">按领取时间</option><option value="expire">按到期时间</option><option value="accountCount">按账号数</option><option value="status">按状态</option></select><select id="trialOrder" onchange="setTrialPage(1)"><option value="desc">倒序</option><option value="asc">正序</option></select><button class="secondary" onclick="resetTrialFilters()">重置</button></div><div class="table-wrap"><div id="trialTable"><p class="muted" style="padding:12px">加载中...</p></div></div><div class="pager" id="trialPager"></div></section>
<section class="panel full tab-card" data-tab="data"><h2>黑名单</h2><div class="form"><div class="field col-5"><label>机器码</label><input id="blMachineId" placeholder="机器码"></div><div class="field col-5"><label>原因</label><input id="blReason" placeholder="原因"></div><button class="danger col-1" onclick="addToBlacklist(event)">拉黑</button><button class="secondary col-1" onclick="loadBlacklist()">刷新</button></div><div id="blacklistTable" style="margin-top:14px"></div></section>
</div></div><script>
var ADMIN_SECRET=localStorage.getItem('lovart_admin_secret')||'';
var activationRows=[],trialRows=[],issuedRows=[],activationPage=1,trialPageNo=1,issuedPage=1,PER_PAGE=10;
function getAdminSecret(){if(!ADMIN_SECRET){ADMIN_SECRET=prompt('请输入后台密钥')||'';if(ADMIN_SECRET)localStorage.setItem('lovart_admin_secret',ADMIN_SECRET)}return ADMIN_SECRET}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function jsq(s){return esc(JSON.stringify(String(s==null?'':s)))}
function productName(v){return v==='lovart-modern'?'新版 Lovart':v==='securelink'?'SecureLink':'旧版 Lovart'}
function sourceName(v){return v==='issue_link'?'领取链接':v==='reseller_link'?'经销商链接':v==='trial'?'体验领取':v==='admin_adjust'?'后台调整':v==='bound_secondary'?'绑定副机':'后台生成'}
function planName(v){return v==='permanent'?'永久卡':'月卡'}
function issuedDurationName(r){if(r.plan==='permanent')return '永久';var ms=Number(r.expire||0)-Number(r.issuedAt||0);if(!isFinite(ms)||ms<=0)return '-';var minutes=Math.round(ms/60000);if(minutes<60)return Math.max(1,minutes)+' 分钟';var hours=Math.round(ms/3600000);if(hours<24)return Math.max(1,hours)+' 小时';var days=Math.round(ms/86400000);return Math.max(1,days)+' 天'}
function statusName(v){return v==='active'?'正常':'已过期'}
function trialStatusName(v){return v==='blacklisted'?'拉黑':(v==='active'?'正常':'已过期')}
function durationName(a){if(a.plan==='permanent')return '永久';var ms=Number(a.expire||0)-Number(a.activatedAt||0);var days=Math.max(1,Math.round(ms/86400000));return days+' 天'}
function switchAdminTab(tab){document.querySelectorAll('.tab-card').forEach(function(el){el.classList.toggle('active',el.getAttribute('data-tab')===tab)});document.getElementById('tabTools').classList.toggle('active',tab==='tools');document.getElementById('tabData').classList.toggle('active',tab==='data')}
function val(id){var el=document.getElementById(id);return el?String(el.value||''):''}
function cmp(a,b,field,order){var av=a[field],bv=b[field];if(av==null)av='';if(bv==null)bv='';if(typeof av==='string')av=av.toLowerCase();if(typeof bv==='string')bv=bv.toLowerCase();var r=av>bv?1:(av<bv?-1:0);return order==='asc'?r:-r}
function pageSlice(list,page){return list.slice((page-1)*PER_PAGE,page*PER_PAGE)}
function renderPager(id,total,page,onPage){var el=document.getElementById(id);if(!el)return;var pages=Math.max(1,Math.ceil(total/PER_PAGE));var start=total?((page-1)*PER_PAGE+1):0;var end=Math.min(page*PER_PAGE,total);el.innerHTML='<span>显示 '+start+'-'+end+' / 共 '+total+' 条，每页 10 条</span><button class="secondary" '+(page<=1?'disabled':'')+' onclick="'+onPage+'('+(page-1)+')">上一页</button><span>第 '+page+' / '+pages+' 页</span><button class="secondary" '+(page>=pages?'disabled':'')+' onclick="'+onPage+'('+(page+1)+')">下一页</button>'}
function setActivationPage(page){activationPage=Math.max(1,page);renderActivations()}
function setIssuedPage(page){issuedPage=Math.max(1,page);renderIssuedLicenses()}function setTrialPage(page){trialPageNo=Math.max(1,page);renderTrials()}
function resetActivationFilters(){document.getElementById('activationSearch').value='';document.getElementById('activationProduct').value='';document.getElementById('activationStatus').value='';document.getElementById('activationSort').value='activatedAt';document.getElementById('activationOrder').value='desc';setActivationPage(1)}
function resetTrialFilters(){document.getElementById('trialSearch').value='';document.getElementById('trialStatus').value='';document.getElementById('trialSort').value='claimedAt';document.getElementById('trialOrder').value='desc';setTrialPage(1)}
function resetIssuedFilters(){document.getElementById('issuedSearch').value='';document.getElementById('issuedProduct').value='';setIssuedPage(1)}
function clearCustomDays(customId){var el=document.getElementById(customId);if(el)el.value=''}
function setupDayInputs(){[['licenseDays','licenseCustomDays'],['adjustDays','adjustCustomDays'],['issueDays','issueCustomDays']].forEach(function(pair){var sel=document.getElementById(pair[0]);var custom=document.getElementById(pair[1]);if(sel)sel.addEventListener('change',function(){clearCustomDays(pair[1])});if(custom)custom.addEventListener('input',function(){custom.title=custom.value.trim()?'当前按自定义天数生成':'留空则按左侧有效期生成'})})}
function toggleDays(show){document.getElementById('licenseDays').disabled=!show;document.getElementById('licenseCustomDays').disabled=!show;if(!show)clearCustomDays('licenseCustomDays')}
function toggleIssueDays(show){document.getElementById('issueDays').disabled=!show;document.getElementById('issueCustomDays').disabled=!show;if(!show)clearCustomDays('issueCustomDays')}
function readDays(selectId,customId){var custom=document.getElementById(customId);var raw=custom&&custom.value.trim();var v=raw?parseInt(raw,10):parseInt(document.getElementById(selectId).value,10);return Math.max(1,Math.min(v||1,3650))}
function updateLicenseProduct(){var p=document.querySelector('input[name="licProduct"]:checked').value;var el=document.getElementById('accountCount');var show=p!=='lovart-legacy'&&p!=='securelink';el.style.display=show?'block':'none';el.disabled=!show}
async function post(action,body,admin){var headers={'Content-Type':'application/json'};if(admin!==false){var secret=getAdminSecret();if(secret)headers['x-admin-secret']=secret}var res=await fetch('/api?action='+action,{method:'POST',headers:headers,body:JSON.stringify(body||{})});var text=await res.text();var data;try{data=JSON.parse(text)}catch(e){data={success:false,message:text||res.statusText}}if(!data.success&&String(data.message||'').includes('后台密钥')){localStorage.removeItem('lovart_admin_secret');ADMIN_SECRET=''}return data}
async function busy(btn,text,fn){var old=btn.innerText;btn.disabled=true;btn.innerText=text;try{return await fn()}finally{btn.disabled=false;btn.innerText=old}}
async function genLicense(event){var mid=document.getElementById('machineId').value.trim();if(!mid)return alert('请输入机器码');await busy(event.target,'生成中...',async function(){var data=await post('license',{machineId:mid,product:document.querySelector('input[name="licProduct"]:checked').value,type:document.querySelector('input[name="licType"]:checked').value,days:readDays('licenseDays','licenseCustomDays'),accountCount:parseInt(document.getElementById('accountCount').value)});if(!data.success)return alert(data.message||'生成失败');document.getElementById('licenseResult').style.display='block';document.getElementById('licenseCodeDisplay').innerText=data.licenseKey})}
function fillAdjustMachine(machineId,currentCount){switchAdminTab('tools');document.getElementById('adjustMachineId').value=machineId||'';document.getElementById('adjustCurrentCount').value=currentCount==null?'':currentCount;var target=document.getElementById('adjustTargetCount');target.value=currentCount==null?30:currentCount;document.getElementById('adjustResult').style.display='none';var panel=document.getElementById('adjustLicensePanel');if(panel){panel.scrollIntoView({behavior:'smooth',block:'center'});if(panel.animate)panel.animate([{boxShadow:'0 0 0 3px rgba(126,87,255,.8)'},{boxShadow:'0 0 0 0 rgba(126,87,255,0)'}],{duration:1200})}target.focus({preventScroll:true});target.select()}
async function adjustCustomerAccounts(event){var mid=document.getElementById('adjustMachineId').value.trim();var target=parseInt(document.getElementById('adjustTargetCount').value,10);if(!mid)return alert('请输入机器码');if(!Number.isFinite(target)||target<0||target>500)return alert('目标账号数必须是 0-500');var currentRaw=document.getElementById('adjustCurrentCount').value.trim();var current=currentRaw===''?null:parseInt(currentRaw,10);await busy(event.target,'生成中...',async function(){var data=await post('adjust_customer_accounts',{machineId:mid,currentCount:current,targetCount:target,days:readDays('adjustDays','adjustCustomDays')},true);if(!data.success)return alert(data.message||'生成失败');var summary='目标账号数：'+data.accountCount+' 个';if(data.currentCount!=null){summary+='；当前 '+data.currentCount+' 个';if(data.addCount>0)summary+='；预计增加 '+data.addCount+' 个';else if(data.removeCount>0)summary+='；预计删除 '+data.removeCount+' 个';else summary+='；数量不变'}document.getElementById('adjustResult').style.display='block';document.getElementById('adjustSummary').innerText=summary;document.getElementById('adjustLicenseDisplay').innerText=data.licenseKey;loadIssuedLicenses()})}
function fillOpsMachine(machineId){document.getElementById('opsMachineId').value=machineId||'';switchAdminTab('tools');loadClientAccounts()}
function flagName(v){return v==='zero_points'?'0积分':v==='replace_required'?'需替换':v}
function showBuildSha(data){var el=document.getElementById('opsBuildSha');if(el&&data&&data.buildSha)el.textContent=data.buildSha;return data}
setInterval(function(){fetch('/api?action=health').then(function(r){return r.json()}).then(function(data){var el=document.getElementById('opsBuildSha');if(!el){var box=document.getElementById('clientAccountsBox');if(box){el=document.createElement('p');el.id='opsBuildSha';el.className='muted';box.parentNode.insertBefore(el,box)}}if(el&&data&&data.buildSha)el.textContent='资源服务 buildSha：'+data.buildSha}).catch(function(){})},30000)
async function loadClientAccounts(){var mid=document.getElementById('opsMachineId').value.trim();if(!mid)return alert('请输入机器码');var box=document.getElementById('clientAccountsBox');box.innerHTML='<p class="muted">读取中...</p>';var data=await post('list_client_accounts',{machineId:mid},true);if(!data.success)return box.innerHTML='<p class="muted">'+esc(data.message||'读取失败')+'</p>';var s=data.snapshot;if(!s)return box.innerHTML='<p class="muted">暂无该设备上报的账号快照；客户软件在线 30 秒左右会自动上报。</p>';var rows=s.accounts||[];var html='<div class="stats"><div class="stat"><b>'+rows.length+'</b>本机账号</div><div class="stat"><b>'+new Date(s.updatedAt).toLocaleString()+'</b>最近上报</div></div>';if(!rows.length){box.innerHTML=html+'<p class="muted">该设备暂无账号。</p>';return}html+='<div class="table-wrap"><table><thead><tr><th>选择</th><th>邮箱</th><th>来源</th><th>积分</th><th>状态</th></tr></thead><tbody>';rows.forEach(function(a){var flags=(a.flags||[]).map(flagName).join('，');var points=a.points&&a.points.status==='ready'?(a.points.firstPoints+'/'+a.points.currentPoints):'-';var checked=(a.flags||[]).length?' checked':'';html+='<tr><td><input type="checkbox" class="ops-account" value="'+esc(a.email)+'"'+checked+'></td><td>'+esc(a.email)+'</td><td>'+esc(a.source||'-')+'</td><td>'+esc(points)+'</td><td>'+(flags?'<span class="badge badge-risk">'+esc(flags)+'</span>':'<span class="badge badge-muted">正常</span>')+'</td></tr>'});html+='</tbody></table></div><button class="secondary" style="margin-top:10px" onclick="useCheckedOpsEmails()">把选中邮箱填入删除列表</button>';box.innerHTML=html}
function useCheckedOpsEmails(){var emails=Array.from(document.querySelectorAll('.ops-account:checked')).map(function(i){return i.value});document.getElementById('opsEmails').value=emails.join('\\n');document.getElementById('opsDeleteCount').value=emails.length||document.getElementById('opsDeleteCount').value}
async function loadAccountCommands(){var mid=document.getElementById('opsMachineId').value.trim();var box=document.getElementById('accountCommandsBox');if(!box||!mid)return;var data=await post('list_account_commands',{machineId:mid},true);if(!data.success)return box.innerHTML='<p class="muted">'+esc(data.message||'命令查询失败')+'</p>';var rows=data.list||[];box.innerHTML='<h3>命令状态</h3>'+(rows.length?'<div class="table-wrap"><table><thead><tr><th>命令</th><th>状态</th><th>尝试</th><th>结果</th></tr></thead><tbody>'+rows.map(function(r){var x=r.result||{};return '<tr><td>'+esc(r.commandId)+'</td><td>'+esc(r.status)+'</td><td>'+esc(r.attemptCount)+'</td><td>删除 '+esc(x.removed||0)+'，补充 '+esc(x.added||0)+(x.missingEmails&&x.missingEmails.length?'，缺失：'+esc(x.missingEmails.join('、')):'')+(r.lastError?'，失败：'+esc(r.lastError):'')+'</td></tr>'}).join('')+'</tbody></table></div>':'<p class="muted">暂无命令。</p>')}
async function sendAccountMaintenance(event){var mid=document.getElementById('opsMachineId').value.trim();if(!mid)return alert('请输入机器码');var del=parseInt(document.getElementById('opsDeleteCount').value,10)||0;var rep=parseInt(document.getElementById('opsReplenishCount').value,10)||0;var emails=document.getElementById('opsEmails').value.trim();if(!del&&!rep&&!emails)return alert('请填写删除数量、补充数量或指定邮箱');if(!confirm('确定下发账号运维命令吗？\\n\\n删除数量：'+del+'\\n补充数量：'+rep+'\\n指定邮箱：'+(emails?emails.split(/\\r?\\n|,/).filter(Boolean).length:'未指定，按优先级删除')))return;await busy(event.target,'下发中...',async function(){var data=await post('remote_account_maintenance',{machineId:mid,deleteCount:del,replenishCount:rep,emails:emails},true);alert((data.message||'已下发')+(data.commandId?'\\n命令：'+data.commandId:''));loadClientAccounts();loadAccountCommands()})}
async function loadAccountPools(){var box=document.getElementById('accountPoolsBox');if(!box)return;box.innerHTML='<p class="muted">读取中...</p>';var data=await post('list_account_pools',{},true);if(!data.success)return box.innerHTML='<p class="muted">'+esc(data.message||'读取失败')+'</p>';var rows=data.list||[];if(!rows.length)return box.innerHTML='<p class="muted">暂无机器码绑定。</p>';var html='<div class="table-wrap"><table><thead><tr><th>绑定机器码</th><th>更新时间</th><th>操作</th></tr></thead><tbody>';rows.forEach(function(p){html+='<tr><td>'+esc((p.machineIds||[]).join('\\n')).replace(/\\n/g,'<br>')+'</td><td>'+new Date(p.updatedAt||p.createdAt||Date.now()).toLocaleString()+'</td><td><button class="secondary" onclick="fillAccountPool('+jsq((p.machineIds||[]).join('\\n'))+')">填入</button> <button class="danger" onclick="deleteAccountPool('+jsq(p.poolId)+')">删除</button></td></tr>'});box.innerHTML=html+'</tbody></table></div>'}
function fillAccountPool(machineIds){var ids=String(machineIds||'').split(/\\r?\\n|,|;|\\s+/).filter(Boolean);document.getElementById('bindPrimaryMachineId').value=ids[0]||'';document.getElementById('bindSecondaryMachineId').value=ids[1]||'';switchAdminTab('tools');document.getElementById('bindSecondaryMachineId').focus()}
async function genBoundSecondaryLicense(event){var primary=document.getElementById('bindPrimaryMachineId').value.trim();var secondary=document.getElementById('bindSecondaryMachineId').value.trim();if(!primary||!secondary)return alert('请填写第一台和第二台电脑机器码');if(primary===secondary)return alert('两台电脑机器码不能相同');await busy(event.target,'生成中...',async function(){var data=await post('bind_secondary_license',{primaryMachineId:primary,secondaryMachineId:secondary},true);if(!data.success)return alert(data.message||'生成失败');document.getElementById('bindResult').style.display='block';document.getElementById('bindSummary').innerText='B 卡密账号数：0；到期时间：'+(data.plan==='permanent'?'永久':new Date(data.expireTime).toLocaleString())+'；客户需要从 A 导出账号后在 B 导入';document.getElementById('bindLicenseDisplay').innerText=data.licenseKey;loadAccountPools();loadIssuedLicenses()})}
async function deleteAccountPool(poolId){if(!confirm('确定删除这个机器码绑定吗？删除后这些电脑不再共用自动发放账号。'))return;var data=await post('delete_account_pool',{poolId:poolId},true);alert(data.message||'已删除');loadAccountPools()}
async function genAccounts(event){var domains=Array.from(document.querySelectorAll('#domainGroup input:checked')).map(function(i){return i.value}).join(',');if(!domains)return alert('请至少选择一个域名');await busy(event.target,'生成中...',async function(){var data=await post('accounts',{domains:domains,count:parseInt(document.getElementById('count').value)});if(!data.success)return alert(data.message||'生成失败');document.getElementById('accountResult').style.display='block';document.getElementById('outputCode').value=data.code})}
async function genCloudflareAccounts(event){await busy(event.target,'生成中...',async function(){var data=await post('cloudflare_accounts',{count:parseInt(document.getElementById('cloudflareCount').value)},true);if(!data.success)return alert(data.message||'生成失败');document.getElementById('cloudflareAccountResult').style.display='block';document.getElementById('cloudflareOutputCode').value=data.code})}
async function genIssueLink(event){await busy(event.target,'生成中...',async function(){var data=await post('create_issue_token',{plan:document.querySelector('input[name="issuePlan"]:checked').value,days:readDays('issueDays','issueCustomDays'),accountCount:parseInt(document.getElementById('issueCount').value)},true);if(!data.success)return alert(data.message||'生成失败');document.getElementById('issueResult').style.display='block';document.getElementById('issueLinkDisplay').value=data.link;document.getElementById('issueTokenDisplay').innerText=data.token})}
function copyTrialLink(){navigator.clipboard.writeText(location.origin+'/api?action=trial').then(function(){alert('体验链接已复制')})}
var refreshAccountsEnabled=true;
function renderRefreshSwitch(enabled){refreshAccountsEnabled=!!enabled;var text=document.getElementById('refreshSwitchText');var btn=document.getElementById('refreshSwitchBtn');var card=document.getElementById('refreshSwitchCard');if(text)text.innerText=enabled?'开启':'关闭';if(btn){btn.innerText=enabled?'关闭替换账号':'开启替换账号';btn.className=enabled?'danger':'ok'}if(card){card.className=enabled?'stat':'stat risk'}}
var trialActivationAccountsEnabled=false;
function renderTrialActivationSwitch(enabled){trialActivationAccountsEnabled=!!enabled;var text=document.getElementById('trialActivationSwitchText');var btn=document.getElementById('trialActivationSwitchBtn');var card=document.getElementById('trialActivationSwitchCard');if(text)text.innerText=enabled?'开启':'关闭';if(btn){btn.innerText=enabled?'关闭体验首激发号':'开启体验首激发号';btn.className=enabled?'danger':'ok'}if(card){card.className=enabled?'stat':'stat risk'}}
async function loadAdminSettings(){var data=await post('admin_settings',{},true);if(!data.success)return;var s=data.settings||{};renderRefreshSwitch(s.refreshAccountsEnabled);renderTrialActivationSwitch(s.trialActivationAccountsEnabled)}
async function toggleRefreshSwitch(event){var next=!refreshAccountsEnabled;var msg=next?'确定开启替换失效账号吗？':'确定关闭替换失效账号吗？关闭后本地软件将无法替换失效账号。';if(!confirm(msg))return;await busy(event.target,'保存中...',async function(){var data=await post('update_admin_settings',{refreshAccountsEnabled:next},true);if(!data.success)return alert(data.message||'保存失败');renderRefreshSwitch(data.settings&&data.settings.refreshAccountsEnabled);alert(data.message||'设置已保存')})}
async function toggleTrialActivationSwitch(event){var next=!trialActivationAccountsEnabled;var msg=next?'确定开启体验卡首激发号吗？开启后体验卡首次激活会云端下发 10 个账号。':'确定关闭体验卡首激发号吗？关闭后体验卡激活不会自动下发账号。';if(!confirm(msg))return;await busy(event.target,'保存中...',async function(){var data=await post('update_admin_settings',{trialActivationAccountsEnabled:next},true);if(!data.success)return alert(data.message||'保存失败');renderTrialActivationSwitch(data.settings&&data.settings.trialActivationAccountsEnabled);alert(data.message||'设置已保存')})}
function fmtBytes(bytes){var n=Number(bytes)||0;if(n>=1073741824)return (n/1073741824).toFixed(2)+' GB';if(n>=1048576)return (n/1048576).toFixed(2)+' MB';if(n>=1024)return (n/1024).toFixed(1)+' KB';return n+' B'}
async function loadStorageStats(){var box=document.getElementById('storageStatsBox');if(!box)return;box.innerHTML='<p class="muted">读取中...</p>';var data=await post('storage_stats',{},true);if(!data.success)return box.innerHTML='<p class="muted">'+esc(data.message||'读取失败')+'</p>';var s=data.stats||{};document.getElementById('storageUsedMb').innerText=s.totalMb==null?'-':s.totalMb;document.getElementById('storageMode').innerText=s.database?'数据库':'临时文件';document.getElementById('storageTableCount').innerText=(s.tables||[]).length;document.getElementById('storageCheckedAt').innerText=s.checkedAt?new Date(s.checkedAt).toLocaleTimeString():'-';var rows=s.tables||[];if(!rows.length){box.innerHTML='<p class="muted">暂无空间明细。</p>';return}var html='<div class="table-wrap"><table><thead><tr><th>名称</th><th>占用</th><th>记录数</th></tr></thead><tbody>';rows.forEach(function(t){html+='<tr><td>'+esc(t.name)+'</td><td>'+esc(fmtBytes(t.bytes))+'</td><td>'+esc(t.rows==null?'-':t.rows)+'</td></tr>'});box.innerHTML=html+'</tbody></table></div>'}
async function loadStats(){var data=await post('activation_stats',{},true);if(!data.success)return;document.getElementById('statTotal').innerText=data.stats.total;document.getElementById('statMonthly').innerText=data.stats.activeMonthly;document.getElementById('statPerm').innerText=data.stats.activePermanent;document.getElementById('statExpired').innerText=data.stats.expired;if(document.getElementById('statRisk'))document.getElementById('statRisk').innerText=data.stats.risk||0}
async function loadIssuedLicenses(){var data=await post('list_issued_licenses',{},true);var el=document.getElementById('issuedTable');if(!data.success)return el.innerHTML='<p class="muted" style="padding:12px">'+esc(data.message||'加载失败')+'</p>';issuedRows=data.list||[];document.getElementById('issuedTotal').innerText=issuedRows.length;issuedPage=1;renderIssuedLicenses()}
function renderIssuedLicenses(){var el=document.getElementById('issuedTable');var q=val('issuedSearch').trim().toLowerCase();var p=val('issuedProduct');var rows=issuedRows.filter(function(r){if(p&&r.product!==p)return false;if(!q)return true;return String(r.machineId||'').toLowerCase().includes(q)||sourceName(r.source).toLowerCase().includes(q)||issuedDurationName(r).toLowerCase().includes(q)||String(r.licenseHash||'').toLowerCase().includes(q)||String(r.revokeReason||'').toLowerCase().includes(q)});var pages=Math.max(1,Math.ceil(rows.length/PER_PAGE));if(issuedPage>pages)issuedPage=pages;if(!rows.length){el.innerHTML='<p class=\"muted\" style=\"padding:12px\">暂无匹配的授权发放记录</p>';renderPager('issuedPager',0,1,'setIssuedPage');return}var html='<table><thead><tr><th>发放时间</th><th>机器码</th><th>产品</th><th>来源</th><th>激活时长</th><th>账号数</th><th>到期</th><th>状态</th><th>卡密哈希</th><th>操作</th></tr></thead><tbody>';pageSlice(rows,issuedPage).forEach(function(r){var status=r.revoked?'<span class=\"badge badge-risk\">已撤销</span><div class=\"muted\">'+esc(r.revokeReason||'无原因')+'</div>':'<span class=\"badge badge-ok\">正常</span>';var action=r.revoked?'<button class=\"secondary\" onclick=\"toggleLicenseRevocation('+jsq(r.licenseHash)+',true)\">恢复</button>':'<button class=\"danger\" onclick=\"toggleLicenseRevocation('+jsq(r.licenseHash)+',false)\">撤销</button>';html+='<tr class=\"'+(r.revoked?'risk-row':'')+'\"><td>'+new Date(r.issuedAt).toLocaleString()+'</td><td>'+esc(r.machineId)+'</td><td>'+esc(productName(r.product))+'</td><td>'+esc(sourceName(r.source))+'</td><td>'+esc(issuedDurationName(r))+'</td><td>'+esc(r.accountCount)+'</td><td>'+(r.plan==='permanent'?'永久':new Date(r.expire).toLocaleString())+'</td><td>'+status+'</td><td>'+esc(r.licenseHash||'-')+'</td><td>'+action+'</td></tr>'});el.innerHTML=html+'</tbody></table>';renderPager('issuedPager',rows.length,issuedPage,'setIssuedPage')}
async function toggleLicenseRevocation(hash,isRevoked){if(isRevoked){if(!confirm('确定恢复这张卡密吗？'))return;var restored=await post('restore_license',{licenseHash:hash},true);alert(restored.message||'已完成');if(restored.success)loadIssuedLicenses();return}var reason=prompt('请输入撤销原因（例如：退款、盗用、破解）','疑似盗用');if(reason===null)return;var data=await post('revoke_license',{licenseHash:hash,reason:reason},true);alert(data.message||'已完成');if(data.success)loadIssuedLicenses()}
async function loadActivations(){await loadStats();var data=await post('list_activations',{},true);var el=document.getElementById('activationTable');if(!data.success)return el.innerHTML='<p class="muted" style="padding:12px">'+esc(data.message||'加载失败')+'</p>';activationRows=data.list||[];activationPage=1;renderActivations()}
function renderActivations(){var el=document.getElementById('activationTable');var q=val('activationSearch').trim().toLowerCase();var status=val('activationStatus');var p=val('activationProduct');var sort=val('activationSort')||'activatedAt';var order=val('activationOrder')||'desc';var rows=activationRows.filter(function(a){var risk=a.risk||'';var rowStatus=risk?'risk':a.status;if(p&&a.product!==p)return false;if(status&&rowStatus!==status)return false;if(!q)return true;return String(a.machineId||'').toLowerCase().includes(q)||productName(a.product).toLowerCase().includes(q)||durationName(a).toLowerCase().includes(q)||String(risk).toLowerCase().includes(q)}).sort(function(a,b){return cmp(a,b,sort,order)});var pages=Math.max(1,Math.ceil(rows.length/PER_PAGE));if(activationPage>pages)activationPage=pages;if(!rows.length){el.innerHTML='<p class="muted" style="padding:12px">暂无匹配的真实激活记录</p>';renderPager('activationPager',0,1,'setActivationPage');return}var html='<table><thead><tr><th>最近激活</th><th>最后在线</th><th>机器码</th><th>产品</th><th>时长</th><th>套餐账号</th><th>本地账号</th><th>今日替换数</th><th>到期</th><th>风险</th><th>状态</th><th>操作</th></tr></thead><tbody>';pageSlice(rows,activationPage).forEach(function(a){var risk=a.risk||'';var statusHtml=risk?'<span class="badge badge-risk">重点检查</span>':'<span class="badge badge-ok">'+esc(statusName(a.status))+'</span>';html+='<tr class="'+(risk?'risk-row':'')+'"><td>'+new Date(a.activatedAt).toLocaleString()+'</td><td>'+(a.lastSeenAt?new Date(a.lastSeenAt).toLocaleString():'-')+'</td><td>'+esc(a.machineId)+'</td><td>'+esc(productName(a.product))+'</td><td>'+esc(durationName(a))+'</td><td>'+esc(a.accountCount)+'</td><td>'+esc(a.reportedAccountCount==null?'-':a.reportedAccountCount)+'</td><td>'+esc(a.todayRefreshCount||0)+'</td><td>'+(a.plan==='permanent'?'永久':new Date(a.expire).toLocaleString())+'</td><td>'+(risk?'<span class="badge badge-risk">'+esc(risk)+'</span>':'<span class="badge badge-muted">无</span>')+'</td><td>'+statusHtml+'</td><td><button class="secondary" onclick="fillAdjustMachine('+jsq(a.machineId)+','+Number(a.accountCount||0)+')">调整</button> <button class="secondary" onclick="fillOpsMachine('+jsq(a.machineId)+')">运维</button></td></tr>'});el.innerHTML=html+'</tbody></table>';renderPager('activationPager',rows.length,activationPage,'setActivationPage')}
async function loadTrialStats(){var data=await post('trial_stats',{},true);if(!data.success)return;document.getElementById('trialTotal').innerText=data.stats.total||0;document.getElementById('trialToday').innerText=data.stats.today||0;document.getElementById('trialActive').innerText=data.stats.active||0;document.getElementById('trialExpired').innerText=data.stats.expired||0;document.getElementById('trialBlacklisted').innerText=data.stats.blacklisted||0;document.getElementById('trialConverted').innerText=data.stats.converted||0}
async function loadTrials(){await loadTrialStats();var data=await post('list_trial_claims',{},true);var el=document.getElementById('trialTable');if(!data.success)return el.innerHTML='<p class="muted" style="padding:12px">'+esc(data.message||'加载失败')+'</p>';trialRows=data.list||[];trialPageNo=1;renderTrials()}
function renderTrials(){var el=document.getElementById('trialTable');var q=val('trialSearch').trim().toLowerCase();var status=val('trialStatus');var sort=val('trialSort')||'claimedAt';var order=val('trialOrder')||'desc';var rows=trialRows.filter(function(t){if(status==='converted'&&!t.converted)return false;if(status==='notConverted'&&t.converted)return false;if(status&&status!=='converted'&&status!=='notConverted'&&t.status!==status)return false;if(!q)return true;return String(t.machineId||'').toLowerCase().includes(q)||String(t.blacklistReason||'').toLowerCase().includes(q)}).sort(function(a,b){return cmp(a,b,sort,order)});var pages=Math.max(1,Math.ceil(rows.length/PER_PAGE));if(trialPageNo>pages)trialPageNo=pages;if(!rows.length){el.innerHTML='<p class="muted" style="padding:12px">暂无匹配的体验领取记录</p>';renderPager('trialPager',0,1,'setTrialPage');return}var html='<table><thead><tr><th>领取时间</th><th>机器码</th><th>账号数</th><th>到期时间</th><th>状态</th><th>是否转正式卡</th><th>拉黑原因</th></tr></thead><tbody>';pageSlice(rows,trialPageNo).forEach(function(t){var isBad=t.status==='blacklisted';var badge=isBad?'badge-risk':(t.status==='active'?'badge-ok':'badge-muted');html+='<tr class="'+(isBad?'risk-row':'')+'"><td>'+new Date(t.claimedAt).toLocaleString()+'</td><td>'+esc(t.machineId)+'</td><td>'+esc(t.accountCount)+'</td><td>'+new Date(t.expire).toLocaleString()+'</td><td><span class="badge '+badge+'">'+esc(trialStatusName(t.status))+'</span></td><td>'+(t.converted?'<span class="badge badge-ok">已转正式</span>':'<span class="badge badge-muted">否</span>')+'</td><td>'+esc(t.blacklistReason||'-')+'</td></tr>'});el.innerHTML=html+'</tbody></table>';renderPager('trialPager',rows.length,trialPageNo,'setTrialPage')}
async function loadBlacklist(){var data=await post('list_blacklist',{},true);var el=document.getElementById('blacklistTable');if(!data.success)return el.innerText=data.message||'加载失败';if(!data.list.length)return el.innerHTML='<p class="muted">暂无黑名单</p>';var html='<div class="table-wrap"><table><thead><tr><th>机器码</th><th>原因</th><th>日期</th><th>操作</th></tr></thead><tbody>';data.list.forEach(function(b){html+='<tr><td>'+esc(b.machineId)+'</td><td>'+esc(b.reason||'-')+'</td><td>'+new Date(b.createdAt).toLocaleString()+'</td><td><button class="secondary" onclick="removeFromBlacklist(&quot;'+esc(b.machineId)+'&quot;)">移除</button></td></tr>'});el.innerHTML=html+'</tbody></table></div>'}
async function addToBlacklist(event){var mid=document.getElementById('blMachineId').value.trim();if(!mid)return alert('请输入机器码');await busy(event.target,'处理中...',async function(){var data=await post('add_blacklist',{machineId:mid,reason:document.getElementById('blReason').value.trim()},true);alert(data.message||'已完成');loadBlacklist()})}
async function removeFromBlacklist(mid){if(!confirm('确定移除 '+mid+' 吗？'))return;var data=await post('remove_blacklist',{machineId:mid},true);alert(data.message||'已完成');loadBlacklist()}
function copyText(id){navigator.clipboard.writeText(document.getElementById(id).innerText).then(function(){alert('已复制')})}
function copyInput(id){var el=document.getElementById(id);el.select();document.execCommand('copy');alert('已复制')}
window.onload=function(){setupDayInputs();updateLicenseProduct();loadAdminSettings();loadStorageStats();loadIssuedLicenses();loadActivations();loadTrials();loadBlacklist();loadAccountPools()}
</script></body></html>`;
}

// The Render auth routes share the same signed-card policy as the resource
// routes. Exporting the verifier keeps signature, machine, expiry, blacklist,
// and revocation checks in one place.
module.exports.authorizeCloudLicense = authorizeCloudLicense;
