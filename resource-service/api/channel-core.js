const crypto = require('crypto');

const SESSION_COOKIE = 'lovart_reseller_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function randomId(prefix, bytes = 12) {
  return String(prefix || '') + crypto.randomBytes(bytes).toString('hex').toUpperCase();
}

function hashToken(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function createPasswordRecord(password, saltValue) {
  const value = String(password || '');
  if (value.length < 8) throw new Error('密码至少 8 位');
  const salt = saltValue || crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(value, salt, 64).toString('hex');
  return { passwordHash, passwordSalt: salt };
}

function verifyPassword(password, passwordHash, passwordSalt) {
  try {
    const actual = crypto.scryptSync(String(password || ''), String(passwordSalt || ''), 64);
    const expected = Buffer.from(String(passwordHash || ''), 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch (error) {
    return false;
  }
}

function parseCookies(header) {
  const result = {};
  String(header || '').split(';').forEach(part => {
    const index = part.indexOf('=');
    if (index <= 0) return;
    const key = part.slice(0, index).trim();
    const raw = part.slice(index + 1).trim();
    try { result[key] = decodeURIComponent(raw); } catch (error) { result[key] = raw; }
  });
  return result;
}

function sessionCookie(token, maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000)) {
  return `${SESSION_COOKIE}=${encodeURIComponent(String(token || ''))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, Number(maxAgeSeconds) || 0)}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function normalizeUsername(value) {
  const username = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{2,31}$/.test(username)) {
    throw new Error('账号需为 3-32 位字母、数字、下划线或横线');
  }
  return username;
}

function cents(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.round(number));
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_MS,
  randomId,
  hashToken,
  createPasswordRecord,
  verifyPassword,
  parseCookies,
  sessionCookie,
  clearSessionCookie,
  normalizeUsername,
  cents
};
