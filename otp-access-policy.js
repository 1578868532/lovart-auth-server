const crypto = require('crypto');

function createOtpAccessVerifier(options = {}) {
    const baseUrl = String(options.baseUrl || '').replace(/\/+$/, '');
    const fetchImpl = options.fetchImpl || global.fetch;
    const now = options.now || Date.now;
    const cacheTtlMs = Math.max(0, Number(options.cacheTtlMs) || 0);
    const timeoutMs = Math.max(1000, Number(options.timeoutMs) || 8000);
    const cache = new Map();

    return async function verifyOtpAccess(auth, targetEmail) {
        // Resource-issued LV3 cards must be rechecked on every OTP access path,
        // including sessions created through /api/activate. This prevents an
        // already-issued session from bypassing later expiry, revocation or a
        // machine blacklist. Only auth-server-native legacy sessions retain the
        // historical database-only path.
        const isLocalCard = auth && auth.licenseMode === 'local-lv2';
        const isResourceSession = auth && auth.license && auth.license.source === 'resource-card';
        if (!isLocalCard && !isResourceSession) return { allowed: true, legacySession: true };
        const email = String(targetEmail || '').trim().toLowerCase();
        const licenseKey = String(auth.licenseKey || (auth.license && auth.license.licenseKey) || (auth.session && auth.session.licenseKey) || '').trim();
        const machineId = String(auth.machineId || '').trim();
        if (!baseUrl || typeof fetchImpl !== 'function') return { allowed: false, error: 'otp_access_service_unavailable' };
        if (!email || !licenseKey || !machineId) return { allowed: false, error: 'otp_access_invalid_request' };

        const licenseHash = crypto.createHash('sha256').update(licenseKey).digest('hex').slice(0, 16);
        const cacheKey = `${licenseHash}:${machineId}:${email}`;
        const cached = cache.get(cacheKey);
        if (cached && cached.expiresAt > now()) return cached.result;

        let result;
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), timeoutMs);
            let response;
            try {
                response = await fetchImpl(baseUrl + '/api?action=otp_access_check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ licenseKey, machineId, targetEmail: email }),
                    signal: controller.signal
                });
            } finally {
                clearTimeout(timeout);
            }
            const data = await response.json().catch(() => ({}));
            result = response.ok && data.success === true && data.allowed === true
                ? { allowed: true }
                : { allowed: false, error: String(data.message || 'otp_access_denied') };
        } catch (error) {
            result = { allowed: false, error: 'otp_access_service_unavailable' };
        }

        if (cacheTtlMs > 0) cache.set(cacheKey, { result, expiresAt: now() + cacheTtlMs });
        if (cache.size > 1000) {
            for (const [key, value] of cache) if (value.expiresAt <= now()) cache.delete(key);
        }
        return result;
    };
}

module.exports = { createOtpAccessVerifier };
