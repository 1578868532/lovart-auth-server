const test = require('node:test');
const assert = require('node:assert/strict');
const { createOtpAccessVerifier } = require('../otp-access-policy');

const auth = {
    licenseMode: 'local-lv2',
    licenseKey: 'LV3.test.signature',
    machineId: 'machine-1'
};

test('current desktop licenses are checked against the card service', async () => {
    let request = null;
    const verify = createOtpAccessVerifier({
        baseUrl: 'https://card.example',
        fetchImpl: async (url, options) => {
            request = { url, options };
            return { ok: true, json: async () => ({ success: true, allowed: true }) };
        },
        timeoutMs: 1000
    });
    const result = await verify(auth, 'User@Example.com');
    assert.equal(result.allowed, true);
    assert.equal(request.url, 'https://card.example/api?action=otp_access_check');
    const body = JSON.parse(request.options.body);
    assert.equal(body.machineId, 'machine-1');
    assert.equal(body.targetEmail, 'user@example.com');
    assert.equal(body.licenseKey, auth.licenseKey);
});

test('card-service revocation or blacklist denial fails closed', async () => {
    const verify = createOtpAccessVerifier({
        baseUrl: 'https://card.example',
        fetchImpl: async () => ({ ok: false, json: async () => ({ success: false, allowed: false, message: '该卡密已被撤销' }) }),
        timeoutMs: 1000
    });
    const result = await verify(auth, 'user@example.com');
    assert.equal(result.allowed, false);
    assert.match(result.error, /撤销/);
});

test('card-service outages fail closed', async () => {
    const verify = createOtpAccessVerifier({
        baseUrl: 'https://card.example',
        fetchImpl: async () => { throw new Error('offline'); },
        timeoutMs: 1000
    });
    const result = await verify(auth, 'user@example.com');
    assert.deepEqual(result, { allowed: false, error: 'otp_access_service_unavailable' });
});

test('legacy server sessions keep their existing database authorization path', async () => {
    let called = false;
    const verify = createOtpAccessVerifier({
        baseUrl: 'https://card.example',
        fetchImpl: async () => { called = true; throw new Error('should not run'); }
    });
    const result = await verify({ licenseMode: 'cloud-session' }, 'user@example.com');
    assert.equal(result.allowed, true);
    assert.equal(result.legacySession, true);
    assert.equal(called, false);
});
