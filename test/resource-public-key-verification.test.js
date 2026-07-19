const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
process.env.LOVART_LICENSE_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' });
process.env.LOVART_LICENSE_PRIVATE_KEY = 'invalid-signing-key';
delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;
delete process.env.CHANNEL_DATABASE_URL;
delete process.env.CHANNEL_POSTGRES_URL;

const { app } = require('../server');

async function withServer(run) {
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

function makeLicense(machineId) {
  const payload = Buffer.from(JSON.stringify({
    machineId,
    plan: 'monthly',
    expire: Date.now() + 86400000,
    accountCount: 30
  }), 'utf8');
  const payloadB64 = payload.toString('base64url');
  const signature = crypto.sign(null, payload, privateKey).toString('base64url');
  return `LV3.${payloadB64}.${signature}`;
}

test('resource OTP access verifies existing cards with the public key when the signing private key is invalid', async () => {
  await withServer(async baseUrl => {
    const machineId = `test-${crypto.randomBytes(8).toString('hex')}`;
    const response = await fetch(`${baseUrl}/api?action=otp_access_check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: makeLicense(machineId),
        machineId,
        targetEmail: 'account@example.com'
      })
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, allowed: true });
  });
});
