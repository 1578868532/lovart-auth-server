const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lovart-auth-activation-'));

process.env.DATA_DIR = dataDir;
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
    durationDays: 1,
    accountCount: 30,
    issuedAt: Date.now()
  }), 'utf8');
  const signature = crypto.sign(null, payload, privateKey).toString('base64url');
  return `LV3.${payload.toString('base64url')}.${signature}`;
}

async function post(baseUrl, route, body) {
  const response = await fetch(`${baseUrl}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { response, data: await response.json() };
}

test('resource-issued LV3 cards create and verify auth sessions', async () => {
  await withServer(async baseUrl => {
    const machineId = `mac-${crypto.randomBytes(8).toString('hex')}`;
    const licenseKey = makeLicense(machineId);

    const activation = await post(baseUrl, '/api/activate', { licenseKey, machineId });
    assert.equal(activation.response.status, 200);
    assert.equal(activation.data.success, true);
    assert.equal(typeof activation.data.sessionToken, 'string');
    assert.equal(activation.data.maxAccounts, 30);
    assert.equal(activation.data.durationDays, 1);

    const verification = await post(baseUrl, '/api/verify', {
      sessionToken: activation.data.sessionToken,
      machineId
    });
    assert.equal(verification.response.status, 200);
    assert.equal(verification.data.success, true);
    assert.equal(verification.data.maxAccounts, 30);

    const wrongMachine = await post(baseUrl, '/api/activate', {
      licenseKey,
      machineId: `${machineId}-other`
    });
    assert.equal(wrongMachine.response.status, 403);
    assert.match(wrongMachine.data.message, /本机|匹配/);
  });
});

test.after(() => {
  fs.rmSync(dataDir, { recursive: true, force: true });
});
