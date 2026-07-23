const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
}

function close(server) {
  return new Promise(resolve => server.close(resolve));
}

async function post(baseUrl, route, body, headers = {}) {
  const response = await fetch(`${baseUrl}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
  return { response, data: await response.json() };
}

test('legacy OTP accepts new auth first and falls back to the legacy database', async () => {
  const verifyCalls = [];
  const newAuthServer = http.createServer((req, res) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      const body = JSON.parse(raw || '{}');
      verifyCalls.push({ sessionToken: body.sessionToken, machineId: body.machineId });
      const accepted = body.sessionToken === 'new-session-token' && body.machineId === 'machine-new';
      res.writeHead(accepted ? 200 : 401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(accepted ? { success: true, expire: Date.now() + 60000 } : { success: false }));
    });
  });
  await listen(newAuthServer);

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lovart-otp-dual-auth-'));
  process.env.DATA_DIR = dataDir;
  process.env.ADMIN_SECRET = 'test-admin-secret';
  process.env.LOVART_NEW_AUTH_SERVER_URL = `http://127.0.0.1:${newAuthServer.address().port}`;
  process.env.OTP_AUTH_CACHE_TTL_MS = '60000';
  delete process.env.NODE_ENV;
  delete process.env.DATABASE_URL;
  delete process.env.POSTGRES_URL;
  delete process.env.CHANNEL_DATABASE_URL;
  delete process.env.CHANNEL_POSTGRES_URL;
  delete process.env.LICENSE_PRIVATE_KEY;

  const { app } = require('../server');
  const otpServer = http.createServer(app);
  await listen(otpServer);
  const baseUrl = `http://127.0.0.1:${otpServer.address().port}`;

  try {
    const newSession = await post(baseUrl, '/api/otp/mark-baseline', { targetEmail: 'new@example.com' }, {
      Authorization: 'Bearer new-session-token',
      'x-machine-id': 'machine-new'
    });
    assert.equal(newSession.response.status, 200);
    assert.equal(newSession.data.success, true);
    assert.equal(verifyCalls.filter(call => call.sessionToken === 'new-session-token').length, 1);

    const cachedNewSession = await post(baseUrl, '/api/otp/mark-baseline', { targetEmail: 'new@example.com' }, {
      Authorization: 'Bearer new-session-token',
      'x-machine-id': 'machine-new'
    });
    assert.equal(cachedNewSession.response.status, 200);
    assert.equal(verifyCalls.filter(call => call.sessionToken === 'new-session-token').length, 1);

    const created = await post(baseUrl, '/api/admin/create-license', {
      days: 30,
      maxSlots: 1,
      maxAccounts: 1,
      plan: 'monthly'
    }, { 'x-admin-secret': 'test-admin-secret' });
    assert.equal(created.response.status, 200);

    const activated = await post(baseUrl, '/api/activate', {
      licenseKey: created.data.license.licenseKey,
      machineId: 'machine-legacy'
    });
    assert.equal(activated.response.status, 200);

    const legacySession = await post(baseUrl, '/api/otp/mark-baseline', { targetEmail: 'legacy@example.com' }, {
      Authorization: `Bearer ${activated.data.sessionToken}`,
      'x-machine-id': 'machine-legacy'
    });
    assert.equal(legacySession.response.status, 200);
    assert.equal(legacySession.data.success, true);
    assert.ok(verifyCalls.some(call => call.sessionToken === activated.data.sessionToken));
  } finally {
    await close(otpServer);
    await close(newAuthServer);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
