const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const card = 'DOLA-11111111-22222222-33333333-44444444';
process.env.DOLA_LICENSE_HASHES = crypto.createHash('sha256').update(card).digest('hex');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dola-correct-account-'));
process.env.OTP_ONLY_MODE = 'true';
delete process.env.DATABASE_URL;
delete process.env.AUTH_DATABASE_URL;
const { app } = require('../server');

async function withServer(run) {
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { return await run(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise(resolve => server.close(resolve)); }
}
async function post(base, route, body) {
  const response = await fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { response, data: await response.json() };
}

test('OTP-only service permits Dola cloud activation but keeps legacy authorization retired', async () => {
  await withServer(async base => {
    const machineId = 'dola-correct-machine';
    const activated = await post(base, '/api/activate', { licenseKey: card, machineId });
    assert.equal(activated.response.status, 200);
    assert.equal(activated.data.plan, 'dola-permanent');
    const verified = await post(base, '/api/verify', { sessionToken: activated.data.sessionToken, machineId });
    assert.equal(verified.response.status, 200);
    assert.equal(verified.data.plan, 'dola-permanent');
    const legacy = await post(base, '/api/activate', { licenseKey: 'LV-NOT-DOLA', machineId });
    assert.equal(legacy.response.status, 410);
    assert.equal(legacy.data.errorCode, 'LEGACY_AUTH_DISABLED');
  });
});
test.after(() => fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true }));
