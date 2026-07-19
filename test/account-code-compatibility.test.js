const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

process.env.ADMIN_SECRET = 'account-code-test-admin';
process.env.LOVART_DATA_SECURE_KEY = 'intentionally-incompatible-server-key';
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

function decryptWithDesktopKey(code) {
  const key = crypto.scryptSync('LOVART_DATA_SECURE_KEY', 'salt', 32);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
  let plain = decipher.update(code, 'hex', 'utf8');
  plain += decipher.final('utf8');
  return JSON.parse(plain);
}

test('generated account codes always decrypt with the released desktop key', async () => {
  await withServer(async baseUrl => {
    const response = await fetch(`${baseUrl}/api?action=accounts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-secret': 'account-code-test-admin'
      },
      body: JSON.stringify({ count: 2, domains: ['yxd.ccwu.cc'] })
    });

    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.success, true);
    const accounts = decryptWithDesktopKey(result.code);
    assert.equal(accounts.length, 2);
    assert.ok(accounts.every(account => account.email.endsWith('@yxd.ccwu.cc')));
  });
});
