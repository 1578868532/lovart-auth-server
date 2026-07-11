const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { createOtpState } = require('../lib/otp-state');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lovart-auth-otp-api-'));
process.env.DATA_DIR = dataDir;

const { createApp } = require('../server');

test.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));

function requestJson(port, method, requestPath, body, headers = {}) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      method,
      path: requestPath,
      headers: {
        ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        ...headers
      }
    }, response => {
      let rawBody = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { rawBody += chunk; });
      response.on('end', () => {
        resolve({
          statusCode: response.statusCode,
          body: rawBody ? JSON.parse(rawBody) : null
        });
      });
    });
    request.on('error', reject);
    request.end(payload);
  });
}

async function createAuthorizedFixture(worker, state = createOtpState({
  now: Date.now,
  sessionTtlMs: 300_000,
  bufferMaxAgeMs: 600_000,
  bufferMaxSize: 20
}), clock = Date.now) {
  const app = createApp({ otpWorker: worker, otpState: state, now: clock });
  const server = app.listen(0);
  await once(server, 'listening');
  const port = server.address().port;
  const machineId = `machine-${crypto.randomUUID()}`;
  const license = await requestJson(port, 'POST', '/api/admin/create-license', { days: 1 }, {
    'x-admin-secret': 'dev-local-only-not-for-production'
  });
  const activation = await requestJson(port, 'POST', '/api/activate', {
    licenseKey: license.body.license.licenseKey,
    machineId
  });

  return {
    port,
    state,
    close: async () => {
      server.close();
      await once(server, 'close');
    },
    otpHeaders: {
      authorization: `Bearer ${activation.body.sessionToken}`,
      'x-machine-id': machineId
    }
  };
}

function otpRequest(targetEmail, requestId) {
  return { targetEmail, requestId };
}

test('returns a stable 502 when baseline snapshot fails', async () => {
  const error = new Error('proxy credentials and URL must remain private');
  error.code = 'imap_proxy_failed';
  const fixture = await createAuthorizedFixture({
    snapshotBaseline: async () => { throw error; },
    getStatus: () => ({ connected: false, lastErrorCode: 'imap_proxy_failed' })
  });

  try {
    const response = await requestJson(fixture.port, 'POST', '/api/otp/mark-baseline', otpRequest('person@example.test'), fixture.otpHeaders);

    assert.equal(response.statusCode, 502);
    assert.deepEqual(response.body, { success: false, status: 'error', error: 'imap_proxy_failed' });
  } finally {
    await fixture.close();
  }
});

test('returns waiting when the worker is healthy and no qualifying message exists', async () => {
  let scanPendingCalls = 0;
  const fixture = await createAuthorizedFixture({
    snapshotBaseline: async () => ({ uidValidity: '7', uid: 100 }),
    scanPending: async () => { scanPendingCalls += 1; },
    getStatus: () => ({ connected: true, lastErrorCode: null })
  });

  try {
    const baseline = await requestJson(fixture.port, 'POST', '/api/otp/mark-baseline', otpRequest('person@example.test'), fixture.otpHeaders);
    const response = await requestJson(fixture.port, 'POST', '/api/otp/get', otpRequest('person@example.test', 'waiting-request'), fixture.otpHeaders);

    assert.deepEqual(baseline.body, { success: true, baselineReady: true });
    assert.deepEqual(response.body, { success: false, status: 'waiting', error: 'waiting' });
    assert.equal(scanPendingCalls, 0);
  } finally {
    await fixture.close();
  }
});

test('only returns a worker failure that occurred after the OTP session began', async () => {
  let clock = 10_000;
  const state = createOtpState({ now: () => clock, sessionTtlMs: 300_000, bufferMaxAgeMs: 600_000, bufferMaxSize: 20 });
  const fixture = await createAuthorizedFixture({
    snapshotBaseline: async () => ({ uidValidity: '7', uid: 100 }),
    getStatus: () => ({ connected: false, lastErrorCode: 'imap_network_failed' })
  }, state, () => clock);

  try {
    await requestJson(fixture.port, 'POST', '/api/otp/mark-baseline', otpRequest('person@example.test'), fixture.otpHeaders);
    state.setWorkerError({ code: 'imap_network_failed', at: clock });
    const waiting = await requestJson(fixture.port, 'POST', '/api/otp/get', otpRequest('person@example.test', 'error-request'), fixture.otpHeaders);
    clock += 1;
    state.setWorkerError({ code: 'imap_proxy_failed', at: clock });
    const failure = await requestJson(fixture.port, 'POST', '/api/otp/get', otpRequest('person@example.test', 'error-request'), fixture.otpHeaders);

    assert.deepEqual(waiting.body, { success: false, status: 'waiting', error: 'waiting' });
    assert.equal(failure.statusCode, 502);
    assert.deepEqual(failure.body, { success: false, status: 'error', error: 'imap_proxy_failed' });
  } finally {
    await fixture.close();
  }
});

test('returns and consumes a UID-qualified OTP message', async () => {
  const fixture = await createAuthorizedFixture({
    snapshotBaseline: async () => ({ uidValidity: '7', uid: 100 }),
    getStatus: () => ({ connected: true, lastErrorCode: null })
  });

  try {
    await requestJson(fixture.port, 'POST', '/api/otp/mark-baseline', otpRequest('person@example.test'), fixture.otpHeaders);
    fixture.state.addMessage({
      uidValidity: '7',
      uid: 101,
      to: 'person@example.test',
      text: 'verification',
      code: '123456',
      receivedAt: Date.now(),
      messageId: 'candidate-101'
    });

    const response = await requestJson(fixture.port, 'POST', '/api/otp/get', otpRequest('person@example.test', 'success-request'), fixture.otpHeaders);

    assert.deepEqual(response.body, { success: true, code: '123456' });
  } finally {
    await fixture.close();
  }
});

test('rejects an unauthenticated OTP status request', async () => {
  const app = createApp({
    otpWorker: {
      getStatus: () => ({
        connected: true,
        lastErrorCode: null,
        mailboxAddress: 'mailbox@example.test',
        rawOtp: '123456'
      })
    },
    otpState: createOtpState({ now: Date.now, sessionTtlMs: 300_000, bufferMaxAgeMs: 600_000, bufferMaxSize: 20 }),
    now: Date.now
  });
  const server = app.listen(0);
  await once(server, 'listening');

  try {
    const response = await requestJson(server.address().port, 'GET', '/api/otp/status');
    const authorized = await requestJson(server.address().port, 'GET', '/api/otp/status', undefined, {
      'x-admin-secret': 'dev-local-only-not-for-production'
    });

    assert.equal(response.statusCode, 403);
    assert.equal(authorized.statusCode, 200);
    assert.equal(JSON.stringify(authorized.body).includes('mailbox@example.test'), false);
    assert.equal(JSON.stringify(authorized.body).includes('123456'), false);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
