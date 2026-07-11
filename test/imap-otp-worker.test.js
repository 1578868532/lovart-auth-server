const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createImapOtpWorker } = require('../lib/imap-otp-worker');

function createClient(overrides = {}) {
  return Object.assign(new EventEmitter(), {
    mailbox: { uidValidity: 9n, uidNext: 44 },
    connect: async () => {},
    mailboxOpen: async () => {},
    logout: async () => {},
    fetch: async function* () {},
    fetchOne: async () => null,
    ...overrides
  });
}

function createWorker(client, overrides = {}) {
  return createImapOtpWorker({
    createClient: () => client,
    parseMessage: async () => ({
      subject: 'Lovart verification code',
      from: { text: 'Lovart <no-reply@lovart.ai>' },
      to: { text: 'person@example.test' },
      text: 'Your code is 123456',
      date: new Date(0),
      messageId: 'message-1'
    }),
    onCandidate: () => {},
    onError: () => {},
    getMinimumPendingBaseline: () => 43,
    now: () => 1,
    config: {},
    ...overrides
  });
}

test('snapshotBaseline returns uidNext minus one with string UIDVALIDITY', async () => {
  const client = createClient();
  const worker = createWorker(client);

  await worker.start();

  assert.deepEqual(await worker.snapshotBaseline(), { uidValidity: '9', uid: 43 });
  await worker.stop();
});

test('scanPending reads headers by UID then source only for a likely Lovart OTP', async () => {
  const fetches = [];
  const sourceFetches = [];
  const candidates = [];
  const client = createClient({
    fetch: async function* (range, query, options) {
      fetches.push({ range, query, options });
      yield {
        uid: 44,
        envelope: {
          subject: 'Lovart verification code',
          from: [{ address: 'no-reply@lovart.ai' }],
          to: [{ address: 'person@example.test' }]
        },
        internalDate: new Date(0)
      };
      yield {
        uid: 45,
        envelope: {
          subject: 'A different message',
          from: [{ address: 'news@example.test' }],
          to: [{ address: 'person@example.test' }]
        },
        internalDate: new Date(1)
      };
    },
    fetchOne: async (uid, query, options) => {
      sourceFetches.push({ uid, query, options });
      return { uid, source: Buffer.from('raw-message') };
    }
  });
  const worker = createWorker(client, { onCandidate: candidate => candidates.push(candidate) });

  await worker.start();
  await worker.scanPending(43);

  assert.deepEqual(fetches, [{
    range: '44:*',
    query: { envelope: true, internalDate: true },
    options: { uid: true }
  }]);
  assert.deepEqual(sourceFetches, [{ uid: 44, query: { source: true }, options: { uid: true } }]);
  assert.deepEqual(candidates, [{
    uidValidity: '9',
    uid: 44,
    to: 'person@example.test',
    text: 'Your code is 123456',
    code: '123456',
    receivedAt: new Date(0),
    messageId: 'message-1'
  }]);
  await worker.stop();
});

test('multiple exists events coalesce into one serialized follow-up scan', async () => {
  let releaseFirstFetch;
  let fetchCalls = 0;
  let activeFetches = 0;
  let maxActiveFetches = 0;
  const client = createClient({
    fetch: async function* () {
      fetchCalls += 1;
      activeFetches += 1;
      maxActiveFetches = Math.max(maxActiveFetches, activeFetches);
      if (fetchCalls === 1) {
        await new Promise(resolve => { releaseFirstFetch = resolve; });
      }
      activeFetches -= 1;
    }
  });
  const worker = createWorker(client);

  await worker.start();
  client.emit('exists', 44);
  client.emit('exists', 45);
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(fetchCalls, 1);
  releaseFirstFetch();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(fetchCalls, 2);
  assert.equal(maxActiveFetches, 1);
  await worker.stop();
});

test('exists during an active scan queues one follow-up range for newly arrived UID', async () => {
  let releaseFirstRange;
  let firstRangeFinished = false;
  const fetches = [];
  const sourceFetches = [];
  const candidates = [];
  const client = createClient({
    fetch: async function* (range, query, options) {
      fetches.push({ range, query, options });
      if (range === '44:*') {
        yield {
          uid: 44,
          envelope: {
            subject: 'Lovart verification code',
            from: [{ address: 'no-reply@lovart.ai' }],
            to: [{ address: 'person@example.test' }]
          },
          internalDate: new Date(44)
        };
        await new Promise(resolve => { releaseFirstRange = resolve; });
        firstRangeFinished = true;
        return;
      }
      if (range === '45:*') {
        yield {
          uid: 45,
          envelope: {
            subject: 'Lovart verification code',
            from: [{ address: 'no-reply@lovart.ai' }],
            to: [{ address: 'person@example.test' }]
          },
          internalDate: new Date(45)
        };
      }
    },
    fetchOne: async (uid, query, options) => {
      sourceFetches.push({ uid, query, options });
      return { uid, source: Buffer.from(`OTP ${uid}`) };
    }
  });
  const worker = createWorker(client, {
    parseMessage: async source => ({
      to: { text: 'person@example.test' },
      text: `Your verification code is ${source.toString().slice(4)}0000`,
      messageId: `message-${source.toString().slice(4)}`
    }),
    onCandidate: candidate => candidates.push(candidate),
    getMinimumPendingBaseline: () => {
      assert.equal(firstRangeFinished, true, 'follow-up baseline is read only after the active scan completes');
      return 43;
    }
  });

  await worker.start();
  const firstScan = worker.scanPending(43);
  await new Promise(resolve => setImmediate(resolve));
  client.emit('exists', 45);
  releaseFirstRange();
  await firstScan;
  await new Promise(resolve => setImmediate(resolve));

  assert.deepEqual(fetches.map(fetch => fetch.range), ['44:*', '45:*']);
  assert.deepEqual(sourceFetches.map(fetch => fetch.uid), [44, 45]);
  assert.deepEqual(candidates.map(candidate => candidate.uid), [44, 45]);
  await worker.stop();
});

test('source fetch failure leaves its UID pending for a later scan', async () => {
  const fetchRanges = [];
  let sourceAttempts = 0;
  const client = createClient({
    fetch: async function* (range) {
      fetchRanges.push(range);
      yield {
        uid: 44,
        envelope: {
          subject: 'Lovart verification code',
          from: [{ address: 'no-reply@lovart.ai' }],
          to: [{ address: 'person@example.test' }]
        },
        internalDate: new Date(0)
      };
    },
    fetchOne: async () => {
      sourceAttempts += 1;
      if (sourceAttempts === 1) throw new Error('source unavailable');
      return { source: Buffer.from('raw-message') };
    }
  });
  const worker = createWorker(client);

  await worker.start();
  await assert.rejects(worker.scanPending(43), /source unavailable/);
  assert.equal(worker.getStatus().lastProcessedUid, 43);
  await worker.scanPending(43);

  assert.deepEqual(fetchRanges, ['44:*', '44:*']);
  await worker.stop();
});

test('classifies proxy, authentication, and generic IMAP failures', async () => {
  const cases = [
    ['proxy handshake failed', 'imap_proxy_failed'],
    ['AUTHENTICATION failed', 'imap_auth_failed'],
    ['socket timeout', 'imap_network_failed']
  ];

  for (const [message, code] of cases) {
    const errors = [];
    const client = createClient();
    const worker = createWorker(client, {
      onError: error => errors.push(error),
      config: { setTimeout: () => 1, clearTimeout: () => {} }
    });
    await worker.start();

    client.emit('error', new Error(message));

    assert.deepEqual(errors, [{ code, at: 1 }]);
    assert.equal(worker.getStatus().lastErrorCode, code);
    await worker.stop();
  }
});

test('stop logs out once and cancels a scheduled reconnect', async () => {
  const clients = [];
  const scheduled = [];
  let logoutCalls = 0;
  const client = createClient({ logout: async () => { logoutCalls += 1; } });
  const worker = createImapOtpWorker({
    createClient: () => {
      clients.push(client);
      return client;
    },
    parseMessage: async () => ({}),
    onCandidate: () => {},
    onError: () => {},
    getMinimumPendingBaseline: () => 43,
    now: () => 1,
    config: {
      setTimeout: callback => {
        scheduled.push(callback);
        return callback;
      },
      clearTimeout: handle => {
        const index = scheduled.indexOf(handle);
        if (index >= 0) scheduled.splice(index, 1);
      }
    }
  });

  await worker.start();
  client.emit('close');
  assert.equal(scheduled.length, 1);

  await worker.stop();
  for (const reconnect of scheduled) await reconnect();

  assert.equal(logoutCalls, 1);
  assert.equal(clients.length, 1);
});

test('reconnect disposes the failed client once and continues with a new client', async () => {
  const scheduled = [];
  let firstLogoutCalls = 0;
  let secondFetchCalls = 0;
  const firstClient = createClient({
    logout: async () => {
      firstLogoutCalls += 1;
      throw new Error('logout failed');
    }
  });
  const secondClient = createClient({
    mailbox: { uidValidity: 9n, uidNext: 45 },
    fetch: async function* () {
      secondFetchCalls += 1;
    }
  });
  const clients = [firstClient, secondClient];
  const worker = createImapOtpWorker({
    createClient: () => clients.shift(),
    parseMessage: async () => ({}),
    onCandidate: () => {},
    onError: () => {},
    getMinimumPendingBaseline: () => 43,
    now: () => 1,
    config: {
      setTimeout: callback => {
        scheduled.push(callback);
        return callback;
      },
      clearTimeout: handle => {
        const index = scheduled.indexOf(handle);
        if (index >= 0) scheduled.splice(index, 1);
      }
    }
  });

  await worker.start();
  firstClient.emit('close');
  assert.equal(scheduled.length, 1);
  await scheduled[0]();

  assert.equal(firstLogoutCalls, 1);
  assert.equal(secondFetchCalls, 1);
  assert.equal(worker.getStatus().connected, true);
  await worker.stop();
});
