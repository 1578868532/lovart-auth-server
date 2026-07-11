const test = require('node:test');
const assert = require('node:assert/strict');
const { createOtpState } = require('../lib/otp-state');

function createState(overrides = {}) {
  return createOtpState({
    now: () => 10_000,
    sessionTtlMs: 300_000,
    bufferMaxAgeMs: 600_000,
    bufferMaxSize: 10,
    ...overrides
  });
}

test('only consumes a message with the same UIDVALIDITY and a UID after baseline', () => {
  const state = createState();
  state.establishBaseline({ targetEmail: 'a@example.test', machineId: 'm1', uidValidity: 7n, uid: 42 });
  state.addMessage({ uidValidity: 7n, uid: 42, to: 'a@example.test', text: 'code 123456', code: '123456', receivedAt: 10_001, messageId: 'old' });
  state.addMessage({ uidValidity: 8n, uid: 99, to: 'a@example.test', text: 'code 234567', code: '234567', receivedAt: 10_002, messageId: 'other-mailbox' });
  state.addMessage({ uidValidity: 7n, uid: 43, to: 'a@example.test', text: 'code 345678', code: '345678', receivedAt: 10_003, messageId: 'new' });

  assert.equal(state.matchAndConsume({ targetEmail: 'a@example.test', machineId: 'm1' }).code, '345678');
  assert.equal(state.matchAndConsume({ targetEmail: 'a@example.test', machineId: 'm1' }), null);
});

test('legacy request without a UID baseline only consumes mail observed after its session began', () => {
  let clock = 100;
  const state = createState({ now: () => clock });
  const request = { targetEmail: 'a@example.test', machineId: 'm1', requestId: 'legacy-r1' };

  state.addMessage({ uidValidity: 7n, uid: 40, to: 'a@example.test', text: 'old', code: '111111', receivedAt: 1, observedAt: 99, messageId: 'old' });
  const session = state.createOrGetSession(request);
  state.addMessage({ uidValidity: 7n, uid: 41, to: 'a@example.test', text: 'new', code: '222222', receivedAt: 1, observedAt: 100, messageId: 'new' });

  assert.equal(state.matchAndConsume({ ...request, observedAfter: session.createdAt }).code, '222222');
});

test('returns a stable worker failure instead of waiting', () => {
  const state = createState({ now: () => 0 });
  const error = { code: 'imap_proxy_failed', at: 1 };

  state.setWorkerError(error);

  assert.equal(state.getStatus().lastError, error);
});

test('rejects a non-positive message UID', () => {
  const state = createState();

  assert.throws(
    () => state.addMessage({ uidValidity: 7n, uid: 0, to: 'a@example.test', text: '', code: '123456', receivedAt: 10_001, messageId: 'bad' }),
    { name: 'TypeError', message: 'message UID must be a positive integer' }
  );
});

test('removes sessions at the configured TTL using the injected clock', () => {
  let clock = 0;
  const state = createState({ now: () => clock, sessionTtlMs: 1_000 });
  const request = { targetEmail: 'a@example.test', machineId: 'm1', requestId: 'r1' };

  state.createOrGetSession(request);
  clock = 1_000;
  state.expireSessions();

  assert.equal(state.getSession(request), null);
});

test('does not return a session at the TTL boundary without expiring sessions first', () => {
  let clock = 0;
  const state = createState({ now: () => clock, sessionTtlMs: 1_000 });
  const request = { targetEmail: 'a@example.test', machineId: 'm1', requestId: 'r1' };

  state.createOrGetSession(request);
  clock = 1_000;

  assert.equal(state.getSession(request), null);
});

test('reuses a live session and completes it with the client-visible code', () => {
  const state = createState();
  const request = { targetEmail: 'a@example.test', machineId: 'm1', requestId: 'r1' };
  const first = state.createOrGetSession(request);

  const repeated = state.createOrGetSession(request);
  const completed = state.completeSession(repeated, '123456');

  assert.equal(repeated, first);
  assert.equal(completed.status, 'success');
  assert.equal(completed.code, '123456');
  assert.equal(completed.lastErrorCode, null);
});

test('reports pending sessions for the IMAP fallback scanner', () => {
  const state = createState();
  const session = state.createOrGetSession({ targetEmail: 'a@example.test', machineId: 'm1', requestId: 'r1' });
  assert.equal(state.hasPendingSessions(), true);
  state.completeSession(session, '123456');
  assert.equal(state.hasPendingSessions(), false);
});
