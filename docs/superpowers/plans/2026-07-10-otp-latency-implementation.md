# OTP Latency Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return a newly delivered, authorized OTP from the controlled mailbox within 1–3 seconds without accepting any message that existed before the request baseline.

**Architecture:** Replace per-request full-mailbox polling with a server-owned IMAP worker. The worker snapshots `uidValidity` and `uidNext - 1` before a client triggers mail delivery, observes `exists` events while ImapFlow auto-IDLEs, and scans only UIDs above the oldest pending baseline. A pure OTP-state module owns baselines, sessions, matching, redaction and response status so the IMAP adapter and HTTP routes can be tested without a real mailbox.

**Tech Stack:** Node.js CommonJS, `node:test`, Express 5, ImapFlow 1.x, mailparser, Electron 28.

## Global Constraints

- Modify and deploy only `D:\lovat\lovart-auth-server-git`; do not use `D:\lovat\lovart-auth-server` as a source of truth.
- Retain existing license checks and the paths `/api/otp/mark-baseline` and `/api/otp/get`.
- Client-visible OTP responses must never include a code unless it belongs to a successfully authenticated request after its UID baseline.
- Never log raw OTP codes, full mailbox addresses, credentials, session tokens, or proxy URLs.
- Existing desktop versions must continue to accept the existing `success`, `waiting`, `expired`, and `not_found` response fields.
- All new behavior must be covered by `node --test`; a real mailbox is used only for the final deployment smoke test.

---

## File Structure

| File | Responsibility |
|---|---|
| `lib/otp-state.js` | Pure in-memory baseline/session/message state and stable error mapping. |
| `lib/imap-otp-worker.js` | Long-lived ImapFlow connection, UID snapshots, incremental fetches, reconnects, redacted metrics. |
| `test/otp-state.test.js` | Unit tests for UID boundaries, UIDVALIDITY reset, consumption and error mapping. |
| `test/imap-otp-worker.test.js` | Fake-IMAP tests for headers-first reads, `exists` notifications, reconnect and error classification. |
| `server.js` | Construct the state and worker, authorize routes, expose masked status, translate worker outcomes. |
| `test/otp-api.test.js` | HTTP-level tests for baseline failure, waiting, success, expired and status authorization. |
| `desktop/main.js` | Preserve local relay response codes instead of reducing all worker failures to `error`. |
| `desktop/extension/content.js` | Require a successful baseline before clicking the send button and present recoverable status. |
| `DEPLOYMENT.md`, `.env.example` | Document required environment variables, proxy behavior and post-deploy smoke test. |

### Task 1: Create testable UID baseline and OTP state

**Files:**
- Create: `lib/otp-state.js`
- Create: `test/otp-state.test.js`
- Modify: `package.json:7-9`

**Interfaces:**
- Produces `createOtpState({ now, sessionTtlMs, bufferMaxAgeMs, bufferMaxSize })`.
- `createOtpState()` returns `{ establishBaseline, createOrGetSession, getSession, completeSession, addMessage, matchAndConsume, expireSessions, setWorkerError, getStatus }`.
- `establishBaseline({ targetEmail, machineId, uidValidity, uid })` stores `{ uidValidity: String, uid: Number, createdAt: Number }`.
- `addMessage({ uidValidity, uid, to, text, code, receivedAt, messageId })` accepts only numeric UIDs and never logs or transforms `code`.

- [ ] **Step 1: Write the failing state tests**

```js
// test/otp-state.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOtpState } = require('../lib/otp-state');

test('only consumes a message with the same UIDVALIDITY and a UID after baseline', () => {
  const state = createOtpState({ now: () => 10_000, sessionTtlMs: 300_000, bufferMaxAgeMs: 600_000, bufferMaxSize: 10 });
  state.establishBaseline({ targetEmail: 'a@example.test', machineId: 'm1', uidValidity: 7n, uid: 42 });
  state.addMessage({ uidValidity: 7n, uid: 42, to: 'a@example.test', text: 'code 123456', code: '123456', receivedAt: 10_001, messageId: 'old' });
  state.addMessage({ uidValidity: 8n, uid: 99, to: 'a@example.test', text: 'code 234567', code: '234567', receivedAt: 10_002, messageId: 'other-mailbox' });
  state.addMessage({ uidValidity: 7n, uid: 43, to: 'a@example.test', text: 'code 345678', code: '345678', receivedAt: 10_003, messageId: 'new' });
  assert.equal(state.matchAndConsume({ targetEmail: 'a@example.test', machineId: 'm1' }).code, '345678');
  assert.equal(state.matchAndConsume({ targetEmail: 'a@example.test', machineId: 'm1' }), null);
});

test('returns a stable worker failure instead of waiting', () => {
  const state = createOtpState({ now: () => 0, sessionTtlMs: 300_000, bufferMaxAgeMs: 600_000, bufferMaxSize: 10 });
  state.setWorkerError({ code: 'imap_proxy_failed', at: 1 });
  assert.deepEqual(state.getStatus().lastError, { code: 'imap_proxy_failed', at: 1 });
});
```

- [ ] **Step 2: Run the tests and verify the initial failure**

Run: `node --test test/otp-state.test.js`

Expected: `MODULE_NOT_FOUND` for `../lib/otp-state`.

- [ ] **Step 3: Implement the minimal state module**

```js
// lib/otp-state.js
function baselineKey(targetEmail, machineId) { return `${targetEmail || 'global'}\u0000${machineId || 'global'}`; }
function sessionKey(targetEmail, machineId, requestId) { return `${targetEmail || 'global'}\u0000${machineId || 'global'}\u0000${requestId}`; }
function createOtpState({ now = Date.now, sessionTtlMs, bufferMaxAgeMs, bufferMaxSize }) {
  const baselines = new Map();
  const messages = [];
  const sessions = new Map();
  let lastError = null;
  function establishBaseline({ targetEmail, machineId, uidValidity, uid }) {
    const baseline = { uidValidity: String(uidValidity), uid: Number(uid), createdAt: now() };
    baselines.set(baselineKey(targetEmail, machineId), baseline);
    return baseline;
  }
  function createOrGetSession({ targetEmail, machineId, requestId }) {
    const key = sessionKey(targetEmail, machineId, requestId);
    const existing = sessions.get(key);
    if (existing && now() - existing.createdAt < sessionTtlMs) return existing;
    const session = { key, targetEmail, machineId, requestId, createdAt: now(), status: 'pending', code: null, lastErrorCode: null };
    sessions.set(key, session);
    return session;
  }
  function getSession({ targetEmail, machineId, requestId }) { return sessions.get(sessionKey(targetEmail, machineId, requestId)) || null; }
  function completeSession(session, code) { session.status = 'success'; session.code = code; session.lastErrorCode = null; return session; }
  function addMessage(message) {
    const uid = Number(message.uid);
    if (!Number.isInteger(uid) || uid < 1) throw new TypeError('message UID must be a positive integer');
    messages.push({ ...message, uidValidity: String(message.uidValidity), uid, used: false });
    const cutoff = now() - bufferMaxAgeMs;
    while (messages.length > bufferMaxSize || (messages[0] && (messages[0].used || messages[0].receivedAt < cutoff))) messages.shift();
  }
  function matchAndConsume({ targetEmail, machineId }) {
    const baseline = baselines.get(baselineKey(targetEmail, machineId));
    if (!baseline) return null;
    const match = messages.find(item => !item.used && item.uidValidity === baseline.uidValidity && item.uid > baseline.uid && item.to === targetEmail);
    if (!match) return null;
    match.used = true;
    return match;
  }
  function expireSessions() { for (const [key, session] of sessions) if (now() - session.createdAt >= sessionTtlMs) { session.status = 'expired'; sessions.delete(key); } }
  return { establishBaseline, createOrGetSession, getSession, completeSession, addMessage, matchAndConsume, expireSessions, setWorkerError: error => { lastError = error; }, getStatus: () => ({ lastError }), sessionTtlMs, bufferMaxAgeMs, bufferMaxSize };
}
module.exports = { createOtpState };
```

- [ ] **Step 4: Run state tests and the full backend test command**

Run: `node --test test/otp-state.test.js && npm test`

Expected: both tests pass; no test may access a real IMAP server.

- [ ] **Step 5: Commit the state layer**

```powershell
git add lib/otp-state.js test/otp-state.test.js package.json
git commit -m "feat: add UID-aware OTP state"
```

### Task 2: Add an incremental IMAP worker with tests

**Files:**
- Create: `lib/imap-otp-worker.js`
- Create: `test/imap-otp-worker.test.js`
- Modify: `server.js:268-376`

**Interfaces:**
- Produces `createImapOtpWorker({ createClient, parseMessage, onCandidate, onError, now, config })`.
- The returned worker exposes `start()`, `stop()`, `snapshotBaseline()`, `scanPending()`, and `getStatus()`.
- `snapshotBaseline()` resolves `{ uidValidity: string, uid: number }` from `client.mailbox.uidValidity` and `client.mailbox.uidNext - 1`.
- `onCandidate(candidate)` receives `{ uidValidity, uid, to, text, code, receivedAt, messageId }`.

- [ ] **Step 1: Write failing fake-client tests**

```js
// test/imap-otp-worker.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createImapOtpWorker } = require('../lib/imap-otp-worker');

test('snapshots uidNext and reads only UIDs after the requested baseline', async () => {
  const client = Object.assign(new EventEmitter(), {
    mailbox: { uidValidity: 9n, uidNext: 44 }, connect: async () => {}, mailboxOpen: async () => {}, logout: async () => {},
    fetch: async function* (range, query, options) { assert.equal(range, '44:*'); assert.deepEqual(query, { envelope: true, internalDate: true }); assert.deepEqual(options, { uid: true }); yield { uid: 44, envelope: { subject: 'Lovart code', from: [{ address: 'no-reply@lovart.ai' }], to: [{ address: 'a@example.test' }] }, internalDate: new Date(0) }; },
    fetchOne: async (uid, query, options) => ({ uid, source: Buffer.from('source') })
  });
  const candidates = [];
  const worker = createImapOtpWorker({ createClient: () => client, parseMessage: async () => ({ subject: 'Lovart code', from: { text: 'Lovart' }, to: { text: 'a@example.test' }, text: 'code 123456', date: new Date(0), messageId: 'm1' }), onCandidate: item => candidates.push(item), onError: assert.fail, now: () => 1, config: {} });
  await worker.start();
  assert.deepEqual(await worker.snapshotBaseline(), { uidValidity: '9', uid: 43 });
  await worker.scanPending(43);
  assert.equal(candidates.length, 1);
  await worker.stop();
});
```

- [ ] **Step 2: Run the worker test and verify it fails**

Run: `node --test test/imap-otp-worker.test.js`

Expected: `MODULE_NOT_FOUND` for `../lib/imap-otp-worker`.

- [ ] **Step 3: Implement the adapter and replace legacy scanner calls**

```js
// Required incremental scan in lib/imap-otp-worker.js
async function scanPending(baselineUid) {
  const startUid = Math.max(Number(baselineUid) + 1, lastProcessedUid + 1);
  for await (const header of client.fetch(`${startUid}:*`, { envelope: true, internalDate: true }, { uid: true })) {
    lastProcessedUid = Math.max(lastProcessedUid, Number(header.uid));
    if (!looksLikeOtpEnvelope(header.envelope)) continue;
    const full = await client.fetchOne(header.uid, { source: true }, { uid: true });
    const parsed = await parseMessage(full.source);
    const candidate = parseOtpCandidate(parsed, { uidValidity: client.mailbox.uidValidity, uid: header.uid, receivedAt: header.internalDate || now() });
    if (candidate) onCandidate(candidate);
  }
}
```

Use ImapFlow's automatic IDLE behavior (`disableAutoIdle` remains false), subscribe to `client.on('exists', () => scanPending(minimumPendingBaseline()))`, and serialise scans with one promise so an `exists` event never starts a concurrent fetch. On `error` or `close`, classify errors as `imap_auth_failed`, `imap_proxy_failed`, or `imap_network_failed`; reconnect with delays of 1, 2, 4, 8 and 15 seconds, then run `scanPending(minimumPendingBaseline())`. `stop()` clears timers, removes event handlers and logs out once.

- [ ] **Step 4: Run worker and backend tests**

Run: `node --test test/imap-otp-worker.test.js test/otp-state.test.js && node --check server.js`

Expected: all tests pass and syntax check exits 0.

- [ ] **Step 5: Commit the worker**

```powershell
git add lib/imap-otp-worker.js test/imap-otp-worker.test.js server.js
git commit -m "feat: receive OTP messages by UID increment"
```

### Task 3: Integrate explicit OTP API outcomes and protected status

**Files:**
- Modify: `server.js:458-480,731-836,843-851`
- Create: `test/otp-api.test.js`

**Interfaces:**
- `/api/otp/mark-baseline` responds `{ success: true, baselineReady: true }` only after `worker.snapshotBaseline()` succeeds and `state.establishBaseline()` persists it.
- `/api/otp/get` responds success with a consumed code, `waiting` only while worker health is usable, `expired` after session TTL, or a stable worker error code.
- `/api/otp/status` requires `x-admin-secret` and returns only `{ worker, pendingSessions, metrics }`; `worker` contains booleans and error codes but no mail address, proxy URL, session key or OTP.

- [ ] **Step 1: Write failing API tests**

```js
// test/otp-api.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

test('does not report waiting when IMAP baseline setup fails', async () => {
  const { createApp } = require('../server');
  const error = new Error('proxy connect failed'); error.code = 'imap_proxy_failed';
  const app = createApp({ otpWorker: { snapshotBaseline: async () => { throw error; } }, otpState: fakeOtpState() });
  const server = app.listen(0);
  await once(server, 'listening');
  const response = await postJson(server.address().port, '/api/otp/mark-baseline', authorizedBody());
  await once(server.close(), 'close');
  assert.equal(response.statusCode, 502);
  assert.equal(response.body.error, 'imap_proxy_failed');
});
```

Define `once` from `node:events`; define `postJson(port, path, body)` with `http.request`; and make `authorizedBody()` supply a valid local-LV2 test license body accepted by the existing license middleware. Add a small `createApp({ otpWorker, otpState })` factory and export it; do not introduce a test-only `app.request` API. The test must use Node's built-in `http.request` against an ephemeral `app.listen(0)` server.

- [ ] **Step 2: Run API tests and verify they fail**

Run: `node --test test/otp-api.test.js`

Expected: failure because the server does not yet export `createApp` and baseline errors are reduced to a successful response.

- [ ] **Step 3: Implement route integration**

```js
// mark-baseline route behavior
try {
  const snapshot = await otpWorker.snapshotBaseline();
  otpState.establishBaseline({ targetEmail, machineId: auth.machineId, ...snapshot });
  return res.json({ success: true, baselineReady: true });
} catch (error) {
  const code = error.code || 'imap_network_failed';
  otpState.setWorkerError({ code, at: now() });
  return res.status(502).json({ success: false, status: 'error', error: code });
}
```

In `/api/otp/get`, check `otpState.matchAndConsume()` before returning. If no match exists, return the stored worker error when its timestamp is newer than the request's `createdAt`; otherwise return `{ success: false, status: 'waiting', error: 'waiting' }`. Do not call a full mailbox scan from the HTTP request. Start the worker once after `app.listen`, and call `await worker.stop()` from both `SIGINT` and `SIGTERM` handlers.

- [ ] **Step 4: Run backend tests and verify status authentication**

Run: `node --test test/otp-state.test.js test/imap-otp-worker.test.js test/otp-api.test.js && node --check server.js`

Expected: all pass; unauthenticated `GET /api/otp/status` returns 403 and authorized output contains no raw OTP or address.

- [ ] **Step 5: Commit API integration**

```powershell
git add server.js test/otp-api.test.js lib/otp-state.js
git commit -m "feat: expose reliable OTP status"
```

### Task 4: Make the desktop preserve baseline and worker status

**Files:**
- Modify: `D:\lovat\desktop\main.js:2326-2377`
- Modify: `D:\lovat\desktop\extension\content.js:1095-1139`

**Interfaces:**
- Local `GET /mark_ignore` returns `{ status: 'ok' }` only for `{ success: true, baselineReady: true }`; otherwise it preserves the cloud error code in `{ status: 'error', error }` and HTTP 502.
- Local `GET /get_code` maps cloud `waiting` to `{ status: 'waiting' }`, cloud `expired` to `{ status: 'not_found' }`, and cloud worker errors to `{ status: 'error', error }`.
- `fillEmailAndSendCode()` must abort before `forceClickBtn()` when baseline setup fails.

- [ ] **Step 1: Write a small pure mapping test beside the desktop source**

```js
// desktop/test/otp-relay.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { mapCloudOtpResult } = require('../core/otp-relay');
test('preserves waiting and proxy errors', () => {
  assert.deepEqual(mapCloudOtpResult({ success: false, status: 'waiting', error: 'waiting' }), { status: 'waiting' });
  assert.deepEqual(mapCloudOtpResult({ success: false, status: 'error', error: 'imap_proxy_failed' }), { status: 'error', error: 'imap_proxy_failed' });
});
```

- [ ] **Step 2: Run the desktop test and verify it fails**

Run: `node --test test/otp-relay.test.js`

Working directory: `D:\lovat\desktop`

Expected: `MODULE_NOT_FOUND` for `../core/otp-relay`.

- [ ] **Step 3: Extract mapping and gate the send action**

```js
// desktop/core/otp-relay.js
function mapCloudOtpResult(result) {
  if (result.success && result.code) return { status: 'success', code: result.code };
  if (result.status === 'waiting') return { status: 'waiting' };
  if (result.status === 'expired' || result.error === 'not_found') return { status: 'not_found' };
  return { status: 'error', error: result.error || 'otp_service_failed' };
}
module.exports = { mapCloudOtpResult };
```

In `content.js`, replace the ignored baseline fetch with `const baseline = await fetch(...).then(response => response.json()); if (baseline.status !== 'ok') { showStatus('邮箱服务暂不可用，请重试', '#ff4d4f'); loginInProgress = false; return; }`. Keep the existing click only after this guard. In `main.js`, use `mapCloudOtpResult(result)` for `/get_code` and return its exact JSON.

- [ ] **Step 4: Run desktop verification**

Run: `node --test test/otp-relay.test.js; node --check main.js; node --check extension/content.js; node --check core/otp-relay.js`

Working directory: `D:\lovat\desktop`

Expected: test passes and all syntax checks exit 0.

- [ ] **Step 5: Commit desktop changes separately**

```powershell
git add main.js extension/content.js core/otp-relay.js test/otp-relay.test.js
git commit -m "fix: preserve OTP relay failures"
```

Do not stage unrelated existing modifications in the desktop worktree.

### Task 5: Document, deploy, and measure the live path

**Files:**
- Modify: `DEPLOYMENT.md:3-39,57-69`
- Modify: `.env.example:1-7`
- Modify: `docs/superpowers/specs/2026-07-10-otp-latency-design.md`

**Interfaces:**
- New variables: `OTP_IMAP_RECONNECT_MAX_MS=15000`, `OTP_IMAP_HEALTH_CHECK_MS=10000`, and optional `OTP_IMAP_USE_PROXY` / `OTP_IMAP_PROXY_SERVER`.
- No production credentials, hosts beyond the already documented default, session tokens, OTP values, or proxy endpoints are committed.

- [ ] **Step 1: Add deployment documentation and an environment example**

```dotenv
# Optional: only when the deployed service cannot reach IMAP directly.
OTP_IMAP_USE_PROXY=false
OTP_IMAP_PROXY_SERVER=
# IDLE recovery bounds.
OTP_IMAP_RECONNECT_MAX_MS=15000
OTP_IMAP_HEALTH_CHECK_MS=10000
```

Document that Render, not the desktop, owns these variables; a successful smoke test is a baseline request, a controlled newly delivered message, and a status query using `x-admin-secret`.

- [ ] **Step 2: Run the complete pre-deploy suite**

Run: `npm ci; npm test; node --check server.js; npm audit --omit=dev --audit-level=high --registry=https://registry.npmjs.org`

Working directory: `D:\lovat\lovart-auth-server-git`

Expected: tests and syntax check pass; audit reports zero high-or-higher vulnerabilities or the deployment is blocked pending review.

- [ ] **Step 3: Commit deployment documentation**

```powershell
git add DEPLOYMENT.md .env.example docs/superpowers/specs/2026-07-10-otp-latency-design.md
git commit -m "docs: document OTP worker deployment"
```

- [ ] **Step 4: Deploy only the auth service and verify a controlled request**

Run: `D:\lovat\SYNC-Email-OTP.bat`

Expected: the script's deployed health check passes. After Render has deployed, use an administrator-authenticated status request and one controlled inbox delivery to record `p50 <= 3 seconds` and `p95 <= 8 seconds` from INBOX arrival to API success. If either threshold fails, retain the old implementation and investigate the recorded redacted worker metrics before distributing a desktop build.

## Plan Self-Review

- **Spec coverage:** Task 1 implements UID baseline and one-time matching; Task 2 adds IDLE-compatible incremental fetch and reconnect; Task 3 makes errors observable and protects status; Task 4 enforces baseline-before-send client behavior; Task 5 documents proxy ownership and verifies deployment latency.
- **Placeholder scan:** no `TODO`, `TBD`, empty method bodies, or deferred implementation markers are present.
- **Type consistency:** all later tasks use the `snapshotBaseline()` `{ uidValidity, uid }` object and the `createOtpState()` API defined in Task 1. Cloud error codes are `imap_auth_failed`, `imap_proxy_failed`, and `imap_network_failed` throughout.
