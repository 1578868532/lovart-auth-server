function baselineKey(targetEmail, machineId) {
  return `${targetEmail || 'global'}\u0000${machineId || 'global'}`;
}

function sessionKey(targetEmail, machineId, requestId) {
  return `${targetEmail || 'global'}\u0000${machineId || 'global'}\u0000${requestId}`;
}

function createOtpState({
  now = Date.now,
  sessionTtlMs,
  bufferMaxAgeMs,
  bufferMaxSize
}) {
  const baselines = new Map();
  const messages = [];
  const sessions = new Map();
  let lastError = null;

  function establishBaseline({ targetEmail, machineId, uidValidity, uid }) {
    const numericUid = Number(uid);
    if (!Number.isInteger(numericUid) || numericUid < 1) {
      throw new TypeError('baseline UID must be a positive integer');
    }

    const baseline = {
      uidValidity: String(uidValidity),
      uid: numericUid,
      createdAt: now()
    };
    baselines.set(baselineKey(targetEmail, machineId), baseline);
    return baseline;
  }

  function createOrGetSession({ targetEmail, machineId, requestId }) {
    const key = sessionKey(targetEmail, machineId, requestId);
    const existing = sessions.get(key);
    if (existing && now() - existing.createdAt < sessionTtlMs) return existing;

    const session = {
      key,
      targetEmail,
      machineId,
      requestId,
      status: 'pending',
      createdAt: now(),
      code: null,
      lastErrorCode: null
    };
    sessions.set(key, session);
    return session;
  }

  function getSession({ targetEmail, machineId, requestId }) {
    const key = sessionKey(targetEmail, machineId, requestId);
    const session = sessions.get(key);
    if (!session) return null;
    if (now() - session.createdAt >= sessionTtlMs) {
      sessions.delete(key);
      return null;
    }
    return session;
  }

  function completeSession(session, code) {
    session.status = 'success';
    session.code = code;
    session.lastErrorCode = null;
    return session;
  }

  function purgeMessages() {
    const cutoff = now() - bufferMaxAgeMs;
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index];
      if (message.used || message.receivedAt < cutoff) messages.splice(index, 1);
    }
    while (messages.length > bufferMaxSize) messages.shift();
  }

  function addMessage(message) {
    const uid = Number(message.uid);
    if (!Number.isInteger(uid) || uid < 1) {
      throw new TypeError('message UID must be a positive integer');
    }

    const storedMessage = {
      ...message,
      uidValidity: String(message.uidValidity),
      uid,
      used: false
    };
    messages.push(storedMessage);
    purgeMessages();
    return storedMessage;
  }

  function matchAndConsume({ targetEmail, machineId, observedAfter }) {
    purgeMessages();
    const baseline = baselines.get(baselineKey(targetEmail, machineId));
    const legacyObservedAfter = Number(observedAfter);

    const match = messages.find(message => (
      !message.used
      && message.to === targetEmail
      && (baseline
        ? message.uidValidity === baseline.uidValidity && message.uid > baseline.uid
        : Number.isFinite(legacyObservedAfter) && Number(message.observedAt) >= legacyObservedAfter)
    ));
    if (!match) return null;

    match.used = true;
    const index = messages.indexOf(match);
    if (index >= 0) messages.splice(index, 1);
    return match;
  }

  function expireSessions() {
    for (const [key, session] of sessions) {
      if (now() - session.createdAt >= sessionTtlMs) sessions.delete(key);
    }
  }

  function hasPendingSessions() {
    expireSessions();
    return Array.from(sessions.values()).some(session => session.status === 'pending');
  }

  function setWorkerError(error) {
    lastError = error;
  }

  function getStatus() {
    return { lastError };
  }

  return {
    establishBaseline,
    createOrGetSession,
    getSession,
    completeSession,
    addMessage,
    matchAndConsume,
    expireSessions,
    hasPendingSessions,
    setWorkerError,
    getStatus
  };
}

module.exports = { createOtpState };
