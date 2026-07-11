const RECONNECT_DELAYS_MS = [1_000, 2_000, 4_000, 8_000, 15_000];

function createStableError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function classifyImapError(error) {
  const value = `${error && error.code ? error.code : ''} ${error && error.message ? error.message : error}`.toLowerCase();
  if (value.includes('proxy')) return 'imap_proxy_failed';
  if (/(auth|login|credential|password|authenticate)/.test(value)) return 'imap_auth_failed';
  return 'imap_network_failed';
}

function envelopeText(addresses) {
  if (!Array.isArray(addresses)) return '';
  return addresses.map(address => address.address || address.name || '').join(', ');
}

function looksLikeOtpEnvelope(envelope) {
  const sender = envelopeText(envelope && envelope.from).toLowerCase();
  const subject = String(envelope && envelope.subject || '').toLowerCase();
  return sender.includes('lovart') && /(lovart|code|verification|verify|welcome)/.test(subject);
}

function parsedRecipient(parsed, envelope) {
  if (parsed && parsed.to && parsed.to.text) return parsed.to.text;
  return envelopeText(envelope && envelope.to);
}

function extractOtpCode(text) {
  const content = String(text || '');
  const contextual = content.match(/(?:code|verification)[\s\S]{0,300}?(\b\d{6}\b)/i);
  if (contextual && contextual[1] !== '000000') return contextual[1];
  return (content.match(/\b\d{6}\b/g) || []).find(code => code !== '000000') || null;
}

function createImapOtpWorker({
  createClient,
  parseMessage,
  onCandidate = () => {},
  onError = () => {},
  getMinimumPendingBaseline = () => null,
  hasPendingWork = () => false,
  now = Date.now,
  config = {}
}) {
  const schedule = config.setTimeout || setTimeout;
  const cancelSchedule = config.clearTimeout || clearTimeout;
  const scheduleInterval = config.setInterval || setInterval;
  const cancelInterval = config.clearInterval || clearInterval;
  let client = null;
  let clientHandlers = null;
  let started = false;
  let stopping = false;
  let connected = false;
  let uidValidity = null;
  let lastProcessedUid = null;
  let activeScan = null;
  let pendingExistsScan = false;
  let reconnectTimer = null;
  let fallbackTimer = null;
  let reconnectDelayIndex = 0;
  let reconnectCount = 0;
  let failedClient = null;
  let lastEventAt = null;
  let lastErrorCode = null;
  let lastScanDurationMs = 0;
  let lastScanScanned = 0;
  let lastScanCandidates = 0;
  let totalScanScanned = 0;
  let totalScanCandidates = 0;
  const loggedOutClients = new WeakSet();

  function markEvent() {
    lastEventAt = now();
  }

  function getMailbox() {
    if (!connected || !client || !client.mailbox) throw createStableError(lastErrorCode || 'imap_network_failed');
    const mailboxUidNext = Number(client.mailbox.uidNext);
    if (!client.mailbox.uidValidity || !Number.isInteger(mailboxUidNext) || mailboxUidNext < 1) {
      throw createStableError(lastErrorCode || 'imap_network_failed');
    }
    return client.mailbox;
  }

  function detachClient(target = client) {
    if (!target || !clientHandlers || target !== client) return;
    target.removeListener('exists', clientHandlers.exists);
    target.removeListener('error', clientHandlers.error);
    target.removeListener('close', clientHandlers.close);
    clientHandlers = null;
  }

  async function disposeClient(target, ignoreLogoutFailure = false) {
    if (!target) return;
    detachClient(target);
    if (loggedOutClients.has(target)) return;
    loggedOutClients.add(target);
    try {
      await target.logout();
    } catch (error) {
      if (!ignoreLogoutFailure) throw error;
    }
  }

  function reportFailure(error, sourceClient = client) {
    if (stopping || sourceClient !== client || failedClient === sourceClient) return;
    failedClient = sourceClient;
    connected = false;
    lastErrorCode = classifyImapError(error);
    markEvent();
    try {
      onError({ code: lastErrorCode, at: lastEventAt });
    } catch {
      // Callbacks must not interfere with reconnecting the IMAP transport.
    }
    scheduleReconnect();
  }

  async function connectAndOpen() {
    const previousClient = client;
    if (previousClient) await disposeClient(previousClient, true);
    const nextClient = createClient();
    client = nextClient;
    failedClient = null;
    clientHandlers = {
      exists: () => {
        markEvent();
        queueExistsScan().catch(error => reportFailure(error, nextClient));
      },
      error: error => reportFailure(error, nextClient),
      close: error => reportFailure(error || new Error('IMAP connection closed'), nextClient)
    };
    nextClient.on('exists', clientHandlers.exists);
    nextClient.on('error', clientHandlers.error);
    nextClient.on('close', clientHandlers.close);

    await nextClient.connect();
    await nextClient.mailboxOpen('INBOX');
    if (stopping || nextClient !== client) throw createStableError('imap_network_failed');

    const mailboxUidNext = Number(nextClient.mailbox && nextClient.mailbox.uidNext);
    const nextUidValidity = nextClient.mailbox && String(nextClient.mailbox.uidValidity);
    if (!nextUidValidity || !Number.isInteger(mailboxUidNext) || mailboxUidNext < 1) {
      throw createStableError('imap_network_failed');
    }

    const mailboxChanged = uidValidity !== null && uidValidity !== nextUidValidity;
    uidValidity = nextUidValidity;
    if (lastProcessedUid === null || mailboxChanged) lastProcessedUid = mailboxUidNext - 1;
    connected = true;
    lastErrorCode = null;
    markEvent();
  }

  function scheduleReconnect() {
    if (!started || stopping || reconnectTimer) return;
    const delay = RECONNECT_DELAYS_MS[Math.min(reconnectDelayIndex, RECONNECT_DELAYS_MS.length - 1)];
    reconnectDelayIndex = Math.min(reconnectDelayIndex + 1, RECONNECT_DELAYS_MS.length - 1);
    reconnectTimer = schedule(async () => {
      reconnectTimer = null;
      if (!started || stopping) return;
      reconnectCount += 1;
      try {
        await connectAndOpen();
        reconnectDelayIndex = 0;
        await queueScan(getMinimumPendingBaseline());
      } catch (error) {
        reportFailure(error, client);
      }
    }, delay);
  }

  async function scanNow(baselineUid) {
    const mailbox = getMailbox();
    const baseline = Number(baselineUid);
    const startingUid = Math.max(
      Number.isInteger(baseline) && baseline >= 0 ? baseline + 1 : lastProcessedUid + 1,
      lastProcessedUid + 1
    );
    const startedAt = now();
    let scanned = 0;
    let candidates = 0;
    const headers = [];

    try {
      for await (const header of client.fetch(
        `${startingUid}:*`,
        { envelope: true, internalDate: true },
        { uid: true }
      )) {
        const uid = Number(header.uid);
        if (!Number.isInteger(uid) || uid < startingUid) continue;
        scanned += 1;
        headers.push(header);
      }

      for (const header of headers) {
        if (looksLikeOtpEnvelope(header.envelope)) {
          const full = await client.fetchOne(header.uid, { source: true }, { uid: true });
          if (full && full.source) {
            const parsed = await parseMessage(full.source);
            const text = String(parsed && (parsed.text || parsed.html) || '');
            const code = extractOtpCode(text);
            if (code) {
              const candidate = {
                uidValidity: String(mailbox.uidValidity),
                uid: Number(header.uid),
                to: parsedRecipient(parsed, header.envelope),
                text,
                code,
                receivedAt: header.internalDate || now(),
                observedAt: now(),
                messageId: parsed && parsed.messageId ? parsed.messageId : String(header.uid)
              };
              await onCandidate(candidate);
              candidates += 1;
            }
          }
        }
        lastProcessedUid = Math.max(lastProcessedUid, Number(header.uid));
      }
    } finally {
      lastScanDurationMs = now() - startedAt;
      lastScanScanned = scanned;
      lastScanCandidates = candidates;
      totalScanScanned += scanned;
      totalScanCandidates += candidates;
      markEvent();
    }
  }

  function queueScan(baselineUid, queueFollowUpOnActive = false) {
    if (activeScan) {
      if (queueFollowUpOnActive) pendingExistsScan = true;
      return activeScan;
    }
    activeScan = (async () => {
      let nextBaselineUid = baselineUid;
      do {
        pendingExistsScan = false;
        await scanNow(nextBaselineUid);
        if (!pendingExistsScan) return;
        nextBaselineUid = getMinimumPendingBaseline();
      } while (true);
    })().finally(() => {
      activeScan = null;
    });
    return activeScan;
  }

  function queueExistsScan() {
    if (activeScan) return queueScan(undefined, true);
    return queueScan(getMinimumPendingBaseline(), true);
  }

  async function start() {
    if (started && connected) return;
    if (started && reconnectTimer) return;
    started = true;
    stopping = false;
    try {
      await connectAndOpen();
      if (!fallbackTimer) {
        fallbackTimer = scheduleInterval(() => {
          if (started && !stopping && hasPendingWork()) {
            queueScan(getMinimumPendingBaseline()).catch(error => reportFailure(error, client));
          }
        }, Number(config.fallbackIntervalMs) || 2_000);
      }
    } catch (error) {
      reportFailure(error, client);
      throw createStableError(classifyImapError(error));
    }
  }

  async function snapshotBaseline() {
    const mailbox = getMailbox();
    return { uidValidity: String(mailbox.uidValidity), uid: Number(mailbox.uidNext) - 1 };
  }

  async function stop() {
    if (stopping) return;
    stopping = true;
    started = false;
    if (reconnectTimer) {
      cancelSchedule(reconnectTimer);
      reconnectTimer = null;
    }
    if (fallbackTimer) {
      cancelInterval(fallbackTimer);
      fallbackTimer = null;
    }
    const scan = activeScan;
    if (scan) await scan.catch(() => {});
    const clientToClose = client;
    connected = false;
    await disposeClient(clientToClose);
    client = null;
    stopping = false;
  }

  function getStatus() {
    return {
      connected,
      idling: connected,
      uidValidity,
      lastProcessedUid,
      lastEventAt,
      reconnectCount,
      lastErrorCode,
      lastScanDurationMs,
      lastScanScanned,
      lastScanCandidates,
      totalScanScanned,
      totalScanCandidates
    };
  }

  return { start, stop, snapshotBaseline, scanPending: queueScan, getStatus };
}

module.exports = { createImapOtpWorker };
