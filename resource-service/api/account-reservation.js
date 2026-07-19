'use strict';

const RESERVATION_TTL_MS = 10 * 60 * 1000;

function normalizeEmails(values) {
  return Array.from(new Set((Array.isArray(values) ? values : []).map(value => String(value || '').trim().toLowerCase()).filter(Boolean)));
}

function buildReservationCommand({ type, deleteCount, replenishCount, emails, selectionMode, allowFallbackSelection, accounts }) {
  const items = Array.isArray(accounts) ? accounts : [];
  return {
    type,
    deleteCount: Number(deleteCount) || 0,
    replenishCount: Number(replenishCount) || 0,
    emails: Array.isArray(emails) ? emails.map(String) : [],
    selectionMode: selectionMode || 'exact_emails',
    allowFallbackSelection: allowFallbackSelection === true,
    replacementAccountIds: items.map(item => String(item.id)),
    replacementEmails: normalizeEmails(items.map(item => item.email))
  };
}

function decideReservationAck(reservedEmails, result = {}) {
  const reserved = normalizeEmails(reservedEmails);
  const added = normalizeEmails(result.addedEmails);
  if (added.some(email => !reserved.includes(email))) {
    return { status: 'failed', assigned: [], released: reserved, error: 'ACK_EMAIL_MISMATCH' };
  }
  const assigned = reserved.filter(email => added.includes(email));
  const released = reserved.filter(email => !added.includes(email));
  if (result.success === true && assigned.length === reserved.length) return { status: 'completed', assigned, released: [], error: '' };
  if (assigned.length === 0) return { status: 'failed', assigned: [], released, error: String(result.errorCode || 'COMMAND_FAILED') };
  return { status: 'partial', assigned, released, error: 'PARTIAL_REPLACEMENT' };
}

module.exports = { RESERVATION_TTL_MS, normalizeEmails, buildReservationCommand, decideReservationAck };
