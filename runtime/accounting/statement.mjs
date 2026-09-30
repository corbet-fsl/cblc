import { fieldValue } from '@corbet-labs/czkp/primitives';
import { cat, be } from '@corbet-labs/czkp/encoding';
import { policyDigest, integer, SAFE, POLICY_KEYS } from './hashes.mjs';
export const POLICY_WIRE = [
  ['initialCredit','initial_credit',32], ['maximumAvailable','maximum_available',32],
  ['outgoingReservation','outgoing_reservation',32], ['incomingReservation','incoming_reservation',32],
  ['policyRevision','policy_revision',64], ['policyValidFrom','policy_valid_from',64], ['policyValidUntil','policy_valid_until',64],
  ['newcomerPeriod','newcomer_period',64], ['rateWindow','rate_window',64],
  ['newcomerAdmissions','newcomer_admissions',32], ['maximumAdmissions','maximum_admissions',32],
  ['refillPeriod','refill_period',64], ['refillUnits','refill_units',32], ['abandonAfter','abandon_after',64],
];
export const PUBLIC_INPUT_COUNT = 243;
export function validityHorizon(now, policy) {
  const at = BigInt(now), window = BigInt(policy.rateWindow), end = (at / window + 1n) * window;
  return end < BigInt(policy.policyValidUntil) ? end : BigInt(policy.policyValidUntil);
}

export function statementFromInput(input) {
  return { protocolVersion: 2, community: Array.from(input.community), owner: Array.from(input.owner),
    policyDigest: Array.from(input.policy_digest), enrollmentRoot: Array.from(input.enrollment_root), now: Number(input.now), validUntil: Number(input.valid_until),
    genesis: input.genesis, previousVersion: Number(input.previous_version), nextVersion: Number(input.next_version),
    previousState: Array.from(input.previous_state), nextState: Array.from(input.next_state), settlementMarker: Array.from(input.settlement_marker),
    policy: Object.fromEntries(POLICY_WIRE.map(([key, wire]) => [key, Number(input[wire])])) };
}

export function publicInputValues(statement) {
  const bytes = value => {
    if (!Array.isArray(value) || value.length !== 32 || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('Noncanonical statement bytes');
    return value.map(BigInt);
  };
  const safe = value => { const n = integer(value, 64); if (n > SAFE) throw new Error('Statement integer'); return n; };
  if (statement.protocolVersion !== 2 || typeof statement.genesis !== 'boolean') throw new Error('Statement version/boolean');
  const p = statement.policy;
  if (!p || Object.keys(p).length !== POLICY_KEYS.length || !POLICY_KEYS.every(key => Object.hasOwn(p, key))) throw new Error('Exact v2 policy required');
  return [...bytes(statement.community), ...bytes(statement.owner), ...bytes(statement.policyDigest), ...bytes(statement.enrollmentRoot),
    safe(statement.now), safe(statement.validUntil), statement.genesis ? 1n : 0n, safe(statement.previousVersion), safe(statement.nextVersion),
    ...bytes(statement.previousState), ...bytes(statement.nextState), ...bytes(statement.settlementMarker),
    ...POLICY_WIRE.map(([key, , bits]) => bits === 64 ? safe(p[key]) : integer(p[key], bits))];
}

export function statementBytes(statement) {
  publicInputValues(statement); // Validate fixed byte/integer widths first.
  const s = statement, p = s.policy;
  return cat(new TextEncoder().encode('cfrm.account.statement.v2\0'), be(s.protocolVersion, 4),
    ...[s.community, s.owner, s.policyDigest, s.enrollmentRoot].map(value => Uint8Array.from(value)),
    be(s.now, 8), be(s.validUntil, 8), new Uint8Array([s.genesis ? 1 : 0]), be(s.previousVersion, 8), be(s.nextVersion, 8),
    ...[s.previousState, s.nextState, s.settlementMarker].map(value => Uint8Array.from(value)),
    ...POLICY_WIRE.map(([key, , bits]) => be(p[key], bits / 8)));
}

export async function validateStatement(statement) {
  const keys = ['protocolVersion','community','owner','policyDigest','enrollmentRoot','now','validUntil','genesis',
    'previousVersion','nextVersion','previousState','nextState','settlementMarker','policy'];
  const exact = (value, names) => value && !Array.isArray(value) && Object.keys(value).length === names.length
    && names.every(key => Object.hasOwn(value, key));
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
  if (!exact(statement, keys) || !exact(statement.policy, POLICY_KEYS)) throw new Error('Exact account statement required');
  const inputs = publicInputValues(statement), s = statement;
  if (inputs.length !== PUBLIC_INPUT_COUNT || BigInt(s.validUntil) !== validityHorizon(s.now, s.policy)
      || s.now <= 0 || s.now < s.policy.policyValidFrom || s.now >= s.policy.policyValidUntil
      || !equal(s.policyDigest, await policyDigest(Uint8Array.from(s.community), s.policy))) throw new Error('Account policy/time encoding');
  for (const key of ['enrollmentRoot','previousState','nextState','settlementMarker']) fieldValue(Uint8Array.from(s[key]));
  if (!s.enrollmentRoot.some(Boolean) || !s.nextState.some(Boolean)
      || (s.genesis ? s.previousVersion !== 0 || s.nextVersion !== 0 || s.previousState.some(Boolean) || s.settlementMarker.some(Boolean)
        : s.nextVersion !== s.previousVersion + 1 || !s.previousState.some(Boolean))) throw new Error('Account state/version shape');
  return inputs;
}

