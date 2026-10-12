import test from 'node:test';
import assert from 'node:assert/strict';
import { policyDigest } from '../../runtime/accounting/hashes.mjs';
import { publicInputValues, statementBytes, validateStatement, validityHorizon } from '../../runtime/accounting/statement.mjs';
import { expectedProofs } from '../../runtime/extensions/statement.mjs';

const bytes = (n: number) => Array(32).fill(n);
const field = (n: number) => [...Array(31).fill(0), n];
const policy = { initialCredit: 3, maximumAvailable: 4, outgoingReservation: 1, incomingReservation: 1,
  policyRevision: 1, policyValidFrom: 100, policyValidUntil: 250, newcomerPeriod: 100, rateWindow: 100,
  newcomerAdmissions: 2, maximumAdmissions: 4, refillPeriod: 100, refillUnits: 1, abandonAfter: 500 };
const extension = { revision: 1, publicRecordQuorum: 2, changeTokenCost: 1,
  depositDelaySeconds: 100, minimumDepositBatch: 2,
  standingPolicyDigest: Array(32).fill(9) };
const manifest = { issuerKey: Array(64).fill(7), circuitSha256: 'ab'.repeat(32) };

async function account(genesis = true) {
  return { protocolVersion: 2, community: bytes(1), owner: bytes(2),
    policyDigest: Array.from(await policyDigest(Uint8Array.from(bytes(1)), policy)),
    enrollmentRoot: field(3), now: 110, validUntil: 200, genesis,
    previousVersion: genesis ? 0 : 2, nextVersion: genesis ? 0 : 3,
    previousState: field(genesis ? 0 : 4), nextState: field(6), settlementMarker: field(0), policy: { ...policy } };
}

test('account public encoding binds identities, versions and the exclusive policy horizon', async () => {
  const genesis = await account();
  const inputs = await validateStatement(genesis);
  assert.equal(inputs.length, 243);
  assert.deepEqual(inputs.slice(0, 32), Array(32).fill(1n));
  assert.deepEqual(inputs.slice(32, 64), Array(32).fill(2n));
  assert.deepEqual(inputs.slice(128, 133), [110n, 200n, 1n, 0n, 0n]);
  const encoded = statementBytes(genesis), prefix = new TextEncoder().encode('cfrm.account.statement.v2\0');
  assert.deepEqual(encoded.slice(0, prefix.length), prefix);
  assert.deepEqual(encoded.slice(prefix.length, prefix.length + 4), new Uint8Array([0, 0, 0, 2]));
  const transition = await account(false);
  transition.now = 200;
  transition.validUntil = 250;
  assert.equal(validityHorizon(200, policy), 250n);
  assert.deepEqual((await validateStatement(transition)).slice(128, 133), [200n, 250n, 0n, 2n, 3n]);
  const atStart = await account();
  atStart.now = policy.policyValidFrom;
  assert.equal((await validateStatement(atStart)).length, 243);
});

test('account statements reject malformed schemas, noncanonical bytes and unsafe integers', async () => {
  const valid = await account();
  for (const malformed of [null, [], { ...valid, privateOpening: {} },
    { ...valid, policy: { ...valid.policy, privateOpening: {} } }, { ...valid, policy: {} }]) {
    await assert.rejects(validateStatement(malformed), /Exact account/);
  }
  for (const value of [Array(31).fill(1), [...Array(31).fill(0), 256],
    [...Array(31).fill(0), 1.5], [...Array(31).fill(0), '1']]) {
    await assert.rejects(validateStatement({ ...valid, owner: value }), /Noncanonical statement bytes/);
  }
  for (const mutation of [
    { protocolVersion: 1 }, { genesis: 1 }, { now: Number.MAX_SAFE_INTEGER + 1 },
    { now: -1 }, { now: 1n << 64n }, { now: BigInt(Number.MAX_SAFE_INTEGER) + 1n },
    { policy: { ...policy, initialCredit: 2 ** 32 } },
  ]) assert.throws(() => publicInputValues({ ...valid, ...mutation }));
  for (const key of ['enrollmentRoot', 'previousState', 'nextState', 'settlementMarker']) {
    await assert.rejects(validateStatement({ ...valid, [key]: bytes(255) }), /Noncanonical BN254/);
  }
});

test('account validation refuses stale policy, wrong digest and invalid state transitions', async () => {
  const valid = await account();
  for (const mutation of [{ now: 0, validUntil: 100 }, { now: 99, validUntil: 100 },
    { now: 250, validUntil: 250 }, { validUntil: 199 }, { policyDigest: bytes(0) }]) {
    await assert.rejects(validateStatement({ ...valid, ...mutation }), /Account policy\/time/);
  }
  for (const mutation of [{ enrollmentRoot: field(0) }, { nextState: field(0) },
    { previousVersion: 1 }, { nextVersion: 1 }, { previousState: field(1) }, { settlementMarker: field(1) }]) {
    await assert.rejects(validateStatement({ ...valid, ...mutation }), /Account state\/version/);
  }
  const transition = await account(false);
  for (const mutation of [{ nextVersion: 2 }, { nextVersion: 4 }, { previousState: field(0) }]) {
    await assert.rejects(validateStatement({ ...transition, ...mutation }), /Account state\/version/);
  }
});

test('extension update bundles bind each ingestion and exactly one final version advance', async () => {
  const statement = { kind: 'update', policy: extension, account: await account(false),
    update: { previousInbox: { root: field(8) }, inbox: { root: field(9) },
      effect: { kind: 'change', binding: field(10) } } };
  // Opaque parser fixtures only: this test does not construct a verifier or claim a proof.
  const bundle = { version: 1, proofs: [
    { state: field(5), inbox: field(9), proof: '01' },
    { state: field(6), inbox: field(9), proof: '02' },
  ] };
  const [ingestion, final] = await expectedProofs(statement, bundle, manifest);
  assert.equal(ingestion.kind, 'update');
  assert.equal(ingestion.proof, '01');
  assert.equal(ingestion.input.consume_only, true);
  assert.equal(ingestion.input.next_version, statement.account.previousVersion);
  assert.deepEqual(ingestion.input.previous_state, field(4));
  assert.deepEqual(ingestion.input.next_state, field(5));
  assert.deepEqual(ingestion.input.previous_inbox, field(8));
  assert.deepEqual(ingestion.input.inbox, field(9));
  assert.deepEqual(ingestion.input.change_binding, field(0));
  assert.deepEqual(ingestion.input.settlement_marker, field(0));
  assert.equal(final.input.consume_only, false);
  assert.equal(final.input.next_version, 3);
  assert.deepEqual(final.input.previous_state, field(5));
  assert.deepEqual(final.input.next_state, field(6));
  assert.deepEqual(final.input.previous_inbox, field(9));
  assert.deepEqual(final.input.change_binding, field(10));

  const malformed = [
    { ...bundle, proofs: [{ ...bundle.proofs[0], privateOpening: {} }, bundle.proofs[1]] },
    { ...bundle, proofs: [{ ...bundle.proofs[0], inbox: field(8) }, bundle.proofs[1]] },
    { ...bundle, proofs: [{ ...bundle.proofs[0], inbox: field(11) }, bundle.proofs[1]] },
    { ...bundle, proofs: [bundle.proofs[0], { ...bundle.proofs[1], inbox: field(11) }] },
    { ...bundle, proofs: [bundle.proofs[0], { ...bundle.proofs[1], state: field(11) }] },
  ];
  for (const invalid of malformed) await assert.rejects(expectedProofs(statement, invalid, manifest));
  await assert.rejects(expectedProofs({ ...statement, account: await account() }, bundle, manifest), /Invalid ingestion/);

  const single = { ...statement, update: { previousInbox: { root: field(9) },
    inbox: { root: field(9) }, effect: { kind: 'update' } } };
  const [plain] = await expectedProofs(single, { version: 1, proofs: [bundle.proofs[1]] }, manifest);
  assert.deepEqual(plain.input.change_binding, field(0));
  for (const effect of [{ kind: 'other' }, { kind: 'change' }, { kind: 'update', binding: field(1) }]) {
    await assert.rejects(expectedProofs({ ...single, update: { ...single.update, effect } }, bundle, manifest), /Effect shape/);
  }
});

test('extension bundle limits accept 64 ingestions and refuse extra or missing framing', async () => {
  const statement = { kind: 'update', policy: extension, account: await account(false),
    update: { previousInbox: { root: field(0) }, inbox: { root: field(64) }, effect: { kind: 'update' } } };
  const steps = Array.from({ length: 64 }, (_, i) => ({ state: field(i + 40), inbox: field(i + 1), proof: '01' }));
  steps.push({ state: statement.account.nextState, inbox: field(64), proof: '02' });
  assert.equal((await expectedProofs(statement, { version: 1, proofs: steps }, manifest)).length, 65);
  const overLimit = [...steps.slice(0, -1), { state: field(104), inbox: field(65), proof: '01' },
    { state: statement.account.nextState, inbox: field(65), proof: '02' }];
  await assert.rejects(expectedProofs({ ...statement,
    update: { ...statement.update, inbox: { root: field(65) } } },
  { version: 1, proofs: overLimit }, manifest), /Bounded proof bundle/);
  for (const bundle of [{ version: 1, proofs: [] },
    { version: 2, proofs: steps }, { version: 1, proofs: null }, { version: 1, proofs: steps, privateOpening: {} }]) {
    await assert.rejects(expectedProofs(statement, bundle, manifest), /Bounded proof bundle/);
  }
  await assert.rejects(expectedProofs({ ...statement, privateOpening: {} }, { version: 1, proofs: steps }, manifest), /Update shape/);
  await assert.rejects(expectedProofs({ ...statement, update: { ...statement.update, inbox: {} } },
    { version: 1, proofs: steps }, manifest), /Inbox shape/);
});

test('anonymous extension statements bind deposit scope and both record disclosure modes', async () => {
  const bundle = { version: 1, proofs: [{ proof: '01' }] };
  const deposit = { kind: 'deposit', policy: extension, deposit: {
    community: bytes(1), recipient: bytes(2), releaseEpoch: 5, nullifier: field(3),
    authorizationNullifier: field(4), obligation: field(5) } };
  const [mapped] = await expectedProofs(deposit, bundle, manifest);
  assert.equal(mapped.kind, 'deposit');
  assert.deepEqual(mapped.input.extension, { revision: 1, quorum: 2, change_cost: 1, delay: 100, batch: 2,
    standing: extension.standingPolicyDigest });
  assert.deepEqual(mapped.input.issuer_key, manifest.issuerKey);
  assert.deepEqual(mapped.input.scope, bytes(171));
  assert.deepEqual(mapped.input.authorization_nullifier, deposit.deposit.authorizationNullifier);
  assert.equal(mapped.input.release_epoch, 5);
  const record = { kind: 'record', policy: extension, record: { community: bytes(1), owner: bytes(2),
    version: 3, state: field(6), inbox: { root: field(9) }, shares: null,
    context: { purpose: 'firstContact', challenge: bytes(10), expiresAt: 200 } } };
  const [hidden] = await expectedProofs(record, bundle, manifest);
  assert.equal(hidden.kind, 'record');
  assert.equal(hidden.input.purpose, 0);
  assert.equal(hidden.input.present, false);
  assert.deepEqual(hidden.input.shares, [0, 0, 0]);
  assert.deepEqual(hidden.input.challenge, record.record.context.challenge);
  assert.equal(hidden.input.expires_at, 200);
  const visible = { ...record, record: { ...record.record, shares: [5000, 3000, 2000],
    context: { ...record.record.context, purpose: 'forumListing' } } };
  const [published] = await expectedProofs(visible, bundle, manifest);
  assert.equal(published.input.purpose, 1);
  assert.equal(published.input.present, true);
  assert.deepEqual(published.input.shares, visible.record.shares);
  for (const statement of [{ ...deposit, privateOpening: {} },
    { ...deposit, deposit: { ...deposit.deposit, privateOpening: {} } },
    { ...record, kind: 'other' }, { ...record, record: { ...record.record, inbox: {} } },
    { ...record, record: { ...record.record, context: { ...record.record.context, purpose: 'other' } } },
    { ...record, policy: { ...extension, privateOpening: {} } }]) {
    await assert.rejects(expectedProofs(statement, bundle, manifest));
  }
  await assert.rejects(expectedProofs(record, { version: 1, proofs: [{ proof: '01', state: field(1) }] }, manifest), /Anonymous proof/);
  await assert.rejects(expectedProofs(record, { version: 1, proofs: [{ proof: '01' }, { proof: '02' }] }, manifest), /Anonymous proof/);
});
