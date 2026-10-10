import test from 'node:test';
import assert from 'node:assert/strict';
import { hex } from '@corbet-labs/czkp/encoding';
import { fieldBytes, fieldValue, FR_MODULUS, hashesFor, POSEIDON_SCHEME } from '@corbet-labs/czkp/primitives';
import { accountHashes, ackBytes, checkpointFromVerified, DEPTH, IndexedMap, integer, LIMIT,
  noirInput, policyBytes, policyDigest, receiptBytes, receiptDigest, SAFE, SparseTree,
  statePolicyDigest } from '../../runtime/accounting/hashes.mjs';

const bytes = (n: number) => new Uint8Array(32).fill(n);
const policy = { initialCredit: 3, maximumAvailable: 4, outgoingReservation: 1, incomingReservation: 1,
  policyRevision: 1, policyValidFrom: 1, policyValidUntil: 2000, newcomerPeriod: 100, rateWindow: 1000,
  newcomerAdmissions: 2, maximumAdmissions: 4, refillPeriod: 100, refillUnits: 1, abandonAfter: 1000 };

test('policy encoding bounds every quantity and permits only waiting-period tuning without rebinding state', async () => {
  assert.equal(integer(0, 32), 0n);
  assert.equal(integer(LIMIT - 1n, 32), LIMIT - 1n);
  for (const value of [-1, LIMIT, Number.MAX_SAFE_INTEGER + 1, 0.5]) {
    assert.throws(() => integer(value, 32));
  }
  assert.equal(policyBytes(bytes(1), policy).length, 140);
  for (const mutation of [
    { maximumAvailable: 0 }, { initialCredit: 5 }, { outgoingReservation: 0 }, { incomingReservation: 0 },
    { outgoingReservation: 4 }, { incomingReservation: 4 }, { policyRevision: 0 }, { policyValidFrom: 0 },
    { policyValidUntil: 1 }, { newcomerPeriod: 0 }, { rateWindow: 0 }, { refillPeriod: 0 },
    { abandonAfter: 999 }, { newcomerAdmissions: 0 }, { newcomerAdmissions: 5 }, { refillUnits: 0 },
    { refillUnits: 4 }, { policyRevision: SAFE + 1n },
  ]) assert.throws(() => policyBytes(bytes(1), { ...policy, ...mutation }));
  for (const community of [new Uint8Array(31), Array(32).fill(1)]) {
    assert.throws(() => policyBytes(community, policy), /Expected bytes32/);
  }
  const tuned = { ...policy, abandonAfter: 2000 };
  assert.notDeepEqual(await policyDigest(bytes(1), policy), await policyDigest(bytes(1), tuned));
  assert.deepEqual(await statePolicyDigest(bytes(1), policy), await statePolicyDigest(bytes(1), tuned));
  assert.notDeepEqual(await statePolicyDigest(bytes(1), policy),
    await statePolicyDigest(bytes(1), { ...policy, refillUnits: 2 }));
  assert.notDeepEqual(await statePolicyDigest(bytes(1), policy), await statePolicyDigest(bytes(2), policy));
});

test('receipt and acknowledgement encodings bind context and preserve exact Noir input values', async () => {
  const slot = { nonce: bytes(4), group: bytes(5), contactPolicy: bytes(6) };
  const resolution = { historyDigest: bytes(7), ed25519ReceiptDigest: bytes(8), kind: 2, issuedAt: 123 };
  const receipt = receiptBytes(bytes(1), bytes(2), bytes(3), slot, bytes(9), resolution);
  assert.equal(new TextDecoder().decode(receipt.slice(0, 27)), 'cmsg.accounting-receipt.v1\0');
  assert.notDeepEqual(receipt, receiptBytes(bytes(1), bytes(2), bytes(3), slot, bytes(9),
    { ...resolution, issuedAt: 124 }));
  assert.notDeepEqual(await receiptDigest(receipt, bytes(10)), await receiptDigest(receipt, bytes(11)));
  const ack = ackBytes(bytes(1), bytes(2), bytes(3), slot, bytes(10), bytes(9), 123);
  assert.notDeepEqual(ack, ackBytes(bytes(1), bytes(3), bytes(2), slot, bytes(10), bytes(9), 123));
  assert.notDeepEqual(ack, ackBytes(bytes(1), bytes(2), bytes(3), slot, bytes(11), bytes(9), 123));
  assert.throws(() => ackBytes(bytes(1), bytes(2), bytes(3), slot, bytes(10), bytes(9), SAFE + 1n));
  assert.deepEqual(noirInput({ data: new Uint8Array([0, 255]), values: [0n, SAFE, 17, null, true, 'proof'],
    nested: { empty: [] } }), { data: [0, 255], values: ['0', String(SAFE), '17', null, true, 'proof'],
    nested: { empty: [] } });
});

test('checkpoint duplicate guard compares member bytes across equivalent text encodings', async () => {
  // Only the input guard is under test here; these inert callbacks make no proof claim.
  const hashes = { enrollmentNode: async () => 0n, enrollment: async () => 1n };
  const memberId = Buffer.from(bytes(2)).toString('base64url');
  const entry = { memberId, accountKey: '05'.repeat(64), secretHash: hex(fieldBytes(1n)),
    issuedAt: 1, expiresAt: 100, delegationDigest: hex(bytes(6)) };
  for (const alias of [memberId + '=', ' ' + memberId + '\n']) {
    await assert.rejects(checkpointFromVerified(bytes(1), [entry, { ...entry, memberId: alias }], hashes),
      /Duplicate permanent enrollment/);
  }
  for (const length of [0, 31, 33]) {
    await assert.rejects(checkpointFromVerified(bytes(1), [{ ...entry,
      memberId: Buffer.alloc(length, 2).toString('base64url') }], hashes), /Expected bytes32/);
  }
});

test('real Poseidon2 integration preserves authenticated paths and account bindings without proof generation', async t => {
  const { Barretenberg, BackendType } = await import('@aztec/bb.js');
  // Hashing needs no SRS, downloaded setup, network service or proof generation.
  const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true,
    memory: { initial: 2048, maximum: 32768 } });
  t.after(() => api.destroy());
  const hashes = accountHashes(api), legacy = hashesFor(POSEIDON_SCHEME, async () => api);
  const community = bytes(1), owner = bytes(2), secret = bytes(3), peer = bytes(4);
  async function rootFromPath(node, leaf, index, path) {
    let value = leaf, position = BigInt(index);
    for (const sibling of path) {
      value = position & 1n ? await node(sibling, value) : await node(value, sibling);
      position >>= 1n;
    }
    return value;
  }

  await t.test('wrappers retain upstream compatibility and separate account domains', async () => {
    const secretHash = await hashes.secretHash(community, secret);
    assert.deepEqual(secretHash, await legacy.secretHash(community, secret));
    assert.equal(await hashes.marker(community, secret, owner, peer, bytes(5)),
      fieldValue(await legacy.marker(community, secret, owner, peer, bytes(5))));
    assert.equal(await hashes.enrollmentNode(4n, 5n), fieldValue(await legacy.node(fieldBytes(4n), fieldBytes(5n))));
    assert.notEqual(await hashes.node(4n, 5n), await hashes.enrollmentNode(4n, 5n));
    assert.notEqual(await hashes.pairKey(community, owner, secret, peer),
      await hashes.pairKey(community, peer, secret, owner));
    assert.throws(() => hashes.mapLeaf([0n, 0n, 0n]), /Map leaf arity/);
    const entry = { key: new Uint8Array(64).fill(5), secretHash, start: 1, end: 100,
      delegationDigest: bytes(6) };
    assert.notEqual(await hashes.enrollment(community, owner, entry),
      await hashes.enrollment(community, owner, { ...entry, delegationDigest: bytes(7) }));
    const state = { available: 3, reserved: 1n << 64n, outgoingRoot: 8n, outgoingCount: 1,
      incomingRoot: 9n, incomingCount: 1, pairRoot: 10n, pairCount: 1, frontier: 11, createdAt: 1,
      admissionEpoch: 10, admissions: 2, blind: bytes(12) };
    assert.notEqual(await hashes.state(community, owner, bytes(13), secretHash, 1, state),
      await hashes.state(community, owner, bytes(13), secretHash, 2, state));
    const slot = { role: 0, peer, nonce: bytes(14), group: bytes(15), contactPolicy: bytes(16), amount: 1,
      admittedAt: 20, expiresAt: 100, peerAuthority: 17n, ownerAuthority: 18n };
    assert.notEqual(await hashes.obligation(19n, slot, 0), await hashes.obligation(19n, slot, 1));
  });

  await t.test('sparse paths authenticate boundary indices and clones cannot mutate prior roots', async () => {
    const tree = await SparseTree.create(hashes.node), initial = tree.root;
    assert.equal(tree.path(0).length, DEPTH);
    await tree.set(LIMIT - 1n, 21n);
    assert.notEqual(tree.root, initial);
    assert.equal(await rootFromPath(hashes.node, 21n, LIMIT - 1n, tree.path(LIMIT - 1n)), tree.root);
    assert.equal(await rootFromPath(hashes.node, 0n, 0n, tree.path(0n)), tree.root);
    const copy = tree.clone(), original = tree.root;
    await copy.set(0, 22n);
    assert.equal(tree.root, original);
    assert.notEqual(copy.root, original);
    assert.throws(() => tree.path(LIMIT), /Integer bound/);
    await assert.rejects(tree.set(-1, 1n), /Integer bound/);
    await assert.rejects(tree.set(0, FR_MODULUS), /BN254 scalar range/);
  });

  await t.test('indexed insertion authenticates the predecessor before appending and updates remain isolated', async () => {
    let map = await IndexedMap.create(hashes);
    assert.equal(map.count, 1n);
    for (const key of [20n, 10n, 30n]) {
      const previous = map.root, count = map.count;
      const { witness, next } = await map.insert(key, key + 100n);
      assert.equal(await rootFromPath(hashes.node, await hashes.mapLeaf(witness.leaf), witness.index, witness.path), previous);
      const updatedLow = [witness.leaf[0], witness.leaf[1], count, key];
      const intermediate = await rootFromPath(hashes.node, await hashes.mapLeaf(updatedLow), witness.index, witness.path);
      assert.equal(await rootFromPath(hashes.node, 0n, count, witness.append_path), intermediate);
      const added = [key, key + 100n, witness.leaf[2], witness.leaf[3]];
      assert.equal(await rootFromPath(hashes.node, await hashes.mapLeaf(added), count, witness.append_path), next.root);
      assert.equal(map.root, previous);
      map = next;
    }
    const original = map.root, before = map.find(20n)[1][1];
    const { next } = await map.update(20n, 500n);
    assert.equal(next.find(20n)[1][1], 500n);
    assert.equal(map.find(20n)[1][1], before);
    assert.equal(map.root, original);
    assert.notEqual(next.root, original);
    const witness = map.witness(0n);
    witness.leaf[0] = 99n;
    assert.equal(map.witness(0n).leaf[0], 0n);
    for (const key of [0n, 10n]) assert.throws(() => map.absence(key), /already present or sentinel/);
    assert.throws(() => map.witness(31n), /Missing map leaf/);
    await assert.rejects(map.update(0n, 1n), /Unknown map key/);
    await assert.rejects(map.update(40n, 1n), /Unknown map key/);
    const full = map.clone(); full.count = LIMIT;
    await assert.rejects(full.insert(40n, 1n), /exhausted/);
    const malformed = new IndexedMap(hashes, map.tree.clone());
    assert.throws(() => malformed.absence(1n), /No authenticated ordered gap/);
  });

  await t.test('verified enrollment checkpoints bind every entry and reject malformed trusted inputs', async () => {
    const entry = { memberId: Buffer.from(owner).toString('base64url'), accountKey: '05'.repeat(64),
      secretHash: hex(await hashes.secretHash(community, secret)), issuedAt: 1, expiresAt: 100,
      delegationDigest: hex(bytes(6)) };
    const second = { ...entry, memberId: Buffer.from(peer).toString('base64url') };
    const checkpoint = await checkpointFromVerified(community, [entry, second], hashes);
    assert.equal(checkpoint.entries.length, 2);
    for (const item of checkpoint.entries) {
      assert.equal(await rootFromPath(hashes.enrollmentNode, item.leaf, item.index, item.path), checkpoint.root);
    }
    for (const entries of [null, [], Array(65537).fill(entry)]) {
      await assert.rejects(checkpointFromVerified(community, entries, hashes), /checkpoint bound/);
    }
    await assert.rejects(checkpointFromVerified(community, [entry, entry], hashes), /Duplicate permanent enrollment/);
    await assert.rejects(checkpointFromVerified(community, [entry, { ...entry, memberId: entry.memberId + '=' }], hashes),
      /Duplicate permanent enrollment/);
    for (const mutation of [{ accountKey: '05'.repeat(63) }, { issuedAt: 0 }, { expiresAt: 1 },
      { issuedAt: SAFE + 1n }, { secretHash: 'ff'.repeat(32) }, { delegationDigest: '06'.repeat(31) },
      { delegationDigest: '00'.repeat(32) }, { memberId: 'not-a-member' }]) {
      await assert.rejects(checkpointFromVerified(community, [{ ...entry, ...mutation }], hashes));
    }
  });
});
