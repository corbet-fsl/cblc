import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DEFAULT_LIMITS, loadArtifacts, resourceLimits } from '../../runtime/accounting/artifacts.mjs';

const encode = value => new TextEncoder().encode(JSON.stringify(value));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  // Loader fixtures only: no backend is constructed and no proof is claimed.
  const files = new Map([
    ['circuit.json', encode({ bytecode: 'account-loader-fixture' })], ['vk.bin', new Uint8Array([1, 2])],
    ['setup/g1.dat', new Uint8Array(64)], ['setup/g2.dat', new Uint8Array(128)],
    ['peer-reservation/circuit.json', encode({ bytecode: 'peer-loader-fixture' })],
    ['peer-reservation/vk.bin', new Uint8Array([3, 4])], ['barretenberg-threads.wasm', new Uint8Array(9)],
  ]);
  const pin = name => ({ sha256: digest(files.get(name)), bytes: files.get(name).length });
  const manifest = { version: 1, compiler: '1.0.0-beta.26', backend: '5.0.0', verifierTarget: 'noir-recursive',
    accountingMode: 'account-state-v2', hashScheme: 'poseidon2-bn254-fixed-128-v1', numPoints: 2,
    circuitSha256: pin('circuit.json').sha256, vkSha256: pin('vk.bin').sha256,
    setup: ['g1.dat', 'g2.dat'].map(name => ({ name, ...pin('setup/' + name) })),
    peerReservation: { mode: 'peer-reservation-v3', publicInputs: 389, sharesAccountSetup: true,
      stats: { numGatesDyadic: 1 }, circuitSha256: pin('peer-reservation/circuit.json').sha256,
      vkSha256: pin('peer-reservation/vk.bin').sha256 },
    wasm: [{ name: 'barretenberg-threads.wasm', ...pin('barretenberg-threads.wasm') }] };
  const reads = [];
  return { files, manifest, reads,
    load(options = {}) {
      const manifestBytes = encode(manifest);
      return loadArtifacts({ manifestBytes, manifestSha256: digest(manifestBytes),
        readArtifact: async (name, maximum) => { reads.push([name, maximum]); return files.get(name); }, ...options });
    } };
}

test('account artifact loader pins optional peer and browser bytes and isolates returned snapshots', async () => {
  const source = fixture();
  const result = await source.load({ loadPeerReservation: true, loadBrowserWasm: true });
  assert.equal(result.peerReservation.circuit.bytecode, 'peer-loader-fixture');
  assert.deepEqual(result.browserWasm, new Uint8Array(9));
  assert.equal(result.setup['g1.dat'].length, 64);
  assert.equal(result.setup['g2.dat'].length, 128);
  assert.equal(source.reads.length, 7);
  assert(source.reads.every(([, maximum]) => maximum === DEFAULT_LIMITS.maxArtifactBytes));
  source.files.get('vk.bin').fill(255);
  source.files.get('peer-reservation/vk.bin').fill(255);
  source.files.get('barretenberg-threads.wasm').fill(255);
  assert.deepEqual(result.verificationKey, new Uint8Array([1, 2]));
  assert.deepEqual(result.peerReservation.verificationKey, new Uint8Array([3, 4]));
  assert.deepEqual(result.browserWasm, new Uint8Array(9));
  const base = fixture(), baseResult = await base.load();
  assert.equal(baseResult.peerReservation, undefined);
  assert.equal(baseResult.browserWasm, undefined);
  assert.equal(base.reads.length, 4);
});

test('resource and manifest guards reject unsupported contracts before reading artifacts', async () => {
  assert(Object.isFrozen(resourceLimits()));
  assert.deepEqual(resourceLimits(), DEFAULT_LIMITS);
  for (const limits of [{ unknown: 1 }, { maxArtifactBytes: 0 }, { maxTotalBytes: Infinity },
    { maxProofBytes: 0.5 }, { memoryPages: 2047 }, { memoryPages: DEFAULT_LIMITS.memoryPages + 1 }]) {
    assert.throws(() => resourceLimits(limits), /Invalid account resource limits/);
  }
  for (const mutation of [{ version: 2 }, { compiler: 'wrong' }, { backend: 'wrong' },
    { verifierTarget: 'wrong' }, { accountingMode: 'wrong' }, { hashScheme: 'wrong' },
    { numPoints: 0 }, { numPoints: 0.5 }, { numPoints: 9 * 131072 + 1 }, { setup: null }, { setup: [] }]) {
    const source = fixture(); Object.assign(source.manifest, mutation);
    await assert.rejects(source.load(), /Unsupported account artifacts/);
    assert.deepEqual(source.reads, []);
  }
  for (const options of [{ manifestBytes: [] }, { manifestBytes: new Uint8Array(1024 * 1024 + 1) },
    { manifestSha256: 'invalid' }, { manifestSha256: '00'.repeat(32) }]) {
    const source = fixture();
    await assert.rejects(source.load(options), /Manifest pin mismatch/);
    assert.deepEqual(source.reads, []);
  }
});

test('account artifact loader rejects content, length, setup and total-budget mismatches', async () => {
  const missingPin = fixture(); missingPin.manifest.circuitSha256 = 'invalid';
  await assert.rejects(missingPin.load(), /Missing artifact pin/);
  const wrongType = fixture(); wrongType.files.set('circuit.json', [1, 2]);
  await assert.rejects(wrongType.load(), /Artifact size bound/);
  const oversized = fixture();
  await assert.rejects(oversized.load({ limits: { maxArtifactBytes: 1 } }), /Artifact size bound/);
  const corrupt = fixture(); corrupt.files.get('vk.bin')[0] ^= 1;
  await assert.rejects(corrupt.load(), /Artifact digest\/total bound/);
  await assert.rejects(fixture().load({ limits: { maxTotalBytes: 1 } }), /Artifact digest\/total bound/);
  const noBytecode = fixture(); noBytecode.files.set('circuit.json', encode({ bytecode: '' }));
  noBytecode.manifest.circuitSha256 = digest(noBytecode.files.get('circuit.json'));
  await assert.rejects(noBytecode.load(), /Missing compiled circuit/);
  for (const change of [item => { item.name = 'other.dat'; }, item => { item.bytes = 0; },
    item => { item.bytes += 1; }]) {
    const source = fixture(); change(source.manifest.setup[0]);
    await assert.rejects(source.load(), /Invalid setup manifest|Artifact size bound/);
  }
  const duplicate = fixture(); duplicate.manifest.setup[1] = { ...duplicate.manifest.setup[0] };
  await assert.rejects(duplicate.load(), /Invalid setup manifest/);
  const wrongPoints = fixture(); wrongPoints.manifest.numPoints = 3;
  await assert.rejects(wrongPoints.load(), /Setup point count mismatch/);
});

test('optional artifact contracts refuse mismatched peer setup and browser payloads', async () => {
  for (const mutation of [{ mode: 'wrong' }, { publicInputs: 388 }, { sharesAccountSetup: false },
    { stats: {} }, { stats: { numGatesDyadic: 0 } }, { stats: { numGatesDyadic: 2 } }]) {
    const source = fixture(); Object.assign(source.manifest.peerReservation, mutation);
    await assert.rejects(source.load({ loadPeerReservation: true }), /Pinned peer circuit\/setup contract/);
  }
  const missingPeer = fixture(); delete missingPeer.manifest.peerReservation;
  await assert.rejects(missingPeer.load({ loadPeerReservation: true }), /Pinned peer circuit\/setup contract/);
  const emptyPeer = fixture(); emptyPeer.files.set('peer-reservation/circuit.json', encode({ bytecode: '' }));
  emptyPeer.manifest.peerReservation.circuitSha256 = digest(emptyPeer.files.get('peer-reservation/circuit.json'));
  await assert.rejects(emptyPeer.load({ loadPeerReservation: true }), /Missing compiled peer circuit/);
  for (const wasm of [undefined, [], [{ name: 'other.wasm' }],
    [{ name: 'barretenberg-threads.wasm', bytes: 8 }]]) {
    const source = fixture(); source.manifest.wasm = wasm;
    await assert.rejects(source.load({ loadBrowserWasm: true }), /Pinned browser Wasm required|Browser Wasm size/);
  }
  const corruptWasm = fixture(); corruptWasm.files.get('barretenberg-threads.wasm')[0] = 1;
  await assert.rejects(corruptWasm.load({ loadBrowserWasm: true }), /Artifact digest\/total bound/);
});
