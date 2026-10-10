import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp, mkdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {loadArtifacts} from '../../runtime/extensions/artifacts.mts';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');

test('extension artifact JSON is decoded from bounded bytes before selecting a circuit', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cblc-extension-artifacts-'));
  const configPath = join(directory, 'config.json');
  const circuits = {update: {bytecode: 'fixture'}, deposit: {bytecode: 'fixture'}, record: {bytecode: 'fixture'}};
  // These are parser inputs only: no verifier or successful proof is constructed.
  const keys = {update: '0102', deposit: '0304', record: '0506'};
  const circuitBytes = Buffer.from(JSON.stringify(circuits));
  const keyBytes = Buffer.from(JSON.stringify(keys));
  const g1 = new Uint8Array(32), g2 = new Uint8Array(128);
  const manifest = {version: 1, accountingMode: 'account-extension-v1',
    compiler: '1.0.0-beta.26', backend: '5.0.0', verifierTarget: 'noir-recursive',
    numPoints: 1, circuitSha256: digest(circuitBytes), vkSha256: digest(keyBytes),
    setup: [
      {name: 'g1.dat', bytes: g1.length, sha256: digest(g1)},
      {name: 'g2.dat', bytes: g2.length, sha256: digest(g2)},
    ]};
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  try {
    await mkdir(join(directory, 'setup'));
    await Promise.all([
      writeFile(configPath, JSON.stringify({directory, manifestSha256: digest(manifestBytes)})),
      writeFile(join(directory, 'manifest.json'), manifestBytes),
      writeFile(join(directory, 'circuits.json'), circuitBytes),
      writeFile(join(directory, 'keys.json'), keyBytes),
      writeFile(join(directory, 'setup/g1.dat'), g1),
      writeFile(join(directory, 'setup/g2.dat'), g2),
    ]);
    const loaded = await loadArtifacts(configPath);
    assert.equal(loaded.manifest.accountingMode, 'account-extension-v1');
    assert.equal(Buffer.from(loaded.scope.circuitDigest).toString('hex'), digest(circuitBytes));
    assert.equal(Buffer.from(loaded.scope.verifyingKeyDigest).toString('hex'), digest(keyBytes));
    for (const kind of ['update', 'deposit', 'record']) {
      const artifact = loaded.artifacts(kind);
      assert.deepEqual(artifact.circuit, circuits[kind]);
      assert.equal(Buffer.from(artifact.verificationKey).toString('hex'), keys[kind]);
      assert.deepEqual(artifact.setup['g1.dat'], g1);
      assert.deepEqual(artifact.setup['g2.dat'], g2);
    }
    assert.throws(() => loaded.artifacts('record_epoch'), /Record epoch circuit unavailable/);
    assert.throws(() => loaded.artifacts('other'), /Circuit domain/);
    await writeFile(join(directory, 'circuits.json'), '{}');
    await assert.rejects(loadArtifacts(configPath), /Artifact authentication/);
    await writeFile(join(directory, 'manifest.json'), '{}');
    await assert.rejects(loadArtifacts(configPath), /Manifest authentication/);
    await writeFile(configPath, new Uint8Array([0xff]));
    await assert.rejects(loadArtifacts(configPath), TypeError);
    await assert.rejects(loadArtifacts('relative.json'), /Absolute trusted/);
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
});

test('optional record epoch artifacts require one authenticated circuit and key pair', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cblc-record-epoch-artifacts-'));
  const configPath = join(directory, 'config.json');
  // Parser and filesystem vectors only. These bytecodes, keys and setup points
  // are never supplied to a prover/verifier and grant no proof authority.
  const legacyCircuits = {update: {bytecode: 'fixture'}, deposit: {bytecode: 'fixture'}, record: {bytecode: 'fixture'}};
  const legacyKeys = {update: '0102', deposit: '0304', record: '0506'};
  const circuits = {...legacyCircuits, record_epoch: {bytecode: 'record-parser-fixture'}};
  const keys = {...legacyKeys, record_epoch: '0708'};
  const g1 = new Uint8Array(32), g2 = new Uint8Array(128);
  async function writeBundle(programs, verificationKeys) {
    const circuitBytes = Buffer.from(JSON.stringify(programs));
    const keyBytes = Buffer.from(JSON.stringify(verificationKeys));
    const manifest = {version: 1, accountingMode: 'account-extension-v1',
      compiler: '1.0.0-beta.26', backend: '5.0.0', verifierTarget: 'noir-recursive',
      numPoints: 1, circuitSha256: digest(circuitBytes), vkSha256: digest(keyBytes),
      setup: [
        {name: 'g1.dat', bytes: g1.length, sha256: digest(g1)},
        {name: 'g2.dat', bytes: g2.length, sha256: digest(g2)},
      ]};
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    await Promise.all([
      writeFile(configPath, JSON.stringify({directory, manifestSha256: digest(manifestBytes)})),
      writeFile(join(directory, 'manifest.json'), manifestBytes),
      writeFile(join(directory, 'circuits.json'), circuitBytes),
      writeFile(join(directory, 'keys.json'), keyBytes),
      writeFile(join(directory, 'setup/g1.dat'), g1),
      writeFile(join(directory, 'setup/g2.dat'), g2),
    ]);
    return {circuitBytes, keyBytes};
  }
  try {
    await mkdir(join(directory, 'setup'));
    const {circuitBytes, keyBytes} = await writeBundle(circuits, keys);
    const loaded = await loadArtifacts(configPath);
    const selected = loaded.artifacts('record_epoch');
    assert.deepEqual(selected.circuit, circuits.record_epoch);
    assert.equal(Buffer.from(selected.verificationKey).toString('hex'), keys.record_epoch);
    assert.equal(Buffer.from(loaded.scope.circuitDigest).toString('hex'), digest(circuitBytes));
    assert.equal(Buffer.from(loaded.scope.verifyingKeyDigest).toString('hex'), digest(keyBytes));
    assert.throws(() => loaded.artifacts('recordEpoch'), /Circuit domain/);
    await writeFile(join(directory, 'circuits.json'), JSON.stringify({...circuits, record_epoch: {bytecode: 'changed'}}));
    await assert.rejects(loadArtifacts(configPath), /Artifact authentication/);
    await writeFile(join(directory, 'circuits.json'), circuitBytes);
    await writeFile(join(directory, 'keys.json'), JSON.stringify({...keys, record_epoch: '090a'}));
    await assert.rejects(loadArtifacts(configPath), /Artifact authentication/);
    for (const [programs, verificationKeys] of [
      [circuits, legacyKeys],
      [legacyCircuits, keys],
      [{...circuits, record_epoch: null}, keys],
      [circuits, {...keys, record_epoch: ''}],
    ]) {
      await writeBundle(programs, verificationKeys);
      await assert.rejects(loadArtifacts(configPath), /Incomplete record epoch artifact pair/);
    }
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
});
