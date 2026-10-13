// Producer conformance only. No membership, admission or initialized account.
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {realpath, stat, writeFile} from 'node:fs/promises';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {UltraHonkBackend, UltraHonkVerifierBackend} from '@aztec/bb.js';
import {Noir} from '@noir-lang/noir_js';
import {ExtensionWitness, extensionHashes, checkpointFromVerified} from '@corbet-labs/cwlt/extensions';
import {OPTIONS, hex, unhex} from '@corbet-labs/czkp/encoding';
import {publicInputs, witnessInputs} from '@corbet-labs/czkp/abi';
import {boundedFile} from '../../runtime/bounded-file.ts';
import {originalForeignVerificationKey, verifyOriginalNative} from './native-conformance.mts';
import {STANDING,STANDING_DIGEST,STANDING_TABLES} from './standing-fixture.mts';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const json = bytes => JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));

// Select only the actually installed, locked package's bundled native binary.
// An ambient BB_BINARY_PATH must not make a package label describe another tool.
export async function selectedProducer() {
  if (process.env.BB_BINARY_PATH || process.env.BB_WASM_PATH) {
    throw new Error('Producer backend override is unavailable');
  }
  let root = dirname(fileURLToPath(import.meta.resolve('@aztec/bb.js')));
  let metadata;
  for (let depth = 0; depth < 8; depth++) {
    try {
      const candidate = json(await boundedFile(join(root, 'package.json'), 65536));
      if (candidate.name === '@aztec/bb.js') { metadata = candidate; break; }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const parent = dirname(root);
    if (parent === root) break;
    root = parent;
  }
  if (metadata?.version !== '5.2.1') throw new Error('Producer conformance version unavailable');
  const lockBytes = await boundedFile(resolve('package-lock.json'), 8 * 1024 * 1024);
  const packages = json(lockBytes).packages;
  const selected = Object.keys(packages).filter(path => path === 'node_modules/@aztec/bb.js'
    || path.endsWith('/node_modules/@aztec/bb.js'));
  if (selected.length !== 1) throw new Error('Producer backend identities differ');
  const locked = packages['node_modules/@aztec/bb.js'];
  if (locked?.version !== metadata.version || !/^sha512-[A-Za-z0-9+/]+=*$/.test(locked.integrity ?? '')) {
    throw new Error('Producer lock identity differs');
  }
  if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Native producer platform unavailable');
  const bundled = join(root, 'build/amd64-linux/bb');
  const bbPath = await realpath(bundled);
  if (bbPath !== bundled) throw new Error('Bundled producer path differs');
  const before = await stat(bbPath);
  if (!before.isFile() || before.size < 1 || before.size > 512 * 1024 * 1024 || !(before.mode & 0o111)) {
    throw new Error('Bundled producer bound');
  }
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(bbPath)) {
    size += chunk.length;
    if (size > 512 * 1024 * 1024) throw new Error('Bundled producer bound');
    hash.update(chunk);
  }
  if (size !== before.size) throw new Error('Bundled producer changed');
  return {bbPath, receipt: {packageVersion: metadata.version, packageIntegrity: locked.integrity,
    packageLockSha256: sha(lockBytes), nativeBinarySha256: hash.digest('hex')}};
}

// Fixed original extension genesis, using the maintained holder's witness
// construction and the caller's actual initialized original setup factory.
// Its fictional public enrollment data grants no owner authority.
export async function proveUpdateConformance(api, program, verificationKey, producer, transition, nativeSetup, target) {
  const secret = new Uint8Array(32).fill(20);
  let witness;
  let stage = 'witness';
  try {
    const hashes = extensionHashes(api);
    const community = new Uint8Array(createHash('sha256').update(target?.community ?? 'alpha').digest());
    const key = generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).publicKey.export({format: 'jwk'});
    const entries = [{memberId: target?.accountMemberId ?? createHash('sha256').update(Buffer.alloc(48, 7)).digest('base64url'),
      accountKey: Buffer.concat([Buffer.from(key.x, 'base64url'), Buffer.from(key.y, 'base64url')]).toString('hex'),
      secretHash: hex(await hashes.secretHash(community, secret)), issuedAt: target ? target.observation - 1 : 1, expiresAt: target ? target.observation + 10000 : 10000,
      delegationDigest: hex(new Uint8Array(32).fill(30))}];
    const checkpoint = await checkpointFromVerified(community, entries, hashes);
    const policy = target?.accountPolicy ?? {initialCredit: 3, maximumAvailable: 3, outgoingReservation: 1, incomingReservation: 1,
      policyRevision: 1, policyValidFrom: 1, policyValidUntil: 2000, newcomerPeriod: 100,
      rateWindow: 10, newcomerAdmissions: 8, maximumAdmissions: 8, refillPeriod: 10,
      refillUnits: 1, abandonAfter: 100};
    const extension = target?.extensionPolicy ?? {revision: 1, publicRecordQuorum: 2, changeTokenCost: 1,
      depositDelaySeconds: 10, minimumDepositBatch: 2,
      standingPolicyDigest: STANDING_DIGEST};
    const candidate = await ExtensionWitness.genesis({hashes, community, policy, extension, standing: STANDING, policyTables: STANDING_TABLES,
      transition,
      checkpoint, ownerIndex: 0, ownerSecret: secret, now: target?.observation ?? 110});
    const expected = publicInputs(program, candidate.input);
    assert.equal(expected.length, 377);
    const executed = await new Noir(program).execute(witnessInputs(program, candidate.input));
    witness = executed.witness;
    const backend = new UltraHonkBackend(program.bytecode, api);
    stage = 'proof-generation';
    const proof = await backend.generateProof(witness, OPTIONS);
    stage = 'public-input-shape';
    assert(proof.proof.length > 0 && proof.proof.length <= 1024 * 1024);
    assert.equal(proof.publicInputs.length, expected.length);
    assert(proof.publicInputs.every((n, i) => BigInt(n) === BigInt(expected[i])));
    const verifier = new UltraHonkVerifierBackend(api);
    stage = 'native-js-positive';
    assert.equal(await verifier.verifyProof({...proof, verificationKey}, OPTIONS), true);
    const refuses = async changed => {
      assert.equal(await verifier.verifyProof(changed, OPTIONS), false);
    };
    const changed = [...proof.publicInputs]; changed[0] = '0x' + (BigInt(changed[0]) ^ 1n).toString(16).padStart(64, '0');
    stage = 'native-js-public-negative';
    await refuses({...proof, publicInputs: changed, verificationKey});
    let nativeVerification;
    if (nativeSetup) {
      stage = 'foreign-key-identity';
      const foreignKey = await originalForeignVerificationKey(verificationKey);
      assert.notEqual(sha(foreignKey), sha(verificationKey));
      stage = 'native-js-foreign-key-negative';
      // A key of another circuit may be rejected as malformed (throws) or verify false; both refuse.
      let foreignAccepted;
      try { foreignAccepted = await verifier.verifyProof({...proof, verificationKey: foreignKey}, OPTIONS); }
      catch (error) {
        console.error('CBLC-FOREIGN-REJECTION ' + JSON.stringify({name: error?.name, message: String(error?.message).slice(0, 300)}));
        throw error;
      }
      assert.equal(foreignAccepted, false);
      stage = 'original-raw-native-verification';
      nativeVerification = await verifyOriginalNative(proof, verificationKey, nativeSetup.setup, nativeSetup.circuitDigest);
      nativeVerification.publicInputMutation = 'native-js-verified-false';
      nativeVerification.foreignVerificationKey = 'native-js-verified-false';
    }
    const receipt = {version: 1, relation: 'original-update-genesis', authority: 'none',
      ...producer.receipt, verifierTarget: OPTIONS.verifierTarget, publicInputCount: expected.length,
      compressedBytecodeSha256: sha(Buffer.from(program.bytecode, 'base64')), verificationKeySha256: sha(verificationKey),
      proofSha256: sha(proof.proof), ...(nativeVerification ? {nativeVerification} : {})};
    // Public data only. It is associated with the complete group by the caller
    // after every key and the honest manifest have been generated successfully.
    return {receipt, communityId: target?.community ?? 'alpha', policy, extension,
      ...(target ? {configuration: target} : {}),
      account: candidate.statement, proof: hex(proof.proof), publicInputs: proof.publicInputs};
  } catch {
    // Only fixed public stage labels escape, never an upstream error or witness.
    throw new Error(`Original native producer conformance refused: ${stage}`);
  } finally {
    secret.fill(0);
    witness?.fill(0);
  }
}

// Both buffers are real canonical proofs already verified for their own public
// statement. Substitution tests the cryptographic relation without corrupting
// an upstream curve-point encoding or interpreting an API exception as false.
export async function verifyConformanceSubstitution(api, verificationKey, first, second) {
  try {
    assert.equal(first.receipt.verificationKeySha256, sha(verificationKey));
    assert.equal(second.receipt.verificationKeySha256, sha(verificationKey));
    assert.equal(first.receipt.compressedBytecodeSha256, second.receipt.compressedBytecodeSha256);
    assert.notDeepEqual(first.publicInputs, second.publicInputs);
    assert.notEqual(first.receipt.proofSha256, second.receipt.proofSha256);
    const verifier = new UltraHonkVerifierBackend(api);
    for (const [statement, alternate] of [[first, second], [second, first]]) {
      assert.equal(await verifier.verifyProof({publicInputs: statement.publicInputs,
        proof: unhex(alternate.proof), verificationKey}, OPTIONS), false);
    }
    first.receipt.nativeVerification.proofSubstitution = 'native-js-verified-false';
    second.receipt.nativeVerification.proofSubstitution = 'native-js-verified-false';
    for (const [value, alternate] of [[first, second], [second, first]]) {
      (value.receipt.nativeVerification.proofSubstitutionPeers ??= []).push(alternate.receipt.proofSha256);
    }
  } catch {
    throw new Error('Original native producer conformance refused: native-js-proof-substitution');
  }
}

// Reuse the caller's original bundle codec. These bytes are a startup relation
// probe, never a member enrollment, accepted account or private checkpoint.
export async function retainConformance(value, manifestBytes, circuitBytes, keyBytes, encodeBundle) {
  const manifest = json(manifestBytes), circuits = json(circuitBytes), keys = json(keyBytes);
  if (manifest.backend !== value.receipt.packageVersion
      || manifest.circuitSha256 !== sha(circuitBytes) || manifest.vkSha256 !== sha(keyBytes)
      || sha(unhex(keys.update)) !== value.receipt.verificationKeySha256
      || sha(Buffer.from(circuits.update.bytecode, 'base64')) !== value.receipt.compressedBytecodeSha256) {
    throw new Error('Conformance group association differs');
  }
  const manifestSha256 = sha(manifestBytes);
  assert(['alpha', 'omega'].includes(value.communityId));
  const activation = {account: value.account, proof: encodeBundle([{state: value.account.nextState,
    inbox: Array(32).fill(0), proof: value.proof}])};
  const output = {version: 1, use: `${value.communityId}-startup-activation-probe`, authority: 'none',
    communityId: value.communityId, policy: value.policy, extension: value.extension, activation,
    ...(value.configuration ? {configuration: value.configuration} : {}),
    manifestSha256, proofScope: {circuitDigest: Array.from(Buffer.from(manifest.circuitSha256, 'hex')),
      verifyingKeyDigest: Array.from(Buffer.from(manifest.vkSha256, 'hex'))}, producer: value.receipt};
  const bytes = Buffer.from(JSON.stringify(output));
  if (bytes.length > 4 * 1024 * 1024) throw new Error('Public activation bound');
  // Ordinary local corpus generation has no retention destination. The declared
  // artifact route supplies one; a supplied destination must still be absolute.
  if (process.env.ARTIFACT_ROOT === undefined) return output;
  if (!process.env.ARTIFACT_ROOT.startsWith('/')) {
    throw new Error('Public activation destination unavailable');
  }
  const file = `${value.communityId}-activation-${manifestSha256}-${value.receipt.proofSha256}.json`;
  const path = resolve(process.env.ARTIFACT_ROOT, file);
  try { await writeFile(path, bytes, {flag: 'wx', mode: 0o644}); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await boundedFile(path, 4 * 1024 * 1024);
    if (!Buffer.from(existing).equals(bytes)) throw new Error('Retained activation differs');
  }
  console.log(`SCOPED_ACTIVATION_ARTIFACT ${JSON.stringify({communityId: value.communityId, file, sha256: sha(bytes), manifestSha256})}`);
  return output;
}

// Fixed reviewed public fixture data, not caller-provided configuration or
// accepted membership. Only its operational capture path was omitted in source.
export async function alphaStartupRequest() {
  const bytes = await boundedFile('tests/holder/fixtures/alpha-native-request.json', 65536);
  if (sha(bytes) !== 'cf1bc7b2d79a2ab8d02ba9c6311dcf9895265d5faa1a2bb27e6b5d8c6129c8e6') {
    throw new Error('Reviewed alpha fixture configuration differs');
  }
  const request = json(bytes);
  assert.equal(request.purpose, 'cvld.g5-native-fixture-request.v1');
  assert.equal(request.publicParameterSource.sha256, '7b8d1d8b3448b61a8a01d412e350712621daff7b2cbb273bd8db11e37608179a');
  assert.equal(request.community, 'alpha');
  assert.equal(request.observation, 1800000000);
  assert.equal(request.policyEpoch, 4);
  assert.equal(createHash('sha256').update(Buffer.from(request.member)).digest('base64url'), request.accountMemberId);
  return request;
}

// Separately reviewed historical omega startup data. This creates no member or
// authority and must never relabel the alpha proof or renew its configured time.
export async function omegaStartupRequest() {
  const bytes = await boundedFile('tests/holder/fixtures/omega-native-request.json', 65536);
  if (sha(bytes) !== '257c8476d9d21696fc8699497ca70446507ebfa34972f8ed9df70c5236fa1ce4') {
    throw new Error('Reviewed omega fixture configuration differs');
  }
  const request = json(bytes);
  assert.equal(request.purpose, 'cmsg.omega-native-fixture-request.v1');
  assert.equal(request.community, 'omega');
  assert.equal(request.observation, 1791717800);
  assert.equal(request.accountPolicy.policyValidUntil, 1791804200);
  assert.equal(createHash('sha256').update(Buffer.alloc(48, 7)).digest('base64url'), request.accountMemberId);
  return request;
}
