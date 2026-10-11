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
export async function proveUpdateConformance(api, program, verificationKey, producer, transition) {
  const secret = new Uint8Array(32).fill(20);
  let witness;
  try {
    const hashes = extensionHashes(api);
    const community = new Uint8Array(createHash('sha256').update('alpha').digest());
    const key = generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).publicKey.export({format: 'jwk'});
    const entries = [{memberId: createHash('sha256').update(Buffer.alloc(48, 7)).digest('base64url'),
      accountKey: Buffer.concat([Buffer.from(key.x, 'base64url'), Buffer.from(key.y, 'base64url')]).toString('hex'),
      secretHash: hex(await hashes.secretHash(community, secret)), issuedAt: 1, expiresAt: 10000,
      delegationDigest: hex(new Uint8Array(32).fill(30))}];
    const checkpoint = await checkpointFromVerified(community, entries, hashes);
    const policy = {initialCredit: 3, maximumAvailable: 3, outgoingReservation: 1, incomingReservation: 1,
      policyRevision: 1, policyValidFrom: 1, policyValidUntil: 2000, newcomerPeriod: 100,
      rateWindow: 10, newcomerAdmissions: 8, maximumAdmissions: 8, refillPeriod: 10,
      refillUnits: 1, abandonAfter: 100};
    const extension = {revision: 1, publicRecordQuorum: 2, changeTokenCost: 1,
      depositDelaySeconds: 10, minimumDepositBatch: 2};
    const candidate = await ExtensionWitness.genesis({hashes, community, policy, extension,
      transition,
      checkpoint, ownerIndex: 0, ownerSecret: secret, now: 110});
    const expected = publicInputs(program, candidate.input);
    assert.equal(expected.length, 345);
    const executed = await new Noir(program).execute(witnessInputs(program, candidate.input));
    witness = executed.witness;
    const backend = new UltraHonkBackend(program.bytecode, api);
    const proof = await backend.generateProof(witness, OPTIONS);
    assert(proof.proof.length > 0 && proof.proof.length <= 1024 * 1024);
    assert.equal(proof.publicInputs.length, expected.length);
    assert(proof.publicInputs.every((n, i) => BigInt(n) === BigInt(expected[i])));
    const verifier = new UltraHonkVerifierBackend(api);
    assert(await verifier.verifyProof({...proof, verificationKey}, OPTIONS));
    const refuses = async changed => {
      let accepted = false;
      try { accepted = await verifier.verifyProof(changed, OPTIONS); } catch { /* Refusal. */ }
      assert.equal(accepted, false);
    };
    const corrupt = new Uint8Array(proof.proof); corrupt[0] ^= 1;
    await refuses({...proof, proof: corrupt, verificationKey});
    const changed = [...proof.publicInputs]; changed[0] = '0x' + (BigInt(changed[0]) ^ 1n).toString(16).padStart(64, '0');
    await refuses({...proof, publicInputs: changed, verificationKey});
    const receipt = {version: 1, relation: 'original-update-genesis', authority: 'none',
      ...producer.receipt, verifierTarget: OPTIONS.verifierTarget, publicInputCount: expected.length,
      compressedBytecodeSha256: sha(Buffer.from(program.bytecode, 'base64')), verificationKeySha256: sha(verificationKey),
      proofSha256: sha(proof.proof)};
    // Public data only. It is associated with the complete group by the caller
    // after every key and the honest manifest have been generated successfully.
    return {receipt, communityId: 'alpha', policy, extension,
      account: candidate.statement, proof: hex(proof.proof)};
  } catch {
    throw new Error('Original native producer conformance refused');
  } finally {
    secret.fill(0);
    witness?.fill(0);
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
  const activation = {account: value.account, proof: encodeBundle([{state: value.account.nextState,
    inbox: Array(32).fill(0), proof: value.proof}])};
  const output = {version: 1, use: 'alpha-startup-activation-probe', authority: 'none',
    communityId: value.communityId, policy: value.policy, extension: value.extension, activation,
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
  const file = `alpha-activation-${manifestSha256}-${value.receipt.proofSha256}.json`;
  const path = resolve(process.env.ARTIFACT_ROOT, file);
  try { await writeFile(path, bytes, {flag: 'wx', mode: 0o644}); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await boundedFile(path, 4 * 1024 * 1024);
    if (!Buffer.from(existing).equals(bytes)) throw new Error('Retained activation differs');
  }
  console.log(`ALPHA_ACTIVATION_ARTIFACT ${JSON.stringify({file, sha256: sha(bytes), manifestSha256})}`);
  return output;
}
