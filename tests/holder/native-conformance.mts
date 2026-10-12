// Public proof verification only, using the original retained worker protocol.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {realpath, stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {boundedFile} from '../../runtime/bounded-file.ts';

const sha = value => createHash('sha256').update(value).digest();

export async function originalForeignVerificationKey() {
  const bytes = await boundedFile(resolve(process.env.ARTIFACT_ROOT, 'gather-record-fixture/keys.json'), 1024 * 1024);
  if (sha(bytes).toString('hex') !== 'e1533badd256e63b7817018ba59a5cd822f3e936a723d7f31bd85a49a6190ae0') {
    throw new Error('Original negative verification-key group differs');
  }
  const key = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)).update;
  if (!/^[0-9a-f]+$/.test(key) || key.length % 2 !== 0 || key.length > 2 * 1024 * 1024) {
    throw new Error('Original negative verification key bound');
  }
  return Buffer.from(key, 'hex');
}
const fields = values => values.map(value => {
  const encoded = BigInt(value).toString(16).padStart(64, '0');
  assert.equal(encoded.length, 64);
  return Array.from(Buffer.from(encoded, 'hex'));
});

async function execute(worker, request) {
  if (await realpath(worker) !== worker) throw new Error('Original verifier path differs');
  const file = await stat(worker);
  if (!file.isFile() || file.size !== 68078712 || (file.mode & 0o777) !== 0o755) {
    throw new Error('Original verifier file differs');
  }
  const digest = createHash('sha256');
  let read = 0;
  for await (const chunk of createReadStream(worker)) {
    read += chunk.length;
    if (read > 68078712) throw new Error('Original verifier grew');
    digest.update(chunk);
  }
  if (read !== 68078712 || digest.digest('hex') !== '5c5c69cca3ccc1d00e12d7d75bd431b79d68864b88e3c5ba18284c77f2ac46f9') {
    throw new Error('Original verifier bytes differ');
  }
  const input = Buffer.from(JSON.stringify(request));
  if (input.length > 26 * 1024 * 1024) throw new Error('Public verification input bound');
  return new Promise((resolve, reject) => {
    const child = spawn(worker, [], {env: {CZKP_NATIVE_MEMORY_MIB: '4096', RAYON_NUM_THREADS: '2', HARDWARE_CONCURRENCY: '2'},
      stdio: ['pipe', 'pipe', 'ignore']});
    const chunks = [];
    let size = 0, failed = false, timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, 240000);
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > 16384) { failed = true; child.kill('SIGKILL'); }
      else chunks.push(chunk);
    });
    child.stdin.on('error', () => { failed = true; child.kill('SIGKILL'); });
    child.once('error', () => { failed = true; });
    // close follows EOF and process reap. No early verdict or timeout result.
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (failed || timedOut || signal) reject(new Error('Original verifier lifecycle refused'));
      else resolve({code, output: Buffer.concat(chunks)});
    });
    child.stdin.end(input);
  });
}

export async function verifyOriginalNative(proof, verificationKey, setup, circuitDigest) {
  const worker = process.env.CBLC_CONFORMANCE_NATIVE_WORKER;
  if (!worker) throw new Error('Original conformance worker unavailable');
  const receipt = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(
    await boundedFile('artifact-conformance-worker.json', 65536)));
  if (receipt.metadataSha256 !== '23cf333ef4c1bb9acc401e3cf448528978d960fe793dbcc50da7a1ef54f6b212'
      || receipt.workerSha256 !== '5c5c69cca3ccc1d00e12d7d75bd431b79d68864b88e3c5ba18284c77f2ac46f9') {
    throw new Error('Original conformance worker identity differs');
  }
  const scope = {circuitDigest: Array.from(circuitDigest), verifyingKeyDigest: Array.from(sha(verificationKey))};
  const request = {scope, verificationKey: Buffer.from(verificationKey).toString('hex'),
    srsG1: setup['g1.dat'].subarray(0, 4 * 1024 * 1024).toString('hex'),
    srsG2: setup['g2.dat'].toString('hex'),
    proofs: [{publicInputs: fields(proof.publicInputs), proof: Buffer.from(proof.proof).toString('hex')}]};
  const result = await execute(worker, request);
  assert.equal(result.code, 0);
  const verdict = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(result.output));
  assert.deepEqual(Object.keys(verdict).sort(), ['proofScope', 'verified']);
  assert.equal(verdict.verified, true);
  assert.deepEqual(verdict.proofScope, scope);
  // The original binary returns the same coarse error for crypto and parsing
  // refusals. This is not a separate verified=false cryptographic verdict.
  for (const kind of ['public', 'proof', 'key']) {
    const changed = structuredClone(request);
    if (kind === 'public') changed.proofs[0].publicInputs[0][31] ^= 1;
    else if (kind === 'proof') {
      const bytes = Buffer.from(changed.proofs[0].proof, 'hex');
      bytes[bytes.length - 1] ^= 1;
      changed.proofs[0].proof = bytes.toString('hex');
    } else {
      const bytes = Buffer.from(changed.verificationKey, 'hex');
      bytes[bytes.length - 1] ^= 1;
      changed.verificationKey = bytes.toString('hex');
    }
    const refused = await execute(worker, changed);
    assert.equal(refused.code, 1);
    assert.equal(refused.output.length, 0);
  }
  return {workerSourceCommit: receipt.sourceCommit, workerSha256: receipt.workerSha256,
    metadataSha256: receipt.metadataSha256, positiveVerdict: true,
    changedPublicInput: 'coarse-worker-refusal', changedProof: 'coarse-worker-refusal', changedKey: 'coarse-worker-refusal'};
}
