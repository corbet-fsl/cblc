// CI-only holder for fictional members. Prove the actual migrated account circuit, then retain
// PUBLIC proofs/artifacts for the independent Rust issuer test. No private witness is written.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';
import { OPTIONS, hex } from '@corbet-labs/czkp/encoding';
import { accountHashes, checkpointFromVerified } from '../runtime/accounting/hashes.mjs';
import { AccountWitness } from './holder/witness.mjs';
import { createProver } from '@corbet-labs/czkp/prove';
import { noirInput } from '../runtime/accounting/hashes.mjs';
import { publicInputValues } from '../runtime/accounting/statement.mjs';
import { createAccountVerifier } from '../runtime/accounting/runtime.mjs';
import { nodeArtifactOptions } from '../runtime/accounting/node-verifier.mjs';

const directory = resolve(process.env.CBLC_PROOF_DIRECTORY ?? '.proof-test');
await mkdir(resolve(directory,'setup'),{recursive:true});
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const bytes = n => new Uint8Array(32).fill(n);
const compiled = await compile(createFileManager(resolve('experiments/private-accounting/account-state')));
assert(compiled.program?.bytecode);
const circuitBytes = Buffer.from(JSON.stringify(compiled.program));
await writeFile(resolve(directory,'circuit.json'),circuitBytes);
const lock = JSON.parse(await readFile('experiments/private-accounting/account-state/setup-lock.json'));
const setup = {};
for(const spec of lock.files) {
  const response=await fetch(spec.url,{headers:{'User-Agent':'LibraryValidation/1.0',...(spec.range?{Range:`bytes=0-${spec.bytes-1}`}:{})},redirect:'error',signal:AbortSignal.timeout(120000)});
  assert.equal(response.status,spec.range?206:200);
  const chunks=[];let size=0;
  for await(const chunk of response.body) {size+=chunk.length;assert(size<=spec.bytes);chunks.push(chunk);}
  const data=Buffer.concat(chunks);assert.equal(data.length,spec.bytes);assert.equal(digest(data),spec.sha256);
  setup[spec.name]=data;await writeFile(resolve(directory,'setup',spec.name),data);
}
const api=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true,memory:{initial:2048,maximum:32768}});
const records=[];
const needLedger=process.env.CBLC_LEDGER_FIXTURES==='1';
let candidates, ledgerCandidates, artifacts, scope;
try {
  await api.srsInitSrs({pointsBuf:setup['g1.dat'],numPoints:lock.numPoints,g2Point:setup['g2.dat']});
  const backend=new UltraHonkBackend(compiled.program.bytecode,api);
  const verificationKey=await backend.getVerificationKey(OPTIONS);
  await writeFile(resolve(directory,'vk.bin'),verificationKey);
  const manifest={version:1,compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:OPTIONS.verifierTarget,
    accountingMode:'account-state-v2',hashScheme:'poseidon2-bn254-fixed-128-v1',numPoints:lock.numPoints,
    circuitSha256:digest(circuitBytes),vkSha256:digest(verificationKey),setup:lock.files};
  const manifestBytes=Buffer.from(JSON.stringify(manifest));
  await writeFile(resolve(directory,'manifest.json'),manifestBytes);
  await writeFile(resolve(directory,'config.json'),JSON.stringify({directory,manifestSha256:digest(manifestBytes)}));
  scope={circuitDigest:Array.from(Buffer.from(manifest.circuitSha256,'hex')),verifyingKeyDigest:Array.from(Buffer.from(manifest.vkSha256,'hex'))};
  const community=new Uint8Array(createHash('sha256').update('community.example').digest());
  const hashes=accountHashes(api),entries=[];
  for(let index=0;index<2;index++) {
    const root=createPrivateKey({format:'der',type:'pkcs8',key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,7+index)])});
    const publicRoot=createPublicKey(root).export({format:'der',type:'spki'}).subarray(-32).toString('base64url');
    const memberId=createHash('sha256').update(Buffer.alloc(48, 7+index)).digest('base64url');
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
    entries.push({memberId,accountKey:Buffer.concat([Buffer.from(key.x,'base64url'),Buffer.from(key.y,'base64url')]).toString('hex'),
      secretHash:hex(await hashes.secretHash(community,bytes(10+index))),issuedAt:1,expiresAt:10000,delegationDigest:hex(bytes(30+index))});
  }
  const policy={initialCredit:3,maximumAvailable:4,outgoingReservation:1,incomingReservation:1,policyRevision:1,
    policyValidFrom:1,policyValidUntil:2000,newcomerPeriod:100,rateWindow:1000,newcomerAdmissions:2,maximumAdmissions:4,
    refillPeriod:100,refillUnits:1,abandonAfter:1000};
  const checkpoint=await checkpointFromVerified(community,entries,hashes);
  const genesis=await AccountWitness.genesis({hashes,community,policy,checkpoint,ownerIndex:0,ownerSecret:bytes(10),now:110});
  const reserve=await genesis.next.reserve({peerIndex:1,role:0,nonce:bytes(50),group:bytes(51),contactPolicy:bytes(52),now:120});
  const limits={maxBytes:1024*1024,maxMapEntries:256,maxSlots:64};
  for(const candidate of [genesis,reserve]) {
    const restored=await AccountWitness.restoreCheckpoint({hashes,enrollment:checkpoint,
      ownerSecret:bytes(10),expectedStatement:candidate.statement,
      checkpointBytes:candidate.next.exportCheckpoint(limits),limits});
    assert.equal(restored.commitment,candidate.next.commitment);
    assert.deepEqual(restored.exportCheckpoint(limits),candidate.next.exportCheckpoint(limits));
    candidate.next=restored;
  }
  candidates=[genesis,reserve];
  ledgerCandidates=[];
  if(needLedger) {
    const otherGenesis=await AccountWitness.genesis({hashes,community,policy,checkpoint,ownerIndex:1,ownerSecret:bytes(11),now:110});
    const alternate=await genesis.next.reserve({peerIndex:1,role:0,nonce:bytes(53),group:bytes(51),contactPolicy:bytes(52),now:120});
    const tuned=await genesis.next.withPolicy({...policy,abandonAfter:1500});
    const tunedReserve=await tuned.reserve({peerIndex:1,role:0,nonce:bytes(50),group:bytes(51),contactPolicy:bytes(52),now:120});
    ledgerCandidates=[otherGenesis,alternate,tunedReserve];
  }
  artifacts={circuit:compiled.program,verificationKey,manifest,setup,limits:{memoryPages:32768,maxProofBytes:1024*1024}};
} finally {await api.destroy();}
const prover=await createProver({artifacts});
const ledgerRecords=[];
try {
  for(const candidate of candidates) {
    const result=await prover.prove(noirInput(candidate.input),publicInputValues(candidate.statement));
    records.push({statement:candidate.statement,proof:hex(result.proof),proofScope:scope});
  }
  for(const candidate of ledgerCandidates) {
    const result=await prover.prove(noirInput(candidate.input),publicInputValues(candidate.statement));
    ledgerRecords.push({statement:candidate.statement,proof:hex(result.proof),proofScope:scope});
  }
} finally {await prover.destroy();}
// Verify with the shipped server entry, independently of holder proof construction.
const server=await createAccountVerifier(await nodeArtifactOptions(resolve(directory,'config.json')));
try {
  for(const record of [...records,...ledgerRecords]) {
    assert.equal((await server.verify(record)).verified,true);
    const corrupt=structuredClone(record);corrupt.proof=(corrupt.proof.startsWith('00')?'01':'00')+corrupt.proof.slice(2);
    await assert.rejects(server.verify(corrupt));
    const changed=structuredClone(record);changed.statement.nextState[31]^=1;
    await assert.rejects(server.verify(changed));
  }
} finally {await server.destroy();}
await writeFile(resolve(directory,'records.json'),JSON.stringify(records));
await writeFile(resolve(directory,'ledger-records.json'),JSON.stringify([...records,...ledgerRecords]));
console.log(`Verified ${records.length+ledgerRecords.length} real account proofs; rejected corrupted proofs and changed public inputs.`);
