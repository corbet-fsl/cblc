// Recheck the real public proof trace against an instrumented fresh issuer.
// No witness, mock verifier, accepting stub or production member data is used.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {createHash} from 'node:crypto';

const recordDiagnostic=process.argv.length===3&&process.argv[2]==='--record-diagnostic';
if(process.argv.length!==2&&!recordDiagnostic)throw new Error('Unknown extension replay selector');
if(recordDiagnostic&&!process.env.CBLC_EXTENSION_DIRECTORY)throw new Error('Separate diagnostic artifact directory required');
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test'),tracePath=resolve(directory,'public-trace.json');
assert.equal(JSON.parse(await readFile(resolve(directory,'results.json'))).validationScope,recordDiagnostic?'g2-record-diagnostic':'full-extension');
assert((await stat(tracePath)).size <= 256*1024*1024);
const traceBytes=await readFile(tracePath),trace=JSON.parse(traceBytes);
assert(Array.isArray(trace)&&trace.length>0&&trace.length<=256);
// Replay checks and signed public material using the ORIGINAL public epoch pair.
// The actual verifier, signer and challenge state stay live.
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const authorityPath=resolve(directory,'public-epoch-authority.json');
assert((await stat(authorityPath)).size<=8*1024*1024);
const authorityBytes=await readFile(authorityPath),authority=JSON.parse(authorityBytes);
assert.deepEqual(Object.keys(authority).sort(),['checks','snapshots','traceSha256','version']);
assert.equal(authority.version,1);assert.equal(authority.traceSha256,digest(traceBytes));
assert(Array.isArray(authority.snapshots)&&authority.snapshots.length>0&&authority.snapshots.length<=16);
assert(Array.isArray(authority.checks)&&authority.checks.length>0&&authority.checks.length<=128);
const snapshots=new Set();
for(const snapshot of authority.snapshots){
  assert.deepEqual(Object.keys(snapshot).sort(),['rows','sha256']);
  assert(Array.isArray(snapshot.rows)&&snapshot.rows.length===2);
  assert(snapshot.rows.every(row=>typeof row==='string'&&row.length>0&&row.length<=128*1024&&row.length%2===0&&/^[0-9a-f]+$/.test(row)));
  assert.equal(snapshot.sha256,digest(JSON.stringify(snapshot.rows)));
  assert(!snapshots.has(snapshot.sha256));snapshots.add(snapshot.sha256);
}
const epochChecks=new Map();
for(const check of authority.checks){
  assert.deepEqual(Object.keys(check).sort(),['index','requestSha256','snapshotSha256']);
  assert(Number.isInteger(check.index)&&check.index>=0&&check.index<trace.length&&!epochChecks.has(check.index));
  assert(['checkEpochRecord','publication'].includes(trace[check.index].request.op));
  assert.equal(check.requestSha256,digest(JSON.stringify(trace[check.index].request)));
  assert(snapshots.has(check.snapshotSha256));epochChecks.set(check.index,check);
}
assert.deepEqual([...epochChecks.keys()],trace.flatMap((item,index)=>['checkEpochRecord','publication'].includes(item.request.op)?[index]:[]));
const configPath=resolve(directory,'config.json'),config=JSON.parse(await readFile(configPath,'utf8'));
config.directory=directory;await writeFile(configPath,JSON.stringify(config));
const executable=resolve(process.env.CBLC_EXTENSION_ISSUER);
const child=spawn(executable,[configPath,'--replay-public-authority',authorityPath,digest(authorityBytes)],{stdio:['pipe','pipe','inherit']});
const exited=once(child,'exit');
const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
async function call(request) {
  const bytes=JSON.stringify(request);assert(bytes.length<=16*1024*1024);
  child.stdin.write(bytes+'\n');
  const line=await lines.next();assert(!line.done);
  return JSON.parse(line.value);
}
let adversaries=0;
async function refuse(original,mutate,error) {
  const request=structuredClone(original);mutate(request);
  assert.deepEqual(await call(request),{ok:false,error});adversaries++;
}
// Mutate real public evidence at the actual issuer boundary. These cases never
// supply an accepting substitute or manufacture a new private witness.
async function recordAdversaries(request) {
  for(const [mutate,error] of [
    [r=>{r.record.context.challenge.fill(0);},'Admission'],
    [r=>{r.record.context.expiresAt=r.now;},'Expired'],
    [r=>{r.record.context.expiresAt=r.now+101;},'Expired'],
    [r=>{r.record.community[0]^=1;},'InvalidInput'],
    [r=>{r.proof='';},'InvalidInput'],
    [r=>{r.proof='00'.repeat(4*1024*1024+1);},'InvalidInput'],
    [r=>{r.record.shares=[1,2,3];},'InvalidInput'],
    [r=>{r.record.owner.fill(255);},'Admission'],
    [r=>{r.record.version+=1;},'Replay'],
    [r=>{r.record.state[31]^=1;},'Replay'],
    [r=>{r.record.inbox.root[31]^=1;},'Replay'],
    [r=>{r.record.context.purpose='firstContact';},'CryptoProvider'],
    [r=>{r.record.context.challenge[0]^=1;},'CryptoProvider'],
  ]) await refuse(request,mutate,error);
}
async function depositAdversaries(request) {
  for(const mutate of [
    r=>{r.batch=[];},
    r=>{r.batch=r.batch.slice(0,1);},
    r=>{r.batch=Array.from({length:65},()=>({...r.batch[0],proof:''}));},
    r=>{r.batch=[r.batch[0],r.batch[0]];},
    r=>{r.batch[0].deposit.community[0]^=1;},
    r=>{r.batch[0].deposit.releaseEpoch=0;},
    r=>{r.batch[0].deposit.releaseEpoch=Number.MAX_SAFE_INTEGER;},
    r=>{r.batch[0].proof='';},
    r=>{r.batch[0].proof='00'.repeat(4*1024*1024+1);},
    ...['recipient','nullifier','authorizationNullifier','obligation'].map(
      field=>r=>{r.batch[0].deposit[field].fill(0);}),
  ]) await refuse(request,mutate,'InvalidInput');
  await refuse(request,r=>{r.batch[0].deposit.recipient.fill(255);},'Admission');
}
const checked=new Set();
try {
  for(const [index,item] of trace.entries()) {
    const first=item.response.ok&&!checked.has(item.request.op);
    if(first&&item.request.op==='record') await recordAdversaries(item.request);
    if(first&&item.request.op==='deposit') await depositAdversaries(item.request);
    if(epochChecks.has(index))assert.deepEqual(await call({op:'replayPublicEpoch',index}),{ok:true,value:true});
    assert.deepEqual(await call(item.request),item.response,`Exact replay trace index ${index}, ${item.request.op}`);
    if(first&&item.request.op==='deposit') {
      await refuse(item.request,r=>{r.batch[0].deposit.obligation[31]^=1;},'Replay');
      await refuse(item.request,r=>{r.batch[0].deposit.nullifier[31]^=1;},'Replay');
    }
    if(item.response.ok) checked.add(item.request.op);
  }
  child.stdin.end();
  const [code]=await exited;assert.equal(code,0);
} catch(error) {child.kill();await exited;throw error;}
assert(checked.has('record')&&checked.has('deposit'));
console.log(`Replayed ${trace.length} real-proof issuer calls and ${adversaries} adversaries with exact outcomes`);
await writeFile(resolve(directory,'public-epoch-replay-receipt.json'),JSON.stringify({
  authoritySha256:digest(authorityBytes),traceSha256:digest(traceBytes),
  checks:epochChecks.size,snapshots:snapshots.size,
  authority:'original issuer public publication rows; restored after each exact check or signed publication',
  privateWitnessRetained:false,exactVerdicts:true,
}));

// Recheck the counterpart evidence independently, using this build's actual
// Wallet verifier and original signed public material. Never replay it at issuer.
if(!recordDiagnostic){
const waveTracePath=resolve(directory,'public-wave-trace.json');
assert((await stat(waveTracePath)).size<=64*1024*1024);
const waveTrace=JSON.parse(await readFile(waveTracePath,'utf8'));
assert(Array.isArray(waveTrace)&&waveTrace.length>0&&waveTrace.length<=128);
const {fileURLToPath}=await import('node:url');
const peer=spawn(resolve(process.env.CBLC_WAVE_VERIFIER??'target/debug/examples/wave_verifier'),
  [configPath,resolve(directory,'wave-policy.json'),fileURLToPath(import.meta.resolve('@corbet-labs/czkp/node-verifier'))],
  {stdio:['pipe','pipe','inherit']});
const peerExited=once(peer,'exit'),peerLines=createInterface({input:peer.stdout})[Symbol.asyncIterator]();
let accepted=0,refused=0;
try {
  for(const item of waveTrace){
    const bytes=JSON.stringify(item.request);assert(bytes.length<=3*1024*1024);
    peer.stdin.write(bytes+'\n');
    const response=await peerLines.next();assert(!response.done);
    const verdict=JSON.parse(response.value);
    assert.deepEqual(Object.keys(verdict).sort(),['diagnostic','verified']);
    assert.equal(verdict.verified,item.verified);
    if(item.verified)assert.equal(verdict.diagnostic,null);
    else assert.equal(typeof verdict.diagnostic,'string');
    if(item.verified)accepted++;else refused++;
  }
  peer.stdin.end();const [code]=await peerExited;assert.equal(code,0);
}catch(error){peer.kill();await peerExited;throw error;}
assert.equal(accepted,6);assert(refused>=58);
assert.deepEqual(new Set(waveTrace.filter(x=>x.verified).map(x=>x.request.expectedOutcome??"active")),new Set(["active","answer","close","silence"]));
console.log(`Replayed ${accepted} actual member Wave proofs and ${refused} refusals`);
}

// Original R2 proofs bind the public epoch, certified blinded leaf and
// presentation key. The separately signed challenge was checked above; no private
// HPKE plaintext or ancestry signature is retained.
const {loadArtifacts}=await import('../runtime/extensions/artifacts.mjs');
const {verify:verifyExtension}=await import('../runtime/extensions/node-verifier.mjs');
const epochPath=resolve(directory,'public-record-epoch-proofs.json');
assert((await stat(epochPath)).size<=64*1024*1024);
const epochProofs=JSON.parse(await readFile(epochPath));
assert.equal(epochProofs.length,recordDiagnostic?2:3);
const epochArtifacts=await loadArtifacts(configPath);
for(const proof of epochProofs){
  assert.deepEqual(Object.keys(proof.statement.record).sort(),['blindedLeaf','certificate','epoch','owner','presentationKey','shares']);
  await verifyExtension(proof,epochArtifacts);
  const replay=structuredClone(proof);replay.statement.record.presentationKey[0]^=1;
  await assert.rejects(verifyExtension(replay,epochArtifacts));
}
console.log(`Replayed ${epochProofs.length} original exact/descended record-epoch proofs (${recordDiagnostic?'diagnostic only':'full extension suite'})`);
