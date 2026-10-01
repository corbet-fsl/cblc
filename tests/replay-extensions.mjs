// Recheck the real public proof trace against an instrumented fresh issuer.
// No witness, mock verifier, accepting stub or production member data is used.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';

const directory=resolve('.extension-test'),tracePath=resolve(directory,'public-trace.json');
assert((await stat(tracePath)).size <= 256*1024*1024);
const trace=JSON.parse(await readFile(tracePath,'utf8'));
assert(Array.isArray(trace)&&trace.length>0&&trace.length<=256);
const configPath=resolve(directory,'config.json'),config=JSON.parse(await readFile(configPath,'utf8'));
config.directory=directory;await writeFile(configPath,JSON.stringify(config));
const executable=resolve(process.env.CBLC_EXTENSION_ISSUER);
const child=spawn(executable,[configPath],{stdio:['pipe','pipe','inherit']});
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
  for(const item of trace) {
    const first=item.response.ok&&!checked.has(item.request.op);
    if(first&&item.request.op==='record') await recordAdversaries(item.request);
    if(first&&item.request.op==='deposit') await depositAdversaries(item.request);
    assert.deepEqual(await call(item.request),item.response);
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
