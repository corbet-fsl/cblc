// Reproduce the original public worker boundary; no proof or witness generation.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat,realpath} from 'node:fs/promises';
import {resolve,isAbsolute,delimiter} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
assert(process.env.CI);
const report=resolve(process.env.CBLC_DIAGNOSTIC_OUTPUT),evidence=resolve(report,'evidence');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const load=async name=>JSON.parse(await readFile(resolve(evidence,name)));
const attempt=await load('public/public-wave-attempt.json'),material=await load('signed-payload.json');
assert.equal(attempt.sequence,0);assert.equal(attempt.expectedVerified,true);assert.deepEqual(attempt.reply,{verified:false});
const request=attempt.request,s=request.statement,c=s.context,p=material.waveVerifier.extension,w=material.waveVerifier;
assert.deepEqual(c,request.expected);
// Exact cwlt::wave::WaveVerifier::public_input projection from the tested source.
const input={extension:{revision:p.revision,quorum:p.publicRecordQuorum,change_cost:p.changeTokenCost,delay:p.depositDelaySeconds,batch:p.minimumDepositBatch},
  issuer_key:w.certificateKey,scope:w.proofScope.circuitDigest,
  community:c.community,owner:c.owner,peer:c.peer,role:c.role,nonce:c.nonce,group:c.group,contact_policy:c.contactPolicy,
  history:c.history,challenge:c.challenge,opened_at:c.openedAt,expires_at:c.expiresAt,owner_authority:c.ownerAuthority,peer_authority:c.peerAuthority,
  state_policy:s.statePolicy,version:s.version,state:s.state,accepted_at:s.acceptedAt,binding:s.binding};
const sorted=value=>Array.isArray(value)?value.map(sorted):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sorted(value[key])])):value;
// Recorded serde_json features exclude preserve_order. Value maps sort their
// keys; Request/ProofScope structs keep declaration order. Rust adds no newline.
const bytes=Buffer.from(JSON.stringify({statement:sorted({circuit:'wave',input}),proof:request.proof,
  proofScope:{circuitDigest:w.proofScope.circuitDigest,verifyingKeyDigest:w.proofScope.verifyingKeyDigest}}));
assert.deepEqual(bytes,await readFile(resolve(evidence,'worker-request.json')));
assert.match(request.proof,/^(?:[0-9a-f]{2})+$/);assert(request.proof.length<=2*1024*1024);
assert.equal(sha(Buffer.from(request.proof,'hex')),'e58d2242c77bdbeb8af3a87bbbf74bdc67685b8e4f15c089e629888ec5479f29');
assert(bytes.length<=2*1024*1024+65536);
const config=await load('public/config.json');
config.directory=resolve(evidence,'public');
const configPath=resolve(report,'replay-config.json');await writeFile(configPath,JSON.stringify(config));
const script=fileURLToPath(import.meta.resolve('@corbet-labs/czkp/node-verifier'));
const derivation=await load('derivation.json');
assert.equal(sha(await readFile(script)),derivation.sources['czkp/runtime/node-verifier.mjs'].sha256);
let node;
for(const directory of process.env.PATH.split(delimiter)){
  const candidate=resolve(directory,'node');
  if(!isAbsolute(directory))continue;
  if(await stat(candidate).then(s=>s.isFile(),()=>false)){node=candidate;break;}
}
assert(node);
const environment={...process.env};delete environment.NODE_OPTIONS;delete environment.NODE_PATH;
async function execute(args,stdin,diagnostic=false){
  const start=performance.now(),child=spawn(node,args,{cwd:process.cwd(),env:environment,stdio:['pipe','pipe',diagnostic?'pipe':'ignore']});
  let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0),wrote=false,timedOut=false,spawnError=null,writeError=null,readError=null;
  child.stdin.on('error',error=>{writeError=error.code??'write-error';});
  child.stdin.end(stdin,error=>{wrote=!error;});
  child.stdout.on('error',error=>{readError=error.code??'read-error';});
  child.stdout.on('data',chunk=>{stdout=Buffer.concat([stdout,chunk]).subarray(0,4097);if(stdout.length===4097)child.stdout.destroy();});
  if(diagnostic)child.stderr.on('data',chunk=>{stderr=Buffer.concat([stderr,chunk]).subarray(0,65536);});
  child.on('error',error=>{spawnError=error.code??'spawn-error';});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},180000);
  const [code,signal]=await new Promise(resolve=>child.once('close',(code,signal)=>resolve([code,signal])));clearTimeout(timer);
  let verdict=null,accepted=false;
  if(wrote&&!writeError&&!readError&&!timedOut&&!spawnError&&code===0&&stdout.length<=4096){
    try{verdict=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(stdout));assert.deepEqual(verdict,{verified:true,proofScope:w.proofScope});accepted=true;}catch{}
  }
  return {args,cwd:process.cwd(),stdinBytes:stdin.length,stdinSha256:sha(stdin),wrote,writeError,readError,code,signal,timedOut,spawnError,
    milliseconds:performance.now()-start,stdoutHex:stdout.toString('hex'),stderr:diagnostic?stderr.toString('utf8'):null,
    stderrDisposition:diagnostic?'bounded-diagnostic':'null',verdict,accepted};
}
await writeFile(resolve(report,'worker-bindings.json'),JSON.stringify({node,nodeRealpath:await realpath(node),nodeSha256:sha(await readFile(node)),
  script,scriptRealpath:await realpath(script),scriptSha256:sha(await readFile(script)),requestSha256:sha(bytes),
  configSha256:sha(await readFile(configPath)),removedEnvironment:['NODE_OPTIONS','NODE_PATH'],heapMegabytes:4096,timeoutSeconds:180,
  relevantEnvironment:Object.fromEntries(['UV_THREADPOOL_SIZE','RAYON_NUM_THREADS','OMP_NUM_THREADS','BB_BINARY_PATH'].map(k=>[k,environment[k]??null])),
  inheritedEnvironment:'current CI environment; original full environment was not retained',
  authorityClaim:false,proofRegeneration:false},null,2)+'\n');
const original=await execute(['--max-old-space-size=4096',script,configPath],bytes);
await writeFile(resolve(report,'original-worker-process.json'),JSON.stringify(original,null,2)+'\n');
// Recheck immutable inputs before the independent diagnostic worker import.
execFileSync('python3',['.ci/g2-wave-inputs.py','check'],{timeout:30000,stdio:['ignore','inherit','inherit']});
assert.equal(sha(await readFile(configPath)),sha(Buffer.from(JSON.stringify(config))));
// Separate diagnostic call. Its result cannot turn the original refusal green.
const imported=await execute(['--max-old-space-size=4096',resolve('.ci/g2-wave-module.mjs'),script,configPath,resolve(evidence,'worker-request.json')],Buffer.alloc(0),true);
await writeFile(resolve(report,'exported-worker-diagnostic.json'),JSON.stringify(imported,null,2)+'\n');
console.log(JSON.stringify({originalWorkerAccepted:original.accepted,exportedDiagnosticAccepted:imported.accepted}));
if(!original.accepted||!imported.accepted)process.exitCode=1;
