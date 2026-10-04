// Actual retained Rust peer first; separate public transport instrumentation next.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,delimiter} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
assert(process.env.CI);
const report=resolve(process.env.CBLC_DIAGNOSTIC_OUTPUT),evidence=resolve(report,'evidence');
const sha=b=>createHash('sha256').update(b).digest('hex');
const load=async p=>JSON.parse(await readFile(p));
const attempt=await load(resolve(evidence,'public/public-wave-attempt.json'));
assert.equal(attempt.sequence,0);assert.equal(attempt.expectedVerified,true);assert.deepEqual(attempt.reply,{verified:false});
const request=Buffer.from(JSON.stringify(attempt.request)+'\n');
assert(request.length<3*1024*1024);
await writeFile(resolve(report,'peer-request.json'),request);
const original=(await load(resolve(evidence,'public/config.json'))).directory;
const config=resolve(original,'config.json'),policy=resolve(original,'wave-policy.json');
const script=fileURLToPath(import.meta.resolve('@corbet-labs/czkp/node-verifier'));
const executable=resolve(report,'peer/wave_verifier');
const inputBindings=await load(resolve(report,'replay-input-bindings.json'));
assert.equal(sha(await readFile(executable)),inputBindings.peer.files.wave_verifier);
const args=[config,policy,script];
await writeFile(resolve(report,'peer-environment.json'),JSON.stringify({node:inputBindings.node,nodeSha256:inputBindings.node_sha256,
  relevantEnvironment:Object.fromEntries(['UV_THREADPOOL_SIZE','RAYON_NUM_THREADS','OMP_NUM_THREADS','BB_BINARY_PATH','LD_LIBRARY_PATH'].map(k=>[k,process.env[k]??null])),
  source:'current CI environment; original complete environment was not retained'},null,2)+'\n');
async function peer(environment){
  const start=performance.now(),child=spawn(executable,args,{cwd:process.cwd(),env:environment,stdio:['pipe','pipe','pipe']});
  let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0),writeError=null,readError=null,spawnError=null,timedOut=false,wrote=false;
  child.stdin.on('error',e=>{writeError=e.code??'write-error';});
  child.stdin.write(request,e=>{wrote=!e;});
  child.stdout.on('error',e=>{readError=e.code??'read-error';});
  child.stdout.on('data',data=>{stdout=Buffer.concat([stdout,data]).subarray(0,4097);
    if(stdout.includes(10))child.stdin.end();
    if(stdout.length===4097)child.stdout.destroy();});
  child.stderr.on('data',data=>{stderr=Buffer.concat([stderr,data]).subarray(0,16384);});
  child.on('error',e=>{spawnError=e.code??'spawn-error';});
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},195000);
  const [code,signal]=await new Promise(done=>child.once('close',(code,signal)=>done([code,signal])));clearTimeout(timer);
  let verdict=null,accepted=false;
  if(wrote&&!writeError&&!readError&&!spawnError&&!timedOut&&code===0&&stdout.length<=4096){
    try{verdict=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(stdout));assert.deepEqual(verdict,{verified:true});accepted=true;}catch{}
  }
  return {args,cwd:process.cwd(),stdinSha256:sha(request),stdinBytes:request.length,wrote,writeError,readError,spawnError,
    code,signal,timedOut,milliseconds:performance.now()-start,stdoutHex:stdout.toString('hex'),stderr:stderr.toString('utf8'),verdict,accepted};
}
const first=await peer({...process.env});
await writeFile(resolve(report,'original-rust-peer.json'),JSON.stringify(first,null,2)+'\n');
execFileSync('python3',['.ci/g2-wave-inputs.py','peer-check'],{timeout:30000,stdio:['ignore','inherit','inherit']});
const capture=resolve(report,'capture');await mkdir(capture);
const wrappers=resolve(report,'capture-path');await mkdir(wrappers);
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
// timeout owns a separate process group. Its shorter diagnostic deadline keeps
// descendants bounded even if the Rust peer later kills its configured wrapper.
const wrapper='#!/bin/sh\nexec timeout --kill-after=5s 170s '+quote(inputBindings.node)+' '+quote(resolve('.ci/g2-wave-capture.mjs'))+' "$@"\n';
await writeFile(resolve(wrappers,'node'),wrapper,{mode:0o755});
const environment={...process.env,PATH:wrappers+delimiter+process.env.PATH,G2_WAVE_CAPTURE:capture,
  G2_WAVE_REAL_NODE:inputBindings.node,G2_WAVE_SCRIPT:script,G2_WAVE_CONFIG:config,
  G2_WAVE_EXPECTED_FRAME:resolve(evidence,'worker-request.json')};
const second=await peer(environment);
await writeFile(resolve(report,'captured-rust-peer.json'),JSON.stringify(second,null,2)+'\n');
const captured=await readFile(resolve(capture,'worker-stdin.json')).catch(()=>null);
const expected=await readFile(resolve(evidence,'worker-request.json'));
await writeFile(resolve(report,'peer-bindings.json'),JSON.stringify({executable,executableSha256:sha(await readFile(executable)),
  originalConfig:config,originalPolicy:policy,script,node:inputBindings.node,nodeSha256:inputBindings.node_sha256,
  wrapperSha256:sha(Buffer.from(wrapper)),expectedFrameSha256:sha(expected),capturedFrameSha256:captured?sha(captured):null,
  capturedFrameEqualsReconstruction:captured?captured.equals(expected):null,
  originalResultPreserved:true,proofRegeneration:false,authorityClaim:false},null,2)+'\n');
console.log(JSON.stringify({originalRustPeerAccepted:first.accepted,capturedRustPeerAccepted:second.accepted,
  capturedFrameEqualsReconstruction:captured?captured.equals(expected):null}));
if(!first.accepted||!second.accepted)process.exitCode=1;
