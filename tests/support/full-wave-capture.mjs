// CI-only observation of the full fixture's actual worker, never a replay or verifier.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,rename,stat,realpath} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import {resolve,delimiter,isAbsolute} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
const load=async path=>JSON.parse(await readFile(path));

export async function fullWaveCapture(directory,script,config,peer){
  assert(process.env.CI);
  const root=resolve(directory,'full-wave-capture'),wrappers=resolve(root,'path');
  await mkdir(root);await mkdir(wrappers);
  let node;
  for(const path of process.env.PATH.split(delimiter)){
    if(!isAbsolute(path))continue;
    const candidate=resolve(path,'node');
    if(await stat(candidate).then(value=>value.isFile(),()=>false)){node=candidate;break;}
  }
  assert(node);
  const helper=fileURLToPath(import.meta.url),control=resolve(root,'pending.json');
  // Independent process-group lifetime below the Rust worker's 180-second bound.
  const wrapper='#!/bin/sh\nexec timeout --kill-after=5s 170s '+quote(node)+' '+quote(helper)+' --capture-worker "$@"\n';
  await writeFile(resolve(wrappers,'node'),wrapper,{mode:0o755});
  await writeFile(resolve(root,'binding.json'),JSON.stringify({scope:'instrumented-full-extension-wave',
    node,nodeRealpath:await realpath(node),nodeSha256:sha(await readFile(node)),
    script,scriptRealpath:await realpath(script),scriptSha256:sha(await readFile(script)),
    peer,peerSha256:sha(await readFile(peer)),helper,helperSha256:sha(await readFile(helper)),
    fixtureNode:process.execPath,fixtureNodeVersion:process.version,cwd:process.cwd(),
    relevantEnvironment:Object.fromEntries(['UV_THREADPOOL_SIZE','RAYON_NUM_THREADS','OMP_NUM_THREADS','BB_BINARY_PATH'].map(key=>[key,process.env[key]??null])),
    wrapperSha256:sha(Buffer.from(wrapper)),proofRegeneration:'original-full-fixture',replay:false,
    captureDeadlineSeconds:160,supervisorDeadlineSeconds:170,rustDeadlineSeconds:180},null,2)+'\n');
  return {
    environment:{...process.env,PATH:wrappers+delimiter+process.env.PATH,CBLC_FULL_WAVE_CAPTURE:root,
      CBLC_FULL_WAVE_NODE:node,CBLC_FULL_WAVE_SCRIPT:script,CBLC_FULL_WAVE_CONFIG:config},
    async before(sequence){
      assert(Number.isSafeInteger(sequence)&&sequence>=0&&sequence<128);
      await writeFile(control+'.tmp',JSON.stringify({sequence}));await rename(control+'.tmp',control);
    },
    async after(sequence){
      const result=await load(resolve(root,`worker-${sequence}.json`)).catch(error=>{
        if(error.code==='ENOENT')return null;throw error;
      });
      // Prechecks may refuse before creating any worker. Never replace their verdict.
      console.log(JSON.stringify({fullFixtureWaveBoundary:{sequence,workerObserved:result!==null,
        stdoutBytes:result?.stdoutBytes??null,stdoutShape:result?.stdoutShape??'not_observed',
        stdinEof:result?.stdinEof??null,workerExit:result?.code===0?'success':result===null?'not_observed':'unsuccessful',
        captureFailure:result?.error??null}}));
    }
  };
}

// This classifier supplies a fixed diagnostic only. Rust still parses the entire
// original stdout; recognizing a JSON suffix here never makes a verdict acceptable.
function outputShape(output,scope){
  if(output.length===0)return 'empty';if(output.length>4096)return 'over_limit';
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(output);}catch{return 'invalid_utf8';}
  const envelope=value=>{try{
    assert.deepEqual(Object.keys(value).sort(),['proofScope','verified']);
    assert.equal(typeof value.verified,'boolean');assert.deepEqual(value.proofScope,scope);return true;
  }catch{return false;}};
  try{return envelope(JSON.parse(text))?'exact_envelope':'json_wrong_envelope';}catch{}
  for(let at=1;at<text.length;at++)if(text[at]==='{'){
    try{if(envelope(JSON.parse(text.slice(at))))return 'leading_output_before_envelope';}catch{}
  }
  return 'not_single_json';
}

async function captureWorker(){
  const root=resolve(process.env.CBLC_FULL_WAVE_CAPTURE),pending=await load(resolve(root,'pending.json'));
  assert.deepEqual(Object.keys(pending),['sequence']);
  assert(Number.isSafeInteger(pending.sequence)&&pending.sequence>=0&&pending.sequence<128);
  const path=resolve(root,`worker-${pending.sequence}.json`);
  const record={scope:'instrumented-full-extension-wave',sequence:pending.sequence,stdinBytes:0,stdinEof:false,
    stdinSha256:null,stdoutBytes:null,stdoutShape:null,code:null,signal:null,error:null,timedOut:false};
  const save=()=>writeFileSync(path,JSON.stringify(record,null,2)+'\n');
  let child;
  const timer=setTimeout(()=>{record.error='capture_deadline';record.timedOut=true;save();
    if(child)child.kill('SIGKILL');else process.exit(124);},160000);
  try{
    assert(process.env.CI);
    const args=process.argv.slice(3);
    assert.deepEqual(args,['--max-old-space-size=4096',process.env.CBLC_FULL_WAVE_SCRIPT,process.env.CBLC_FULL_WAVE_CONFIG]);
    const parts=[];
    for await(const part of process.stdin){record.stdinBytes+=part.length;assert(record.stdinBytes<=2*1024*1024+65536);parts.push(part);}
    const bytes=Buffer.concat(parts),request=JSON.parse(bytes);record.stdinEof=true;record.stdinSha256=sha(bytes);save();
    assert.deepEqual(Object.keys(request).sort(),['proof','proofScope','statement']);
    assert.deepEqual(Object.keys(request.statement).sort(),['circuit','input']);assert.equal(request.statement.circuit,'wave');
    const start=performance.now();
    child=spawn(process.env.CBLC_FULL_WAVE_NODE,args,{cwd:process.cwd(),env:process.env,stdio:['pipe','pipe','pipe']});
    let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0);
    child.stdin.on('error',()=>{record.error='worker_input_write';});
    child.stdout.on('error',()=>{record.error='worker_output_read';});
    child.on('error',()=>{record.error='worker_spawn';});
    child.stdout.on('data',part=>{const chunk=part.subarray(0,4097-stdout.length);stdout=Buffer.concat([stdout,chunk]);
      process.stdout.write(chunk);if(stdout.length===4097)child.stdout.destroy();});
    child.stderr.on('data',part=>{stderr=Buffer.concat([stderr,part]).subarray(0,4096);});
    process.stdout.on('error',()=>{record.error='parent_output_write';child.kill('SIGKILL');});
    child.stdin.end(bytes);
    const [code,signal]=await new Promise(done=>child.once('close',(code,signal)=>done([code,signal])));
    Object.assign(record,{args,code,signal,milliseconds:performance.now()-start,stdoutBytes:stdout.length,
      stdoutShape:outputShape(stdout,request.proofScope),stdoutSha256:sha(stdout),stdoutHex:stdout.toString('hex'),stderrHex:stderr.toString('hex')});save();
    process.exitCode=record.timedOut?124:record.error?1:code??1;
  }catch{record.error='capture_validation_or_io';save();if(child)child.kill('SIGKILL');process.exitCode=1;}
  finally{clearTimeout(timer);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(process.argv[2]!=='--capture-worker')process.exitCode=1;
  else await captureWorker();
}
