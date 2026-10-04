// CI-only public transport capture; never substitutes for the first peer result.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
const dir=resolve(process.env.G2_WAVE_CAPTURE),sha=b=>createHash('sha256').update(b).digest('hex');
const record={stdinBytes:0,stdinEof:false,stdinSha256:null,code:null,signal:null,timedOut:false,error:null};
const save=()=>writeFileSync(resolve(dir,'worker-process.json'),JSON.stringify(record,null,2)+'\n');
let child;
// Shorter than both the independent170s group supervisor and Rust's180s limit.
const timer=setTimeout(()=>{record.timedOut=true;record.error='capture-deadline';save();
  if(child)child.kill('SIGKILL');else process.exit(124);},160000);
try{
  const args=process.argv.slice(2);
  assert.deepEqual(args,['--max-old-space-size=4096',process.env.G2_WAVE_SCRIPT,process.env.G2_WAVE_CONFIG]);
  const parts=[];
  for await(const part of process.stdin){record.stdinBytes+=part.length;assert(record.stdinBytes<=2*1024*1024+65536);
    parts.push(part);record.stdinSha256=sha(Buffer.concat(parts));save();}
  record.stdinEof=true;
  const bytes=Buffer.concat(parts),request=JSON.parse(bytes),expected=JSON.parse(readFileSync(process.env.G2_WAVE_EXPECTED_FRAME));
  assert.deepEqual(Object.keys(request).sort(),['proof','proofScope','statement']);
  assert.deepEqual(Object.keys(request.statement).sort(),['circuit','input']);assert.equal(request.statement.circuit,'wave');
  assert.deepEqual(Object.keys(request.statement.input).sort(),Object.keys(expected.statement.input).sort());
  assert.equal(request.proof,expected.proof);
  assert.deepEqual(Object.keys(request.proofScope).sort(),['circuitDigest','verifyingKeyDigest']);
  for(const digest of Object.values(request.proofScope))assert(Array.isArray(digest)&&digest.length===32&&digest.every(n=>Number.isInteger(n)&&n>=0&&n<=255));
  record.stdinSha256=sha(bytes);writeFileSync(resolve(dir,'worker-stdin.json'),bytes);save();
  const start=performance.now();
  child=spawn(process.env.G2_WAVE_REAL_NODE,args,{cwd:process.cwd(),env:process.env,stdio:['pipe','pipe','pipe']});
  let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0);
  child.stdin.on('error',e=>{record.writeError=e.code??'write-error';});
  child.stdout.on('error',e=>{record.readError=e.code??'read-error';});
  child.on('error',e=>{record.error=e.code??'spawn-error';});
  child.stdout.on('data',part=>{const remaining=4097-stdout.length,chunk=part.subarray(0,remaining);
    stdout=Buffer.concat([stdout,chunk]);process.stdout.write(chunk);if(stdout.length===4097)child.stdout.destroy();});
  // The outer Rust process normally discards stderr; retain a bounded copy here.
  child.stderr.on('data',part=>{stderr=Buffer.concat([stderr,part]).subarray(0,4096);});
  process.stdout.on('error',()=>{record.error='parent-stdout';child.kill('SIGKILL');});
  child.stdin.end(bytes);
  const [code,signal]=await new Promise(done=>child.once('close',(code,signal)=>done([code,signal])));
  Object.assign(record,{args,code,signal,milliseconds:performance.now()-start,stdoutHex:stdout.toString('hex'),
    stderr:stderr.toString('utf8'),stdoutSha256:sha(stdout)});save();
  process.exitCode=record.timedOut?124:record.writeError||record.readError||record.error?1:code??1;
}catch(error){record.error=error?.code??'capture-validation-or-io';save();if(child)child.kill('SIGKILL');process.exitCode=1;}
finally{clearTimeout(timer);}
