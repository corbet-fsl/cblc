import {Barretenberg} from '@aztec/bb.js';
import {createProver} from '@corbet-labs/czkp/prove';
import {loadCircuitSetup} from '@corbet-labs/czkp/setup';
import {witnessInputs,publicInputs} from '@corbet-labs/czkp/abi';

async function main() {
  const input=await (await fetch('/input',{cache:'no-store'})).json();
  const artifacts={...input.artifacts,verificationKey:Uint8Array.from(input.artifacts.verificationKey),setup:{}};
  artifacts.loadSetup=verificationOnly=>loadCircuitSetup(artifacts.manifest,artifacts.circuitKind,async(name,max)=>{
    const response=await fetch('/setup/'+name,{cache:'no-store'});
    if(!response.ok)throw new Error('Setup fetch');
    const parts=[];let size=0;for await(const chunk of response.body){size+=chunk.length;if(size>max)throw new Error('Setup size');parts.push(chunk);}
    const bytes=new Uint8Array(size);let at=0;for(const part of parts){bytes.set(part,at);at+=part.length;}return bytes;
  },verificationOnly);
  let configuredThreads;
  const prover=await createProver({artifacts,threads:input.threads,browserFactory:options=>{
    configuredThreads=options.threads;
    return Barretenberg.new({...options,wasmPath:'/barretenberg.wasm'});
  }});
  try {
    const result=await prover.prove(witnessInputs(artifacts.circuit,input.witness),publicInputs(artifacts.circuit,input.witness));
    if(configuredThreads!==input.expectedThreads)throw new Error('Unexpected prover thread count');
    return {ok:true,configuredThreads,isolated:crossOriginIsolated,sharedArrayBuffer:typeof SharedArrayBuffer==='function',
      userAgent:navigator.userAgent,proofBytes:result.proof.length,timings:result.timings};
  }finally{await prover.destroy();}
}
main().catch(error=>({ok:false,error:String(error)})).then(result=>parent.postMessage(result, new URL(document.referrer).origin));
