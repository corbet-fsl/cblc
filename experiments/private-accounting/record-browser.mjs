import {Barretenberg} from '@aztec/bb.js';
import {createProver} from '@corbet-labs/czkp/prove';
import {witnessInputs,publicInputs} from '@corbet-labs/czkp/abi';

async function main() {
  const input=await (await fetch('/input',{cache:'no-store'})).json();
  const artifacts={...input.artifacts,verificationKey:Uint8Array.from(input.artifacts.verificationKey),setup:{}};
  for(const file of ['g1.dat','g2.dat'])artifacts.setup[file]=new Uint8Array(await (await fetch('/setup/'+file)).arrayBuffer());
  let actualThreads;
  const prover=await createProver({artifacts,threads:input.threads,browserFactory:options=>{
    actualThreads=options.threads;
    return Barretenberg.new({...options,wasmPath:'/barretenberg.wasm'});
  }});
  try {
    const result=await prover.prove(witnessInputs(artifacts.circuit,input.witness),publicInputs(artifacts.circuit,input.witness));
    if(actualThreads!==input.expectedThreads)throw new Error('Unexpected prover thread count');
    return {ok:true,threads:actualThreads,isolated:crossOriginIsolated,sharedArrayBuffer:typeof SharedArrayBuffer==='function',
      userAgent:navigator.userAgent,proofBytes:result.proof.length,timings:result.timings};
  }finally{await prover.destroy();}
}
main().catch(error=>({ok:false,error:String(error)})).then(result=>parent.postMessage(result, new URL(document.referrer).origin));
