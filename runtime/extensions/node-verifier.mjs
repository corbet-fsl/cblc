// Bounded public-proof worker. Member openings never enter this process.
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {loadArtifacts} from './artifacts.mjs';
import {expectedProofs,exact,equal} from './statement.mjs';
import {publicInputs} from '@corbet-labs/czkp/abi';
import {createVerifier} from '@corbet-labs/czkp/verify';
import {unhex} from '@corbet-labs/czkp/encoding';
export async function verify(record,artifacts) {
  if(!exact(record,['statement','proof','proofScope'])||!exact(record.proofScope,['circuitDigest','verifyingKeyDigest'])||!equal(record.proofScope.circuitDigest,artifacts.scope.circuitDigest)||!equal(record.proofScope.verifyingKeyDigest,artifacts.scope.verifyingKeyDigest)
      ||typeof record.proof!=='string'||record.proof.length>8*1024*1024)throw new Error('Proof scope/bound');
  const bundle=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(unhex(record.proof)));
  const expected=await expectedProofs(record.statement,bundle,artifacts.manifest);
  const selected=artifacts.artifacts(expected[0].kind);
  const verifier=await createVerifier({artifacts:selected,publicInputs:input=>publicInputs(selected.circuit,input)});
  try {for(const step of expected)await verifier.verify({statement:step.input,proof:step.proof,proofScope:artifacts.scope});}
  finally{await verifier.destroy();}
  return {verified:true,proofScope:artifacts.scope};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  console.log=()=>{};
  try {
    if(process.argv.length!==3)throw new Error('Trusted configuration required');
    const chunks=[];let size=0;for await(const chunk of process.stdin){size+=chunk.length;if(size>9*1024*1024)throw new Error('Input bound');chunks.push(chunk);}
    const result=await verify(JSON.parse(Buffer.concat(chunks)),await loadArtifacts(process.argv[2]));
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{process.exitCode=1;}
}
