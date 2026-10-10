// Node 24 strips TypeScript types; use the current server runtime directly.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {createAccountVerifier} from '../runtime/accounting/runtime.mjs';
import {nodeArtifactOptions} from '../runtime/accounting/node-verifier.mjs';

const directory=resolve(process.env.CBLC_PROOF_DIRECTORY??'.proof-test');
const records=JSON.parse(await readFile(resolve(directory,'ledger-records.json'),'utf8'));
assert.equal(records.length,6);
const verifier=await createAccountVerifier(await nodeArtifactOptions(resolve(directory,'config.json')));
try {
  for(const record of records) {
    assert.equal((await verifier.verify(record)).verified,true);
    const corrupt=structuredClone(record);
    corrupt.proof=(corrupt.proof.startsWith('00')?'01':'00')+corrupt.proof.slice(2);
    await assert.rejects(verifier.verify(corrupt));
    const changed=structuredClone(record);changed.statement.nextState[31]^=1;
    await assert.rejects(verifier.verify(changed));
    const scope=structuredClone(record);scope.proofScope.circuitDigest[0]^=1;
    await assert.rejects(verifier.verify(scope));
  }
} finally {await verifier.destroy();}
console.log('Replayed 6 real account proofs; rejected corrupted proofs, public inputs and scope.');
