// Node 24 strips TypeScript types for this legacy SDK fixture cross-check.
// The authoritative production replay is the Rust real_proof integration test.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {createAccountVerifier} from '../runtime/accounting/runtime.mjs';
import {nodeArtifactOptions} from '../runtime/accounting/node-verifier.mjs';
import {verifyPublicProofRecords} from '../runtime/accounting/real-proof-check.mjs';

const directory=resolve(process.env.CBLC_PROOF_DIRECTORY??'.proof-test');
const records=JSON.parse(await readFile(resolve(directory,'ledger-records.json'),'utf8'));
assert.equal(records.length,6);
const options=await nodeArtifactOptions(resolve(directory,'config.json'));
// Exercise the shared real-proof helper on every run, including fixture-cache
// hits. This is public fixture replay, not evidence of a browser ceremony.
assert.deepEqual(await verifyPublicProofRecords(options,records),
  {ok:true,realAccountProofs:6,corruptionAndScopeRejections:12});
const verifier=await createAccountVerifier(options);
try {
  for(const record of records) {
    assert.equal((await verifier.verify(record)).verified,true);
    const changed=structuredClone(record);changed.statement.nextState[31]^=1;
    await assert.rejects(verifier.verify(changed));
  }
} finally {await verifier.destroy();}
console.log('Replayed 6 real account proofs; rejected corrupted proofs, public inputs and scope.');
