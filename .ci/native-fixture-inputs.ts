// Public fictional fixture export for cvfy's lower-level native integration test.
// Production domain statement mapping belongs to cblc's Rust prepared module.
import {readFile, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {publicInputValues} from '../runtime/accounting/statement.mjs';

const directory = resolve(process.env.CBLC_PROOF_DIRECTORY ?? '.proof-test');
const records = JSON.parse(await readFile(resolve(directory, 'records.json'), 'utf8'));
const native = records.map((record: {statement: unknown; proof: string; proofScope: unknown}) => ({
  publicInputs: publicInputValues(record.statement).map((field: bigint) =>
    Array.from(Buffer.from(field.toString(16).padStart(64, '0'), 'hex'))),
  proof: record.proof,
  proofScope: record.proofScope,
}));
await writeFile(resolve(directory, 'native-records.json'), JSON.stringify(native));
