// Recheck the real public proof trace against an instrumented fresh issuer.
// No witness, mock verifier, accepting stub or production member data is used.
import assert from 'node:assert/strict';
import {readFile,writeFile,stat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {once} from 'node:events';

const directory=resolve('.extension-test'),tracePath=resolve(directory,'public-trace.json');
assert((await stat(tracePath)).size <= 256*1024*1024);
const trace=JSON.parse(await readFile(tracePath,'utf8'));
assert(Array.isArray(trace)&&trace.length>0&&trace.length<=256);
const configPath=resolve(directory,'config.json'),config=JSON.parse(await readFile(configPath,'utf8'));
config.directory=directory;await writeFile(configPath,JSON.stringify(config));
const executable=resolve(process.env.CBLC_EXTENSION_ISSUER);
const child=spawn(executable,[configPath],{stdio:['pipe','pipe','inherit']});
const exited=once(child,'exit');
const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
try {
  for(const item of trace) {
    const bytes=JSON.stringify(item.request);assert(bytes.length<=16*1024*1024);
    child.stdin.write(bytes+'\n');
    const line=await lines.next();assert(!line.done);
    assert.deepEqual(JSON.parse(line.value),item.response);
  }
  child.stdin.end();
  const [code]=await exited;assert.equal(code,0);
} catch(error) {child.kill();await exited;throw error;}
console.log(`Replayed ${trace.length} real-proof issuer calls with exact outcomes`);
