// Compile public policy artifacts on CI. Never receives member openings.
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const recordEpoch=process.argv.length===3&&process.argv[2]==='--record-epoch';
if(process.argv.length!==2&&!recordEpoch)throw new Error('Unknown extension compile selector');
if(recordEpoch&&(!process.env.CBLC_EXTENSION_DIRECTORY||resolve(process.env.CBLC_EXTENSION_DIRECTORY)===resolve('.extension-test')))
  throw new Error('Separate record epoch artifact directory required');
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test');
await mkdir(directory,{recursive:true});
const programs={};
// The existing three-circuit fixture stays byte-identical by default. The
// explicit mode compiles only the original fourth relation, not optimized v01
// update/deposit variants or a replacement for main's 32-level account maps.
for(const kind of recordEpoch?['update','deposit','record','record_epoch']:['update','deposit','record']) {
  const result=await compile(createFileManager(resolve('circuits/extensions',kind)));
  if(!result.program?.bytecode) throw new Error('Missing compiled extension program');
  programs[kind]=result.program;
  console.log(`Compiled extension ${kind}`);
}
await writeFile(resolve(directory,'circuits.json'),JSON.stringify(programs));
