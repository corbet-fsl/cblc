// Compile public policy artifacts on CI. Never receives member openings.
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test');
await mkdir(directory,{recursive:true});
const programs={};
for(const kind of ['update','deposit','record']) {
  const result=await compile(createFileManager(resolve('circuits/extensions',kind)));
  if(!result.program?.bytecode) throw new Error('Missing compiled extension program');
  programs[kind]=result.program;
  console.log(`Compiled extension ${kind}`);
}
await writeFile(resolve(directory,'circuits.json'),JSON.stringify(programs));
