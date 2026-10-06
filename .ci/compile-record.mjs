// Diagnostic wrapper around the original compile.mjs call for one unchanged
// entry point. Reads public circuit source only; never receives a witness.
import {compile,createFileManager} from '@noir-lang/noir_wasm';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
const directory=process.env.CBLC_DIAGNOSTIC_OUTPUT;
if(!directory||!isAbsolute(directory))throw new Error('Absolute diagnostic output required');
const compilerBytes=await readFile('node_modules/@noir-lang/noir_wasm/package.json');
const started=performance.now();
const result=await compile(createFileManager(resolve('circuits/extensions/record_epoch')));
if(!result.program?.bytecode)throw new Error('Missing compiled record epoch program');
const artifact=Buffer.from(JSON.stringify(result.program));
const sha=b=>createHash('sha256').update(b).digest('hex');
const report={purpose:'diagnostic-only',productAcceptance:false,node:process.version,
  compilerPackage:JSON.parse(compilerBytes).version,compilerPackageSha256:sha(compilerBytes),
  programCompiler:result.program.noir_version??null,compileMilliseconds:performance.now()-started,
  peakRssKiB:process.resourceUsage().maxRSS,artifactBytes:artifact.length,
  encodedBytecodeCharacters:result.program.bytecode.length,
  decodedBytecodeBytes:Buffer.from(result.program.bytecode,'base64').length,
  circuitSha256:sha(artifact),
  publicParameters:result.program.abi.parameters.filter(p=>p.visibility==='public').map(p=>p.name),
  sizeMeaning:'Serialized artifact and encoded/decoded ACIR bytecode bytes, not backend gate count'};
await mkdir(directory,{recursive:true});
await writeFile(resolve(directory,'record_epoch.json'),artifact);
await writeFile(resolve(directory,'compile.json'),JSON.stringify(report,null,2)+'\n');
process.stdout.write(JSON.stringify(report)+'\n');
