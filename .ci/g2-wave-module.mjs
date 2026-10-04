// CI diagnostic only: expose a refusal from the same original public verifier.
// This never replaces the original process verdict or receives a private witness.
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
console.log=()=>{};
try {
  if(process.argv.length!==5)throw new Error('Diagnostic arguments');
  const bytes=await readFile(process.argv[4]);
  if(bytes.length>3*1024*1024)throw new Error('Public input limit');
  const {verify}=await import(pathToFileURL(process.argv[2]).href);
  process.stdout.write(JSON.stringify(await verify(JSON.parse(bytes),process.argv[3]))+'\n');
} catch(error) {
  process.stderr.write(JSON.stringify({name:String(error?.name).slice(0,128),message:String(error?.message).slice(0,4096)})+'\n');
  process.exitCode=1;
}
