// Peer-release (wave, outcome) circuits: compiled public ABI widths, verification
// keys under the pinned maintained backend, and an authenticated artifact group.
// Public data only; no witness, proof or member opening is produced here.
import assert from 'node:assert/strict';
import {createHash,createECDH} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {Barretenberg,BackendType,UltraHonkBackend} from '@aztec/bb.js';
import {OPTIONS,hex} from '@corbet-labs/czkp/encoding';
import {selectedProducer} from './holder/prover-conformance.mts';
if(process.argv.length!==2||!process.env.CBLC_EXTENSION_DIRECTORY||resolve(process.env.CBLC_EXTENSION_DIRECTORY)===resolve('.extension-test'))
  throw new Error('Separate wave artifact directory required');
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY);
const sha=b=>createHash('sha256').update(b).digest();
const programs=JSON.parse(await readFile(resolve(directory,'circuits.json')));
assert.deepEqual(Object.keys(programs).sort(),['outcome','wave']);
const width=type=>{
  if(['field','integer','boolean'].includes(type.kind))return 1;
  if(type.kind==='array')return type.length*width(type.type);
  if(type.kind==='struct')return type.fields.reduce((count,field)=>count+width(field.type),0);
  throw new Error('Unsupported compiled public ABI');
};
const widths={};
for(const kind of ['wave','outcome']) {
  assert(programs[kind]?.bytecode,'Missing compiled circuit');
  widths[kind]=programs[kind].abi.parameters.filter(parameter=>parameter.visibility==='public')
    .reduce((count,parameter)=>count+width(parameter.type),0);
}
console.log(`Compiled public ABI widths ${JSON.stringify(widths)}`);
const expected={wave:618,outcome:651};
assert.deepEqual(widths,expected,'wave public ABI widths');
const lock=JSON.parse(await readFile('circuits/extensions/setup-lock.json'));
await mkdir(resolve(directory,'setup'),{recursive:true});
const setup={};
for(const f of lock.files){
  const response=await fetch(f.url,{headers:{'User-Agent':'LibraryValidation/1.0',...(f.range?{Range:`bytes=0-${f.bytes-1}`}:{})},redirect:'error',signal:AbortSignal.timeout(120000)});
  assert.equal(response.status,f.range?206:200);
  const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;assert(size<=f.bytes);chunks.push(chunk);}
  const data=Buffer.concat(chunks);assert.equal(data.length,f.bytes);assert.equal(sha(data).toString('hex'),f.sha256);
  setup[f.name]=data;await writeFile(resolve(directory,'setup',f.name),data);
}
const producer=await selectedProducer();
const api=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true,bbPath:producer.bbPath});
const keys={};
try{await api.srsInitSrs({pointsBuf:setup['g1.dat'],numPoints:lock.numPoints,g2Point:setup['g2.dat']});
  for(const kind of ['wave','outcome']){
    const started=Date.now();
    keys[kind]=hex(await new UltraHonkBackend(programs[kind].bytecode,api).getVerificationKey(OPTIONS));
    console.log(`Verification key ${kind}: ${Date.now()-started} ms`);
  }
}finally{await api.destroy();}
const keyBytes=Buffer.from(JSON.stringify(keys));await writeFile(resolve(directory,'keys.json'),keyBytes);
const issuer=createECDH('prime256v1');issuer.setPrivateKey(Buffer.alloc(32,3));
const manifest={version:1,accountingMode:'account-extension-v1',compiler:'1.0.0-beta.26',backend:producer.receipt.packageVersion,verifierTarget:OPTIONS.verifierTarget,
  circuitSha256:sha(await readFile(resolve(directory,'circuits.json'))).toString('hex'),vkSha256:sha(keyBytes).toString('hex'),numPoints:lock.numPoints,setup:lock.files,issuerKey:Array.from(issuer.getPublicKey().subarray(1))};
const manifestBytes=Buffer.from(JSON.stringify(manifest));
await writeFile(resolve(directory,'manifest.json'),manifestBytes);
await writeFile(resolve(directory,'config.json'),JSON.stringify({directory,manifestSha256:sha(manifestBytes).toString('hex')}));
console.log('Generated authenticated wave artifact group; proofs remain unqualified');
