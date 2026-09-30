import {readFile,stat} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {unhex} from '@corbet-labs/czkp/encoding';
const digest=b=>createHash('sha256').update(b).digest('hex');
async function bounded(path,max) {if((await stat(path)).size>max)throw new Error('Artifact bound');const b=await readFile(path);if(b.length>max)throw new Error('Artifact bound');return b;}
export async function loadArtifacts(configPath) {
  if(!isAbsolute(configPath))throw new Error('Absolute trusted artifact configuration required');
  const config=JSON.parse(await bounded(configPath,65536));
  if(!isAbsolute(config.directory))throw new Error('Absolute artifact directory required');
  const manifestBytes=await bounded(resolve(config.directory,'manifest.json'),65536);
  if(digest(manifestBytes)!==config.manifestSha256)throw new Error('Manifest authentication');
  const manifest=JSON.parse(manifestBytes);
  if(manifest.version!==1||manifest.accountingMode!=='account-extension-v1'||manifest.compiler!=='1.0.0-beta.26'||manifest.backend!=='5.0.0'||manifest.verifierTarget!=='noir-recursive')throw new Error('Extension artifact suite');
  const circuitBytes=await bounded(resolve(config.directory,'circuits.json'),64*1024*1024),vkBytes=await bounded(resolve(config.directory,'keys.json'),1024*1024);
  if(digest(circuitBytes)!==manifest.circuitSha256||digest(vkBytes)!==manifest.vkSha256)throw new Error('Artifact authentication');
  const setup={};
  for(const spec of manifest.setup) {
    if(!['g1.dat','g2.dat'].includes(spec.name)||!Number.isSafeInteger(spec.bytes)||spec.bytes>128*1024*1024)throw new Error('Setup bound');
    const data=await bounded(resolve(config.directory,'setup',spec.name),spec.bytes);
    if(data.length!==spec.bytes||digest(data)!==spec.sha256)throw new Error('Setup authentication');setup[spec.name]=data;
  }
  if(!setup['g1.dat']||!setup['g2.dat']||manifest.numPoints*32!==setup['g1.dat'].length||setup['g2.dat'].length!==128)throw new Error('Setup completeness');
  const circuits=JSON.parse(circuitBytes),keys=JSON.parse(vkBytes);
  return {manifest,scope:{circuitDigest:Array.from(unhex(manifest.circuitSha256)),verifyingKeyDigest:Array.from(unhex(manifest.vkSha256))},
    artifacts(kind){if(!['update','deposit','record'].includes(kind))throw new Error('Circuit domain');
      return {manifest,circuit:circuits[kind],verificationKey:unhex(keys[kind]),setup,limits:{memoryPages:65536,maxProofBytes:1024*1024}};}};
}
