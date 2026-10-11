import {boundedFile as bounded} from '../bounded-file.ts';
import {resolve,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {unhex} from '@corbet-labs/czkp/encoding';
const digest=b=>createHash('sha256').update(b).digest('hex');
const json=bytes=>JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
export async function loadArtifacts(configPath) {
  if(!isAbsolute(configPath))throw new Error('Absolute trusted artifact configuration required');
  const config=json(await bounded(configPath,65536));
  if(!isAbsolute(config.directory))throw new Error('Absolute artifact directory required');
  const manifestBytes=await bounded(resolve(config.directory,'manifest.json'),65536);
  if(digest(manifestBytes)!==config.manifestSha256)throw new Error('Manifest authentication');
  const manifest=json(manifestBytes);
  if(manifest.version!==1||manifest.accountingMode!=='account-extension-v1'||manifest.compiler!=='1.0.0-beta.26'||manifest.backend!=='5.2.1'||manifest.verifierTarget!=='noir-recursive')throw new Error('Extension artifact suite');
  const circuitBytes=await bounded(resolve(config.directory,'circuits.json'),64*1024*1024),vkBytes=await bounded(resolve(config.directory,'keys.json'),1024*1024);
  if(digest(circuitBytes)!==manifest.circuitSha256||digest(vkBytes)!==manifest.vkSha256)throw new Error('Artifact authentication');
  const setup={};
  for(const spec of manifest.setup) {
    if(!['g1.dat','g2.dat'].includes(spec.name)||!Number.isSafeInteger(spec.bytes)||spec.bytes>128*1024*1024)throw new Error('Setup bound');
    const data=await bounded(resolve(config.directory,'setup',spec.name),spec.bytes);
    if(data.length!==spec.bytes||digest(data)!==spec.sha256)throw new Error('Setup authentication');setup[spec.name]=data;
  }
  if(!setup['g1.dat']||!setup['g2.dat']||manifest.numPoints*32!==setup['g1.dat'].length||setup['g2.dat'].length!==128)throw new Error('Setup completeness');
  const circuits=json(circuitBytes),keys=json(vkBytes);
  const recordEpochCircuit=Object.hasOwn(circuits,'record_epoch'),recordEpochKey=Object.hasOwn(keys,'record_epoch');
  if(recordEpochCircuit!==recordEpochKey||(recordEpochCircuit&&(
    typeof circuits.record_epoch?.bytecode!=='string'||!circuits.record_epoch.bytecode||
    typeof keys.record_epoch!=='string'||!keys.record_epoch)))throw new Error('Incomplete record epoch artifact pair');
  return {manifest,scope:{circuitDigest:Array.from(unhex(manifest.circuitSha256)),verifyingKeyDigest:Array.from(unhex(manifest.vkSha256))},
    artifacts(kind){if(!['update','deposit','record','record_epoch'].includes(kind))throw new Error('Circuit domain');
      if(kind==='record_epoch'&&!recordEpochCircuit)throw new Error('Record epoch circuit unavailable');
      return {manifest,circuit:circuits[kind],verificationKey:unhex(keys[kind]),setup,limits:{memoryPages:65536,maxProofBytes:1024*1024}};}};
}
