// Test-only retention of the actual public startup inputs. These are not an
// admission grant or a reconstructed opening; the consumer configures trust.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir,copyFile,lstat} from 'node:fs/promises';
import {resolve} from 'node:path';

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const keys=(value,names)=>assert.deepEqual(Object.keys(value).sort(),[...names].sort());
const policyKeys=['initialCredit','maximumAvailable','outgoingReservation','incomingReservation',
  'policyRevision','policyValidFrom','policyValidUntil','newcomerPeriod','rateWindow',
  'newcomerAdmissions','maximumAdmissions','refillPeriod','refillUnits','abandonAfter'];
const statementKeys=['protocolVersion','community','owner','policyDigest','enrollmentRoot',
  'now','validUntil','genesis','previousVersion','nextVersion','previousState','nextState',
  'settlementMarker','policy'];
const scopeKeys=['circuitDigest','verifyingKeyDigest'];

function publicStatement(value) {
  keys(value,statementKeys);
  keys(value.policy,policyKeys);
}

export async function retainRecordStartup({initialize,scope,manifestSha256,sourceCommit}) {
  if(!process.env.ARTIFACT_ROOT)return;
  assert.match(sourceCommit,/^[0-9a-f]{40}$/);
  // Exact original public owner request only: no holder, leaf, Merkle path,
  // opening, secret, signing key or private recordWitness response is accepted.
  keys(initialize,['op','policy','extension','scope','root','activation']);
  assert.equal(initialize.op,'init');
  keys(initialize.policy,policyKeys);
  keys(initialize.extension,['revision','publicRecordQuorum','changeTokenCost',
    'depositDelaySeconds','minimumDepositBatch']);
  keys(initialize.scope,scopeKeys);
  assert.deepEqual(initialize.scope,scope);
  keys(initialize.activation,['account','proof']);
  publicStatement(initialize.activation.account);
  assert.deepEqual(initialize.activation.account.policy,initialize.policy);
  assert.equal(initialize.activation.account.genesis,true);
  assert.match(initialize.activation.proof,/^(?:[0-9a-f]{2})+$/);

  const account=resolve(process.env.CBLC_PROOF_DIRECTORY??'.proof-test');
  const retained=resolve(process.env.ARTIFACT_ROOT,'native-startup-fixture');
  await mkdir(resolve(retained,'account/setup'),{recursive:true});
  const bounded={
    'config.json':65536,'manifest.json':65536,'circuit.json':64*1024*1024,
    'vk.bin':1024*1024,'records.json':16*1024*1024,'ledger-records.json':16*1024*1024,
    'setup/g1.dat':128*1024*1024,'setup/g2.dat':1024,
  };
  const configuration=JSON.parse(await readFile(resolve(account,'config.json')));
  keys(configuration,['directory','manifestSha256']);
  const manifestBytes=await readFile(resolve(account,'manifest.json'));
  const manifest=JSON.parse(manifestBytes);
  assert.equal(configuration.manifestSha256,digest(manifestBytes));
  assert.equal(manifest.accountingMode,'account-state-v2');
  assert.deepEqual(manifest.setup.map(file=>file.name).sort(),['g1.dat','g2.dat']);
  for(const [name,count] of [['records.json',2],['ledger-records.json',6]]) {
    const records=JSON.parse(await readFile(resolve(account,name)));
    assert.equal(records.length,count);
    for(const record of records) {
      keys(record,['statement','proof','proofScope']);
      publicStatement(record.statement);
      keys(record.proofScope,scopeKeys);
      assert.match(record.proof,/^(?:[0-9a-f]{2})+$/);
    }
  }
  // Original three-circuit fixture provenance also identifies the original
  // account generation on cache hits. Never relabel cached proofs as new ones.
  const sourceBytes=await readFile(resolve('.extension-test/source.txt'));
  const provenance=sourceBytes.toString().split('\n');
  assert.equal(provenance.length,3);
  assert.match(provenance[0],/^[0-9a-f]{40}$/);
  assert.equal(provenance[1],`${digest(await readFile('package-lock.json'))}  package-lock.json`);
  assert.equal(provenance[2],'');
  const files={};
  for(const [name,maximum] of Object.entries(bounded)) {
    const source=resolve(account,name),info=await lstat(source);
    assert(info.isFile()&&!info.isSymbolicLink());
    assert(info.size<=maximum);
    const expected=digest(await readFile(source));
    const target=resolve(retained,'account',name);
    await copyFile(source,target);
    assert.equal(digest(await readFile(target)),expected);
    files[`account/${name}`]={sha256:expected,bytes:info.size};
  }
  assert.equal(files['account/circuit.json'].sha256,manifest.circuitSha256);
  assert.equal(files['account/vk.bin'].sha256,manifest.vkSha256);
  for(const file of manifest.setup) {
    assert.equal(files[`account/setup/${file.name}`].sha256,file.sha256);
    assert.equal(files[`account/setup/${file.name}`].bytes,file.bytes);
  }
  // Config bytes remain exactly the actual producer's. The consuming test must
  // rebase its directory explicitly while retaining the same manifest pin.
  const startupBytes=JSON.stringify(initialize);
  assert(Buffer.byteLength(startupBytes)<=4*1024*1024);
  await writeFile(resolve(retained,'init.json'),startupBytes);
  files['init.json']={sha256:digest(startupBytes),bytes:Buffer.byteLength(startupBytes)};
  await writeFile(resolve(retained,'account-generation.txt'),sourceBytes);
  files['account-generation.txt']={sha256:digest(sourceBytes),bytes:sourceBytes.length};
  const metadataBytes=JSON.stringify({version:1,purpose:'cblc.native-startup-test.v1',
    sourceCommit,accountGenerationCommit:provenance[0],extensionManifestSha256:manifestSha256,
    extensionScope:scope,accountManifestSha256:configuration.manifestSha256,
    // Public fictional test-seed provenance, not a trust source. The original
    // accounting admission/device fixture differs from the Gather G1 fixture.
    fixtureSeeds:{accountAdmissionIssuer:1,accountDevice:2,accountResponseOperator:9,
      epochCertificateIssuer:3,balancePublisher:31,gatherG1Issuer:31,gatherG1Device:13},files});
  await writeFile(resolve(retained,'startup-artifacts.json'),metadataBytes);
  console.log(`CBLC_STARTUP_ARTIFACT ${JSON.stringify({sourceCommit,
    accountGenerationCommit:provenance[0],metadataSha256:digest(metadataBytes)})}`);
}
