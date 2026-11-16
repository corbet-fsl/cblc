// Native member world: a real enrollment of several fictional members of ONE community
// at ONE chosen time, every member's genesis proved and accepted by the real account
// service, record recipients registered, a record epoch published and a real record-epoch
// proof checked natively, and one completed pin spend (SpentChange). Consumers pin the
// capture by the SHA-256 of its member-world.json, retained write-once under
// $ARTIFACT_ROOT/native-member-world-retained/<digest>/. Only public statements, proofs,
// signed requests and acceptances are written; no opening, owner secret or private key.
//
// node tests/native-member-world.mts --community <id> --now <unix seconds> [options]
//   --members <hex,...>        48-byte member pseudonyms (default [7;48],[8;48],[9;48]); the
//                              first one owns the activation, fixture member numbers are 7, 8, ...
//   --policy <file>            JSON with accountPolicy, extensionPolicy and optionally
//                              checkpointPeriodSeconds / nativeWrapper (tests/holder/fixtures/*.json fit)
//   --device-seed <n>          device key [n; 32] that signs every member request (default 2)
//   --group <dir>              existing artifact group (circuits.json, keys.json, manifest.json,
//                              setup/) to prove under; its bytecode and keys must equal this tree's
//   --policy-epoch <n> --record-period <s>     record epoch descriptor (default 1, 86400)
//   --pin-member <i> --pin-field <f> --pin-expected <hex32>:<revision> --pin-replacement <hex32>
// Environment: CBLC_EXTENSION_DIRECTORY (work directory holding `compile.mts --record-epoch`
// output), CBLC_BB (native worker), CBLC_MEMBER_WORLD_ISSUER (examples/member_world_issuer),
// ARTIFACT_ROOT + CI_COMMIT_SHA to retain.
import assert from 'node:assert/strict';
import {createECDH,createHash,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {readFile,writeFile,mkdir,copyFile,rename,rm,stat,readdir} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {parseArgs} from 'node:util';
import {Barretenberg,BackendType,UltraHonkBackend} from '@aztec/bb.js';
import {OPTIONS,hex} from '@corbet-labs/czkp/encoding';
import {publicInputs,witnessInputs} from '@corbet-labs/czkp/abi';
import {createProver} from '@corbet-labs/czkp/prove';
import {fieldBytes} from '@corbet-labs/czkp/primitives';
import {extensionHashes,checkpointFromVerified} from '@corbet-labs/cwlt/extensions';
import {VoucherWitness} from '@corbet-labs/cwlt/voucher-wallet';
import {STANDING,STANDING_DIGEST,STANDING_TABLES} from './holder/standing-fixture.mts';
import {loadArtifacts} from '../runtime/extensions/artifacts.mts';
import {prepareRecordEpoch} from './holder/record-epoch.mts';
import {recordPresentationBytes,verifyRecordPresentation} from './holder/record-epoch-codec.mts';
import {selectedProducer} from './holder/prover-conformance.mts';

const sha=b=>createHash('sha256').update(b).digest();
const bytes=n=>new Uint8Array(32).fill(n);
const toArray=Array.from.bind(Array);
const unhex=(text,size)=>{assert.match(text,new RegExp(`^[0-9a-f]{${size*2}}$`),`${size}-byte lowercase hex`);return Buffer.from(text,'hex');};

// ---- Arguments: the community and the time are the world; every other value has a default.
const {values:args}=parseArgs({strict:true,options:{
  community:{type:'string'},now:{type:'string'},members:{type:'string'},policy:{type:'string'},
  'device-seed':{type:'string',default:'2'},group:{type:'string'},'policy-epoch':{type:'string',default:'1'},
  'record-period':{type:'string',default:'86400'},'pin-member':{type:'string',default:'1'},'pin-field':{type:'string',default:'age'},
  'pin-expected':{type:'string',default:`${'01'.repeat(32)}:1`},'pin-replacement':{type:'string',default:'02'.repeat(32)}}});
const integer=(name,text,minimum=0)=>{assert.match(text??'',/^[0-9]+$/,`--${name} integer`);const v=Number(text);assert(Number.isSafeInteger(v)&&v>=minimum,`--${name} bound`);return v;};
const communityId=args.community;
assert(typeof communityId==='string'&&communityId.length>0&&communityId.length<=128,'--community required');
const NOW=integer('now',args.now,1);
const deviceSeed=integer('device-seed',args['device-seed'],1);assert(deviceSeed<=255);
const policyEpoch=integer('policy-epoch',args['policy-epoch'],1);
const recordPeriod=integer('record-period',args['record-period'],1);
const pseudonyms=(args.members?args.members.split(','):[7,8,9].map(n=>Buffer.alloc(48,n).toString('hex'))).map(text=>unhex(text,48));
assert(pseudonyms.length>=2&&pseudonyms.length<=16,'A member world has 2 to 16 members');
const MEMBER_BASE=7;
const pinMember=integer('pin-member',args['pin-member']);assert(pinMember>0&&pinMember<pseudonyms.length,'--pin-member is a non-activation member');
const [pinExpected,pinRevision]=args['pin-expected'].split(':');
const pinChange={community:communityId,member:pseudonyms[pinMember].toString('hex'),field:args['pin-field'],
  expected:{fingerprint:unhex(pinExpected,32).toString('hex'),revision:integer('pin-expected revision',pinRevision,1)},
  replacement:unhex(args['pin-replacement'],32).toString('hex')};

// ---- Policy: alpha-style defaults measured from NOW (tests/holder/fixtures/alpha-native-request.json).
const configured=args.policy?JSON.parse(await readFile(resolve(args.policy))):{};
if(configured.community!==undefined)assert.equal(configured.community,communityId,'Policy file names another community');
if(configured.observation!==undefined)assert.equal(configured.observation,NOW,'Policy file names another time');
const policy=configured.accountPolicy??{initialCredit:3,maximumAvailable:3,outgoingReservation:1,incomingReservation:1,
  policyRevision:1,policyValidFrom:NOW-1,policyValidUntil:NOW+86400,newcomerPeriod:100,rateWindow:10,
  newcomerAdmissions:8,maximumAdmissions:8,refillPeriod:10,refillUnits:1,abandonAfter:100};
const extension=configured.extensionPolicy??{revision:1,publicRecordQuorum:2,changeTokenCost:1,depositDelaySeconds:10,
  minimumDepositBatch:2,standingPolicyDigest:STANDING_DIGEST};
assert.deepEqual(extension.standingPolicyDigest,STANDING_DIGEST,'The reference standing parameters are the only ones proved here');
assert(policy.policyValidFrom<=NOW&&NOW<policy.policyValidUntil,'NOW lies outside the policy validity');
const ledger={maxAuthorizationSeconds:configured.nativeWrapper?.maxAuthorizationSeconds??configured.maxAuthorizationSeconds??100,
  checkpointPeriodSeconds:configured.nativeWrapper?.checkpointPeriodSeconds??configured.checkpointPeriodSeconds??86400};
const slot=Math.floor(NOW/ledger.checkpointPeriodSeconds);

// ---- Artifact group: this tree's record-epoch compile, optionally proved under an existing group.
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'');
assert(process.env.CBLC_EXTENSION_DIRECTORY&&directory!==resolve('.extension-test'),'Separate member world directory required');
const kinds=['update','deposit','record','record_epoch','voucher_epoch'];
const compiled=JSON.parse(await readFile(resolve(directory,'circuits.json')));
assert.deepEqual(Object.keys(compiled).sort(),[...kinds].sort(),'Run runtime/extensions/compile.mts --record-epoch first');
const lock=JSON.parse(await readFile('circuits/extensions/setup-lock.json'));
await mkdir(resolve(directory,'setup'),{recursive:true});
const group=args.group?resolve(args.group):undefined;
const setup={};
for(const f of lock.files){
  let data;
  if(group)data=await readFile(resolve(group,'setup',f.name));
  else {
    const response=await fetch(f.url,{headers:{'User-Agent':'LibraryValidation/1.0',...(f.range?{Range:`bytes=0-${f.bytes-1}`}:{})},redirect:'error',signal:AbortSignal.timeout(120000)});
    assert.equal(response.status,f.range?206:200);
    const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;assert(size<=f.bytes);chunks.push(chunk);}
    data=Buffer.concat(chunks);
  }
  assert.equal(data.length,f.bytes);assert.equal(sha(data).toString('hex'),f.sha256);
  setup[f.name]=data;await writeFile(resolve(directory,'setup',f.name),data);
}
const producer=await selectedProducer();
const keyApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true,bbPath:producer.bbPath});
const keys={};
try{await keyApi.srsInitSrs({pointsBuf:setup['g1.dat'],numPoints:lock.numPoints,g2Point:setup['g2.dat']});
  for(const kind of kinds)keys[kind]=hex(await new UltraHonkBackend(compiled[kind].bytecode,keyApi).getVerificationKey(OPTIONS));
}finally{await keyApi.destroy();}
let circuitBytes,keyBytes,manifestBytes;
if(group) {
  // Only the compiler's absolute source paths (file_map, debug symbols) may differ.
  circuitBytes=await readFile(resolve(group,'circuits.json'));keyBytes=await readFile(resolve(group,'keys.json'));
  manifestBytes=await readFile(resolve(group,'manifest.json'));
  const programs=JSON.parse(circuitBytes),groupKeys=JSON.parse(keyBytes),manifest=JSON.parse(manifestBytes);
  for(const kind of kinds) {
    for(const field of ['noir_version','hash','abi','bytecode'])
      assert.deepEqual(programs[kind][field],compiled[kind][field],`Group ${kind} ${field} differs from this source tree`);
    assert.equal(groupKeys[kind],keys[kind],`Group ${kind} verification key differs`);
  }
  assert.equal(manifest.circuitSha256,sha(circuitBytes).toString('hex'));assert.equal(manifest.vkSha256,sha(keyBytes).toString('hex'));
  assert.deepEqual(manifest.setup,lock.files);
  await writeFile(resolve(directory,'circuits.json'),circuitBytes);
} else {
  circuitBytes=await readFile(resolve(directory,'circuits.json'));keyBytes=Buffer.from(JSON.stringify(keys));
  manifestBytes=Buffer.from(JSON.stringify({version:1,accountingMode:'account-extension-v1',compiler:'1.0.0-beta.26',
    backend:producer.receipt.packageVersion,verifierTarget:OPTIONS.verifierTarget,circuitSha256:sha(circuitBytes).toString('hex'),
    vkSha256:sha(keyBytes).toString('hex'),numPoints:lock.numPoints,setup:lock.files}));
}
await writeFile(resolve(directory,'keys.json'),keyBytes);await writeFile(resolve(directory,'manifest.json'),manifestBytes);
const manifestSha256=sha(manifestBytes).toString('hex');
const configPath=resolve(directory,'config.json');
await writeFile(configPath,JSON.stringify({directory,manifestSha256}));
const artifacts=await loadArtifacts(configPath);

// ---- Holder side: the maintained cwlt witness construction and planner.
const {default:init,prepare}=await import('../.extension-wasm/cwlt.js');
await init({module_or_path:await readFile('.extension-wasm/cwlt_bg.wasm')});
const transition=input=>JSON.parse(prepare(JSON.stringify(input)));
const encodeBundle=proofs=>Buffer.from(JSON.stringify({version:1,proofs})).toString('hex');
let activeProver;
async function proof(kind,input,label) {
  const selected=artifacts.artifacts(kind);
  if(activeProver&&activeProver.kind!==kind){await activeProver.prover.destroy();activeProver=undefined;}
  activeProver??={kind,prover:await createProver({artifacts:selected,backendType:'NativeUnixSocket'})};
  // The prover verifies its own proof against the pinned key before returning it.
  const result=await activeProver.prover.prove(witnessInputs(selected.circuit,input),publicInputs(selected.circuit,input));
  console.log(`Generated and verified ${label} (${Math.round(result.timings.proveMs)} ms)`);
  return hex(result.proof);
}
const hashApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true,bbPath:producer.bbPath});
const hashes=extensionHashes(hashApi);
const issuerPath=resolve(process.env.CBLC_MEMBER_WORLD_ISSUER??'target/debug/examples/member_world_issuer');
const child=spawn(issuerPath,[],{stdio:['pipe','pipe','inherit']});
let pending;const lines=createInterface({input:child.stdout});
lines.on('line',line=>{const waiter=pending;pending=undefined;if(!waiter)throw new Error('Unexpected issuer reply');waiter.resolve(JSON.parse(line));});
child.on('exit',code=>{if(pending)pending.reject(new Error(`Issuer exited ${code}`));});
async function call(request,expected=true){assert(!pending);const result=await new Promise((resolve,reject)=>{pending={resolve,reject};child.stdin.write(JSON.stringify(request)+'\n');});
  assert.equal(result.ok,expected,`Issuer ${request.op}: ${result.error??'unexpected success'}`);return expected?result.value:result.error;}

const community=new Uint8Array(sha(communityId));
// The fixture certificate issuer (P-256 private scalar 3s) signs accepted states and record leaves.
const certificateIssuer=createECDH('prime256v1');certificateIssuer.setPrivateKey(Buffer.alloc(32,3));
const issuerKey=toArray(certificateIssuer.getPublicKey().subarray(1));
const world={version:1,community:communityId,now:NOW,policy,extension,ledger,enrollment:{},members:[]};
try {
  // ---- Enrollment: public entries only. The member secrets and account keys stay here.
  const entries=pseudonyms.map((pseudonym,i)=>{
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
    return {memberId:sha(pseudonym).toString('base64url'),accountKey:Buffer.concat([Buffer.from(key.x,'base64url'),Buffer.from(key.y,'base64url')]).toString('hex'),
      secretHash:undefined,issuedAt:NOW-1,expiresAt:NOW+10000,delegationDigest:hex(bytes(30+i))};
  });
  for(let i=0;i<entries.length;i++)entries[i].secretHash=hex(await hashes.secretHash(community,bytes(20+i)));
  const checkpoint=await checkpointFromVerified(community,entries,hashes);
  const root=toArray(fieldBytes(checkpoint.root));
  world.enrollment={entries,root,slot,checkpointPeriodSeconds:ledger.checkpointPeriodSeconds};

  // ---- Every member's genesis at NOW, each against its own enrollment index.
  const genesis=[];
  for(let i=0;i<pseudonyms.length;i++) {
    const candidate=await VoucherWitness.genesis({hashes,community,policy,extension,standing:STANDING,policyTables:STANDING_TABLES,
      transition,checkpoint,ownerIndex:i,ownerSecret:bytes(20+i),now:NOW});
    // The account owner is the enrolled member identity, SHA-256 of the pseudonym.
    assert.deepEqual(toArray(candidate.statement.owner),toArray(sha(pseudonyms[i])));
    candidate.preparedProof=await proof('update',candidate.input,`genesis ${i}`);
    genesis.push(candidate);
  }
  const bundle=c=>encodeBundle([{state:c.statement.nextState,inbox:toArray(c.input.inbox),proof:c.preparedProof}]);
  const activation={account:genesis[0].statement,proof:encodeBundle([{state:genesis[0].statement.nextState,inbox:Array(32).fill(0),proof:genesis[0].preparedProof}])};
  const initialize={op:'init',community:communityId,now:NOW,deviceSeed,scope:artifacts.scope,policy,extension,
    maxAuthorizationSeconds:ledger.maxAuthorizationSeconds,checkpointPeriodSeconds:ledger.checkpointPeriodSeconds,
    artifacts:configPath,activation,slot,root};
  // A changed activation proof never opens the ledger.
  const forged=structuredClone(initialize);const original=genesis[0].preparedProof;
  forged.activation.proof=encodeBundle([{state:genesis[0].statement.nextState,inbox:Array(32).fill(0),proof:(original.startsWith('00')?'01':'00')+original.slice(2)}]);
  await call(forged,false);
  const {ledgerPolicy,...keysOut}=await call(initialize);
  world.ledgerPolicy=ledgerPolicy;
  world.activation=activation;
  world.keys={...keysOut,certificateIssuerPublicKey:issuerKey};

  // ---- Accept each genesis through the account service, then register its recipient.
  const members=[];
  for(let i=0;i<pseudonyms.length;i++) {
    const c=genesis[i];
    const update={previousInbox:{root:toArray(c.input.previous_inbox)},inbox:{root:toArray(c.input.inbox)},effect:c.update?.effect??{kind:'update'}};
    const applied=await call({op:'apply',member:MEMBER_BASE+i,pseudonym:pseudonyms[i].toString('hex'),statement:c.statement,update,proof:bundle(c)});
    const holder=c.next;holder.certificate=applied.certificate;members.push(holder);
    world.members.push({index:i,ownerIndex:i,member:MEMBER_BASE+i,activation:i===0,pseudonym:pseudonyms[i].toString('hex'),
      owner:toArray(c.statement.owner),memberId:entries[i].memberId,
      genesis:{statement:c.statement,update,proof:bundle(c)},apply:applied});
  }
  // The same accepted genesis cannot be applied a second time.
  {
    const c=genesis[1],update={previousInbox:{root:toArray(c.input.previous_inbox)},inbox:{root:toArray(c.input.inbox)},effect:{kind:'update'}};
    await call({op:'apply',member:MEMBER_BASE+1,pseudonym:pseudonyms[1].toString('hex'),statement:c.statement,update,proof:bundle(c)},false);
  }
  for(let i=0;i<pseudonyms.length;i++)
    world.members[i].recipient=await call({op:'recordRecipient',member:MEMBER_BASE+i,pseudonym:pseudonyms[i].toString('hex'),now:NOW});

  // ---- Record epoch over the accepted frontier, and one member's real record-epoch proof.
  const descriptor=await call({op:'recordEpoch',now:NOW,policyEpoch,periodSeconds:recordPeriod});
  assert.deepEqual(await call({op:'recordEpoch',now:NOW,policyEpoch,periodSeconds:recordPeriod}),descriptor); // Exact retry.
  assert.equal(descriptor.leafCount,pseudonyms.length);
  world.recordEpoch={policyEpoch,periodSeconds:recordPeriod,descriptor};
  {
    const index=pinMember,holder=members[index];
    const witness=await call({op:'recordWitness',member:MEMBER_BASE+index});
    const key=generateKeyPairSync('ed25519');
    const publicKey=toArray(key.publicKey.export({type:'spki',format:'der'}).subarray(-32));
    const candidate=await prepareRecordEpoch(holder,publicKey,witness,artifacts.scope,issuerKey,{frozenHolder:holder.clone()});
    const framed=Buffer.from(JSON.stringify({version:1,proofs:[{proof:await proof('record_epoch',candidate.input,`record epoch ${index}`)}]})).toString('hex');
    const context={purpose:'forumListing',challenge:Array(32).fill(193),expiresAt:Math.min(NOW+50,witness.epoch.expiresAt)};
    const presentation={record:structuredClone(candidate.statement.record),context,publicKey,
      signature:toArray(sign(null,recordPresentationBytes(candidate.statement.record,context),key.privateKey)),proof:framed};
    await verifyRecordPresentation(presentation,context,witness.epoch,candidate.statement.record.owner,NOW);
    await call({op:'issueRecordChallenge',owner:presentation.record.owner,context});
    const changed=structuredClone(presentation);changed.record.blindedLeaf[31]^=1;
    changed.signature=toArray(sign(null,recordPresentationBytes(changed.record,changed.context),key.privateKey));
    await call({op:'checkEpochRecord',challenge:context.challenge,presentation:changed,now:NOW},false);
    // Below quorum: the native owner check accepts the proof and publishes no shares.
    assert.equal(await call({op:'checkEpochRecord',challenge:context.challenge,presentation,now:NOW}),null);
    world.recordEpoch.proof={member:index,statement:candidate.statement,proof:framed,proofScope:artifacts.scope,presentation};
  }

  // ---- Completed pin spend: a change token bound to the exact CPNS change, accepted.
  {
    const index=pinMember;
    const binding=await call({op:'binding',change:pinChange});
    const change=await members[index].changeToken(binding,NOW+1);
    const update={previousInbox:{root:toArray(change.input.previous_inbox)},inbox:{root:toArray(change.input.inbox)},effect:change.update.effect};
    assert.deepEqual(update.effect,{kind:'change',binding});
    const statement=change.statement;
    change.preparedProof=await proof('update',change.input,`change token ${index}`);
    const applied=await call({op:'apply',member:MEMBER_BASE+index,pseudonym:pseudonyms[index].toString('hex'),statement,update,proof:bundle(change)});
    await call({op:'apply',member:MEMBER_BASE+index,pseudonym:pseudonyms[index].toString('hex'),statement,update,proof:bundle(change)},false);
    const evidence=await call({op:'pinSpend',change:pinChange});
    world.pinChange={member:index,change:pinChange,binding,changeToken:{statement,update,proof:bundle(change)},apply:applied,evidence:'pin-spend.json'};
    await writeFile(resolve(directory,'pin-spend.json'),JSON.stringify(evidence));
  }
} finally {child.stdin.end();await activeProver?.prover.destroy();await hashApi.destroy();}

// ---- Files and their manifest; the manifest digest names the retained capture.
const activationProbe={version:1,use:`${communityId}-member-world-activation`,authority:'none',communityId,policy,extension,
  activation:world.activation,configuration:{community:communityId,observation:NOW,accountPolicy:policy,extensionPolicy:extension,
    checkpointPeriodSeconds:ledger.checkpointPeriodSeconds,maxAuthorizationSeconds:ledger.maxAuthorizationSeconds},
  manifestSha256,proofScope:artifacts.scope,producer:producer.receipt};
await writeFile(resolve(directory,'activation.json'),JSON.stringify(activationProbe));
await writeFile(resolve(directory,'world.json'),JSON.stringify(world));
const portableConfig=JSON.stringify({directory:'.',manifestSha256});
await writeFile(resolve(directory,'ledger-policy.json'),JSON.stringify(world.ledgerPolicy));
const sourceCommit=process.env.CI_COMMIT_SHA;
// Plain consumer notes: how to install the same ledger and replay this world.
const readme=[`# Native member world: ${communityId} at ${NOW}`,'',
  `Producer: cblc ${sourceCommit??'(uncommitted)'}, tests/native-member-world.mts with examples/member_world_issuer.rs.`,
  `Regenerate: bash .ci/member-world.sh ${process.argv.slice(2).join(' ')}`,
  '(needs CI_COMMIT_SHA and ARTIFACT_ROOT; the tools of .ci/record-epoch.sh). Proofs are not reproducible bytes: a rerun is a new capture under a new digest.',
  'Pin: this directory name is the SHA-256 of member-world.json, which lists every other file with its SHA-256.','',
  '## Install the same ledger',
  `- AccountLedgerPolicy: ledger-policy.json. ExtensionPolicy: member-world.json "extension". Trust: community "${communityId}", policy digest base64url([3;32]).`,
  `- Artifacts: config.json (directory "." is this capture; rebase it), manifest ${manifestSha256}, native worker CBLC_BB.`,
  '- Activation: activation.json "activation" {account, proof} (owner index 0 genesis).',
  `- Enrollment: admit root world.json enrollment.root at slot ${slot} (checkpoint period ${ledger.checkpointPeriodSeconds} s) through the trusted checkpoint path; the real enrollment flow cannot produce this root.`,
  '- Keys: operator Ed25519 seed [9;32], certificate issuer P-256 scalar [3;32] (identity [0x1d;32], period from 1), '+
    `Policy key seed [1;32], device seed [${deviceSeed};32] signs every AccountRequest and RecipientRequest.`,'',
  '## Members (world.json "members", in owner index order)',
  ...world.members.map(m=>`- ownerIndex ${m.ownerIndex}${m.activation?' (activation owner)':''}: pseudonym ${m.pseudonym}, fixture member ${m.member} (root and recipient seed [${m.member};32])`),
  '','## Replay',
  `- Genesis applies: members[i].apply.request (signed AccountRequest) with members[i].genesis.update, at a clock in [${NOW}, ${world.members[0].genesis.statement.validUntil}).`,
  '- Recipients: members[i].recipient.request (signed RecipientRequest), valid 100 s from its issuedAt; then a record epoch can be prepared.',
  `- Pin spend: pin-spend.json are the exact evidence bytes for verify_completed_pin_change of the change in world.json pinChange.change (member index ${world.pinChange.member}); clock >= acceptance.acceptedAt.`,
  `- Record epoch of this producer: world.json recordEpoch (policy epoch ${policyEpoch}, period ${recordPeriod} s), with one natively checked record-epoch proof.`,''].join('\n');
await writeFile(resolve(directory,'README.md'),readme);
const holds={
  'README.md':'consumer notes: regeneration command, ledger installation, members, replay windows',
  'ledger-policy.json':'the exact AccountLedgerPolicy of the producing ledger (serde of cblc AccountLedgerPolicy)',
  'world.json':'community, NOW, policies, enrollment (public entries, root, slot), per member: genesis statement/update/proof bundle, the signed AccountRequest and its acceptance and certificate, the signed RecipientRequest; the record epoch descriptor and one record-epoch proof; the pin change',
  'activation.json':'activation probe (statement and proof bundle of member 0 genesis), in the shape of the alpha/omega startup probes',
  'pin-spend.json':'completed SpentChange evidence bytes {request, acceptance, update} as verify_completed_pin_change decodes them',
  'config.json':'artifact configuration; directory "." is relative to this capture (rebase it)',
  'manifest.json':'extension artifact manifest (pin: manifestSha256)','circuits.json':'compiled five-circuit group',
  'keys.json':'verification keys of the five circuits','setup/g1.dat':'SRS G1 (setup-lock.json)','setup/g2.dat':'SRS G2 (setup-lock.json)'};
await writeFile(resolve(directory,'portable-config.json'),portableConfig);
const sources={'config.json':'portable-config.json'};
const files={};
for(const name of Object.keys(holds)) {
  const data=await readFile(resolve(directory,sources[name]??name));
  files[name]={sha256:sha(data).toString('hex'),bytes:data.length,holds:holds[name]};
}
const metadata={version:1,purpose:'cblc.native-member-world.v1',sourceCommit:sourceCommit??null,community:communityId,
  communityDigest:toArray(community),now:NOW,policy,extension,ledger,slot,manifestSha256,proofScope:artifacts.scope,
  recordEpoch:{policyEpoch,periodSeconds:recordPeriod,epoch:world.recordEpoch.descriptor.epoch},
  seeds:{policyKey:1,operator:9,certificateIssuer:3,device:deviceSeed,memberRoot:'[member; 32]',recipient:'[member; 32]',
    note:'fictional public test seeds, never trust'},
  keys:world.keys,members:world.members.map(m=>({index:m.index,ownerIndex:m.ownerIndex,member:m.member,activation:m.activation,pseudonym:m.pseudonym,
    owner:m.owner,memberId:m.memberId,recipientKey:m.recipient.request.recipientKey})),
  pinChange:{member:world.pinChange.member,change:pinChange,binding:world.pinChange.binding},
  producer:producer.receipt,files};
const metadataBytes=Buffer.from(JSON.stringify(metadata));
await writeFile(resolve(directory,'member-world.json'),metadataBytes);
const digest=sha(metadataBytes).toString('hex');
console.log(`CBLC_MEMBER_WORLD ${JSON.stringify({community:communityId,now:NOW,members:pseudonyms.length,digest})}`);
if(process.env.ARTIFACT_ROOT) {
  assert(isAbsolute(process.env.ARTIFACT_ROOT),'Absolute ARTIFACT_ROOT required');
  assert.match(sourceCommit??'',/^[0-9a-f]{40}$/,'The fixture source commit (CI_COMMIT_SHA) is required to retain');
  const parent=resolve(process.env.ARTIFACT_ROOT,'native-member-world-retained'),destination=resolve(parent,digest);
  await mkdir(parent,{recursive:true});
  // Write-once: an existing capture is verified and left untouched.
  if(!await stat(destination).then(()=>true,()=>false)) {
    const staging=resolve(parent,`.staging.${randomBytes(8).toString('hex')}`);
    await mkdir(resolve(staging,'setup'),{recursive:true});
    try {
      for(const name of Object.keys(holds))await copyFile(resolve(directory,sources[name]??name),resolve(staging,name));
      await writeFile(resolve(staging,'member-world.json'),metadataBytes);
      await rename(staging,destination);
    } finally {await rm(staging,{recursive:true,force:true});}
  }
  assert.deepEqual(await readFile(resolve(destination,'member-world.json')),metadataBytes);
  for(const [name,file] of Object.entries(files))assert.equal(sha(await readFile(resolve(destination,name))).toString('hex'),file.sha256);
  assert.deepEqual((await readdir(destination)).sort(),[...Object.keys(holds).filter(n=>!n.includes('/')),'member-world.json','setup'].sort());
  console.log(`CBLC_RETAINED_MEMBER_WORLD ${destination}`);
}
