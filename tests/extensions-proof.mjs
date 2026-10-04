// Real member/issuer round trips using fictional test identities and test keys.
// No member opening is written to disk or passed to the issuer process.
import assert from 'node:assert/strict';
import {createHash,createECDH,createPrivateKey,generateKeyPairSync,sign} from 'node:crypto';
import {readFile,writeFile,mkdir,rename} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {cpus,totalmem} from 'node:os';
import {Barretenberg,BackendType,UltraHonkBackend} from '@aztec/bb.js';
import {Noir} from '@noir-lang/noir_js';
import {OPTIONS,hex,be,canonicalSignature,zeros} from '@corbet-labs/czkp/encoding';
import {publicInputs,witnessInputs} from '@corbet-labs/czkp/abi';
import {recordEpochPublicInputs} from '@corbet-labs/czkp/record';
import {createProver} from '@corbet-labs/czkp/prove';
import {ExtensionWitness,extensionHashes,checkpointFromVerified,contactBytes,receiptBytes,ackBytes} from '@corbet-labs/cwlt/extensions';
import {receiptDigest} from '@corbet-labs/cwlt/hashes';
import {encodeExtensionCheckpoint,restoreExtensionCheckpoint} from './holder/extension-checkpoint.mjs';
import {loadArtifacts} from '../runtime/extensions/artifacts.mjs';
import {verify as verifyExtension} from '../runtime/extensions/node-verifier.mjs';
import init,{prepare} from '../.extension-wasm/cwlt.js';
await init({module_or_path:await readFile('.extension-wasm/cwlt_bg.wasm')});
const transition=input=>JSON.parse(prepare(JSON.stringify(input)));
const recordDiagnostic=process.argv.length===3&&process.argv[2]==='--record-diagnostic';
if(process.argv.length!==2&&!recordDiagnostic)throw new Error('Unknown extension fixture selector');
if(recordDiagnostic&&!process.env.CBLC_EXTENSION_DIRECTORY)throw new Error('Separate diagnostic artifact directory required');
const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test');
const sha=b=>createHash('sha256').update(b).digest();
const bytes=n=>new Uint8Array(32).fill(n);
const toArray=Array.from.bind(Array);
const programs=JSON.parse(await readFile(resolve(directory,'circuits.json')));
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
const keyApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true});
const keys={};
try{await keyApi.srsInitSrs({pointsBuf:setup['g1.dat'],numPoints:lock.numPoints,g2Point:setup['g2.dat']});
  for(const kind of ['update','deposit','record','record_epoch','wave','outcome'])keys[kind]=hex(await new UltraHonkBackend(programs[kind].bytecode,keyApi).getVerificationKey(OPTIONS));
}finally{await keyApi.destroy();}
const keyBytes=Buffer.from(JSON.stringify(keys));await writeFile(resolve(directory,'keys.json'),keyBytes);
const issuer=createECDH('prime256v1');issuer.setPrivateKey(Buffer.alloc(32,3));
const manifest={version:1,accountingMode:'account-extension-v1',compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:OPTIONS.verifierTarget,
  circuitSha256:sha(await readFile(resolve(directory,'circuits.json'))).toString('hex'),vkSha256:sha(keyBytes).toString('hex'),numPoints:lock.numPoints,setup:lock.files,issuerKey:toArray(issuer.getPublicKey().subarray(1))};
const manifestBytes=Buffer.from(JSON.stringify(manifest));await writeFile(resolve(directory,'manifest.json'),manifestBytes);
const configPath=resolve(directory,'config.json');await writeFile(configPath,JSON.stringify({directory,manifestSha256:sha(manifestBytes).toString('hex')}));
const artifacts=await loadArtifacts(configPath),benchmarks=[],publicCases=[],publicTrace=[];
const hashApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true});
const hashes=extensionHashes(hashApi);
const child=spawn(resolve(process.env.CBLC_EXTENSION_ISSUER??'target/debug/examples/extension_issuer'),[configPath],{stdio:['pipe','pipe','inherit']});
let pending;const lines=createInterface({input:child.stdout});
lines.on('line',line=>{const waiter=pending;pending=undefined;if(!waiter)throw new Error('Unexpected issuer reply');waiter.resolve(JSON.parse(line));});
child.on('exit',code=>{if(pending)pending.reject(new Error(`Issuer exited ${code}`));});
async function call(request,expected=true,retain=true){assert(!pending);const result=await new Promise((resolve,reject)=>{pending={resolve,reject};child.stdin.write(JSON.stringify(request)+'\n');});
  assert.equal(result.ok,expected,`Issuer ${request.op}: ${result.error??'unexpected success'}`);publicCases.push({operation:request.op,ok:result.ok,error:result.error});
  if(retain)publicTrace.push({request:structuredClone(request),response:result});return result.value;}
let activeProver;
async function proof(kind,input,label,measure=false){
  if(recordDiagnostic&&kind!=='record_epoch')measure=false;
  const selected=artifacts.artifacts(kind),witness=witnessInputs(selected.circuit,input),expected=publicInputs(selected.circuit,input);
  let chosen;
  for(const backendType of measure?['NativeUnixSocket','Wasm']:['NativeUnixSocket']){
    if(activeProver&&(activeProver.kind!==kind||backendType!=='NativeUnixSocket')){await activeProver.prover.destroy();activeProver=undefined;}
    const prover=activeProver?.prover??await createProver({artifacts:selected,backendType});
    if(backendType==='NativeUnixSocket')activeProver={kind,prover};
    try{const result=await prover.prove(witness,expected);chosen??=hex(result.proof);
      if(measure){benchmarks.push({label,kind,backend:backendType,...result.timings});console.log(`Measured ${label} ${backendType}: ${JSON.stringify(result.timings)}`);}}
    finally{if(backendType!=='NativeUnixSocket')await prover.destroy();}
  }
  console.log(`Generated and verified ${label}`);
  return chosen;
}
const encodeBundle=proofs=>Buffer.from(JSON.stringify({version:1,proofs})).toString('hex');
let now=110,publishedEpoch;
async function submit(member,candidates,label,measure=false,expected=true,options={}){
  const proofs=[];
  for(let i=0;i<candidates.length;i++){
    const c=candidates[i];proofs.push({state:c.statement.nextState,inbox:toArray(c.input.inbox),proof:c.preparedProof??await proof('update',c.input,label,measure&&i===candidates.length-1)});
  }
  const first=candidates[0],last=candidates.at(-1),statement={...last.statement,previousState:first.statement.previousState};
  const update={previousInbox:{root:toArray(first.input.previous_inbox)},inbox:{root:toArray(last.input.inbox)},effect:last.update?.effect??{kind:'update'}};
  const request={op:'apply',member,statement,update,proof:encodeBundle(proofs),
    expectAncestry:publishedEpoch!==undefined&&statement.now<(publishedEpoch+1)*100,...options};
  const certificate=await call(request,expected);
  if(expected) {
    const original=last.next,limits={maxBytes:1024*1024,maxMapEntries:256,maxSlots:64};
    const checkpointBytes=encodeExtensionCheckpoint(original,limits);
    const options={hashes,extension:original.extension,transition,enrollment:original.checkpoint,
      ownerSecret:original.ownerSecret,expectedStatement:statement,checkpointBytes,limits};
    const restored=await restoreExtensionCheckpoint(options);
    assert.equal(restored.commitment,original.commitment);
    assert.deepEqual(encodeExtensionCheckpoint(restored,limits),checkpointBytes);
    // Checkpoint bytes stay in this fictional member's memory, never artifacts.
    for(const key of ['debt','accepted','declined','punished','authorization']) {
      const corrupt=JSON.parse(new TextDecoder().decode(checkpointBytes));
      corrupt.opening[key]=(BigInt(corrupt.opening[key])+1n).toString();
      await assert.rejects(restoreExtensionCheckpoint({...options,checkpointBytes:new TextEncoder().encode(JSON.stringify(corrupt))}));
    }
    restored.certificate=certificate;last.next=restored;
  }
  return {next:last.next,request};
}
async function anonymous(candidate,label,measure=false){return {statement:candidate.statement,proof:encodeBundle([{proof:await proof(candidate.statement.kind,candidate.input,label,measure)}])};}
const extension={revision:1,publicRecordQuorum:2,changeTokenCost:1,depositDelaySeconds:10,minimumDepositBatch:2};
const policy={initialCredit:3,maximumAvailable:3,outgoingReservation:1,incomingReservation:1,policyRevision:1,policyValidFrom:1,policyValidUntil:2000,
  newcomerPeriod:100,rateWindow:10,newcomerAdmissions:8,maximumAdmissions:8,refillPeriod:10,refillUnits:1,abandonAfter:100};
const community=new Uint8Array(sha('community.example'));
const signing=[],entries=[],members=[];
try{
  for(let i=0;i<4;i++){
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});signing.push(key.privateKey);
    const jwk=key.publicKey.export({format:'jwk'});entries.push({memberId:sha(Buffer.alloc(48,7+i)).toString('base64url'),accountKey:Buffer.concat([Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]).toString('hex'),
      secretHash:hex(await hashes.secretHash(community,bytes(20+i))),issuedAt:1,expiresAt:10000,delegationDigest:hex(bytes(30+i))});
  }
  const checkpoint=await checkpointFromVerified(community,entries,hashes);
  const genesis=[];
  for(let i=0;i<4;i++)genesis.push(await ExtensionWitness.genesis({hashes,community,policy,extension,transition,checkpoint,ownerIndex:i,ownerSecret:bytes(20+i),now:now++}));
  const wasmHashes=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true});
  try {
    const limits={maxBytes:1024*1024,maxMapEntries:256,maxSlots:64};
    const checkpointBytes=encodeExtensionCheckpoint(genesis[0].next,limits);
    const restored=await restoreExtensionCheckpoint({hashes:extensionHashes(wasmHashes),extension,transition,
      enrollment:checkpoint,ownerSecret:bytes(20),expectedStatement:genesis[0].statement,checkpointBytes,limits});
    assert.deepEqual(encodeExtensionCheckpoint(restored,limits),checkpointBytes);
  } finally {await wasmHashes.destroy();}
  genesis[0].preparedProof=await proof('update',genesis[0].input,'genesis');
  // Capacity uses the actual pinned proof size, including hex/JSON framing.
  // This checks the transport bound only; repeated genesis is not a valid chain.
  const capacityProbe=encodeBundle(Array.from({length:65},()=>({state:Array(32).fill(255),inbox:Array(32).fill(255),proof:genesis[0].preparedProof})));
  assert(capacityProbe.length/2<=4*1024*1024);
  const activation={account:genesis[0].statement,proof:encodeBundle([{state:genesis[0].statement.nextState,inbox:Array(32).fill(0),proof:genesis[0].preparedProof}])};
  const initialize={op:'init',policy,extension,scope:artifacts.scope,root:toArray((await import('@corbet-labs/czkp/primitives')).fieldBytes(checkpoint.root)),activation};
  const badActivation=structuredClone(initialize);
  const forgedGenesis=genesis[0].preparedProof;
  badActivation.activation.proof=encodeBundle([{state:genesis[0].statement.nextState,inbox:Array(32).fill(0),proof:(forgedGenesis.startsWith('00')?'01':'00')+forgedGenesis.slice(2)}]);
  await call(badActivation,false);
  await call(initialize);
  for(let i=0;i<4;i++)members[i]=(await submit(7+i,[genesis[i]],'genesis')).next;
  await call({op:'retry',member:7,now}); // No epoch: retry must retain the original absence.
  for(let i=0;i<4;i++)await call({op:'recordRecipient',member:7+i,now});
  await call({op:'recordEpochRollback',now});
  await call({op:'recordEpoch',now,failCommit:true},false);
  await call({op:'retry',member:7,now}); // Failed publication installs no marker or clock.
  const record=async(index,label,measure=false)=>anonymous(members[index].record({purpose:'forumListing',challenge:toArray(bytes(now%255)),expiresAt:now+90}),label,measure);
  const stale=await record(0,'record-below-quorum');
  assert.equal(await call({op:'record',record:stale.statement.record,proof:stale.proof,now}),null);
  let nonce=60;
  const signContact=(index,owner,slot)=>canonicalSignature(sign('sha256',contactBytes(community,owner,slot),{key:signing[index],dsaEncoding:'ieee-p1363'}));
  async function contact(sender,recipient){
    const n=bytes(nonce++),group=bytes(nonce++),contactPolicy=bytes(nonce++);
    const outgoing=await members[sender].reserve({peerIndex:recipient,role:0,nonce:n,group,contactPolicy,now:now++});
    members[sender]=(await submit(7+sender,[outgoing],'reserve')).next;
    const s=members[sender].slots.get(outgoing.event.toString());
    const incoming=await members[recipient].reserve({peerIndex:sender,role:1,nonce:n,group,contactPolicy,openedAt:s.admittedAt,expiresAt:s.expiresAt,now:now++});
    members[recipient]=(await submit(7+recipient,[incoming],'reserve')).next;
    const r=members[recipient].slots.get(incoming.event.toString());
    return {sender,recipient,outgoing:outgoing.event,incoming:incoming.event,senderSignature:signContact(sender,members[recipient].owner.member,r),recipientSignature:signContact(recipient,members[sender].owner.member,s)};
  }
  const first=await contact(0,1),noise=await contact(3,1);
  const burns=[];
  for(const [i,c] of [first,noise].entries()){
    const candidate=await members[1].punish(c.incoming,now++,c.senderSignature);
    const malformed=structuredClone(candidate.input);malformed.old.available=BigInt(malformed.old.available)+1n;
    await assert.rejects(new Noir(programs.update).execute(witnessInputs(programs.update,malformed)));
    members[1]=(await submit(8,[candidate],'punishment',i===0)).next;
    assert.equal(members[1].opening.reserved,BigInt(1-i));
    burns.push({member:members[1],delivery:candidate.delivery});
  }
  assert.equal(members[1].opening.available,1n);
  now=Math.ceil((now+extension.depositDelaySeconds)/10)*10;
  const deposits=[];
  for(const [i,b] of burns.entries())deposits.push(await anonymous(await b.member.deposit(b.delivery,b.member.certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'deposit',i===0));
  const beforeQueueRecord=await record(0,'record-before-delivery');
  assert.equal(await call({op:'record',record:beforeQueueRecord.statement.record,proof:beforeQueueRecord.proof,now}),null);
  const batch=deposits.map(d=>({deposit:d.statement.deposit,proof:d.proof}));
  await call({op:'deposit',batch,now});
  await call({op:'deposit',batch,now}); // Exact retry cannot append twice.
  // A real verified update during preparation must remain available and make
  // the stale candidate publication fail; no unpublished lineage can escape.
  members[2]=(await submit(9,[await members[2].reblind(now++)],'publication-racing-update',false,true,{racePublication:true})).next;
  await call({op:'recordEpoch',now});publishedEpoch=Math.floor(now/100);
  await call({op:'recordEpoch',now}); // Actual publication returns the original object.
  const tuning=await call({op:'tuneWaiting',seconds:120,now});
  assert.equal(tuning.revision,1);
  for(let i=0;i<members.length;i++)members[i]=await members[i].withPolicy({...policy,abandonAfter:tuning.seconds});
  await call({op:'recordEpoch',now}); // Same root/object survives authorized waiting-only tuning.
  await call({op:'retry',member:7,now}); // Publishing cannot recertify a prior acceptance.
  const recordEpochProofs=[];
  let priorAncestrySignature;
  async function epochRecord(index,label,measure=false){
    // Fictional member-only decryption output. Never retained in publicTrace,
    // result reports or proof artifacts; only the resulting ZK proof is public.
    const witness=await call({op:'recordWitness',member:7+index},true,false);
    const context={purpose:'forumListing',challenge:toArray(bytes(193+index)),expiresAt:Math.min(now+50,witness.epoch.expiresAt)};
    const candidate=await members[index].recordEpoch(context,witness,artifacts.scope,manifest.issuerKey);
    const encoded=await proof('record_epoch',candidate.input,label,measure);
    const record={statement:candidate.statement,proof:encodeBundle([{proof:encoded}]),proofScope:artifacts.scope};
    await verifyExtension(record,artifacts);recordEpochProofs.push(record);
    for(const field of ['challenge','purpose','community','owner','root','epoch','scope','shares']){
      const changed=structuredClone(record),r=changed.statement.record;
      if(field==='challenge')r.context.challenge[0]^=1;
      else if(field==='purpose')r.context.purpose='firstContact';
      else if(field==='community')r.epoch.community[0]^=1;
      else if(field==='owner')r.owner[0]^=1;
      else if(field==='root')r.epoch.root[0]^=1;
      else if(field==='epoch')r.epoch.epoch+=1;
      else if(field==='shares')r.shares=r.shares===null?[0,0,10000]:null;
      else r.epoch.proofScope.verifyingKeyDigest[0]^=1;
      await assert.rejects(verifyExtension(changed,artifacts));
    }
    if(candidate.input.descended){
      const highS=Array.from(candidate.input.certificate),order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
      highS.splice(32,32,...be(order-BigInt('0x'+hex(highS.slice(32))),32));
      for(const change of [v=>{v.certificate[0]^=1;},v=>{v.frozen_state[31]^=1;},
        v=>{v.required_inbox[0]^=1;},v=>{v.issued_at=v.epoch_start-1;},v=>{v.path[0][0]^=1;},
        v=>{v.version+=1n;},v=>{v.descended=false;},v=>{v.certificate=highS;},
        ...(priorAncestrySignature?[v=>{v.certificate=priorAncestrySignature;}]:[])]){
        const changed=structuredClone(candidate.input);change(changed);
        await assert.rejects(new Noir(programs.record_epoch).execute(witnessInputs(programs.record_epoch,changed)));
      }
      priorAncestrySignature=Array.from(candidate.input.certificate);
    }
    return candidate.statement.record.shares;
  }
  assert.equal(await epochRecord(1,'record-epoch-exact',true),null);
  {
    // Genuine frozen state with a pending punishment: exact state/version alone
    // must not authorize an exact-branch proof before the required inbox drains.
    const witness=await call({op:'recordWitness',member:7},true,false);
    const context={purpose:'forumListing',challenge:toArray(bytes(197)),expiresAt:Math.min(now+50,witness.epoch.expiresAt)};
    await assert.rejects(members[0].recordEpoch(context,witness,artifacts.scope,manifest.issuerKey));
    const local=members[0].record(context),leaf=witness.leaf;
    const {extension,version,state,state_policy,registered_secret,opening}=local.input;
    assert.equal(Number(version),leaf.version);assert.deepEqual(toArray(state),leaf.state);
    assert.notDeepEqual(toArray(opening.inbox),leaf.requiredInbox);
    const path=structuredClone(witness.path);while(path.length<32)path.push(Array(32).fill(0));
    const record={epoch:witness.epoch,owner:local.statement.record.owner,context,shares:local.statement.record.shares};
    const exact={...recordEpochPublicInputs(record,artifacts.scope,manifest.issuerKey),extension,
      version,state,state_policy,registered_secret,opening,frozen_version:leaf.version,frozen_state:leaf.state,
      required_inbox:leaf.requiredInbox,blinding:leaf.blinding,index:witness.index,path,
      descended:false,issued_at:0,certificate:Array(64).fill(0)};
    await assert.rejects(new Noir(programs.record_epoch).execute(witnessInputs(programs.record_epoch,exact)));
  }
  await call({op:'record',record:stale.statement.record,proof:stale.proof,now},false);
  await call({op:'record',record:beforeQueueRecord.statement.record,proof:beforeQueueRecord.proof,now},false);
  const omitted=await members[0].reblind(now++);
  await submit(7,[omitted],'stale-frontier',false,false);
  async function drain(index,refuseCommit=false){
    const queued=await call({op:'inbox',member:7+index,now,owner:toArray(members[index].owner.member)});assert(queued.entries.length>0);
    let holder=members[index];const steps=[];
    for(const entry of queued.entries){const c=await holder.consume(entry,now);steps.push(c);holder=c.next;}
    const final=await holder.reblind(now++);steps.push(final);
    // Reuse the genuine proof bytes to check a failed atomic commit and then
    // accept the SAME predecessor/obligation chain without generating them twice.
    if(refuseCommit){
      const failed=await submit(7+index,steps,'failed-ingestion-commit',false,false,{failCommit:true});
      const bundle=JSON.parse(Buffer.from(failed.request.proof,'hex'));
      steps.forEach((step,i)=>step.preparedProof=bundle.proofs[i].proof);
      const stillQueued=await call({op:'inbox',member:7+index,now:final.statement.now,owner:toArray(members[index].owner.member)});
      assert.deepEqual(stillQueued.entries,queued.entries);
    }
    members[index]=(await submit(7+index,steps,'forced-ingestion',false,true,
      {refuseUncertified:publishedEpoch!==undefined&&final.statement.now<(publishedEpoch+1)*100,
        probeAncestry:refuseCommit})).next;
    await call({op:'retry',member:7+index,now});
    const empty=await call({op:'inbox',member:7+index,now,owner:toArray(members[index].owner.member)});assert.equal(empty.entries.length,0);
  }
  await drain(0,true);
  assert.equal(await epochRecord(0,'record-epoch-late-ingestion',true),null);
  if(!recordDiagnostic){
  await drain(3);
  assert.equal(members[0].opening.available,2n);assert.equal(members[0].opening.punished,1n);
  await assert.rejects(members[0].expire(first.outgoing,now));
  const below=await record(0,'record-below');assert.equal(await call({op:'record',record:below.statement.record,proof:below.proof,now}),null);
  const binding=await call({op:'binding',member:7});
  const change=await members[0].changeToken(binding,now++);
  const badOwner=structuredClone(change.input);badOwner.owner=members[2].owner.member;
  await assert.rejects(new Noir(programs.update).execute(witnessInputs(programs.update,badOwner)));
  const spent=await submit(7,[change],'change-token');members[0]=spent.next;
  await call({op:'pins',member:7});
  await call(spent.request,false); // Same predecessor/marker cannot authorize a new request.
  // A genuine counterpart Answer supplies the second counted first contact.
  const acceptedContact=await contact(0,2);
  members[2]=(await submit(9,[await members[2].activate(acceptedContact.incoming,now++,acceptedContact.senderSignature)],'activate')).next;
  members[0]=(await submit(7,[await members[0].activate(acceptedContact.outgoing,now++,acceptedContact.recipientSignature)],'activate-outgoing')).next;
  const policyPath=resolve(directory,'wave-policy.json');
  await writeFile(policyPath,JSON.stringify(await call({op:'publication'})));
  const peerVerifier=spawn(resolve('target/debug/examples/wave_verifier'),[configPath,policyPath,fileURLToPath(import.meta.resolve('@corbet-labs/czkp/node-verifier'))],{stdio:['pipe','pipe','inherit']});
  let peerWait;const peerLines=createInterface({input:peerVerifier.stdout});
  peerLines.on('line',line=>{const w=peerWait;peerWait=undefined;w.resolve(JSON.parse(line));});
  peerVerifier.on('exit',code=>{if(peerWait)peerWait.reject(new Error(`Peer verifier exited ${code}`));});
  const publicWaveTrace=[];
  // Retain only this fictional fixture's public boundary, including a refusal.
  // The pending request survives a process exit; private inputs stay in memory.
  async function retainWaveAttempt(request,expectedVerified,reply=null){
    assert(publicWaveTrace.length<128);
    const attempt={sequence:publicWaveTrace.length,expectedVerified,request,reply};
    const encoded=JSON.stringify(attempt);assert(Buffer.byteLength(encoded)<=3*1024*1024);
    const path=resolve(directory,'public-wave-attempt.json');
    await writeFile(path+'.tmp',encoded);await rename(path+'.tmp',path);
  }
  async function checkWave(statement,expected,proof,at,ok){
    const request={statement,expected,proof,now:at};
    await retainWaveAttempt(request,ok);
    const reply=await new Promise((resolve,reject)=>{peerWait={resolve,reject};peerVerifier.stdin.write(JSON.stringify(request)+'\n');});
    await retainWaveAttempt(request,ok,reply);
    assert.equal(reply.verified,ok);
    publicWaveTrace.push({request:{statement,expected,proof,now:at},verified:ok});
  }
  try {
    for(const [index,event] of [[0,acceptedContact.outgoing],[2,acceptedContact.incoming]]) {
      const candidate=await members[index].wave(event,{history:bytes(201),challenge:bytes(202)},artifacts.scope.circuitDigest,manifest.issuerKey);
      const encoded=await proof('wave',candidate.input,'accepted-active-wave',index===0);
      const statement=candidate.statement.wave,expected=statement.context;
      await checkWave(statement,expected,encoded,now,true);
      for(const key of ['peer','owner','community','group','nonce','contactPolicy','history','challenge','ownerAuthority','peerAuthority']) {
        const wrong=structuredClone(expected);wrong[key][0]^=1;await checkWave(statement,wrong,encoded,now,false);
      }
      for(const key of ['role','openedAt','expiresAt']) {
        const wrong=structuredClone(expected);wrong[key]++;await checkWave(statement,wrong,encoded,now,false);
      }
      await checkWave(statement,expected,encoded,expected.expiresAt,false);
      const wrong=structuredClone(statement);wrong.state[31]^=1;await checkWave(wrong,expected,encoded,now,false);
      for(const mutate of [i=>i.slot.phase=1,i=>i.slot.outcome=1,i=>i.slot.answered=true,i=>i.slot.self_punished=true,
        i=>i.opening.debt+=1n,i=>i.opening.inbox[0]^=1,i=>i.certificate[0]^=1,i=>i.issuer_key[0]^=1,
        i=>i.selected.leaf[1]+=1n,i=>i.state_policy[0]^=1,i=>i.scope[0]^=1]) {
        const wrong=structuredClone(candidate.input);mutate(wrong);
        await assert.rejects(new Noir(programs.wave).execute(witnessInputs(programs.wave,wrong)));
      }
    }
  } finally {peerVerifier.stdin.end();peerLines.close();}
  async function settledEvidence(index,event,outcome,resolution,acknowledgment){
    const candidate=await members[index].waveOutcome(event,{history:resolution?.historyDigest??bytes(213),challenge:bytes(214)},
      artifacts.scope.circuitDigest,manifest.issuerKey,outcome,resolution,acknowledgment);
    const encoded=await proof('outcome',candidate.input,`settled-${outcome}`,outcome==='answer'&&index===2);
    const statement=candidate.statement.outcome,expected=statement.evidence.context;
    const request={statement,expected,proof:encoded,now,expectedOutcome:outcome,expectedReceiptDigest:statement.receiptDigest};
    const peer=spawn(resolve('target/debug/examples/wave_verifier'),[configPath,policyPath,fileURLToPath(import.meta.resolve('@corbet-labs/czkp/node-verifier'))],{stdio:['pipe','pipe','inherit']});
    const replies=createInterface({input:peer.stdout})[Symbol.asyncIterator]();
    async function check(request,verified){
      await retainWaveAttempt(request,verified);
      peer.stdin.write(JSON.stringify(request)+'\n');const reply=await replies.next();assert(!reply.done);
      const response=JSON.parse(reply.value);await retainWaveAttempt(request,verified,response);
      assert.deepEqual(response,{verified});publicWaveTrace.push({request:structuredClone(request),verified});
    }
    try{
      await check(request,true);
      for(const mutate of [r=>r.statement.evidence.state[31]^=1,r=>r.statement.receiptDigest[0]^=1,
        r=>r.expectedOutcome=outcome==='answer'?'close':'answer',r=>r.expected.history[0]^=1,
        r=>r.expected.peer[0]^=1,r=>r.statement.evidence.context.challenge[0]^=1,
        r=>r.proof=(r.proof.startsWith('00')?'01':'00')+r.proof.slice(2)]){
        const bad=structuredClone(request);mutate(bad);await check(bad,false);
      }
    }finally{peer.stdin.end();}
    for(const mutate of [i=>i.slot.phase=2,i=>i.certificate[0]^=1,i=>i.opening.debt+=1n,
      ...(outcome==='silence'?[i=>i.receipt_digest[0]^=1,i=>i.outcome=2]:[i=>i.resolution.signature[0]^=1,i=>i.resolution.history_digest[0]^=1,i=>i.peer_enrollment.key[0]^=1]),
      ...(outcome==='answer'?[i=>i.acknowledgment.signature[0]^=1]:[])]){
      const bad=structuredClone(candidate.input);mutate(bad);
      await assert.rejects(new Noir(programs.outcome).execute(witnessInputs(programs.outcome,bad)));
    }
  }
  const replySlot=members[2].slots.get(acceptedContact.incoming.toString());
  const resolution={kind:1,issuedAt:BigInt(now),historyDigest:zeros(),ed25519ReceiptDigest:zeros()};
  const replyBytes=receiptBytes(community,members[2].owner.member,members[0].owner.member,replySlot,members[2].owner.delegationDigest,resolution);
  resolution.signature=canonicalSignature(sign('sha256',replyBytes,{key:signing[2],dsaEncoding:'ieee-p1363'}));
  const answerDigest=await receiptDigest(replyBytes,resolution.signature);
  const acknowledgment={issuedAt:BigInt(now),signature:canonicalSignature(sign('sha256',ackBytes(community,members[0].owner.member,members[2].owner.member,replySlot,answerDigest,members[0].owner.delegationDigest,now),{key:signing[0],dsaEncoding:'ieee-p1363'}))};
  members[2]=(await submit(9,[await members[2].settle(acceptedContact.incoming,resolution,acknowledgment,now++)],'answer')).next;
  await settledEvidence(2,acceptedContact.incoming,'answer',resolution,acknowledgment);
  now=Math.ceil((now+10)/10)*10;
  const answerCandidate=await members[2].deposit({slot:replySlot,kind:1},members[2].certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10);
  const forged=structuredClone(answerCandidate.input);forged.certificate=Array(64).fill(0);
  await assert.rejects(new Noir(programs.deposit).execute(witnessInputs(programs.deposit,forged)));
  const linked=structuredClone(answerCandidate.input);
  linked.authorization_nullifier=(await import('@corbet-labs/czkp/primitives')).fieldBytes(await hashes.raw([acceptedContact.incoming,40,0]));
  await assert.rejects(new Noir(programs.deposit).execute(witnessInputs(programs.deposit,linked)));
  const answer=await anonymous(answerCandidate,'answer-deposit');
  await call({op:'deposit',batch:[{deposit:answer.statement.deposit,proof:answer.proof},batch[1]],now});
  await drain(0);
  await settledEvidence(0,acceptedContact.outgoing,'answer',resolution,acknowledgment);
  assert.equal(members[0].opening.accepted,1n);assert.equal(members[0].opening.punished,1n);
  const visible=await record(0,'record-quorum',true);
  assert.deepEqual(await call({op:'record',record:visible.statement.record,proof:visible.proof,now}),[5000,0,5000]);
  const falseShares=structuredClone(visible.statement.record);falseShares.shares=[5001,0,4999];
  await call({op:'record',record:falseShares,proof:visible.proof,now},false);
  // Spend the last available unit, then punish an established conversation at zero.
  members[0]=(await submit(7,[await members[0].changeToken(bytes(211),now++)],'second-change')).next;
  assert.equal(members[0].opening.available,0n);
  const established=await members[0].punish(acceptedContact.outgoing,now++,acceptedContact.recipientSignature);
  members[0]=(await submit(7,[established],'established-punishment')).next;
  assert.equal(members[0].opening.debt,1n);
  const blocked=await members[0].reserve({peerIndex:2,role:0,nonce:bytes(221),group:bytes(222),contactPolicy:bytes(223),now}).catch(()=>null);
  if(blocked)await assert.rejects(new Noir(programs.update).execute(witnessInputs(programs.update,blocked.input)));
  now=Math.ceil((now+10)/10)*10;
  const establishedDeposit=await anonymous(await members[0].deposit(established.delivery,members[0].certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'established-deposit');
  await call({op:'deposit',batch:[{deposit:establishedDeposit.statement.deposit,proof:establishedDeposit.proof},batch[1]],now});
  await drain(2);assert.equal(members[2].opening.available,2n);assert.equal(members[2].opening.punished,1n);
  members[0]=(await submit(7,[await members[0].refill(now++)],'debt-refill')).next;
  assert.equal(members[0].opening.debt,0n);assert.equal(members[0].opening.available,0n);
  now=Math.max(now,Number(members[0].opening.frontier)+10);
  members[0]=(await submit(7,[await members[0].refill(now++)],'spendable-refill')).next;
  assert.equal(members[0].opening.available,1n);
  const declinedContact=await contact(0,3);
  members[3]=(await submit(10,[await members[3].activate(declinedContact.incoming,now++,declinedContact.senderSignature)],'decline-activate')).next;
  const declinedSlot=members[3].slots.get(declinedContact.incoming.toString());
  const decline={kind:2,issuedAt:BigInt(now),historyDigest:zeros(),ed25519ReceiptDigest:zeros()};
  decline.signature=canonicalSignature(sign('sha256',receiptBytes(community,members[3].owner.member,members[0].owner.member,declinedSlot,members[3].owner.delegationDigest,decline),{key:signing[3],dsaEncoding:'ieee-p1363'}));
  members[3]=(await submit(10,[await members[3].settle(declinedContact.incoming,decline,undefined,now++)],'decline')).next;
  await settledEvidence(3,declinedContact.incoming,'close',decline);
  now=Math.ceil((now+10)/10)*10;
  const declineProof=await anonymous(await members[3].deposit({slot:declinedSlot,kind:2},members[3].certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'decline-deposit');
  await call({op:'deposit',batch:[{deposit:declineProof.statement.deposit,proof:declineProof.proof},batch[1]],now});
  await drain(0);assert.equal(members[0].opening.declined,1n);assert.equal(members[0].opening.reserved,1n);
  await assert.rejects(members[0].cancel(declinedContact.outgoing,now));
  const rounded=await record(0,'record-rounding');
  assert.deepEqual(await call({op:'record',record:rounded.statement.record,proof:rounded.proof,now}),[3333,3333,3334]);
  // Anonymous transport can deliver established punishment before the Answer.
  // Both deposits must remain consumable in that order without a late refund.
  const reordered=await contact(2,1);
  members[1]=(await submit(8,[await members[1].activate(reordered.incoming,now++,reordered.senderSignature)],'reordered-activate')).next;
  const delayedSlot=members[1].slots.get(reordered.incoming.toString());
  const delayedAnswer={kind:1,issuedAt:BigInt(now),historyDigest:zeros(),ed25519ReceiptDigest:zeros()};
  const delayedBytes=receiptBytes(community,members[1].owner.member,members[2].owner.member,delayedSlot,members[1].owner.delegationDigest,delayedAnswer);
  delayedAnswer.signature=canonicalSignature(sign('sha256',delayedBytes,{key:signing[1],dsaEncoding:'ieee-p1363'}));
  const delayedDigest=await receiptDigest(delayedBytes,delayedAnswer.signature);
  const delayedAck={issuedAt:BigInt(now),signature:canonicalSignature(sign('sha256',ackBytes(community,members[2].owner.member,members[1].owner.member,delayedSlot,delayedDigest,members[2].owner.delegationDigest,now),{key:signing[2],dsaEncoding:'ieee-p1363'}))};
  const answered=(await submit(8,[await members[1].settle(reordered.incoming,delayedAnswer,delayedAck,now++)],'reordered-answer')).next;
  const early=await answered.punish(reordered.incoming,now++,reordered.senderSignature);
  members[1]=(await submit(8,[early],'reordered-punishment')).next;
  now=Math.ceil((now+10)/10)*10;
  const earlyProof=await anonymous(await members[1].deposit(early.delivery,members[1].certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'early-punishment-deposit');
  const lateProof=await anonymous(await answered.deposit({slot:delayedSlot,kind:1},answered.certificate,artifacts.scope.circuitDigest,manifest.issuerKey,now/10),'late-answer-deposit');
  await call({op:'deposit',batch:[{deposit:earlyProof.statement.deposit,proof:earlyProof.proof},batch[1]],now});
  assert(Math.floor(now/100)>publishedEpoch);
  await call({op:'recordEpoch',now});publishedEpoch=Math.floor(now/100);
  await call({op:'deposit',batch:[{deposit:lateProof.statement.deposit,proof:lateProof.proof},batch[1]],now});
  // The frozen required root is now IN THE MIDDLE of the genuine consumed
  // chain, proving minimum-frontier inclusion rather than equality only.
  await drain(2);
  assert.deepEqual(await epochRecord(2,'record-epoch-minimum-frontier'),[0,0,10000]);
  assert.equal(members[2].opening.available,1n);assert.equal(members[2].opening.reserved,0n);
  assert.equal(members[2].opening.accepted,0n);assert.equal(members[2].opening.punished,2n);
  await assert.rejects(members[2].expire(reordered.outgoing,now));
  const silent=await contact(3,2);
  members[2]=(await submit(9,[await members[2].activate(silent.incoming,now++,silent.senderSignature)],'silent-recipient-activate')).next;
  members[3]=(await submit(10,[await members[3].activate(silent.outgoing,now++,silent.recipientSignature)],'silent-sender-activate')).next;
  now=Number(members[3].slots.get(silent.outgoing.toString()).expiresAt);
  members[3]=(await submit(10,[await members[3].expire(silent.outgoing,now++)],'fixed-refund')).next;
  await settledEvidence(3,silent.outgoing,'silence');
  // A newer epoch can publish between a genuine proof check and its final CAS.
  // The update must certify the NEW frozen leaf, while an exact old retry keeps
  // its original certificate (or original absence), never a reminted one.
  now=Math.ceil((now+1)/100)*100;
  publishedEpoch=Math.floor(now/100);
  members[3]=(await submit(10,[await members[3].reblind(now++)],'epoch-racing-acceptance',false,true,{raceEpoch:true})).next;
  await call({op:'retry',member:7,now});
  await call({op:'retry',member:10,now});
  await call({op:'recordEpoch',now});
  members[3]=(await submit(10,[await members[3].reblind(now++)],'concurrent-exact-acceptance',false,true,{raceAcceptance:'same'})).next;
  await call({op:'retry',member:10,now});
  await submit(9,[await members[2].reblind(now++)],'concurrent-stale-cas',false,false,{raceAcceptance:'stale'});
  await writeFile(resolve(directory,'public-wave-trace.json'),JSON.stringify(publicWaveTrace));
  }
  await writeFile(resolve(directory,'public-record-epoch-proofs.json'),JSON.stringify(recordEpochProofs));
  console.log(recordDiagnostic?'Diagnostic exact and late-ingestion record proofs passed; full extension suite not selected':'Real proofs passed all three outcomes, rounding, forced ingestion, pin spend, zero-balance debt and negative scenarios');
  await writeFile(resolve(directory,'results.json'),JSON.stringify({validationScope:recordDiagnostic?'g2-record-diagnostic':'full-extension',benchmarks,checks:publicCases,platform:{node:process.version,cpu:cpus()[0]?.model,memoryBytes:totalmem(),threads:1},scope:artifacts.scope},null,2));
  // Only fictional public requests/proofs cross this fixture pipe. Replaying
  // them measures issuer coverage without generating another set of proofs.
  await writeFile(resolve(directory,'public-trace.json'),JSON.stringify(publicTrace));
}finally{child.stdin.end();await activeProver?.prover.destroy();await hashApi.destroy();}
