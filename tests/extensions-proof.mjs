// Real member/issuer round trips using fictional test identities and test keys.
// No member opening is written to disk or passed to the issuer process.
import assert from 'node:assert/strict';
import {createHash,createECDH,createPrivateKey,generateKeyPairSync,sign} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {cpus,totalmem} from 'node:os';
import {Barretenberg,BackendType,UltraHonkBackend} from '@aztec/bb.js';
import {Noir} from '@noir-lang/noir_js';
import {OPTIONS,hex,canonicalSignature,zeros} from '@corbet-labs/czkp/encoding';
import {publicInputs,witnessInputs} from '@corbet-labs/czkp/abi';
import {createProver} from '@corbet-labs/czkp/prove';
import {ExtensionWitness,extensionHashes,checkpointFromVerified,contactBytes,receiptBytes,ackBytes} from '@corbet-labs/cwlt/extensions';
import {receiptDigest} from '@corbet-labs/cwlt/hashes';
import {loadArtifacts} from '../runtime/extensions/artifacts.mjs';
import init,{prepare} from '../.extension-wasm/cwlt.js';
await init({module_or_path:await readFile('.extension-wasm/cwlt_bg.wasm')});
const transition=input=>JSON.parse(prepare(JSON.stringify(input)));
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
  for(const kind of ['update','deposit','record'])keys[kind]=hex(await new UltraHonkBackend(programs[kind].bytecode,keyApi).getVerificationKey(OPTIONS));
}finally{await keyApi.destroy();}
const keyBytes=Buffer.from(JSON.stringify(keys));await writeFile(resolve(directory,'keys.json'),keyBytes);
const issuer=createECDH('prime256v1');issuer.setPrivateKey(Buffer.alloc(32,3));
const manifest={version:1,accountingMode:'account-extension-v1',compiler:'1.0.0-beta.26',backend:'5.0.0',verifierTarget:OPTIONS.verifierTarget,
  circuitSha256:sha(await readFile(resolve(directory,'circuits.json'))).toString('hex'),vkSha256:sha(keyBytes).toString('hex'),numPoints:lock.numPoints,setup:lock.files,issuerKey:toArray(issuer.getPublicKey().subarray(1))};
const manifestBytes=Buffer.from(JSON.stringify(manifest));await writeFile(resolve(directory,'manifest.json'),manifestBytes);
const configPath=resolve(directory,'config.json');await writeFile(configPath,JSON.stringify({directory,manifestSha256:sha(manifestBytes).toString('hex')}));
const artifacts=await loadArtifacts(configPath),benchmarks=[],publicCases=[];
const hashApi=await Barretenberg.new({backend:BackendType.NativeUnixSocket,threads:1,skipSrsInit:true});
const hashes=extensionHashes(hashApi);
const child=spawn(resolve('target/debug/examples/extension_issuer'),[configPath],{stdio:['pipe','pipe','inherit']});
let pending;const lines=createInterface({input:child.stdout});
lines.on('line',line=>{const waiter=pending;pending=undefined;if(!waiter)throw new Error('Unexpected issuer reply');waiter.resolve(JSON.parse(line));});
child.on('exit',code=>{if(pending)pending.reject(new Error(`Issuer exited ${code}`));});
async function call(request,expected=true){assert(!pending);const result=await new Promise((resolve,reject)=>{pending={resolve,reject};child.stdin.write(JSON.stringify(request)+'\n');});
  assert.equal(result.ok,expected,`Issuer ${request.op}: ${result.error??'unexpected success'}`);publicCases.push({operation:request.op,ok:result.ok,error:result.error});return result.value;}
let activeProver;
async function proof(kind,input,label,measure=false){
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
let now=110;
async function submit(member,candidates,label,measure=false,expected=true){
  const proofs=[];
  for(let i=0;i<candidates.length;i++){
    const c=candidates[i];proofs.push({state:c.statement.nextState,inbox:toArray(c.input.inbox),proof:c.preparedProof??await proof('update',c.input,label,measure&&i===candidates.length-1)});
  }
  const first=candidates[0],last=candidates.at(-1),statement={...last.statement,previousState:first.statement.previousState};
  const update={previousInbox:{root:toArray(first.input.previous_inbox)},inbox:{root:toArray(last.input.inbox)},effect:last.update?.effect??{kind:'update'}};
  const request={op:'apply',member,statement,update,proof:encodeBundle(proofs)};
  const certificate=await call(request,expected);if(expected)last.next.certificate=certificate;
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
  await call({op:'record',record:stale.statement.record,proof:stale.proof,now},false);
  await call({op:'record',record:beforeQueueRecord.statement.record,proof:beforeQueueRecord.proof,now},false);
  const omitted=await members[0].reblind(now++);
  await submit(7,[omitted],'stale-frontier',false,false);
  async function drain(index){
    const queued=await call({op:'inbox',owner:toArray(members[index].owner.member)});assert(queued.entries.length>0);
    let holder=members[index];const steps=[];
    for(const entry of queued.entries){const c=await holder.consume(entry,now);steps.push(c);holder=c.next;}
    const final=await holder.reblind(now++);steps.push(final);
    members[index]=(await submit(7+index,steps,'forced-ingestion')).next;
    const empty=await call({op:'inbox',owner:toArray(members[index].owner.member)});assert.equal(empty.entries.length,0);
  }
  await drain(0);await drain(3);
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
  const replySlot=members[2].slots.get(acceptedContact.incoming.toString());
  const resolution={kind:1,issuedAt:BigInt(now),historyDigest:zeros(),ed25519ReceiptDigest:zeros()};
  const replyBytes=receiptBytes(community,members[2].owner.member,members[0].owner.member,replySlot,members[2].owner.delegationDigest,resolution);
  resolution.signature=canonicalSignature(sign('sha256',replyBytes,{key:signing[2],dsaEncoding:'ieee-p1363'}));
  const answerDigest=await receiptDigest(replyBytes,resolution.signature);
  const acknowledgment={issuedAt:BigInt(now),signature:canonicalSignature(sign('sha256',ackBytes(community,members[0].owner.member,members[2].owner.member,replySlot,answerDigest,members[0].owner.delegationDigest,now),{key:signing[0],dsaEncoding:'ieee-p1363'}))};
  members[2]=(await submit(9,[await members[2].settle(acceptedContact.incoming,resolution,acknowledgment,now++)],'answer')).next;
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
  await call({op:'deposit',batch:[earlyProof,lateProof].map(d=>({deposit:d.statement.deposit,proof:d.proof})),now});
  await drain(2);
  assert.equal(members[2].opening.available,1n);assert.equal(members[2].opening.reserved,0n);
  assert.equal(members[2].opening.accepted,0n);assert.equal(members[2].opening.punished,2n);
  await assert.rejects(members[2].expire(reordered.outgoing,now));
  console.log('Real proofs passed all three outcomes, rounding, forced ingestion, pin spend, zero-balance debt and negative scenarios');
  await writeFile(resolve(directory,'results.json'),JSON.stringify({benchmarks,checks:publicCases,platform:{node:process.version,cpu:cpus()[0]?.model,memoryBytes:totalmem(),threads:1},scope:artifacts.scope},null,2));
}finally{child.stdin.end();await activeProver?.prover.destroy();await hashApi.destroy();}
