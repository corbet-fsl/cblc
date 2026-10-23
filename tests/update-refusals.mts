// Account update circuit diet: refusal tests for every check that the diet merged.
//
// The update circuit shares ONE P-256 check between the contact actions (2, 7, 8) and the
// resolution action (3), and ONE peer enrollment path between action 1 and action 3 with a
// changed peer authority. Each of the former separate checks must still refuse a wrong key,
// a wrong signature and a wrong message, and no witness may make two merged branches
// active at once. Witness execution only (no proof, no issuer): real wallet witnesses
// from fictional members with generated test keys, then tampered.
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {Barretenberg,BackendType} from '@aztec/bb.js';
import {Noir} from '@noir-lang/noir_js';
import {hex,canonicalSignature,zeros} from '@corbet-labs/czkp/encoding';
import {fieldBytes} from '@corbet-labs/czkp/primitives';
import {witnessInputs} from '@corbet-labs/czkp/abi';
import {extensionHashes,checkpointFromVerified,contactBytes,receiptBytes,ackBytes} from '@corbet-labs/cwlt/extensions';
import {enrollmentInput} from '@corbet-labs/cwlt/account';
import {VoucherWitness} from '@corbet-labs/cwlt/voucher-wallet';
import {receiptDigest} from '@corbet-labs/cwlt/hashes';
import {STANDING,STANDING_DIGEST,STANDING_TABLES} from './holder/standing-fixture.mts';

const directory=resolve(process.env.CBLC_EXTENSION_DIRECTORY??'.extension-test');
const programs=JSON.parse(await readFile(resolve(directory,'circuits.json')));
assert.ok(programs.update?.bytecode,'compiled update circuit');
const {default:init,prepare}=await import('../.extension-wasm/cwlt.js');
await init({module_or_path:await readFile('.extension-wasm/cwlt_bg.wasm')});
const transition=input=>JSON.parse(prepare(JSON.stringify(input)));
const noir=new Noir(programs.update);
const sha=b=>createHash('sha256').update(b).digest();
const bytes=n=>new Uint8Array(32).fill(n);
const toArray=Array.from.bind(Array);

// ---- Refusal helpers. A witness is converted before the assertion, so a malformed
// tamper (wrong shape) throws loudly instead of passing as a "refusal".
const FAILURE=/constraint|assert|solve|fail/i;
let accepted=0,refusals=0;
async function runs(label,input) {
  await noir.execute(witnessInputs(programs.update,input)).catch(error=>{throw new Error(`${label}: untampered witness refused: ${error.message}`);});
  accepted++;
}
async function refuses(label,input,change) {
  const tampered=structuredClone(input);
  change(tampered);
  const witness=witnessInputs(programs.update,tampered);
  await assert.rejects(noir.execute(witness),error=>{
    assert.match(String(error?.message),FAILURE,`${label}: the refusal must be a failed constraint`);
    return true;
  },`${label}: must be refused`);
  refusals++;
}
const flip=array=>{array[0]^=1;};
const bump=(object,key)=>{
  const value=object[key];
  object[key]=typeof value==='bigint'?value+1n:typeof value==='number'?value+1:typeof value==='string'?value.slice(0,-1)+(value.endsWith('0')?'1':'0'):(()=>{throw new Error(`Unsupported tamper type ${typeof value}`);})();
};

// ---- Fictional members.
const community=new Uint8Array(sha('community-example'));
const policy={initialCredit:3,maximumAvailable:3,outgoingReservation:1,incomingReservation:1,policyRevision:1,policyValidFrom:1,policyValidUntil:3000000,
  newcomerPeriod:100,rateWindow:10,newcomerAdmissions:8,maximumAdmissions:8,refillPeriod:10,refillUnits:1,abandonAfter:100};
const extension={revision:1,publicRecordQuorum:2,changeTokenCost:1,depositDelaySeconds:10,minimumDepositBatch:2,standingPolicyDigest:STANDING_DIGEST};
const hashApi=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true});
try {
  const hashes=extensionHashes(hashApi);
  const MEMBERS=4,signing=[],entries=[];
  for(let i=0;i<MEMBERS;i++){
    const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});signing.push(key.privateKey);
    const jwk=key.publicKey.export({format:'jwk'});
    entries.push({memberId:sha(Buffer.alloc(48,7+i)).toString('base64url'),accountKey:Buffer.concat([Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]).toString('hex'),
      secretHash:hex(await hashes.secretHash(community,bytes(20+i))),issuedAt:1,expiresAt:3000000,delegationDigest:hex(bytes(30+i))});
  }
  const checkpoint=await checkpointFromVerified(community,entries,hashes);
  let now=110;
  const members=[];
  for(let i=0;i<MEMBERS;i++)members.push((await VoucherWitness.genesis({hashes,community,policy,extension,standing:STANDING,policyTables:STANDING_TABLES,transition,checkpoint,
    ownerIndex:i,ownerSecret:bytes(20+i),now:now++})).next);
  const signature=(index,message)=>canonicalSignature(sign('sha256',message,{key:signing[index],dsaEncoding:'ieee-p1363'}));
  const signContact=(index,owner,slot)=>signature(index,contactBytes(community,owner,slot));
  const witnesses=[];                       // every valid candidate, for the cross-action test
  const record=(name,action,candidate)=>{assert.equal(Number(candidate.input.action),action,`${name} is action ${action}`);witnesses.push({name,action,input:candidate.input});return candidate;};
  let nonce=60;
  async function contact(sender,recipient){
    const n=bytes(nonce++),group=bytes(nonce++),contactPolicy=bytes(nonce++);
    const outgoing=await members[sender].reserve({peerIndex:recipient,role:0,nonce:n,group,contactPolicy,now:now++});
    members[sender]=outgoing.next;
    const s=members[sender].slots.get(outgoing.event.toString());
    const incoming=await members[recipient].reserve({peerIndex:sender,role:1,nonce:n,group,contactPolicy,openedAt:s.admittedAt,expiresAt:s.expiresAt,now:now++});
    members[recipient]=incoming.next;
    const r=members[recipient].slots.get(incoming.event.toString());
    return {sender,recipient,outgoing,incoming,
      senderSignature:signContact(sender,members[recipient].owner.member,r),recipientSignature:signContact(recipient,members[sender].owner.member,s)};
  }
  // A valid signature of the same key over a different contact message (the slot differs).
  const elsewhere=(index,owner,slot)=>signContact(index,owner,{...slot,nonce:bytes(201)});
  // The recipient's Answer (kind 1, acknowledged by the sender) or Close (kind 2), settled by the recipient
  // (side 'recipient', role 1) or by the sender on its outgoing slot (side 'sender', role 0). The recipient signs.
  async function receipt(c,side,kind,peerDelegation=members[c.sender].owner.delegationDigest){
    const owner=side==='recipient'?c.recipient:c.sender;
    const slot=members[owner].slots.get((side==='recipient'?c.incoming:c.outgoing).event.toString());
    const resolution={kind,issuedAt:BigInt(now),historyDigest:zeros(),ed25519ReceiptDigest:zeros()};
    const responder=members[c.recipient].owner,other=members[c.sender].owner;
    resolution.signature=signature(c.recipient,receiptBytes(community,responder.member,other.member,slot,responder.delegationDigest,resolution));
    // A valid signature of the same key over a different receipt (another issue time).
    const later={...resolution,issuedAt:resolution.issuedAt+1n};
    const otherReceipt=signature(c.recipient,receiptBytes(community,responder.member,other.member,slot,responder.delegationDigest,later));
    let acknowledgment;
    if(kind===1&&side==='recipient') {
      const digest=await receiptDigest(receiptBytes(community,responder.member,other.member,slot,responder.delegationDigest,resolution),resolution.signature);
      acknowledgment={issuedAt:BigInt(now),signature:signature(c.sender,ackBytes(community,other.member,responder.member,slot,digest,peerDelegation,now))};
    }
    return {resolution,acknowledgment,otherReceipt};
  }
  const otherKey=index=>structuredClone(enrollmentInput(checkpoint.entries[index]).key);

  // ---- Action 1: reserve. The shared peer enrollment path must verify the peer under the root.
  const A=await contact(0,2);   // sender 0 -> recipient 2: reserve, both activations, Answer at both ends
  const B=await contact(0,1);   // sender 0 -> recipient 1: punished unanswered (7)
  for(const [label,candidate] of [['reserve role 0',A.outgoing],['reserve role 1',A.incoming]]) {
    record(label,1,candidate);
    await runs(label,candidate.input);
    await refuses(`${label}: peer enrollment path`,candidate.input,w=>{bump(w.peer_enrollment.path,0);});
    await refuses(`${label}: peer enrollment index`,candidate.input,w=>{w.peer_enrollment.index=Number(w.peer_enrollment.index)^1;});
    await refuses(`${label}: peer delegation digest`,candidate.input,w=>{flip(w.peer_enrollment.delegation_digest);});
    await refuses(`${label}: peer key`,candidate.input,w=>{w.peer_enrollment.key=otherKey(3);});
  }

  // ---- Contact check (actions 2, 7, 8): wrong key, wrong signature, wrong message.
  async function contactRefusals(label,input,{slot,signer,owner,wrongKey}) {
    await runs(label,input);
    await refuses(`${label}: wrong signature`,input,w=>{flip(w.contact_signature);});
    await refuses(`${label}: valid signature over another message`,input,w=>{w.contact_signature=elsewhere(signer,owner,slot);});
    await refuses(`${label}: wrong key`,input,w=>{w.peer_enrollment.key=wrongKey;});
    await refuses(`${label}: wrong message (slot nonce)`,input,w=>{flip(w.slot.nonce);});
    await refuses(`${label}: wrong message (slot expiry)`,input,w=>{bump(w.slot,'expires_at');});
    await refuses(`${label}: no signature`,input,w=>{w.contact_signature=new Uint8Array(64);});
  }
  // Action 2, role 1 (the recipient activates with the sender's signature) and role 0 (the sender with the recipient's).
  const activated=record('activate role 1',2,await members[2].activate(A.incoming.event,now++,A.senderSignature));
  await contactRefusals('activate role 1',activated.input,{slot:members[2].slots.get(A.incoming.event.toString()),signer:0,owner:members[2].owner.member,wrongKey:otherKey(3)});
  const activatedOutgoing=record('activate role 0',2,await members[0].activate(A.outgoing.event,now++,A.recipientSignature));
  await contactRefusals('activate role 0',activatedOutgoing.input,{slot:members[0].slots.get(A.outgoing.event.toString()),signer:2,owner:members[0].owner.member,wrongKey:otherKey(3)});
  members[2]=activated.next;members[0]=activatedOutgoing.next;

  // Action 7: the recipient punishes an unanswered contact.
  const punish7=record('punish unanswered (7)',7,await members[1].punish(B.incoming.event,now++,B.senderSignature));
  await contactRefusals('punish unanswered (7)',punish7.input,{slot:members[1].slots.get(B.incoming.event.toString()),signer:0,owner:members[1].owner.member,wrongKey:otherKey(3)});

  // ---- Resolution check (action 3): wrong key, wrong signature, wrong message, and no contact signature in its place.
  async function resolutionRefusals(label,input,{signerField,validContact,otherReceipt}) {
    await runs(label,input);
    await refuses(`${label}: wrong signature`,input,w=>{flip(w.resolution.signature);});
    await refuses(`${label}: no signature`,input,w=>{w.resolution.signature=new Uint8Array(64);});
    await refuses(`${label}: wrong key`,input,w=>{w[signerField].key=otherKey(3);});
    await refuses(`${label}: valid signature over another receipt`,input,w=>{w.resolution.signature=otherReceipt;});
    await refuses(`${label}: wrong message (history digest)`,input,w=>{flip(w.resolution.history_digest);});
    await refuses(`${label}: wrong message (slot nonce)`,input,w=>{flip(w.slot.nonce);});
    // A genuine contact signature cannot stand in for the resolution signature, nor sit beside a wrong one.
    await refuses(`${label}: contact signature instead of the resolution signature`,input,w=>{w.contact_signature=validContact;w.resolution.signature=validContact;});
    await refuses(`${label}: valid contact signature beside a wrong resolution signature`,input,w=>{w.contact_signature=validContact;flip(w.resolution.signature);});
  }
  // Role 1: the recipient's Answer with the sender's acknowledgment (peer authority unchanged).
  const reply=await receipt(A,'recipient',1);
  const settle=record('answer role 1',3,await members[2].settle(A.incoming.event,reply.resolution,reply.acknowledgment,now++));
  await resolutionRefusals('answer role 1',settle.input,{signerField:'receipt_owner_enrollment',validContact:A.senderSignature,otherReceipt:reply.otherReceipt});
  await refuses('answer role 1: acknowledgment signature',settle.input,w=>{flip(w.acknowledgment.signature);});
  members[2]=settle.next;
  // Role 0: the sender settles its outgoing slot with the recipient's Answer.
  const outgoingReply=await receipt(A,'sender',1);
  const settleOutgoing=record('answer role 0',3,await members[0].settle(A.outgoing.event,outgoingReply.resolution,undefined,now++));
  await resolutionRefusals('answer role 0',settleOutgoing.input,{signerField:'peer_enrollment',validContact:A.recipientSignature,otherReceipt:outgoingReply.otherReceipt});
  members[0]=settleOutgoing.next;
  // Role 1: Close (kind 2; no acknowledgment, no peer authority check).
  const E=await contact(3,2);
  members[2]=(await members[2].activate(E.incoming.event,now++,E.senderSignature)).next;
  const closeReply=await receipt(E,'recipient',2);
  const close=record('close role 1',3,await members[2].settle(E.incoming.event,closeReply.resolution,undefined,now++));
  await resolutionRefusals('close role 1',close.input,{signerField:'receipt_owner_enrollment',validContact:E.senderSignature,otherReceipt:closeReply.otherReceipt});

  // ---- Action 3 with a CHANGED peer authority: the shared enrollment path verifies the renewed peer.
  const renewed=entries.map((entry,i)=>i===1?{...entry,delegationDigest:hex(bytes(77))}:entry);
  const renewedCheckpoint=await checkpointFromVerified(community,renewed,hashes);
  const D=await contact(1,2);
  members[2]=(await members[2].activate(D.incoming.event,now++,D.senderSignature)).next;
  const renewedReply=await receipt(D,'recipient',1,bytes(77));
  members[2].checkpoint=renewedCheckpoint;  // the recipient has refreshed to the current roster (the peer's renewed delegation)
  const changed=record('answer role 1, renewed peer',3,await members[2].settle(D.incoming.event,renewedReply.resolution,renewedReply.acknowledgment,now++,
    renewedCheckpoint.entries[1],renewedCheckpoint.entries[2]));
  const renewedInput=structuredClone(changed.input);
  renewedInput.enrollment_root=toArray(fieldBytes(renewedCheckpoint.root));
  renewedInput.owner_enrollment=enrollmentInput(renewedCheckpoint.entries[2]);
  assert.notEqual(hex(renewedCheckpoint.entries[1].delegationDigest),hex(checkpoint.entries[1].delegationDigest));
  await runs('answer role 1, renewed peer',renewedInput);
  await refuses('renewed peer: enrollment path',renewedInput,w=>{bump(w.peer_enrollment.path,0);});
  await refuses('renewed peer: enrollment index',renewedInput,w=>{w.peer_enrollment.index=Number(w.peer_enrollment.index)^1;});
  await refuses('renewed peer: enrollment key',renewedInput,w=>{w.peer_enrollment.key=otherKey(3);});
  await refuses('renewed peer: wrong root',renewedInput,w=>{w.enrollment_root=toArray(fieldBytes(checkpoint.root));});
  await refuses('renewed peer: wrong resolution signature',renewedInput,w=>{flip(w.resolution.signature);});
  await refuses('renewed peer: wrong acknowledgment signature',renewedInput,w=>{flip(w.acknowledgment.signature);});
  // With the peer authority UNCHANGED the path is not consulted (historical authority, as before the diet).
  const unchanged=structuredClone(settle.input);bump(unchanged.peer_enrollment.path,0);
  await runs('unchanged peer authority ignores the path',unchanged);

  // ---- Action 8: the recipient punishes after its own Answer.
  const C=await contact(0,3);
  members[3]=(await members[3].activate(C.incoming.event,now++,C.senderSignature)).next;
  const answeredC=await receipt(C,'recipient',1);
  members[3]=(await members[3].settle(C.incoming.event,answeredC.resolution,answeredC.acknowledgment,now++)).next;
  const punish8=record('punish answered (8)',8,await members[3].punish(C.incoming.event,now++,C.senderSignature));
  await contactRefusals('punish answered (8)',punish8.input,{slot:members[3].slots.get(C.incoming.event.toString()),signer:0,owner:members[3].owner.member,wrongKey:otherKey(2)});

  // ---- No witness makes two merged branches active: the action is one value, and every other
  // action selector refuses a witness built for this one.
  const SELECTORS=[1,2,3,7,8];
  for(const w of witnesses) for(const other of SELECTORS.filter(a=>a!==w.action))
    await refuses(`${w.name} as action ${other}`,w.input,t=>{t.action=other;});
  console.log(`update refusals: ${accepted} untampered witnesses accepted, ${refusals} tampered witnesses refused`);
} finally { await hashApi.destroy(); }
