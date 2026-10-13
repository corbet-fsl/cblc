// Original genuine punishment/ingestion journey, using the current main holder.
// Private packets, frozen openings and signed descendants stay in member RAM.
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {Noir} from '@noir-lang/noir_js';
import {witnessInputs} from '@corbet-labs/czkp/abi';
import {canonicalSignature} from '@corbet-labs/czkp/encoding';
import {contactBytes} from '@corbet-labs/cwlt/extensions';
import {prepareRecordEpoch} from './record-epoch.mts';
import {recordEpochPublicInputs,recordLeafCommitment,recordPresentationBytes,verifyRecordCertificate} from './record-epoch-codec.mts';

export async function ingestedRecordEpoch({members,call,submit,anonymous,proof,artifacts,
  issuerKey,now,programs,hashes,community,signing,extension}) {
  let nonce=60;
  const bytes=n=>new Uint8Array(32).fill(n),toArray=Array.from.bind(Array);
  const signContact=(index,owner,slot)=>canonicalSignature(sign('sha256',contactBytes(community,owner,slot),
    {key:signing[index],dsaEncoding:'ieee-p1363'}));
  // These are the existing original fixture's actual counterpart-signed contacts.
  async function contact(sender,recipient) {
    const n=bytes(nonce++),group=bytes(nonce++),contactPolicy=bytes(nonce++);
    const outgoing=await members[sender].reserve({peerIndex:recipient,role:0,nonce:n,group,contactPolicy,now:now++});
    members[sender]=(await submit(7+sender,[outgoing],'epoch-reserve')).next;
    const s=members[sender].slots.get(outgoing.event.toString());
    const incoming=await members[recipient].reserve({peerIndex:sender,role:1,nonce:n,group,contactPolicy,
      openedAt:s.admittedAt,expiresAt:s.expiresAt,now:now++});
    members[recipient]=(await submit(7+recipient,[incoming],'epoch-reserve')).next;
    const r=members[recipient].slots.get(incoming.event.toString());
    return {sender,recipient,outgoing:outgoing.event,incoming:incoming.event,
      senderSignature:signContact(sender,members[recipient].owner.member,r),
      recipientSignature:signContact(recipient,members[sender].owner.member,s)};
  }
  const first=await contact(0,1),noise=await contact(3,1),late=await contact(0,2);
  const burns=[];
  for(const c of [first,noise]) {
    const candidate=await members[1].punish(c.incoming,now++,c.senderSignature);
    members[1]=(await submit(8,[candidate],'epoch-punishment')).next;
    burns.push({member:members[1],delivery:candidate.delivery});
  }
  const later=await members[2].punish(late.incoming,now++,late.senderSignature);
  members[2]=(await submit(9,[later],'epoch-late-punishment')).next;
  now=Math.ceil((now+extension.depositDelaySeconds)/10)*10;
  const deposits=[];
  for(const burn of burns)deposits.push(await anonymous(await burn.member.deposit(burn.delivery,
    burn.member.certificate,artifacts.scope.circuitDigest,issuerKey,now/10),'epoch-deposit'));
  const batch=deposits.map(value=>({deposit:value.statement.deposit,proof:value.proof}));
  await call({op:'deposit',batch,now});
  await call({op:'deposit',batch,now}); // Real replay cannot append another entry.
  const owner=toArray(members[0].owner.member);
  const queued=await call({op:'inbox',member:7,owner,now});
  assert.equal(queued.entries.length,1);
  now=Math.ceil((now+1)/100)*100;
  await call({op:'recordEpoch',now});
  const frozen=members.map(member=>member.clone());
  const witness=await call({op:'recordWitness',member:7},true,false);
  assert.deepEqual(witness.leaf.requiredInbox,queued.root.root);
  assert.notDeepEqual(toArray(frozen[0].opening.inbox),witness.leaf.requiredInbox);
  const key=generateKeyPairSync('ed25519');
  const publicKey=toArray(key.publicKey.export({type:'spki',format:'der'}).subarray(-32));
  await assert.rejects(prepareRecordEpoch(members[0],publicKey,witness,artifacts.scope,issuerKey,
    {frozenHolder:frozen[0]}),/Required record opening unavailable/);
  // The authentic frozen certificate is insufficient while its required inbox
  // differs from the actual committed opening. Execute the original relation.
  const local=frozen[0].record({purpose:'forumListing',challenge:toArray(bytes(197)),expiresAt:now+50});
  const {extension:ext,version,state,state_policy,registered_secret,opening}=local.input;
  assert.equal(Number(version),witness.leaf.version);
  assert.deepEqual(toArray(state),witness.leaf.state);
  const pending={epoch:witness.epoch,owner,presentationKey:publicKey,
    blindedLeaf:toArray(await recordLeafCommitment(witness.epoch.community,witness.epoch.epoch,witness.leaf,hashes.raw)),
    certificate:witness.certificate,shares:local.statement.record.shares};
  await verifyRecordCertificate(pending);
  const impossible={...recordEpochPublicInputs(pending,artifacts.scope,issuerKey),extension:ext,
    version,state,state_policy,registered_secret,opening,required_inbox:witness.leaf.requiredInbox,role:witness.leaf.role,blinding:witness.leaf.blinding};
  await assert.rejects(new Noir(programs.record_epoch).execute(witnessInputs(programs.record_epoch,impossible)));
  // This later genuine deposit extends the frozen required root. Its companion
  // is the original valid replay, preserving the actual minimum-batch protocol.
  const lateProof=await anonymous(await members[2].deposit(later.delivery,members[2].certificate,
    artifacts.scope.circuitDigest,issuerKey,now/10),'epoch-post-freeze-deposit');
  await call({op:'deposit',batch:[{deposit:lateProof.statement.deposit,proof:lateProof.proof},batch[1]],now});
  const all=await call({op:'inbox',member:7,owner,now});
  assert.equal(all.entries.length,2);
  assert.notDeepEqual(all.root.root,witness.leaf.requiredInbox);
  let holder=members[0];const steps=[];
  for(const [index,entry] of all.entries.entries()) {
    const consumed=await holder.consume(entry,now);steps.push(consumed);holder=consumed.next;
    if(index===0)assert.deepEqual(toArray(holder.opening.inbox),witness.leaf.requiredInbox);
  }
  const final=await holder.reblind(now++);steps.push(final);
  members[0]=(await submit(7,steps,'epoch-minimum-frontier-ingestion')).next;
  const empty=await call({op:'inbox',member:7,owner,now});assert.equal(empty.entries.length,0);
  assert.equal(members[0].opening.punished,2n);
  const descendant=members[0].clone();
  const acceptedWitness=await call({op:'recordWitness',member:7},true,false);
  assert(acceptedWitness.ancestry,'Actual certified service result required');
  assert.equal(acceptedWitness.ancestry.record.leaf.version,Number(descendant.version));
  assert.deepEqual(acceptedWitness.ancestry.record.leaf.requiredInbox,all.root.root);
  const minimum=await prepareRecordEpoch(descendant,publicKey,acceptedWitness,artifacts.scope,issuerKey,
    {frozenHolder:frozen[0]});
  assert.deepEqual(minimum.statement.record.shares,[0,0,10000]);
  const publicProofs=[];
  async function prove(candidate,label) {
    const encoded=await proof('record_epoch',candidate.input,label);
    const framed=Buffer.from(JSON.stringify({version:1,proofs:[{proof:encoded}]})).toString('hex');
    publicProofs.push({statement:candidate.statement,proof:framed,proofScope:artifacts.scope});
    return framed;
  }
  async function present(candidate,framed,challenge,expected) {
    const context={purpose:'forumListing',challenge:toArray(bytes(challenge)),expiresAt:Math.min(now+50,witness.epoch.expiresAt)};
    const record=candidate.statement.record;
    const presentation={record,context,publicKey,
      signature:toArray(sign(null,recordPresentationBytes(record,context),key.privateKey)),proof:framed};
    await call({op:'issueRecordChallenge',owner:record.owner,context});
    assert.deepEqual(await call({op:'checkEpochRecord',challenge:context.challenge,presentation,now}),expected);
    return presentation;
  }
  const minimumProof=await prove(minimum,'record-epoch-minimum-frontier');
  await present(minimum,minimumProof,223,[0,0,10000]);
  // Later real activity cannot invalidate the cached proof of the exact signed
  // descendant. Its retained opening remains in RAM; never use a newer opening
  // with an older certificate merely because its version is greater.
  members[0]=(await submit(7,[await members[0].reblind(now++)],'epoch-descendant-later-activity')).next;
  const retained=await prepareRecordEpoch(descendant,publicKey,acceptedWitness,artifacts.scope,issuerKey,
    {frozenHolder:frozen[0]});
  assert.deepEqual(retained.statement.record,minimum.statement.record);
  await present(retained,minimumProof,224,[0,0,10000]);
  // A member whose frozen inbox was empty keeps that original leaf across an
  // actual accepted update. Both witnesses come from genuine HPKE packets.
  const stableWitness=await call({op:'recordWitness',member:8},true,false);
  const stable=await prepareRecordEpoch(members[1],publicKey,stableWitness,artifacts.scope,issuerKey,
    {frozenHolder:frozen[1]});
  const stableProof=await prove(stable,'record-epoch-frozen-reuse');
  await present(stable,stableProof,225,null);
  members[1]=(await submit(8,[await members[1].reblind(now++)],'epoch-frozen-later-activity')).next;
  await call({op:'recordEpoch',now}); // Actual same-epoch descriptor/object retry.
  const refreshedWitness=await call({op:'recordWitness',member:8},true,false);
  assert.deepEqual(refreshedWitness.epoch,stableWitness.epoch);
  assert.deepEqual(refreshedWitness.leaf,stableWitness.leaf);
  assert.deepEqual(refreshedWitness.certificate,stableWitness.certificate);
  const reused=await prepareRecordEpoch(members[1],publicKey,refreshedWitness,artifacts.scope,issuerKey,
    {frozenHolder:frozen[1]});
  assert.deepEqual(reused.statement.record,stable.statement.record);
  const finalPresentation=await present(reused,stableProof,226,null);
  const expired={...finalPresentation,context:{...finalPresentation.context,challenge:toArray(bytes(227))}};
  expired.signature=toArray(sign(null,recordPresentationBytes(expired.record,expired.context),key.privateKey));
  await call({op:'issueRecordChallenge',owner:expired.record.owner,context:expired.context});
  // Check the exclusive boundary last; retain main's observed clock afterward.
  await call({op:'checkEpochRecord',challenge:expired.context.challenge,presentation:expired,now:expired.context.expiresAt},false);
  return publicProofs;
}
