// Real record-epoch scenarios over actual service output and the native checker.
// This is a relying-party fixture, not Forum composition or a verifier substitute.
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {prepareRecordEpoch} from './record-epoch.mts';
import {recordPresentationBytes,verifyRecordPresentation} from './record-epoch-codec.mts';

export async function exactRecordEpoch({members,call,proof,artifacts,issuerKey,now,deferExpiry=false,retainNativeFixture}) {
  for(let index=0;index<members.length;index++)await call({op:'recordRecipient',member:7+index,now});
  await call({op:'recordEpoch',now});
  await call({op:'recordEpoch',now}); // Original exact root/object survives retry.
  // Check the actual export route/configuration before expensive proving.
  // This material is not proof authority; the native owner check remains below.
  const fixture=await call({op:'recordFixtureMaterial',now},true,false);
  // Private leaf/opening output never joins publicTrace or the report artifacts.
  const witness=await call({op:'recordWitness',member:7},true,false);
  const key=generateKeyPairSync('ed25519');
  const publicKey=Array.from(key.publicKey.export({type:'spki',format:'der'}).subarray(-32));
  const candidate=await prepareRecordEpoch(members[0],publicKey,witness,artifacts.scope,issuerKey,
    {frozenHolder:members[0].clone()});
  const encoded=await proof('record_epoch',candidate.input,'record-epoch-exact');
  const framed=Buffer.from(JSON.stringify({version:1,proofs:[{proof:encoded}]})).toString('hex');
  const bind=context=>({record:structuredClone(candidate.statement.record),context,publicKey,
    signature:Array.from(sign(null,recordPresentationBytes(candidate.statement.record,context),key.privateKey)),proof:framed});
  const context={purpose:'forumListing',challenge:Array(32).fill(193),expiresAt:Math.min(now+50,witness.epoch.expiresAt)};
  const presentation=bind(context);
  await verifyRecordPresentation(presentation,context,witness.epoch,candidate.statement.record.owner,now);
  // The same genuine cached proof also crosses the storage-free relying owner
  // through actual issuer material and a configured, signed Balance publication.
  assert.equal(await call({op:'verifyPublishedRecord',presentation,now}),true);
  // Explicit fictional test custody stays separate from publicTrace. Retain
  // the actual first native success before later negative/replay checks can fail.
  const presentationSeed=Array.from(Buffer.from(key.privateKey.export({format:'jwk'}).d,'base64url'));
  assert.equal(presentationSeed.length,32);
  const result={statement:candidate.statement,proof:framed,proofScope:artifacts.scope,
    gatherFixture:{...fixture,presentationSeed}};
  if(retainNativeFixture)await retainNativeFixture(result);
  await call({op:'issueRecordChallenge',owner:presentation.record.owner,context});
  const check=(value,expected=false,at=now)=>call({op:'checkEpochRecord',challenge:context.challenge,presentation:value,now:at},expected);
  for(const mutate of [
    p=>{p.context.challenge[0]^=1;},p=>{p.context.purpose='firstContact';},p=>{p.signature[0]^=1;},
    p=>{p.publicKey[0]^=1;},p=>{p.proof='';},p=>{p.record.epoch.epoch+=1;},
    p=>{p.record.epoch.root[0]^=1;},p=>{p.record.epoch.downloadDigest[0]^=1;},
  ]) {
    const changed=structuredClone(presentation);mutate(changed);await check(changed);
  }
  // Fresh valid presentation signatures bind damaged public proof/certificate
  // fields too, so the actual native checker must reject them independently.
  for(const mutate of [
    p=>{p.record.certificate[0]^=1;},p=>{p.record.blindedLeaf[31]^=1;},
    p=>{p.record.presentationKey[0]^=1;},p=>{p.record.shares=[0,0,10000];},
    p=>{const bundle=JSON.parse(Buffer.from(p.proof,'hex'));const original=bundle.proofs[0].proof;
      bundle.proofs[0].proof=(original.startsWith('00')?'01':'00')+original.slice(2);
      p.proof=Buffer.from(JSON.stringify(bundle)).toString('hex');},
  ]) {
    const changed=structuredClone(presentation);mutate(changed);
    changed.signature=Array.from(sign(null,recordPresentationBytes(changed.record,changed.context),key.privateKey));
    await check(changed);
  }
  assert.equal(await check(presentation,true),null); // Actual below-quorum proof.
  await check(presentation); // The same live challenge is consumed exactly once.
  const contact={...context,purpose:'firstContact',challenge:Array(32).fill(211)};
  const second=bind(contact);
  assert.equal(second.proof,presentation.proof); // No per-use expensive proof.
  await call({op:'issueRecordChallenge',owner:second.record.owner,context:contact});
  assert.equal(await call({op:'checkEpochRecord',challenge:contact.challenge,presentation:second,now}),null);
  if(!deferExpiry) {
    const expiry={...context,challenge:Array(32).fill(221)};
    const expired=bind(expiry);
    await call({op:'issueRecordChallenge',owner:expired.record.owner,context:expiry});
    // Main's observed clock cannot return from a future expiry to earlier success.
    // The continued journey checks the exclusive boundary with its final epoch.
    await call({op:'checkEpochRecord',challenge:expiry.challenge,presentation:expired,now:expiry.expiresAt},false);
  }
  return result;
}
