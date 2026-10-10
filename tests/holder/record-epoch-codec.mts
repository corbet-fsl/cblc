// Test-only faithful original CZKP a666c638 record codec.
// No SDK/runtime export or proof/currentness authority is introduced here.
// Canonical record-epoch codecs only. Callers authenticate the descriptor and
// enforce current policy/time independently; decoding is never authorization.
import {cat,be} from '@corbet-labs/czkp/encoding';
import {fieldValue,fieldBytes,limbs32} from '@corbet-labs/czkp/primitives';
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
export function recordBytes(v,size=32) {
  if(!(Array.isArray(v)||v instanceof Uint8Array)||v.length!==size||Array.from(v).some(b=>!Number.isInteger(b)||b<0||b>255))throw new Error('Record byte width');
  return Array.from(v);
}
const same=(a,b)=>{a=recordBytes(a);b=recordBytes(b);return a.every((v,i)=>v===b[i]);};
const safe=(v,positive=false)=>{if(!Number.isSafeInteger(v)||v<(positive?1:0))throw new Error('Record integer');return v;};

export function recordEpochPublicInputs(record,scope,issuerKey) {
  if(!exact(record,['epoch','owner','presentationKey','blindedLeaf','certificate','shares']))throw new Error('Record epoch public shape');
  const e=record.epoch;
  if(!exact(e,['purpose','community','policyEpoch','epoch','startsAt','expiresAt','root','issuerKey','proofScope','leafCount','downloadDigest','downloadBytes'])
    ||e.purpose!=='cblc.record-epoch.v3'||!exact(e.proofScope,['circuitDigest','verifyingKeyDigest'])
    ||!exact(scope,['circuitDigest','verifyingKeyDigest'])
    ||!same(e.proofScope.circuitDigest,scope.circuitDigest)||!same(e.proofScope.verifyingKeyDigest,scope.verifyingKeyDigest))throw new Error('Record epoch scope');
  const period=safe(e.expiresAt,true)-safe(e.startsAt,true);
  if(period<=0||BigInt(safe(e.epoch,true))*BigInt(period)!==BigInt(e.startsAt)
    ||safe(e.policyEpoch,true)===0||safe(e.leafCount,true)>2**20
    ||safe(e.downloadBytes,true)>64*1024*1024)throw new Error('Record epoch bounds');
  for(const v of [e.community,e.root,e.issuerKey,e.downloadDigest,scope.circuitDigest,scope.verifyingKeyDigest,record.owner])
    if(!recordBytes(v).some(Boolean))throw new Error('Zero record binding');
  if(!recordBytes(record.presentationKey).some(Boolean))throw new Error('Record presentation key');
  if(fieldValue(Uint8Array.from(recordBytes(record.blindedLeaf)))===0n)throw new Error('Zero blinded leaf');
  recordBytes(record.certificate,64);
  const shares=record.shares;
  if(shares!==null&&(!Array.isArray(shares)||shares.length!==3||shares.some(v=>!Number.isInteger(v)||v<0||v>10000)||shares.reduce((a,b)=>a+b,0)!==10000))throw new Error('Record shares');
  return {record_issuer_key:recordBytes(e.issuerKey),record_certificate:recordBytes(record.certificate,64),blinded_leaf:recordBytes(record.blindedLeaf),scope:recordBytes(scope.circuitDigest),verification_scope:recordBytes(scope.verifyingKeyDigest),
    community:recordBytes(e.community),owner:recordBytes(record.owner),epoch:e.epoch,epoch_start:e.startsAt,epoch_end:e.expiresAt,
    epoch_root:recordBytes(e.root),leaf_count:e.leafCount,presentation_key:limbs32(Uint8Array.from(recordBytes(record.presentationKey))).map(String),
    present:shares!==null,shares:shares??[0,0,0]};
}

// Fixed-width, domain-separated Ed25519 message. Both purpose and expiry are
// signed with the challenge; the proof's complete public record is bound too.
export function recordPresentationBytes(record,context) {
  const e=record.epoch;
  recordEpochPublicInputs(record,e.proofScope,Array(64).fill(1));
  if(!exact(context,['purpose','challenge','expiresAt'])||!['firstContact','forumListing'].includes(context.purpose)
    ||!recordBytes(context.challenge).some(Boolean)||safe(context.expiresAt,true)<=e.startsAt||context.expiresAt>e.expiresAt)throw new Error('Record context');
  return cat(new TextEncoder().encode('cblc.record-presentation.v3\0'),e.community,be(e.policyEpoch,8),be(e.epoch,8),
    be(e.startsAt,8),be(e.expiresAt,8),e.root,e.proofScope.circuitDigest,e.proofScope.verifyingKeyDigest,
    e.issuerKey,be(e.leafCount,4),e.downloadDigest,be(e.downloadBytes,8),record.owner,record.presentationKey,record.blindedLeaf,record.certificate,
    [record.shares===null?0:1],...(record.shares??[0,0,0]).map(n=>be(n,2)),
    [context.purpose==='firstContact'?0:1],context.challenge,be(context.expiresAt,8));
}

// Signature and context check only. Always verify the cached ZK proof as well,
// against the independently authenticated latest epoch, before consuming the
// relying party's one-use challenge. A decoded record grants no authority.
export async function verifyRecordPresentation(presentation,expected,epoch,owner,now) {
  if(!exact(presentation,['record','context','publicKey','signature','proof'])||typeof presentation.proof!=='string'||!presentation.proof.length)throw new Error('Missing record proof');
  const {record,context}=presentation;
  const equal=(a,b)=>recordBytes(a).every((n,i)=>n===recordBytes(b)[i]);
  if(!Number.isSafeInteger(now)||now<epoch.startsAt||now>=epoch.expiresAt||now>=context.expiresAt)throw new Error('Expired record');
  // Field-order independent equality via the already validated canonical bytes.
  const canonical=recordPresentationBytes(record,context);
  const trusted=recordPresentationBytes({...record,epoch,owner},expected);
  if(canonical.length!==trusted.length||!canonical.every((n,i)=>n===trusted[i]))throw new Error('Wrong epoch, owner or challenge');
  await verifyRecordCertificate(record);
  const publicKey=recordBytes(presentation.publicKey);
  if(!equal(publicKey,record.presentationKey))throw new Error('Wrong presentation key');
  const key=await crypto.subtle.importKey('raw',Uint8Array.from(publicKey),'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',key,Uint8Array.from(recordBytes(presentation.signature,64)),canonical))throw new Error('Invalid presentation signature');
}

export const RECORD_EPOCH_DOMAIN=0x63626c632e7265636f72642d65706f63682e7632n;
export async function recordLeafCommitment(community,epoch,leaf,hash) {
  if(!exact(leaf,['owner','version','state','requiredInbox','blinding']))throw new Error('Frozen leaf shape');
  const state=recordBytes(leaf.state),blinding=recordBytes(leaf.blinding);
  if(fieldValue(Uint8Array.from(state))===0n||!blinding.some(Boolean))throw new Error('Frozen leaf bounds');
  if(typeof hash!=='function')throw new Error('Maintained Poseidon2 backend required');
  return fieldBytes(await hash([RECORD_EPOCH_DOMAIN,1n,...limbs32(Uint8Array.from(recordBytes(community))),BigInt(safe(epoch,true)),
    ...limbs32(Uint8Array.from(recordBytes(leaf.owner))),BigInt(safe(leaf.version)),fieldValue(Uint8Array.from(state)),
    ...limbs32(Uint8Array.from(recordBytes(leaf.requiredInbox))),...limbs32(Uint8Array.from(blinding))]));
}
export async function recordNode(left,right,hash){
  if(typeof hash!=='function')throw new Error('Maintained Poseidon2 backend required');
  return fieldBytes(await hash([RECORD_EPOCH_DOMAIN,2n,...limbs32(Uint8Array.from(recordBytes(left))),...limbs32(Uint8Array.from(recordBytes(right)))]));
}

export function recordCertificateBytes(community,epoch,leaf){
  if(fieldValue(Uint8Array.from(recordBytes(leaf)))===0n)throw new Error('Zero blinded leaf');
  return cat(new TextEncoder().encode('cblc.record-leaf.v1\0'),recordBytes(community),be(safe(epoch,true),8),recordBytes(leaf));
}
export async function verifyRecordCertificate(record){
  const key=await crypto.subtle.importKey('raw',Uint8Array.from(recordBytes(record.epoch.issuerKey)),'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',key,Uint8Array.from(recordBytes(record.certificate,64)),
    recordCertificateBytes(record.epoch.community,record.epoch.epoch,record.blindedLeaf)))throw new Error('Invalid record issuer certificate');
}
