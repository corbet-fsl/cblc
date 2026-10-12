// Peer-release (wave and outcome) witness builder over cwlt's existing ExtensionWitness.
// It reuses the account witness, its hashes, maps and opening encoders; it adds only the
// two statements the `wave` and `outcome` circuits prove. Pure member-side construction:
// no network, no storage, no proving. audit-C2 debt: this witness logic moves to Rust
// after v0.1.
import {limbs32,fieldBytes} from '@corbet-labs/czkp/primitives';
import {zeros} from '@corbet-labs/czkp/encoding';
import {enrollmentInput,slotInput} from '@corbet-labs/cwlt/account';
import {extInput} from '@corbet-labs/cwlt/extensions';

type Bytes=Uint8Array;
export type Outcome='answer'|'close'|'silence';
export interface WaveContextInput {history:Bytes;challenge:Bytes}
export interface Settled {
  outcome:Outcome;
  resolution?:{kind:number;issuedAt:bigint;historyDigest:Bytes;ed25519ReceiptDigest:Bytes;signature:Bytes};
  acknowledgment?:{issuedAt:bigint;signature:Bytes};
}
// The slice of ExtensionWitness this builder reads. Everything is read through the
// public members of the real class; tests pass a structurally identical stub.
export interface WaveSource {
  clone():WaveSource;owner:any;ownerSecret:Bytes;community:Bytes;statePolicyHash:Bytes;extension:any;
  certificate?:{acceptedAt:bigint;signature:Bytes};outgoing:any;incoming:any;slots:Map<string,any>;
  hashes:{obligation(event:bigint,slot:any,phase:number):Promise<bigint>;raw(values:bigint[]):Promise<bigint>};
  commitment:bigint;version:bigint;opening:any;now:bigint;input(blind:Bytes,now:bigint):{old:any};
}
const copy=(value:Bytes)=>Uint8Array.from(value);
const OUTCOME_CODE={answer:1,close:2,silence:3} as const;
const WAVE_DOMAIN=0x63776c742e657874656e73696f6e2d776176652e7631n;
const OUTCOME_DOMAIN=0x63776c742e657874656e73696f6e2d6f7574636f6d652e7631n;

/** Build the `wave` statement/input (no settled), or the `outcome` ones (settled). */
export async function waveEvidence(source:WaveSource,event:bigint,{history,challenge}:WaveContextInput,
    scope:Bytes,issuerKey:Bytes,settled?:Settled) {
  // All mutable state is detached before the first asynchronous hash.
  const state=source.clone() as WaveSource;
  state.owner=structuredClone(source.owner);state.ownerSecret=copy(source.ownerSecret);
  state.community=copy(source.community);state.statePolicyHash=copy(source.statePolicyHash);
  state.extension=structuredClone(source.extension);
  state.certificate=source.certificate?structuredClone(source.certificate):undefined;
  state.outgoing=source.outgoing.clone();state.incoming=source.incoming.clone();
  history=copy(history);challenge=copy(challenge);scope=copy(scope);issuerKey=copy(issuerKey);
  settled=settled?structuredClone(settled):undefined;
  if(settled&&!Object.hasOwn(OUTCOME_CODE,settled.outcome))throw new Error('Unknown settled outcome');
  const slot=state.slots.get(event.toString());
  const code=settled?OUTCOME_CODE[settled.outcome]:0;
  // Wave needs an active reservation (phase 2); answer/close a settled-able one (3 after
  // activation), silence an expired one (5).
  if(!slot||slot.phase!==(code===3?5:code?3:2)||!state.certificate)throw new Error('Accepted active reservation required');
  const map=slot.role===0?state.outgoing:state.incoming,found=map.find(event);
  if(!found)throw new Error('Missing reservation membership');
  const selected=map.witness(found[0]),payload=await state.hashes.obligation(event,slot,slot.phase);
  if(selected.leaf[1]!==payload)throw new Error('Reservation opening differs');
  const receiptDigest=code&&code!==3?copy(settled!.resolution!.ed25519ReceiptDigest):zeros();
  const binding=fieldBytes(await state.hashes.raw([code?OUTCOME_DOMAIN:WAVE_DOMAIN,1n,
    ...limbs32(state.ownerSecret),state.commitment,payload,...limbs32(challenge),...limbs32(history),
    ...(code?[BigInt(code),...limbs32(receiptDigest)]:[])]));
  const context={community:Array.from(state.community),owner:Array.from(state.owner.member),peer:Array.from(slot.peer),role:slot.role,
    nonce:Array.from(slot.nonce),group:Array.from(slot.group),contactPolicy:Array.from(slot.contactPolicy),history:Array.from(history),challenge:Array.from(challenge),
    openedAt:Number(slot.admittedAt),expiresAt:Number(slot.expiresAt),ownerAuthority:Array.from(fieldBytes(slot.ownerAuthority)),peerAuthority:Array.from(fieldBytes(slot.peerAuthority))};
  const certificate=state.certificate;
  const wave={context,statePolicy:Array.from(state.statePolicyHash),version:Number(state.version),state:Array.from(fieldBytes(state.commitment)),
    acceptedAt:certificate.acceptedAt,binding:Array.from(binding),certificate:Array.from(certificate.signature)};
  // The extended opening is exactly the one the real witness encodes for `update`.
  const opening=state.input(zeros(),state.now).old;
  const result:any={statement:{kind:'wave',policy:state.extension,certificateKey:Array.from(issuerKey),wave},input:{extension:extInput(state.extension),issuer_key:issuerKey,scope,
    community:state.community,owner:state.owner.member,peer:slot.peer,role:slot.role,nonce:slot.nonce,group:slot.group,contact_policy:slot.contactPolicy,
    history,challenge,opened_at:slot.admittedAt,expires_at:slot.expiresAt,owner_authority:fieldBytes(slot.ownerAuthority),peer_authority:fieldBytes(slot.peerAuthority),
    state_policy:state.statePolicyHash,version:state.version,state:fieldBytes(state.commitment),accepted_at:certificate.acceptedAt,binding,
    secret:state.ownerSecret,opening,slot:slotInput(slot),selected,certificate:certificate.signature}};
  if(code) {
    const resolution=settled!.resolution??{kind:0,issuedAt:0n,historyDigest:zeros(),ed25519ReceiptDigest:zeros(),signature:new Uint8Array(64)};
    const acknowledgment=settled!.acknowledgment??{issuedAt:0n,signature:new Uint8Array(64)};
    result.statement={kind:'outcome',policy:state.extension,certificateKey:Array.from(issuerKey),
      outcome:{evidence:wave,outcome:settled!.outcome,receiptDigest:Array.from(receiptDigest)}};
    Object.assign(result.input,{outcome:code,receipt_digest:receiptDigest,owner_enrollment:enrollmentInput(slot.ownerEnrollment),peer_enrollment:enrollmentInput(slot.peerEnrollment),
      resolution:{kind:resolution.kind,issued_at:resolution.issuedAt,history_digest:resolution.historyDigest,ed25519_receipt_digest:resolution.ed25519ReceiptDigest,signature:resolution.signature},
      acknowledgment:{issued_at:acknowledgment.issuedAt,signature:acknowledgment.signature}});
  }
  return result;
}
/** Wave statement for an accepted active reservation. */
export const wave=(source:WaveSource,event:bigint,context:WaveContextInput,scope:Bytes,issuerKey:Bytes)=>
  waveEvidence(source,event,context,scope,issuerKey);
/** Outcome statement for a settled reservation (answer, close or silence). */
export const waveOutcome=(source:WaveSource,event:bigint,context:WaveContextInput,scope:Bytes,issuerKey:Bytes,
    outcome:Outcome,resolution?:Settled['resolution'],acknowledgment?:Settled['acknowledgment'])=>{
  if(!Object.hasOwn(OUTCOME_CODE,outcome))throw new Error('Unknown settled outcome');
  return waveEvidence(source,event,context,scope,issuerKey,{outcome,resolution,acknowledgment});
};
