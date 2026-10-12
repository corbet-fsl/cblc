// Real peer-release proofs for the issuer-accepted holders of the extension harness:
// a reservation (`wave`) and a settled Answer (`outcome`), proved through the
// existing prover backends (native socket and wasm, timings measured by the caller's
// `prove`). The statements are written for the counterpart verifiers (cwlt WaveVerifier,
// native and browser); no witness leaves this module.
import {waveEvidence,waveOutcome,type WaveSource,type Settled} from '../../runtime/extensions/waves.mts';
type Bytes=Uint8Array;
type Prove=(kind:'wave'|'outcome',input:object,label:string,measure:boolean)=>Promise<string>;
export interface WaveFixtureCase {kind:'wave'|'outcome';statement:object;proof:string;expectedOutcome?:string}
/** JSON for the Rust serde types: safe integers only, nothing else is lossy. */
export const waveJson=(value:unknown)=>JSON.stringify(value,(_,v)=>{
  if(typeof v==='bigint'){if(v>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Unsafe integer in a wave statement');return Number(v);}
  return v instanceof Uint8Array?Array.from(v):v;});
export async function reservationCase(holder:WaveSource,event:bigint,context:{history:Bytes;challenge:Bytes},
    scope:Bytes,issuerKey:Bytes,prove:Prove):Promise<WaveFixtureCase> {
  const built=await waveEvidence(holder,event,context,scope,issuerKey);
  return {kind:'wave',statement:built.statement,proof:await prove('wave',built.input,'wave-reservation',true)};
}
export async function outcomeCase(holder:WaveSource,event:bigint,context:{history:Bytes;challenge:Bytes},
    scope:Bytes,issuerKey:Bytes,settled:Settled,prove:Prove):Promise<WaveFixtureCase> {
  const built=await waveOutcome(holder,event,context,scope,issuerKey,settled.outcome,settled.resolution,settled.acknowledgment);
  return {kind:'outcome',statement:built.statement,proof:await prove('outcome',built.input,`wave-outcome-${settled.outcome}`,true),expectedOutcome:settled.outcome};
}
