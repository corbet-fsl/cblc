// Counterpart verification of the retained real wave and Answer proofs through the
// browser build of cwlt's WaveVerifier (wasm) with bb.js doing only the proof check.
// Context, lease and issuer-certificate checks run in Rust, exactly as natively.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdtemp} from 'node:fs/promises';
import {resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {Barretenberg,BackendType,UltraHonkVerifierBackend} from '@aztec/bb.js';
import {OPTIONS} from '@corbet-labs/czkp/encoding';
import {loadArtifacts} from '../runtime/extensions/artifacts.mts';
const fixtureDirectory=process.env.CBLC_WAVE_FIXTURE;
if(!fixtureDirectory||!process.env.CBLC_WAVE_WASM)throw new Error('The retained fixture and the wasm build are required');
const text=await readFile(resolve(fixtureDirectory,'wave-roundtrip.json'));
assert.equal(fixtureDirectory.replace(/\/$/,'').split('/').pop(),createHash('sha256').update(text).digest('hex'),'content address');
const fixture=JSON.parse(text.toString());
const config=JSON.parse(await readFile(resolve(fixtureDirectory,'config.json')));
const temporary=await mkdtemp(resolve(tmpdir(),'wave-browser-'));
const configPath=resolve(temporary,'config.json');
await writeFile(configPath,JSON.stringify({directory:resolve(fixtureDirectory),manifestSha256:config.manifestSha256}));
const group=await loadArtifacts(configPath);
const {default:init,BrowserWaveVerifier}=await import(resolve(process.env.CBLC_WAVE_WASM,'cwlt.js'));
await init({module_or_path:await readFile(resolve(process.env.CBLC_WAVE_WASM,'cwlt_bg.wasm'))});
const wave=group.artifacts('wave'),outcome=group.artifacts('outcome');
// Same verification-only setup as czkp's backend: one complete compressed G1 chunk and the pinned G2 point.
const api=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true,memory:{initial:2048,maximum:wave.limits.memoryPages}});
const points=Math.min(131072,group.manifest.numPoints);
await api.srsInitSrs({pointsBuf:wave.setup['g1.dat'].subarray(0,points*32),numPoints:points,g2Point:wave.setup['g2.dat']});
try {
  const backend=new UltraHonkVerifierBackend(api);
  const check=selected=>async (fields:Uint8Array,proof:Uint8Array)=>{
    const inputs=[];for(let i=0;i<fields.length;i+=32)inputs.push('0x'+Buffer.from(fields.subarray(i,i+32)).toString('hex'));
    return backend.verifyProof({proof,publicInputs:inputs,verificationKey:selected.verificationKey},OPTIONS);
  };
  const byKind=Object.fromEntries(fixture.cases.map(c=>[c.kind,c]));
  const reservation=byKind.wave.statement.wave,settled=byKind.outcome.statement.outcome;
  const policy={community:reservation.context.community,extension:byKind.wave.statement.policy,
    proofScope:fixture.extensionScope,certificateKey:fixture.issuerKey,manifestSha256:Array(32).fill(1),
    statePolicy:reservation.statePolicy,validFrom:1,validUntil:reservation.context.expiresAt+1000};
  const now=Math.max(reservation.acceptedAt,settled.evidence.acceptedAt)+1;
  const verifier=new BrowserWaveVerifier(JSON.stringify(policy),BigInt(now),BigInt(reservation.context.expiresAt+1000),check(wave),check(outcome));
  const proof=c=>Uint8Array.from(Buffer.from(c.proof,'hex'));
  const ok=await verifier.verify(JSON.stringify(reservation),proof(byKind.wave),JSON.stringify(reservation.context),BigInt(now));
  assert.deepEqual(JSON.parse(ok),reservation.context);
  const flipped=proof(byKind.wave);flipped[40]^=1;
  await assert.rejects(verifier.verify(JSON.stringify(reservation),flipped,JSON.stringify(reservation.context),BigInt(now)));
  const other={...reservation.context,nonce:reservation.context.nonce.map((b:number,i:number)=>i?b:b^1)};
  await assert.rejects(verifier.verify(JSON.stringify(reservation),proof(byKind.wave),JSON.stringify(other),BigInt(now)));
  const done=await verifier.verify_outcome(JSON.stringify(settled),proof(byKind.outcome),JSON.stringify(settled.evidence.context),'answer',Uint8Array.from(settled.receiptDigest),BigInt(now));
  assert.deepEqual(JSON.parse(done),settled.evidence.context);
  await assert.rejects(verifier.verify_outcome(JSON.stringify(settled),proof(byKind.wave),JSON.stringify(settled.evidence.context),'answer',Uint8Array.from(settled.receiptDigest),BigInt(now)));
  await assert.rejects(verifier.verify_outcome(JSON.stringify(settled),proof(byKind.outcome),JSON.stringify(settled.evidence.context),'close',Uint8Array.from(settled.receiptDigest),BigInt(now)));
  console.log('Browser WaveVerifier accepted the real reservation and Answer and refused every change');
} finally {await api.destroy();}
