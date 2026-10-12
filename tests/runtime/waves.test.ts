import assert from 'node:assert/strict';
import test from 'node:test';
import {waveEvidence,wave,waveOutcome,type WaveSource} from '../../runtime/extensions/waves.mts';

const bytes=(n:number)=>new Uint8Array(32).fill(n);
const PAYLOAD=77n;
const slot=(over:object={})=>({role:0,peer:bytes(2),nonce:bytes(3),group:bytes(4),contactPolicy:bytes(5),amount:1,phase:2,outcome:0,
  answered:false,selfPunished:false,admittedAt:1000n,expiresAt:2000n,peerAuthority:11n,ownerAuthority:12n,
  peerEnrollment:{key:bytes(6),secretHash:1n,start:0n,end:9n,delegationDigest:bytes(7),path:[],index:0n},
  ownerEnrollment:{key:bytes(8),secretHash:2n,start:0n,end:9n,delegationDigest:bytes(9),path:[],index:1n},...over});
const map=(leaf:bigint=PAYLOAD,present=true)=>({find:()=>present?[0]:undefined,witness:()=>({leaf:[0n,leaf,0n,0n],index:0n,path:[],append_path:[]}),clone(){return this;}});
function source(over:Partial<WaveSource>={},s=slot()):WaveSource {
  const value:any={owner:{member:bytes(1)},ownerSecret:bytes(20),community:bytes(30),statePolicyHash:bytes(40),
    extension:{revision:1,publicRecordQuorum:2,changeTokenCost:3,depositDelaySeconds:4,minimumDepositBatch:5},
    certificate:{acceptedAt:50n,signature:bytes(60)},outgoing:map(),incoming:map(),slots:new Map([['5',s]]),
    hashes:{obligation:async()=>PAYLOAD,raw:async(v:bigint[])=>v.reduce((a,b)=>a+b,0n)&((1n<<250n)-1n)},
    commitment:123n,version:3n,opening:{},now:100n,input:()=>({old:{marker:'extended-opening'}}),
    clone(){return {...value};},...over};
  return value;
}
const context={history:bytes(70),challenge:bytes(71)};

test('wave statement binds the reservation, the accepted state and the extended opening',async()=>{
  const out=await wave(source(),5n,context,bytes(80),bytes(81));
  assert.equal(out.statement.kind,'wave');
  assert.deepEqual(out.statement.wave.context.peer,Array.from(bytes(2)));
  assert.equal(out.statement.wave.acceptedAt,50n);
  assert.equal(out.input.opening.marker,'extended-opening');
  assert.equal(out.input.selected.leaf[1],PAYLOAD);
  assert.equal(out.input.outcome,undefined);
});
test('outcome statement adds the settled code and receipt for answer and close',async()=>{
  const resolution={kind:0,issuedAt:5n,historyDigest:bytes(1),ed25519ReceiptDigest:bytes(9),signature:new Uint8Array(64)};
  for(const [outcome,code] of [['answer',1],['close',2]] as const) {
    const out=await waveOutcome(source({},slot({phase:3})),5n,context,bytes(80),bytes(81),outcome,resolution);
    assert.equal(out.statement.kind,'outcome');assert.equal(out.input.outcome,code);
    assert.deepEqual(Array.from(out.input.receipt_digest),Array.from(bytes(9)));
  }
  const silent=await waveOutcome(source({},slot({phase:5})),5n,context,bytes(80),bytes(81),'silence');
  assert.equal(silent.input.outcome,3);assert.deepEqual(Array.from(silent.input.receipt_digest),Array.from(new Uint8Array(32)));
});
test('every missing precondition refuses',async()=>{
  const call=(s:WaveSource)=>wave(s,5n,context,bytes(80),bytes(81));
  await assert.rejects(call(source({certificate:undefined})),/Accepted active reservation/);
  await assert.rejects(call(source({},slot({phase:1}))),/Accepted active reservation/);
  await assert.rejects(call(source({slots:new Map()})),/Accepted active reservation/);
  await assert.rejects(call(source({outgoing:map(PAYLOAD,false)})),/Missing reservation membership/);
  await assert.rejects(call(source({outgoing:map(PAYLOAD+1n)})),/Reservation opening differs/);
  await assert.rejects(waveOutcome(source({},slot({phase:2})),5n,context,bytes(80),bytes(81),'answer'),/Accepted active reservation/);
  await assert.rejects(waveOutcome(source(),5n,context,bytes(80),bytes(81),'other' as never),/Unknown settled outcome/);
});
test('the caller state is not mutated and later caller edits cannot change a built statement',async()=>{
  const s=source();const before=structuredClone({secret:s.ownerSecret,community:s.community});
  const out=await waveEvidence(s,5n,context,bytes(80),bytes(81));
  s.ownerSecret.fill(0);s.community.fill(0);
  assert.deepEqual(Array.from(out.input.secret),Array.from(before.secret));
  assert.deepEqual(Array.from(out.input.community),Array.from(before.community));
});
