// Account update circuit diet: equivalence of the two replaced core primitives.
//  1. indexed::less (std Field::lt) equals the removed 32-byte-halves comparison and
//     the integer order of the canonical representatives, on 0, 1, p-1, equal values,
//     byte-boundary pairs, half-equal pairs and random pairs.
//  2. The compile-time constant indexed::initial_root() equals the runtime
//     computation of the empty map root (the same construction fed by a witness).
// Witness execution only: no proof and no member data.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {compile,createFileManager} from '@noir-lang/noir_wasm';
import {Noir} from '@noir-lang/noir_js';

const P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BATCH=128;
const started=Date.now();
const compiled=await compile(createFileManager(resolve('circuits/extensions/core_probe')));
assert.ok(compiled.program?.bytecode,'core probe compiles');
const noir=new Noir(compiled.program as any);
const field=(v:bigint)=>{assert.ok(v>=0n&&v<P,'canonical field element');return '0x'+v.toString(16);};

// Deterministic generator, so a failing pair reproduces.
let counter=0n;
const random=(bits:number):bigint=>{
  let out=0n;
  for(let produced=0;produced<bits;produced+=256) {
    const block=createHash('sha256').update(`core-probe-${counter++}`).digest();
    out=(out<<256n)|BigInt('0x'+block.toString('hex'));
  }
  return out&((1n<<BigInt(bits))-1n);
};
const canonical=()=>{for(;;){const v=random(256)%(1n<<254n);if(v<P)return v;}};

// Boundary values: 0, 1, p-1 and every byte boundary 2^(8k) +- 1, 2^128 +- 1, the middle of the field.
const edge=new Set<bigint>([0n,1n,2n,P-1n,P-2n,(P-1n)/2n,(P+1n)/2n]);
for(let k=1;k<=31;k++) for(const d of [-1n,0n,1n]) edge.add((1n<<BigInt(8*k))+d);
for(const bit of [127n,128n,129n,252n,253n]) for(const d of [-1n,0n,1n]) edge.add((1n<<bit)+d);
const edges=[...edge].filter(v=>v>=0n&&v<P).sort((a,b)=>a<b?-1:a>b?1:0);
// Every ordered pair of the principal boundaries; every other boundary against its neighbours in order.
const dense=new Set<bigint>([0n,1n,2n,P-1n,P-2n,(P-1n)/2n,(P+1n)/2n]);
for(const bit of [8n,16n,120n,128n,136n,248n,253n]) for(const d of [-1n,0n,1n]) dense.add((1n<<bit)+d);
const pairs:[bigint,bigint][]=[];
for(const a of dense) for(const b of dense) if(a<P&&b<P) pairs.push([a,b]);
for(const [i,a] of edges.entries()) {
  pairs.push([a,a]);                                    // equal values
  for(const j of [i-2,i-1,i+1,i+2]) if(j>=0&&j<edges.length) pairs.push([a,edges[j]]);
}
for(let i=0;i<256;i++) {
  // Equal high 128-bit half, different low half; equal low half, different high half.
  const high=random(125),lowA=random(128),lowB=random(128);
  pairs.push([(high<<128n)|lowA,(high<<128n)|lowB]);
  const low=random(128),highA=random(125),highB=random(125);
  pairs.push([(highA<<128n)|low,(highB<<128n)|low]);
}
for(let i=0;i<512;i++) pairs.push([canonical(),canonical()]);
while(pairs.length%BATCH!==0) pairs.push([canonical(),canonical()]);

console.log(`compiled in ${Date.now()-started} ms`);
let checked=0,less=0;
for(let start=0;start<pairs.length;start+=BATCH) {
  const slice=pairs.slice(start,start+BATCH);
  const out=await noir.execute({left:slice.map(p=>field(p[0])),right:slice.map(p=>field(p[1])),zero:'0x0'});
  const [fresh,old]=out.returnValue as [boolean[],boolean[],string];
  for(const [i,[a,b]] of slice.entries()) {
    const expected=a<b;
    assert.equal(fresh[i],expected,`indexed::less(${a},${b})`);
    assert.equal(old[i],expected,`old less(${a},${b})`);
    checked++;if(expected)less++;
  }
}
assert.ok(less>1000&&checked-less>1000,'both outcomes are exercised');

// The comptime constant is returned and equals the independent runtime construction (asserted in the circuit).
const first=pairs.slice(0,BATCH);
const base={left:first.map(p=>field(p[0])),right:first.map(p=>field(p[1])),zero:'0x0'};
const constant=((await noir.execute(base)).returnValue as [boolean[],boolean[],string])[2];
assert.match(String(constant),/^0x[0-9a-f]+$/);
assert.notEqual(BigInt(constant),0n);
// The check is live: a different witness zero builds a different runtime root and must be refused.
await assert.rejects(()=>noir.execute({...base,zero:'0x1'}));
console.log(`core probe: ${checked} comparison pairs equal; initial_root ${constant}`);
