// Test-only builder of the unlinkable voucher presentation (voucher_epoch relation). It mirrors
// prepareRecordEpoch: the same frozen epoch leaf and issuer certificate, but the owner stays
// private and the public outputs are only the allowance claim (issue) or the bond tag (post).
import {fieldBytes} from '@corbet-labs/czkp/primitives';
import {hex,random,zeros} from '@corbet-labs/czkp/encoding';
import {recordEpochPublicInputs,recordLeafCommitment,recordBytes,verifyRecordCertificate} from './record-epoch-codec.mts';

const bytes=v=>Uint8Array.from(v);
const PUBLIC=['record_issuer_key','record_certificate','scope','verification_scope','community','epoch','epoch_start','epoch_end','epoch_root','leaf_count','blinded_leaf'];

/** Purpose 0 claims `uses` admissions of allowance; purpose 1 posts `tag` for the bond obligation (kind, n). */
export async function prepareVoucherEpoch(holder,witness,scope,issuerKey,{purpose,uses=0,tag=Array(32).fill(0),bondSecret=zeros(),kind=0,n=0n,now,binding,frozenHolder}) {
  witness=structuredClone(witness);scope=structuredClone(scope);
  const equal=(a,b)=>hex(Uint8Array.from(a))===hex(Uint8Array.from(b));
  const leaf=witness.leaf;
  const source=[frozenHolder,holder].find(candidate=>candidate&&equal(candidate.owner.member,leaf.owner)
    &&Number(candidate.version)===leaf.version&&equal(fieldBytes(candidate.commitment),leaf.state)
    &&equal(candidate.opening.inbox,leaf.requiredInbox));
  if(!source)throw new Error('Required voucher opening unavailable');
  const state=source.clone();
  const local=state.record({purpose:'forumListing',challenge:Array(32).fill(1),expiresAt:witness.epoch.expiresAt});
  const {extension,version,state:commitment,state_policy,registered_secret,opening}=local.input;
  const blindedLeaf=Array.from(await recordLeafCommitment(state.community,witness.epoch.epoch,leaf,fields=>state.hashes.raw(fields)));
  const record={epoch:witness.epoch,owner:Array.from(state.owner.member),presentationKey:Array(32).fill(1),
    blindedLeaf,certificate:recordBytes(witness.certificate,64),shares:null};
  await verifyRecordCertificate(record);
  const shared=recordEpochPublicInputs(record,scope,issuerKey);
  // The planner derives the standing tables; any non-contact action gives the same policy.
  const probe=state.input(random(),now);probe.action=11;
  const standing_policy=state.plan(probe).policy;
  const input={extension,...Object.fromEntries(PUBLIC.map(key=>[key,shared[key]])),purpose,uses,now,tag:bytes(tag),binding:bytes(binding),
    owner:state.owner.member,version,state:commitment,required_inbox:leaf.requiredInbox,role:leaf.role,blinding:leaf.blinding,
    state_policy,registered_secret,opening,standing_policy,bond_secret:bondSecret,kind,n};
  const claim=purpose===0?{kind:'issue',uses}:{kind:'post',tag:Array.from(tag)};
  return {statement:{kind:'voucherEpoch',policy:state.extension,presentation:{epoch:witness.epoch,blindedLeaf,
    certificate:record.certificate,purpose:claim,now,binding:Array.from(binding)}},input};
}
