// Test-only original CWLT recordEpoch builder, adapted to current main's holder.
// The driver must authenticate the issued descriptor and open/verify the actual
// common HPKE packet/tree before calling this private witness construction.
import {fieldBytes} from '@corbet-labs/czkp/primitives';
import {hex} from '@corbet-labs/czkp/encoding';
import {recordEpochPublicInputs,recordLeafCommitment,recordBytes,verifyRecordCertificate} from './record-epoch-codec.mts';

const bytes=v=>Uint8Array.from(v);

export async function prepareRecordEpoch(holder,presentationPublicKey,witness,scope,issuerKey,{frozenHolder}={}) {
  witness=structuredClone(witness);scope=structuredClone(scope);
  const equal=(a,b)=>hex(Uint8Array.from(a))===hex(Uint8Array.from(b));
  const matches=(holder,leaf)=>holder&&equal(holder.owner.member,leaf.owner)
    &&Number(holder.version)===leaf.version&&equal(fieldBytes(holder.commitment),leaf.state)
    &&equal(holder.opening.inbox,leaf.requiredInbox);
  // Preserve the original preference for the retained frozen opening. A later
  // ordinary update cannot become a new same-epoch public leaf. If the frozen
  // inbox is pending, only the exact original signed minimum descendant fits.
  let selected=witness.leaf,signature=witness.certificate;
  let source=[frozenHolder,holder].find(candidate=>matches(candidate,selected));
  if(!source){
    selected=witness.ancestry?.record?.leaf;signature=witness.ancestry?.record?.signature;
    if(!selected||!matches(holder,selected))throw new Error('Required record opening unavailable');
    source=holder;
  }
  const state=source.clone();state.community=bytes(source.community);state.owner=structuredClone(source.owner);
  state.statePolicyHash=bytes(source.statePolicyHash);state.extension=structuredClone(source.extension);
  if(!equal(state.community,witness.epoch.community)||!equal(state.owner.member,holder.owner.member))throw new Error('Foreign record witness');
  // Use the actual current MAIN holder's original record input, including all
  // private Opening fields and its maintained shares calculation. No 20-level
  // map, compact AcceptedState/deposit transcript or reconstructed opening is
  // copied from v01. The legacy context below only obtains that local template;
  // its challenge/purpose/expiry fields are not used as record-epoch authority.
  const local=state.record({purpose:'forumListing',challenge:recordBytes(presentationPublicKey),expiresAt:witness.epoch.expiresAt});
  const {extension,version,state:commitment,state_policy,registered_secret,opening}=local.input;
  const blindedLeaf=Array.from(await recordLeafCommitment(state.community,witness.epoch.epoch,selected,fields=>state.hashes.raw(fields)));
  const record={epoch:witness.epoch,owner:Array.from(state.owner.member),presentationKey:recordBytes(presentationPublicKey),
    blindedLeaf,certificate:recordBytes(signature,64),shares:local.statement.record.shares};
  await verifyRecordCertificate(record);
  const input=recordEpochPublicInputs(record,scope,issuerKey);
  return {statement:{kind:'recordEpoch',policy:state.extension,record},input:{...input,extension,
    version,state:commitment,required_inbox:selected.requiredInbox,role:selected.role,blinding:selected.blinding,
    state_policy,registered_secret,opening}};
}
