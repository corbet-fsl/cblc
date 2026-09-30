import {POLICY_WIRE,validateStatement} from '../accounting/statement.mjs';
export const exact=(value,keys)=>!!value&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
export const equal=(a,b)=>Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&a.every((v,i)=>v===b[i]);
export const zero=()=>Array(32).fill(0);
export function policyInput(p) {
  if(!exact(p,['revision','publicRecordQuorum','changeTokenCost','depositDelaySeconds','minimumDepositBatch']))throw new Error('Extension policy shape');
  return {revision:p.revision,quorum:p.publicRecordQuorum,change_cost:p.changeTokenCost,delay:p.depositDelaySeconds,batch:p.minimumDepositBatch};
}
export function updateInput(account,policy,previousInbox,inbox,consume,binding) {
  const s=account;
  return {extension:policyInput(policy),previous_inbox:previousInbox,inbox,consume_only:consume,change_binding:binding,
    community:s.community,owner:s.owner,policy_digest:s.policyDigest,enrollment_root:s.enrollmentRoot,now:s.now,valid_until:s.validUntil,genesis:s.genesis,
    previous_version:s.previousVersion,next_version:s.nextVersion,previous_state:s.previousState,next_state:s.nextState,settlement_marker:s.settlementMarker,
    ...Object.fromEntries(POLICY_WIRE.map(([k,wire])=>[wire,s.policy[k]]))};
}
export async function expectedProofs(statement,bundle,manifest) {
  const p=statement.policy,extension=policyInput(p);
  if(!exact(bundle,['version','proofs'])||bundle.version!==1||!Array.isArray(bundle.proofs)||bundle.proofs.length<1||bundle.proofs.length>65)throw new Error('Bounded proof bundle required');
  if(statement.kind==='update') {
    if(!exact(statement,['kind','policy','account','update']))throw new Error('Update shape');
    await validateStatement(statement.account);
    const u=statement.update,s=statement.account;
    if(!exact(u,['previousInbox','inbox','effect'])||!exact(u.previousInbox,['root'])||!exact(u.inbox,['root']))throw new Error('Inbox shape');
    const change=u.effect.kind==='change';
    if(!exact(u.effect,change?['kind','binding']:['kind'])||(!change&&u.effect.kind!=='update'))throw new Error('Effect shape');
    const result=[];let state=s.previousState,root=u.previousInbox.root;
    for(let i=0;i<bundle.proofs.length;i++) {
      const step=bundle.proofs[i],last=i===bundle.proofs.length-1;
      if(!exact(step,['state','inbox','proof']))throw new Error('Proof step shape');
      if(last) {
        if(!equal(root,u.inbox.root)||!equal(step.inbox,u.inbox.root)||!equal(step.state,s.nextState))throw new Error('Incomplete inbox or state chain');
        result.push({kind:'update',proof:step.proof,input:updateInput({...s,previousState:state},p,root,root,false,change?u.effect.binding:zero())});
      } else {
        if(s.genesis||equal(root,step.inbox))throw new Error('Invalid ingestion step');
        result.push({kind:'update',proof:step.proof,input:updateInput({...s,previousState:state,nextState:step.state,nextVersion:s.previousVersion,settlementMarker:zero()},p,root,step.inbox,true,zero())});
        state=step.state;root=step.inbox;
      }
    }
    return result;
  }
  if(bundle.proofs.length!==1||!exact(bundle.proofs[0],['proof']))throw new Error('Anonymous proof shape');
  const proof=bundle.proofs[0].proof;
  if(statement.kind==='deposit') {
    if(!exact(statement,['kind','policy','deposit']))throw new Error('Deposit shape');
    const d=statement.deposit;
    if(!exact(d,['community','recipient','releaseEpoch','nullifier','authorizationNullifier','obligation']))throw new Error('Deposit fields');
    return [{kind:'deposit',proof,input:{extension,issuer_key:manifest.issuerKey,scope:Array.from(Buffer.from(manifest.circuitSha256,'hex')),
      community:d.community,recipient:d.recipient,release_epoch:d.releaseEpoch,nullifier:d.nullifier,authorization_nullifier:d.authorizationNullifier,obligation:d.obligation}}];
  }
  if(statement.kind!=='record'||!exact(statement,['kind','policy','record']))throw new Error('Statement domain');
  const r=statement.record,c=r.context;
  if(!exact(r,['context','community','owner','version','state','inbox','shares'])||!exact(r.inbox,['root'])||!exact(c,['purpose','challenge','expiresAt'])||!['firstContact','forumListing'].includes(c.purpose))throw new Error('Record shape');
  return [{kind:'record',proof,input:{extension,community:r.community,owner:r.owner,version:r.version,state:r.state,inbox:r.inbox.root,
    purpose:c.purpose==='firstContact'?0:1,challenge:c.challenge,expires_at:c.expiresAt,present:r.shares!==null,shares:r.shares??[0,0,0]}}];
}
