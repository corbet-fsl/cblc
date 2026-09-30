use core::{Enrollment,Opening,Obligation,MapWitness,Resolution,Acknowledgment,ExtensionPolicy,
    limbs,field,hash,secret_hash,marker,pair_key,enrollment_leaf,verify_enrollment,
    verify_peer_authority,policy_bytes,state_policy_hash,state_hash,obligation_hash,
    verify_acknowledgment,verify_resolution,extension_hash,advance,delivery,authorization,verify_contact};
use core::indexed;
global SAFE: u64 = 9007199254740991;
fn main(
    extension: pub ExtensionPolicy, previous_inbox: pub [u8;32], inbox: pub [u8;32],
    consume_only: pub bool, change_binding: pub [u8;32],
    community: pub [u8; 32], owner: pub [u8; 32], policy_digest: pub [u8; 32],
    enrollment_root: pub [u8; 32], now: pub u64, valid_until: pub u64, genesis: pub bool,
    previous_version: pub u64, next_version: pub u64,
    previous_state: pub [u8; 32], next_state: pub [u8; 32], settlement_marker: pub [u8; 32],
    initial_credit: pub u32, maximum_available: pub u32,
    outgoing_reservation: pub u32, incoming_reservation: pub u32,
    policy_revision: pub u64, policy_valid_from: pub u64, policy_valid_until: pub u64,
    newcomer_period: pub u64, rate_window: pub u64, newcomer_admissions: pub u32,
    maximum_admissions: pub u32, refill_period: pub u64, refill_units: pub u32, abandon_after: pub u64,
    owner_secret: [u8; 32], owner_enrollment: Enrollment, peer_enrollment: Enrollment,
    receipt_owner_enrollment: Enrollment,
    delivery_kind: u8, contact_signature: [u8;64],
    old: Opening, new_blind: [u8; 32], action: u8, slot: Obligation,
    own_map: MapWitness, opposite_map: MapWitness, pair_map: MapWitness,
    pair_exists: bool, resolution: Resolution, acknowledgment: Acknowledgment,
) {
    let ext = extension_hash(extension);
    assert((now > 0) & (now <= SAFE));
    assert((previous_version <= SAFE) & (next_version <= SAFE));
    assert((policy_revision > 0) & (policy_revision <= SAFE));
    assert((policy_valid_from > 0) & (policy_valid_from <= now));
    assert((now < policy_valid_until) & (policy_valid_until <= SAFE));
    assert((maximum_available > 0) & (initial_credit <= maximum_available));
    assert((outgoing_reservation > 0) & (outgoing_reservation <= initial_credit));
    assert((incoming_reservation > 0) & (incoming_reservation <= initial_credit));
    assert((newcomer_period > 0) & (newcomer_period <= SAFE));
    assert((rate_window > 0) & (rate_window <= SAFE));
    assert((refill_period > 0) & (refill_period <= SAFE));
    assert((abandon_after > 0) & (abandon_after <= SAFE));
    assert(abandon_after >= rate_window);
    assert((newcomer_admissions > 0) & (newcomer_admissions <= maximum_admissions));
    assert((refill_units > 0) & (refill_units <= initial_credit));
    let window_end = (now / rate_window + 1) * rate_window;
    assert(valid_until == if window_end < policy_valid_until { window_end } else { policy_valid_until });
    let policy = policy_bytes(community, initial_credit, maximum_available,
        outgoing_reservation, incoming_reservation, policy_revision,
        policy_valid_from, policy_valid_until, newcomer_period, rate_window,
        newcomer_admissions, maximum_admissions, refill_period, refill_units, abandon_after);
    assert(core::digest_policy(policy) == policy_digest);
    let state_policy = state_policy_hash(policy);
    assert((owner_secret != [0; 32]) & (new_blind != [0; 32]));
    let registered_secret = secret_hash(community, owner_secret);
    assert(registered_secret == field(owner_enrollment.secret_hash));
    verify_enrollment(community, owner, owner_enrollment, field(enrollment_root), now, valid_until);
    assert(field(next_state) != 0);
    if genesis {
        assert((previous_version == 0) & (next_version == 0));
        assert((previous_state == [0; 32]) & (settlement_marker == [0; 32]));
        let empty = indexed::initial_root();
        assert((previous_inbox==[0;32]) & (inbox==[0;32]) & !consume_only & (change_binding==[0;32]));
        let initial = Opening { available: initial_credit, reserved: 0, debt:0, accepted:0, declined:0, punished:0, inbox:[0;32], authorization:0,
            outgoing_root: empty, outgoing_count: 1, incoming_root: empty, incoming_count: 1,
            pair_root: empty, pair_count: 1, frontier: valid_until, created_at: valid_until,
            admission_epoch: now / rate_window, admissions: 0, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, 0, ext, initial) == field(next_state));
    } else {
        assert(next_version == previous_version + if consume_only {0} else {1});
        assert(old.inbox==previous_inbox);
        assert(consume_only == (action==10));
        if action!=10 { assert(inbox==previous_inbox); }
        if action!=9 { assert(change_binding==[0;32]); }
        assert(new_blind != old.blind);
        assert(state_hash(community, owner, state_policy, registered_secret, previous_version, ext, old) == field(previous_state));
        assert((old.created_at > 0) & (old.created_at <= old.frontier) & (old.frontier <= valid_until));
        let mature = if now >= old.created_at { now - old.created_at >= newcomer_period } else { false };
        let capacity = if mature { maximum_available } else { initial_credit };
        let admission_limit = if mature { maximum_admissions } else { newcomer_admissions };
        let epoch = now / rate_window;
        assert((old.admission_epoch <= epoch) & (old.admissions <= maximum_admissions));
        assert(old.available as u128 + old.reserved <= capacity as u128);
        assert((old.outgoing_count >= 1) & (old.outgoing_count <= 4294967296));
        assert((old.incoming_count >= 1) & (old.incoming_count <= 4294967296));
        assert((old.pair_count >= 1) & (old.pair_count <= 4294967296));
        assert((action >= 1) & (action <= 11)); // reserve, activate, settle, cancel, expire, refill
        let amount = if slot.role == 0 { outgoing_reservation } else { incoming_reservation };
        if (action != 6) & (action != 9) & (action != 11) {
            assert((slot.role < 2) & (slot.peer != owner));
            assert((slot.nonce != [0; 32]) & (slot.group != [0; 32]) & (slot.contact_policy != [0; 32]));
            assert((slot.admitted_at > 0) & (slot.admitted_at <= now));
            assert((slot.expires_at > slot.admitted_at) & (slot.expires_at < policy_valid_until));
            assert(slot.amount == amount);
        }
        let event = marker(community, owner, owner_secret, slot.peer, slot.nonce);
        let pair = pair_key(community, owner, owner_secret, slot.peer);
        if (action != 6) & (action != 9) & (action != 11) { assert((event != 0) & (pair != 0)); }
        let own_root = if slot.role == 0 { old.outgoing_root } else { old.incoming_root };
        let own_count = if slot.role == 0 { old.outgoing_count } else { old.incoming_count };
        let other_root = if slot.role == 0 { old.incoming_root } else { old.outgoing_root };
        let other_count = if slot.role == 0 { old.incoming_count } else { old.outgoing_count };
        let mut changed_root = own_root;
        let mut changed_count = own_count;
        let mut pair_root = old.pair_root;
        let mut pair_count = old.pair_count;
        let mut available = old.available;
        let mut reserved = old.reserved;
        let mut frontier = old.frontier;
        let mut admission_epoch = old.admission_epoch;
        let mut admissions = old.admissions;
        let mut issued: u32 = 0;
        let mut burned: u64 = 0;
        let mut debt = old.debt;
        let mut accepted = old.accepted; let mut declined = old.declined; let mut punished = old.punished;
        let mut authorized: Field = 0;
        assert((old.debt <= SAFE) & (old.accepted <= SAFE) & (old.declined <= SAFE) & (old.punished <= SAFE));
        if action == 1 {
            // Both owners commit the original initiator's common opened-at.
            assert((slot.phase == 1) & (slot.outcome==0) & !slot.answered & !slot.self_punished & (now < slot.expires_at));
            assert(old.debt==0);
            assert(valid_until <= slot.expires_at);
            if slot.role == 0 {
                assert(slot.admitted_at == now);
                assert(slot.expires_at == now + abandon_after);
            }
            // Incoming adopts the exact sender lease verified by the native
            // peer gate. Its proof alone does not establish cross-owner consent.
            let count = if old.admission_epoch == epoch { old.admissions as u64 + 1 } else { 1 };
            assert(count <= admission_limit as u64);
            admission_epoch = epoch; admissions = count as u32;
            verify_enrollment(community, slot.peer, peer_enrollment, field(enrollment_root), now, valid_until);
            assert(slot.peer_authority == enrollment_leaf(community, slot.peer, peer_enrollment));
            assert(slot.owner_authority == enrollment_leaf(community, owner, owner_enrollment));
            // Same event cannot be inserted under another role or a new path.
            indexed::absent(other_root, other_count, event,
                opposite_map.leaf, opposite_map.index, opposite_map.path);
            changed_root = indexed::insert(own_root, own_count, event, obligation_hash(event, slot, 1),
                own_map.leaf, own_map.index, own_map.path, own_map.append_path);
            changed_count = own_count + 1;
            if pair_exists {
                indexed::present(pair_root, pair_count, pair, 1,
                    pair_map.leaf, pair_map.index, pair_map.path);
            } else {
                pair_root = indexed::insert(pair_root, pair_count, pair, 1,
                    pair_map.leaf, pair_map.index, pair_map.path, pair_map.append_path);
                pair_count = pair_count + 1;
            }
            available = old.available - amount;
            reserved = old.reserved + amount as u128;
            assert(settlement_marker == [0; 32]);
        } else if action == 6 {
            assert(now >= old.frontier);
            assert(now - old.frontier >= refill_period);
            let headroom = capacity as u128 - (old.available as u128 + old.reserved);
            let paid = if debt < refill_units as u64 {debt} else {refill_units as u64};
            let remainder=refill_units-paid as u32;
            let grant=if headroom < remainder as u128 {headroom as u32} else {remainder};
            issued=paid as u32+grant;
            debt = debt - paid; burned = paid;
            available = old.available + issued - paid as u32;
            // No backdated proof chain may collect multiple grants inside one
            // accepted window. Even a zero grant consumes the common horizon.
            frontier = valid_until;
            assert(settlement_marker == [0; 32]);
        } else if action==9 {
            assert((change_binding!=[0;32]) & (old.debt==0));
            available = available - extension.change_cost;
            burned = extension.change_cost as u64;
            let c=limbs(change_binding);
            let event=marker(community,owner,owner_secret,owner,change_binding);
            assert(field(settlement_marker)==hash([event,previous_version as Field,c[0],c[1]]));
        } else if action==11 {
            // A final reblind after an atomic sequence of forced inbox transitions.
            assert(settlement_marker==[0;32]);
        } else if (action==7) | (action==8) | (action==10) {
            // A contact-authorized outcome always addresses an existing transcript.
            // Issuer deposits are authenticated separately; ingestion cannot choose
            // another outcome because its opening must hash to the supplied chain.
            let self_punish=(action==7)|(action==8);
            let kind=if action==7 {3} else if action==8 {4} else {delivery_kind};
            let mut next_slot=slot;
            let mut cost: u64=0;
            if self_punish {
                verify_contact(community,owner,slot,peer_enrollment,contact_signature);
                if action==7 {assert((slot.role==1) & ((slot.phase==1)|(slot.phase==2)) & (slot.outcome==0));}
                else {assert(slot.answered & !slot.self_punished);}
                assert((pair_map.leaf[1]==1)|(pair_map.leaf[1]==2));
                pair_root=indexed::update(pair_root,pair_count,pair,pair_map.leaf[1],2,pair_map.leaf,pair_map.index,pair_map.path);
                authorized=authorization(community,owner,owner_secret,slot,kind);
                next_slot.self_punished=true;
            } else {
                let obligation: [u8;32]=delivery(community,owner,slot.peer,slot,kind).to_be_bytes();
                assert(inbox==advance(community,owner,previous_inbox,obligation));
                assert(settlement_marker==[0;32]);
                assert((kind==4)|(slot.role==0));
                // Certified established punishment may arrive before the Answer
                // deposit. Punishment is terminal even when that older delivery
                // follows it; the target must never need to reorder the chain.
                if (kind==3)|(kind==4) {assert(slot.outcome!=3);}
                else {assert((slot.outcome==0)|(slot.outcome==kind)|(slot.outcome==3));}
                if ((kind==1)|(kind==2)) & (slot.outcome==0) {
                    if kind==1 {accepted=accepted+1;} else {declined=declined+1;}
                } else if (kind==3)|(kind==4) {
                    // An established outcome replaces the earlier accepted sent
                    // contact; receiving-side punishment adds one punitive outcome.
                    if (slot.role==0)&(slot.outcome==1) {accepted=accepted-1;}
                    if (slot.role==0)&(slot.outcome==2) {declined=declined-1;}
                    punished=punished+1;
                }
            }
            if (kind==3)|(kind==4) {
                if (slot.phase==1)|(slot.phase==2) {
                    reserved=reserved-slot.amount as u128;
                    if kind==4 {
                        available=available+slot.amount; cost=1;
                    } else {burned=slot.amount as u64;}
                } else {cost=if kind==4 {1} else {slot.amount as u64};}
                next_slot.phase=7;
                if kind==4 {next_slot.answered=true;}
                if !self_punish {next_slot.outcome=3;}
            } else if slot.outcome!=3 {
                // Accepted outcomes release the bond once. Declines retain the
                // sender's wait. Expired reservations were already refunded.
                if (kind==1)&(slot.outcome==0) {
                    if (slot.phase==1)|(slot.phase==2) {
                        available=available+slot.amount;
                        reserved=reserved-slot.amount as u128;
                    } else {assert((slot.phase==4)|(slot.phase==5));}
                    next_slot.phase=3; next_slot.answered=true;
                }
                if (kind==2)&(slot.phase==1) {next_slot.phase=2;}
                next_slot.outcome=kind;
            }
            let paid=if cost < available as u64 {cost} else {available as u64};
            available=available-paid as u32; debt=debt+cost-paid; burned=burned+paid;
            changed_root=indexed::update(own_root,own_count,event,obligation_hash(event,slot,slot.phase),
                obligation_hash(event,next_slot,next_slot.phase),own_map.leaf,own_map.index,own_map.path);
            if self_punish {assert(field(settlement_marker)==hash([event,kind as Field]));}
        } else {
            let next_phase = if action == 2 { 2 } else if action == 4 { 4 } else if action == 5 { 5 } else { 3 };
            assert(slot.phase == if (action == 2) | (action == 4) { 1 } else { 2 });
            let mut changed_slot=slot;
            if action==3 {changed_slot.outcome=resolution.kind; if resolution.kind==1 {changed_slot.answered=true;}}
            changed_root = indexed::update(own_root, own_count, event,
                obligation_hash(event, slot, slot.phase), obligation_hash(event, changed_slot, next_phase),
                own_map.leaf, own_map.index, own_map.path);
            if action == 2 {
                verify_contact(community,owner,slot,peer_enrollment,contact_signature);
                assert(now < slot.expires_at);
                assert(valid_until <= slot.expires_at);
                assert(settlement_marker == [0; 32]);
            } else if action == 4 {
                // Before protected release only; the admission counter and
                // permanent event tombstone prevent refund/reset churn.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            } else if action == 5 {
                assert((slot.role == 0) & (now >= slot.expires_at));
                // The fixed wait refunds the bond regardless of whether a
                // Close receipt was delivered. Admission throughput stays spent.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            } else {
                assert(slot.outcome==0);
                if slot.role==0 {accepted=accepted+1;}
                else {authorized=authorization(community,owner,owner_secret,slot,resolution.kind);}
                if resolution.kind == 1 {
                    assert(now < slot.expires_at);
                    assert(valid_until <= slot.expires_at);
                }
                if slot.role == 0 {
                    // Recipient Close does not change the outgoing refund date.
                    // Only a confirmed Answer may settle this role early.
                    assert(resolution.kind == 1);
                    verify_peer_authority(community, slot, peer_enrollment, field(enrollment_root), now, valid_until);
                }
                // Incoming owner closure has no current-eligibility dependency
                // on the silent counterpart. Historical authority is in slot.
                if slot.role == 1 {
                    let authority = enrollment_leaf(community, owner, receipt_owner_enrollment);
                    assert((authority == slot.owner_authority) | (authority == enrollment_leaf(community, owner, owner_enrollment)));
                }
                let signer = if slot.role == 0 { peer_enrollment } else { receipt_owner_enrollment };
                verify_resolution(community, owner, slot, signer, resolution, now);
                if (slot.role == 1) & (resolution.kind == 1) {
                    verify_peer_authority(community, slot, peer_enrollment, field(enrollment_root), now, valid_until);
                    verify_acknowledgment(community, owner, slot, receipt_owner_enrollment,
                        peer_enrollment, resolution, acknowledgment, now);
                }
                // Incoming Close and confirmed Answer restore the exact bond.
                // There is no additional reward or sender-selected burn.
                available = old.available + amount;
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            }
        }
        let refunded_debt=if debt<available as u64 {debt} else {available as u64};
        available=available-refunded_debt as u32; debt=debt-refunded_debt; burned=burned+refunded_debt;
        assert(available as u128 + reserved <= capacity as u128);
        assert(available as u128 + reserved + burned as u128 == old.available as u128 + old.reserved + issued as u128);
        assert((debt<=SAFE)&(accepted<=SAFE)&(declined<=SAFE)&(punished<=SAFE));
        assert((debt==0)|(available==0));
        let successor = Opening { available, reserved, debt, accepted, declined, punished, inbox, authorization: authorized,
            outgoing_root: if slot.role == 0 { changed_root } else { old.outgoing_root },
            outgoing_count: if slot.role == 0 { changed_count } else { old.outgoing_count },
            incoming_root: if slot.role == 1 { changed_root } else { old.incoming_root },
            incoming_count: if slot.role == 1 { changed_count } else { old.incoming_count },
            pair_root, pair_count, frontier, created_at: old.created_at,
            admission_epoch, admissions, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, next_version, ext, successor) == field(next_state));
    }
}
