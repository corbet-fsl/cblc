use core::voucher::{Voucher,VoucherAux,BondEntry,entry_hash,bond_commit,bond_key,obligation_tag,member_tag,
    admit,remaining,punish_weight,rewarded};
use core::{Enrollment,Opening,Obligation,MapWitness,Resolution,Acknowledgment,ExtensionPolicy,
    limbs,field,hash,secret_hash,marker,pair_key,enrollment_leaf,verify_enrollment,
    verify_peer_authority,policy_bytes,state_policy_hash,state_hash,obligation_hash,
    verify_acknowledgment,verify_resolution,extension_hash,advance,delivery,authorization,verify_contact};
use core::indexed;
use core::standing::{Standing,StandingPolicy,policy_digest as standing_digest,check_policy,check_state,advance as advance_standing,
    answer_received,answer_given,unanswered,punished,punish_given,cap,obligation_punished};
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
    role: pub u8, obligation: pub [u8; 32],
    owner_secret: [u8; 32], owner_enrollment: Enrollment, peer_enrollment: Enrollment,
    receipt_owner_enrollment: Enrollment,
    delivery_kind: u8, contact_signature: [u8;64],
    old: Opening, new_blind: [u8; 32], action: u8, slot: Obligation,
    own_map: MapWitness, opposite_map: MapWitness, pair_map: MapWitness,
    pair_exists: bool, resolution: Resolution, acknowledgment: Acknowledgment,
    standing_policy: StandingPolicy, aux: VoucherAux,
) {
    let ext = extension_hash(extension);
    assert((now > 0) & (now <= SAFE));
    assert((previous_version <= SAFE) & (next_version <= SAFE));
    assert((policy_revision > 0) & (policy_revision <= SAFE));
    assert((policy_valid_from > 0) & (policy_valid_from <= now));
    assert((now < policy_valid_until) & (policy_valid_until <= SAFE));
    // Credit-era policy inputs (initial_credit, maximum_available, newcomer_*, refill_*) are
    // accepted for policy-digest compatibility but never influence a result (temporary).
    assert((outgoing_reservation > 0) & (incoming_reservation > 0));
    // The proof window is at most one day: standing counts days, and the account creation
    // time (the window end at genesis) is therefore accurate to a day.
    assert((rate_window > 0) & (rate_window <= 86400));
    assert((abandon_after > 0) & (abandon_after <= SAFE));
    assert(abandon_after >= rate_window);
    let window_end = (now / rate_window + 1) * rate_window;
    assert(valid_until == if window_end < policy_valid_until { window_end } else { policy_valid_until });
    let day = now / 86400;
    check_policy(standing_policy);
    assert(standing_digest(standing_policy) == field(extension.standing));
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
        // A founder has neither sponsor nor bond; a vouchee has both.
        let bond = if aux.bond_secret == [0; 32] { 0 } else { bond_commit(aux.bond_secret) };
        assert((bond == 0) == (aux.sponsor == 0));
        assert(obligation == [0; 32]);
        let voucher = Voucher { proven: 0, away: 0, reserved: 0, lost: 0, bonus: 0, returned: 0, answers: 0,
            sponsor: aux.sponsor, bond, bond_root: empty, bond_count: 1 };
        let initial = Opening { reserved: 0, accepted:0, declined:0, punished:0, inbox:[0;32], authorization:0,
            outgoing_root: empty, outgoing_count: 1, incoming_root: empty, incoming_count: 1,
            pair_root: empty, pair_count: 1, created_at: valid_until,
            standing: Standing { g: 0, a: (standing_policy.c0 - 1) << 16, c: 0, pr: 0, pg: 0, lc: 0, day: valid_until / 86400 },
            voucher, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, 0, ext, initial) == field(next_state));
    } else {
        assert(next_version == previous_version + if consume_only {0} else {1});
        assert(old.inbox==previous_inbox);
        assert(consume_only == (action==10));
        if action!=10 { assert(inbox==previous_inbox); }
        if action!=9 { assert(change_binding==[0;32]); }
        assert(new_blind != old.blind);
        assert(state_hash(community, owner, state_policy, registered_secret, previous_version, ext, old) == field(previous_state));
        assert(old.created_at > 0);
        let joined = old.created_at / 86400;
        check_state(old.standing, joined);
        let mut standing = advance_standing(old.standing, day, standing_policy);
        // The shared pool: pending first contacts in both roles, sized by standing.
        let pool = cap(standing, standing_policy, joined);
        assert((old.outgoing_count >= 1) & (old.outgoing_count <= 4294967296));
        assert((old.incoming_count >= 1) & (old.incoming_count <= 4294967296));
        assert((old.pair_count >= 1) & (old.pair_count <= 4294967296));
        assert((action >= 1) & (action <= 16) & (action != 6)); // 6 (refill) retired: slots return on settlement
        // 12 admit (sponsor spends a voucher), 13 consume a bond obligation, 14 prove success,
        // 15 reserve the uses of a new link, 16 release the unused uses of an ended link.
        let no_slot = (action == 6) | (action == 9) | (action == 11) | (action >= 12);
        let mut vch = old.voucher;
        assert((vch.bond_count >= 1) & (vch.bond_count <= 4294967296));
        assert((vch.away <= SAFE) & (vch.reserved <= SAFE) & (vch.lost <= SAFE) & (vch.bonus <= SAFE) & (vch.returned <= SAFE) & (vch.answers <= SAFE) & (vch.proven <= SAFE));
        if action != 13 { assert(obligation == [0; 32]); }
        assert(!aux.count | (action == 3) | (action == 10));
        let amount = if slot.role == 0 { outgoing_reservation } else { incoming_reservation };
        if !no_slot {
            assert((slot.role < 2) & (slot.peer != owner));
            assert((slot.nonce != [0; 32]) & (slot.group != [0; 32]) & (slot.contact_policy != [0; 32]));
            assert((slot.admitted_at > 0) & (slot.admitted_at <= now));
            assert((slot.expires_at > slot.admitted_at) & (slot.expires_at < policy_valid_until));
            assert(slot.amount == amount);
        }
        let event = marker(community, owner, owner_secret, slot.peer, slot.nonce);
        let pair = pair_key(community, owner, owner_secret, slot.peer);
        if !no_slot { assert((event != 0) & (pair != 0)); }
        let own_root = if slot.role == 0 { old.outgoing_root } else { old.incoming_root };
        let own_count = if slot.role == 0 { old.outgoing_count } else { old.incoming_count };
        let other_root = if slot.role == 0 { old.incoming_root } else { old.outgoing_root };
        let other_count = if slot.role == 0 { old.incoming_count } else { old.outgoing_count };
        let mut changed_root = own_root;
        let mut changed_count = own_count;
        let mut pair_root = old.pair_root;
        let mut pair_count = old.pair_count;
        let mut reserved = old.reserved;
        let mut accepted = old.accepted; let mut declined = old.declined; let mut punished_count = old.punished;
        let mut authorized: Field = 0;
        assert((old.accepted <= SAFE) & (old.declined <= SAFE) & (old.punished <= SAFE));
        if action == 1 {
            // Both owners commit the original initiator's common opened-at.
            assert((slot.phase == 1) & (slot.outcome==0) & !slot.answered & !slot.self_punished & (now < slot.expires_at));
            assert(valid_until <= slot.expires_at);
            if slot.role == 0 {
                assert(slot.admitted_at == now);
                assert(slot.expires_at == now + abandon_after);
            }
            // Incoming adopts the exact sender lease verified by the native
            // peer gate. Its proof alone does not establish cross-owner consent.
            // Pool check, both roles: pending first contacts (sent and received) stay within the cap.
            assert(old.reserved + amount as u128 <= pool as u128);
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
                // 1 plain pair, 5 a pair already counted toward the success proof.
                assert((pair_map.leaf[1] == 1) | (pair_map.leaf[1] == 5));
                indexed::present(pair_root, pair_count, pair, pair_map.leaf[1],
                    pair_map.leaf, pair_map.index, pair_map.path);
            } else {
                pair_root = indexed::insert(pair_root, pair_count, pair, 1,
                    pair_map.leaf, pair_map.index, pair_map.path, pair_map.append_path);
                pair_count = pair_count + 1;
            }
            reserved = old.reserved + amount as u128;
            assert(settlement_marker == [0; 32]);
        } else if action==9 {
            assert(change_binding!=[0;32]);
            // The change needs pool headroom; it holds nothing (open: v5 prices it no further).
            assert(old.reserved + extension.change_cost as u128 <= pool as u128);
            let c=limbs(change_binding);
            let event=marker(community,owner,owner_secret,owner,change_binding);
            assert(field(settlement_marker)==hash([event,previous_version as Field,c[0],c[1]]));
        } else if action==11 {
            // A final reblind after an atomic sequence of forced inbox transitions.
            assert(settlement_marker==[0;32]);
        } else if action >= 12 {
            assert(settlement_marker == [0; 32]);
            assert(inbox == previous_inbox);
            if action == 12 {
                // The sponsor spends one voucher on an actual admission and remembers the bond.
                assert(aux.bond_secret != [0; 32]);
                assert(vch.bond != bond_commit(aux.bond_secret));
                let (spent, entry) = admit(standing_policy, role, vch, pool);
                vch = spent;
                vch.bond_root = indexed::insert(old.voucher.bond_root, old.voucher.bond_count,
                    bond_key(aux.bond_secret), entry_hash(entry), aux.bond_map.leaf, aux.bond_map.index,
                    aux.bond_map.path, aux.bond_map.append_path);
                vch.bond_count = old.voucher.bond_count + 1;
            } else if action == 13 {
                // One obligation posted through a bond: the tag is the only thing a server saw.
                assert((aux.kind >= 1) & (aux.kind <= 3));
                assert(obligation == obligation_tag(aux.bond_secret, aux.kind, aux.n).to_be_bytes());
                let key = bond_key(aux.bond_secret);
                let e = aux.entry;
                indexed::present(vch.bond_root, vch.bond_count, key, entry_hash(e),
                    aux.bond_map.leaf, aux.bond_map.index, aux.bond_map.path);
                let mut next = e;
                if aux.kind == 1 {
                    // The vouchee proved success: the voucher returns unless it was lost.
                    assert((aux.n == 0) & !e.done);
                    next.done = true;
                    if !e.overshoot {
                        assert(vch.away > 0);
                        vch.away = vch.away - 1;
                    }
                    vch.returned = vch.returned + 1;
                } else if aux.kind == 2 {
                    // The vouchee was punished: a fraction before the v5 curve, decaying like v5.
                    assert(aux.n == e.punished_seen + 1);
                    next.punished_seen = aux.n;
                    standing = obligation_punished(standing, punish_weight(e.limit));
                } else {
                    // The vouchee's own vouchee succeeded: a capped permanent bonus.
                    assert(aux.n == e.rewards_seen + 1);
                    next.rewards_seen = aux.n;
                    vch.bonus = rewarded(standing_policy, vch.bonus);
                }
                vch.bond_root = indexed::update(vch.bond_root, vch.bond_count, key, entry_hash(e),
                    entry_hash(next), aux.bond_map.leaf, aux.bond_map.index, aux.bond_map.path);
            } else if action == 15 {
                // A link of `units` uses is created: remaining allowance covers them.
                assert((aux.units >= 1) & (aux.units <= remaining(standing_policy, role, vch, pool)));
                vch.reserved = vch.reserved + aux.units;
            } else if action == 16 {
                // Unused uses of an expired, revoked or declined link return.
                assert((aux.units >= 1) & (aux.units <= vch.reserved));
                vch.reserved = vch.reserved - aux.units;
            } else {
                // The account's own success proof; every threshold is a public policy value.
                assert(vch.proven == 0);
                assert((day > 0) & (day >= joined + standing_policy.v_days));
                assert(pool > standing_policy.v_brake_cap);
                assert(old.punished <= standing_policy.v_max_punished);
                assert(vch.answers >= standing_policy.v_k);
                vch.proven = day;
            }
        } else if (action==7) | (action==8) | (action==10) {
            // A contact-authorized outcome always addresses an existing transcript.
            // Issuer deposits are authenticated separately; ingestion cannot choose
            // another outcome because its opening must hash to the supplied chain.
            let self_punish=(action==7)|(action==8);
            let kind=if action==7 {3} else if action==8 {4} else {delivery_kind};
            let mut next_slot=slot;
            if self_punish {
                verify_contact(community,owner,slot,peer_enrollment,contact_signature);
                if action==7 {assert((slot.role==1) & ((slot.phase==1)|(slot.phase==2)) & (slot.outcome==0));}
                else {assert(slot.answered & !slot.self_punished);}
                assert((pair_map.leaf[1]==1)|(pair_map.leaf[1]==2)|(pair_map.leaf[1]==5)|(pair_map.leaf[1]==6));
                // 2 punished by me; the counted flag (4) survives.
                let marked = if (pair_map.leaf[1]==5)|(pair_map.leaf[1]==6) {6} else {2};
                pair_root=indexed::update(pair_root,pair_count,pair,pair_map.leaf[1],marked,pair_map.leaf,pair_map.index,pair_map.path);
                authorized=authorization(community,owner,owner_secret,slot,kind);
                next_slot.self_punished=true;
                // Punishing costs the punisher the same as the target: one given punishment.
                standing = punish_given(standing);
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
                    punished_count=punished_count+1;
                    // Obligation consumed: the punishment counts fully against the target.
                    standing = punished(standing, (kind==4) | slot.answered);
                }
            }
            if (kind==3)|(kind==4) {
                // My own wave punished by its target (kind 3): the slot is held until the
                // waiting period ends (phase 8), then settled as a miss. Every other
                // punishment frees a live slot at once.
                let hold = (!self_punish) & (kind==3) & (slot.role==0) & ((slot.phase==1)|(slot.phase==2));
                if ((slot.phase==1)|(slot.phase==2)) & !hold {
                    reserved=reserved-slot.amount as u128;
                }
                next_slot.phase=if hold {8} else {7};
                if kind==4 {next_slot.answered=true;}
                if !self_punish {next_slot.outcome=3;}
            } else if slot.outcome!=3 {
                // An Answer frees the slot once and earns goodwill. Declines retain the
                // sender's wait. Expired reservations were already freed.
                if (kind==1)&(slot.outcome==0) {
                    if (slot.phase==1)|(slot.phase==2) {
                        reserved=reserved-slot.amount as u128;
                    } else {assert((slot.phase==4)|(slot.phase==5));}
                    next_slot.phase=3; next_slot.answered=true;
                    standing = answer_received(standing, standing_policy, joined);
                    if aux.count {
                        pair_root = count_answer(community, slot, peer_enrollment, old.created_at, vch.sponsor,
                            pair_root, pair_count, pair, pair_map);
                        vch.answers = vch.answers + 1;
                    }
                }
                if (kind==2)&(slot.phase==1) {next_slot.phase=2;}
                next_slot.outcome=kind;
            }
            changed_root=indexed::update(own_root,own_count,event,obligation_hash(event,slot,slot.phase),
                obligation_hash(event,next_slot,next_slot.phase),own_map.leaf,own_map.index,own_map.path);
            if self_punish {assert(field(settlement_marker)==hash([event,kind as Field]));}
        } else {
            let next_phase = if action == 2 { 2 } else if action == 4 { 4 } else if action == 5 { 5 } else { 3 };
            assert(slot.phase == if (action == 2) | (action == 4) { 1 } else if action == 5 { slot.phase } else { 2 });
            if action == 5 { assert((slot.phase == 2) | (slot.phase == 8)); }
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
                // Before protected release only; the permanent event tombstone prevents
                // refund/reset churn.
                reserved = old.reserved - amount as u128;
                assert(event == field(settlement_marker));
            } else if action == 5 {
                assert((slot.role == 0) & (now >= slot.expires_at));
                // The fixed wait refunds the bond regardless of whether a
                // Close receipt was delivered; the slot returns and the miss uses part of
                // the starter loan. Phase 8 (punished while held) settles the same way.
                reserved = old.reserved - amount as u128;
                standing = unanswered(standing, standing_policy);
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
                // Incoming Close and a confirmed Answer free the slot. An Answer is a clean
                // conversation in either role; a Close earns nothing and costs nothing.
                reserved = old.reserved - amount as u128;
                if resolution.kind == 1 {
                    standing = if slot.role == 0 { answer_received(standing, standing_policy, joined) }
                        else { answer_given(standing, standing_policy) };
                    if aux.count {
                        pair_root = count_answer(community, slot, peer_enrollment, old.created_at, vch.sponsor,
                            pair_root, pair_count, pair, pair_map);
                        vch.answers = vch.answers + 1;
                    }
                }
                assert(event == field(settlement_marker));
            }
        }
        assert((accepted<=SAFE)&(declined<=SAFE)&(punished_count<=SAFE));
        check_state(standing, joined);
        let successor = Opening { reserved, accepted, declined, punished: punished_count, inbox, authorization: authorized,
            outgoing_root: if slot.role == 0 { changed_root } else { old.outgoing_root },
            outgoing_count: if slot.role == 0 { changed_count } else { old.outgoing_count },
            incoming_root: if slot.role == 1 { changed_root } else { old.incoming_root },
            incoming_count: if slot.role == 1 { changed_count } else { old.incoming_count },
            pair_root, pair_count, created_at: old.created_at, standing, voucher: vch, blind: new_blind };
        assert(state_hash(community, owner, state_policy, registered_secret, next_version, ext, successor) == field(next_state));
    }
}

// Count one answered conversation toward the success proof: the peer is a distinct member
// whose enrollment began before this account joined, and is not the sponsor. The counted
// flag lives in the pair map (value 1 becomes 5), so one peer counts once.
fn count_answer(community: [u8; 32], slot: Obligation, peer: Enrollment, created_at: u64, sponsor: Field,
    pair_root: Field, pair_count: u64, pair: Field, witness: MapWitness) -> Field {
    assert(enrollment_leaf(community, slot.peer, peer) == slot.peer_authority);
    assert(peer.start < created_at);
    assert(member_tag(community, slot.peer) != sponsor);
    indexed::update(pair_root, pair_count, pair, 1, 5, witness.leaf, witness.index, witness.path)
}
