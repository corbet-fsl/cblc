// The reference community's standing parameters and the policy digest czkp and the Noir circuit agree on
// (czkp tests/standing.rs and tests/standing-probe.mts pin the same value).
export const STANDING = {c0:3,hA:14,hG:14,nHalf:25,nC:60,eQ:16384,rMax:40,rAge:2,cMaxQ:52428,cVet:30,ageVet:60,
  boostQ:65536,boostDays:30,slopeQ:262144,midQ:49152,kappaQ:131072,loanUseQ:16384,
  voucher:{slopeQ:[6554,131072,1638400],min:[1,50,500],max:[3,100,1000],days:30,k:3,maxPunished:1,brakeCap:1,rewardCap:2}};
export const STANDING_DIGEST=Array.from(Buffer.from('13869f92e82373e15e5b9bbaf09bb0d2f4a71e7af912d20c68ae8ceb98710231','hex'));
// The derived tables for the default parameters, from the czkp golden vectors, in the
// circuit's private input shape (used where no wallet planner runs, e.g. artifact builds).
import {readFileSync} from 'node:fs';
import {VOUCHER_DEFAULTS} from '../support/standing-input.mts';
const set=JSON.parse(readFileSync(new URL('../vectors/standing/golden.json',import.meta.url),'utf8')).sets.default;
const p=set.params;
export const STANDING_TABLES={c0:p.c0,h_a:p.h_A,h_g:p.h_G,n_half:p.n_half,n_c:p.n_c,e_q:p.e_q,r_max:p.r_max,r_age:p.r_age,
  c_max_q:p.c_max_q,c_vet:p.c_vet,age_vet:p.age_vet,boost_q:p.boost_q,boost_days:p.boost_days,slope_q:p.slope_q,mid_q:p.mid_q,
  kappa_q:p.kappa_q,loan_use_q:p.loan_use_q,...VOUCHER_DEFAULTS,factor:set.factor,trust:set.trust,g_table:set.g_table,a_table:set.a_table};
