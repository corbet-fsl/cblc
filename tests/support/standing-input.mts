// Policy input of the Noir standing relations, shared by the probes.
const s=(n:number|bigint)=>String(n);
// The reference community's voucher parameters (the settings catalogue's values, czkp
// feature `reference`); the oracle predates them.
export const VOUCHER_DEFAULTS={v_slope:['6554','131072','1638400'],v_min:['1','50','500'],v_max:['3','100','1000'],
  v_days:'30',v_k:'3',v_max_punished:'1',v_brake_cap:'1',v_reward_cap:'2'};
export const policyInput=(set:any)=>{const p=set.params;return {
  c0:s(p.c0),h_a:s(p.h_A),h_g:s(p.h_G),n_half:s(p.n_half),n_c:s(p.n_c),e_q:s(p.e_q),r_max:s(p.r_max),r_age:s(p.r_age),
  c_max_q:s(p.c_max_q),c_vet:s(p.c_vet),age_vet:s(p.age_vet),boost_q:s(p.boost_q),boost_days:s(p.boost_days),
  slope_q:s(p.slope_q),mid_q:s(p.mid_q),kappa_q:s(p.kappa_q),loan_use_q:s(p.loan_use_q),factor:s(set.factor),...VOUCHER_DEFAULTS,
  trust:set.trust.map(s),g_table:set.g_table.map(s),a_table:set.a_table.map(s)};};
