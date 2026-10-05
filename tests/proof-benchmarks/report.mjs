// Benchmark evidence stays separate from the decision to adopt a candidate.
const requiredIds = ['relation', 'variant', 'backend', 'sourceId', 'circuitId',
  'witnessSetId', 'dependencyId', 'environmentId', 'runtimeId', 'blockId'];
const phases = ['witnessMs', 'proveMs', 'verifyMs'];
const memories = ['peakRssBytes', 'wasmHighWaterBytes'];
const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;

export function summarize(samples) {
  if (!Array.isArray(samples) || !samples.length || !samples.every(finite)) {
    throw new TypeError('Nonempty finite nonnegative samples required');
  }
  const sorted = [...samples].sort((a, b) => a - b);
  return { n: sorted.length, min: sorted[0], max: sorted.at(-1),
    p50: sorted[Math.ceil(sorted.length * 0.5) - 1], p95: sorted[Math.ceil(sorted.length * 0.95) - 1] };
}

function validate(row) {
  if (!row || requiredIds.some(key => typeof row[key] !== 'string' || !row[key].length)) {
    throw new TypeError('Missing benchmark identity');
  }
  if (!Number.isSafeInteger(row.threadsActual) || row.threadsActual < 1
    || typeof row.cold !== 'boolean' || row.selfVerified !== true
    || !Number.isSafeInteger(row.iteration) || row.iteration < 0
    || row.cold !== (row.iteration === 0)
    || !phases.every(key => finite(row[key]))
    || !Number.isSafeInteger(row.proofBytes) || row.proofBytes <= 0) {
    throw new TypeError('Invalid or unverified benchmark sample');
  }
  for (const key of memories) {
    if (row[key] !== null && (!Number.isSafeInteger(row[key]) || row[key] <= 0)) {
      throw new TypeError('Memory must be positive bytes or explicit null');
    }
  }
}

export function summarizeCases(rows) {
  if (!Array.isArray(rows)) throw new TypeError('Benchmark rows required');
  const groups = new Map();
  for (const row of rows) {
    validate(row); // Dropping invalid rows would bias the result.
    const key = JSON.stringify([...requiredIds.map(id => row[id]), row.threadsActual]);
    const group = groups.get(key) ?? { identity: Object.fromEntries(requiredIds.map(id => [id, row[id]])),
      threadsActual: row.threadsActual, samples: [], iterations: new Set() };
    if (group.iterations.has(row.iteration)) throw new Error('Duplicate benchmark iteration');
    group.iterations.add(row.iteration);
    group.samples.push(row);
    groups.set(key, group);
  }
  return [...groups.values()].map(group => {
    const cold = group.samples.filter(row => row.cold);
    const warm = group.samples.filter(row => !row.cold);
    const contiguous = [...group.iterations].sort((a, b) => a - b).every((value, index) => value === index);
    const timingsComplete = cold.length === 1 && warm.length >= 10 && contiguous;
    const memory = Object.fromEntries(memories.map(key => [key,
      group.samples.every(row => row[key] !== null) ? Math.max(...group.samples.map(row => row[key])) : null]));
    return { ...group.identity, threadsActual: group.threadsActual, nCold: cold.length, nWarm: warm.length,
      cold: cold[0] ?? null, timingsComplete,
      timings: Object.fromEntries(phases.map(key => [key, timingsComplete ? summarize(warm.map(row => row[key])) : null])),
      ...memory, proofBytes: summarize(group.samples.map(row => row.proofBytes)),
      adopted: false, adoptionReason: 'Pending independent correctness, memory and performance review' };
  });
}

const cell = value => String(value ?? 'pending').replaceAll('|', '\\|').replaceAll('\n', ' ');
export function markdownTable(cases) {
  const lines = [
    '| Relation | Variant | Environment / threads | Warm n | Witness p50/p95 ms | Prove p50/p95 ms | Verify p50/p95 ms | Peak RSS B | Wasm high-water B | Proof B (min–max) | Adopted |',
    '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|',
  ];
  for (const row of cases) {
    const timing = key => row.timings[key] ? `${row.timings[key].p50.toFixed(3)}/${row.timings[key].p95.toFixed(3)}` : 'pending';
    lines.push('| ' + [row.relation, row.variant, `${row.environmentId}; ${row.backend}; ${row.threadsActual}`,
      row.nWarm, ...phases.map(timing), row.peakRssBytes, row.wasmHighWaterBytes,
      `${row.proofBytes.min}–${row.proofBytes.max}`, 'no — pending review'].map(cell).join(' | ') + ' |');
  }
  return lines.join('\n') + '\n';
}
