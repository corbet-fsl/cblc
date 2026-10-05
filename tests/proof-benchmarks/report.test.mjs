// Artificial reporting fixtures only; these values are never performance evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { summarize, summarizeCases, markdownTable } from './report.mjs';

const fixture = (iteration, overrides = {}) => ({
  relation: 'fixture', variant: 'baseline', backend: 'fixture-backend',
  sourceId: 'fictional-source', circuitId: 'fictional-circuit', witnessSetId: 'fictional-set',
  dependencyId: 'fictional-lock', environmentId: 'fictional-environment', runtimeId: 'fictional-runtime',
  blockId: 'fictional-block', threadsActual: 1, iteration, cold: iteration === 0, selfVerified: true,
  witnessMs: iteration + 1, proveMs: iteration + 10, verifyMs: 1,
  peakRssBytes: 1000, wasmHighWaterBytes: null, proofBytes: 100, ...overrides,
});
const complete = () => Array.from({ length: 11 }, (_, i) => fixture(i));

test('nearest rank includes slow tail and does not mutate samples', () => {
  const samples = [50, 10, 40, 20, 30];
  assert.deepEqual(summarize(samples), { n: 5, min: 10, max: 50, p50: 30, p95: 50 });
  assert.deepEqual(samples, [50, 10, 40, 20, 30]);
  for (const invalid of [[], [NaN], [Infinity], [-1], ['1']]) assert.throws(() => summarize(invalid));
});
test('cold timing is separate but cold peak memory counts', () => {
  const rows = complete();
  rows[0] = fixture(0, { proveMs: 999, peakRssBytes: 9000 });
  const [report] = summarizeCases(rows);
  assert.equal(report.timings.proveMs.p50, 15);
  assert.equal(report.timings.proveMs.p95, 20);
  assert.equal(report.cold.proveMs, 999);
  assert.equal(report.peakRssBytes, 9000);
  assert.equal(report.wasmHighWaterBytes, null);
  assert.equal(report.adopted, false);
  assert.match(markdownTable([report]), /no — pending review/);
});
test('missing warm samples, cold sample or memory do not qualify', () => {
  for (const rows of [complete().slice(0, 10), complete().slice(1), complete().filter(row => row.iteration !== 5)]) {
    const [report] = summarizeCases(rows);
    assert.equal(report.timingsComplete, false);
    assert.equal(report.timings.proveMs, null);
  }
  const rows = complete(); rows[3].peakRssBytes = null;
  assert.equal(summarizeCases(rows)[0].peakRssBytes, null);
});
test('invalid or repeated samples fail instead of being discarded', () => {
  for (const change of [{ proveMs: NaN }, { circuitId: '' }, { peakRssBytes: undefined },
    { peakRssBytes: 0 }, { proofBytes: null }, { selfVerified: false }, { threadsActual: null }, { cold: true }]) {
    assert.throws(() => summarizeCases([fixture(1, change)]));
  }
  assert.throws(() => summarizeCases([fixture(1), fixture(1)]));
});
test('different source, runtime, witness, lock or block never pool', () => {
  for (const key of ['sourceId', 'circuitId', 'witnessSetId', 'dependencyId', 'environmentId', 'runtimeId', 'blockId']) {
    const reports = summarizeCases([...complete(), fixture(0, { [key]: 'different' })]);
    assert.equal(reports.length, 2);
    assert.equal(reports[1].timingsComplete, false);
  }
});
