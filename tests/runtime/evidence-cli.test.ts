import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

test('public evidence CLI rejects oversized or malformed bytes before starting a verifier', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'cblc-evidence-bound-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const evidence = join(directory, 'evidence.json');
  const script = fileURLToPath(new URL('../../runtime/accounting/real-proof-check.mjs', import.meta.url));
  function run(args: string[]) {
    const result = spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8', maxBuffer: 16 * 1024, timeout: 10_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    return result.stderr;
  }
  assert.match(run([]), /Trusted configuration and public browser evidence required/);
  const file = await open(evidence, 'w');
  try { await file.truncate(128 * 1024 * 1024 + 1); } finally { await file.close(); }
  const args = [join(directory, 'absent-config.json'), evidence];
  assert.match(run(args), /Artifact file bound/);
  await writeFile(evidence, new Uint8Array([0xff]));
  assert.match(run(args), /ERR_ENCODING_INVALID_ENCODED_DATA/);
  await writeFile(evidence, '{');
  assert.match(run(args), /SyntaxError/);
});
