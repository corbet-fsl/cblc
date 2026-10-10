import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const workers = [
  {name: 'accounting', maximum: 3 * 1024 * 1024},
  {name: 'extensions', maximum: 9 * 1024 * 1024},
];

for (const {name, maximum} of workers) {
  const script = fileURLToPath(new URL(`../../runtime/${name}/node-verifier.mjs`, import.meta.url));
  function refuses(args: string[], input: string | Uint8Array = '{}') {
    const result = spawnSync(process.execPath, [script, ...args], {
      input, encoding: 'utf8', maxBuffer: 16 * 1024, timeout: 10_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 1);
    // A module-load failure cannot pass: Node would write its diagnostic here.
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  }

  test(`${name} worker rejects invalid invocation and malformed public input without a verdict`, () => {
    refuses([]);
    refuses(['relative.json', 'extra-argument']);
    for (const input of ['', '{', new Uint8Array([0xff]), '{"proof":"PRIVATE_SENTINEL"']) {
      refuses(['relative.json'], input);
    }
  });

  test(`${name} worker rejects untrusted configuration and artifact files without diagnostics`, async t => {
    const directory = await mkdtemp(join(tmpdir(), `cblc-${name}-worker-`));
    t.after(() => rm(directory, {recursive: true, force: true}));
    const config = join(directory, 'config.json');
    refuses(['relative.json']);
    refuses([join(directory, 'missing.json')]);
    refuses([directory]);
    for (const bytes of ['{', 'null', new Uint8Array([0xff]), ' '.repeat(65537),
      JSON.stringify({directory: 'relative', manifestSha256: '0'.repeat(64)})]) {
      await writeFile(config, bytes);
      refuses([config]);
    }
    const manifest = Buffer.from('{}');
    await writeFile(join(directory, 'manifest.json'), manifest);
    for (const pin of ['0'.repeat(64), createHash('sha256').update(manifest).digest('hex')]) {
      await writeFile(config, JSON.stringify({directory, manifestSha256: pin}));
      refuses([config]); // Wrong digest, then an authenticated unsupported suite.
    }
    await writeFile(join(directory, 'manifest.json'), ' '.repeat(1024 * 1024 + 1));
    refuses([config]);
  });

  test(`${name} worker rejects oversized input before EOF with an empty bounded error channel`, async () => {
    const child = spawn(process.execPath, [script, 'relative.json'], {stdio: ['pipe', 'pipe', 'pipe']});
    let output = '', diagnostics = '', pipeError: Error | undefined;
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output.length > 16384) child.kill('SIGKILL');
    });
    child.stderr.on('data', chunk => {
      diagnostics += chunk;
      if (diagnostics.length > 16384) child.kill('SIGKILL');
    });
    child.stdin.on('error', error => { pipeError = error; });
    try {
      const completion = new Promise<{code: number | null, signal: string | null}>((resolve, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => resolve({code, signal}));
      });
      // Keep stdin open. A worker waiting for EOF instead of enforcing its bound
      // is killed by the deadline and fails the assertion below.
      child.stdin.write(Buffer.alloc(maximum + 1, 0x20));
      const result = await completion;
      assert.equal(result.signal, null);
      assert.equal(result.code, 1);
      assert.equal(child.stdin.writableEnded, false);
      assert.equal(output, '');
      assert.equal(diagnostics, '');
      if (pipeError) assert.equal((pipeError as NodeJS.ErrnoException).code, 'EPIPE');
    } finally {
      clearTimeout(timer);
      child.stdin.destroy();
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
  });
}
