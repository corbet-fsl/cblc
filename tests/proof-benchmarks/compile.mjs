// B0 public-source compilation. Run inside an authenticated CI source closure.
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { readFile, writeFile, mkdir, stat, readdir } from 'node:fs/promises';
import { resolve, isAbsolute, relative } from 'node:path';
import { createHash } from 'node:crypto';

if (!process.env.CI) throw new Error('CI only');
const [planPath, output] = process.argv.slice(2);
if (process.argv.length !== 4 || !isAbsolute(planPath ?? '') || !isAbsolute(output ?? '')) {
  throw new Error('Usage: compile.mjs ABSOLUTE_SOURCE_PLAN_JSON ABSOLUTE_OUTPUT');
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const planBytes = await readFile(planPath);
if (planBytes.length > 65536) throw new Error('Source plan byte bound');
const plan = JSON.parse(planBytes);
const kinds = ['update', 'record_epoch', 'wave', 'outcome', 'deposit', 'record'];
if (plan.schema !== 1 || !Array.isArray(plan.sources) || !plan.sources.length || plan.sources.length > 16) {
  throw new Error('Source plan schema');
}
await mkdir(output, { recursive: true });
const receipt = { schema: 1, benchmark: 'B0', sourcePlanSha256: sha(planBytes), node: process.version,
  compiler: JSON.parse(await readFile(new URL('../../node_modules/@noir-lang/noir_wasm/package.json', import.meta.url))).version,
  dependencyLockSha256: sha(await readFile(new URL('../../experiments/private-accounting/package-lock.json', import.meta.url))),
  provingPerformed: false, sources: [] };
const profilePlan = { schema: 1, bundles: [] };
const names = new Set();
async function fingerprint(root) {
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      if (entry.name === 'target') continue;
      const path = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Circuit source symlink refused');
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push([relative(root, path), sha(await readFile(path))]);
      else throw new Error('Unsupported circuit source entry');
    }
  }
  await visit(root);
  return sha(JSON.stringify(files));
}
try {
  for (const source of plan.sources) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(source.variant ?? '') || names.has(source.variant)
      || !isAbsolute(source.root ?? '') || !/^[a-f0-9]{40}$/.test(source.sourceCommit ?? '')
      || !/^[a-f0-9]{64}$/.test(source.sourceArchiveSha256 ?? '')
      || !Array.isArray(source.absent) || source.absent.some(kind => !kinds.includes(kind))) {
      throw new Error('Source identity');
    }
    names.add(source.variant);
    const directory = resolve(source.root, 'circuits/extensions');
    const sourceFingerprint = await fingerprint(directory);
    const circuits = {};
    const started = performance.now();
    for (const kind of kinds) {
      let present;
      try { present = (await stat(resolve(directory, kind, 'Nargo.toml'))).isFile(); }
      catch (error) { if (error.code !== 'ENOENT') throw error; present = false; }
      if (source.absent.includes(kind)) {
        if (present) throw new Error(`Source unexpectedly contains ${kind}`);
        continue;
      }
      if (!present) throw new Error(`Source unexpectedly lacks ${kind}`);
      const result = await compile(createFileManager(resolve(directory, kind)));
      if (!result.program?.bytecode) throw new Error('Missing compiled program');
      circuits[kind] = result.program;
    }
    if (await fingerprint(directory) !== sourceFingerprint) throw new Error('Circuit source changed while compiling');
    const path = resolve(output, `${source.variant}-circuits.json`);
    const bytes = Buffer.from(JSON.stringify(circuits));
    await writeFile(path, bytes, { flag: 'wx' });
    const identity = { variant: source.variant, sourceCommit: source.sourceCommit,
      sourceArchiveSha256: source.sourceArchiveSha256, dependencyLockSha256: receipt.dependencyLockSha256,
      absent: source.absent };
    profilePlan.bundles.push({ ...identity, path, sha256: sha(bytes) });
    receipt.sources.push({ ...identity, circuitSourceFingerprint: sourceFingerprint,
      bundleSha256: sha(bytes), compileMs: performance.now() - started, artifactBytes: bytes.length });
  }
  await writeFile(resolve(output, 'profile-plan.json'), JSON.stringify(profilePlan, null, 2) + '\n', { flag: 'wx' });
  receipt.ok = true;
} catch (error) {
  receipt.ok = false;
  receipt.error = String(error.message);
  process.exitCode = 1;
} finally {
  await writeFile(resolve(output, 'compile-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
}
