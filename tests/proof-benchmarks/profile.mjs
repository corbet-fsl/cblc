// B0: serial profiles of public compiled bundles. Never loads a witness or SRS.
// Source archives are authenticated by the CI consumer before compilation.
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.CI) throw new Error('CI only');
const [planPath, output] = process.argv.slice(2);
if (process.argv.length !== 4 || !isAbsolute(planPath ?? '') || !isAbsolute(output ?? '')) {
  throw new Error('Usage: profile.mjs ABSOLUTE_PLAN_JSON ABSOLUTE_OUTPUT');
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = /^[a-f0-9]{64}$/;
const revision = /^[a-f0-9]{40}$/;
const kinds = ['update', 'record_epoch', 'wave', 'outcome', 'deposit', 'record'];
const planBytes = await readFile(planPath);
if (planBytes.length > 65536) throw new Error('Plan byte bound');
const plan = JSON.parse(planBytes);
if (plan.schema !== 1 || !Array.isArray(plan.bundles) || plan.bundles.length < 1 || plan.bundles.length > 16) {
  throw new Error('Profile plan schema');
}
await mkdir(output, { recursive: true });
const evidence = { schema: 1, benchmark: 'B0', planSha256: sha(planBytes), node: process.version,
  provingPerformed: false, setupInitialized: false, witnessRead: false, adopted: false, rows: [] };
const names = new Set();
try {
  for (const bundle of plan.bundles) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(bundle.variant ?? '') || names.has(bundle.variant)
      || !revision.test(bundle.sourceCommit ?? '') || !digest.test(bundle.sourceArchiveSha256 ?? '')
      || !digest.test(bundle.dependencyLockSha256 ?? '')
      || !digest.test(bundle.sha256 ?? '') || !isAbsolute(bundle.path ?? '')
      || !Array.isArray(bundle.absent) || bundle.absent.some(kind => !kinds.includes(kind))) {
      throw new Error('Profile bundle identity');
    }
    names.add(bundle.variant);
    if ((await stat(bundle.path)).size > 128 * 1024 * 1024) throw new Error('Bundle byte bound');
    const bytes = await readFile(bundle.path);
    if (sha(bytes) !== bundle.sha256) throw new Error('Compiled bundle authentication');
    const circuits = JSON.parse(bytes);
    for (const relation of kinds) {
      const row = { variant: bundle.variant, sourceCommit: bundle.sourceCommit,
        sourceArchiveSha256: bundle.sourceArchiveSha256, dependencyLockSha256: bundle.dependencyLockSha256,
        bundleSha256: bundle.sha256, relation };
      if (!Object.hasOwn(circuits, relation)) {
        if (!bundle.absent.includes(relation)) throw new Error(`Unexpected missing relation: ${relation}`);
        evidence.rows.push({ ...row, status: 'absent-in-source', numGates: null, numGatesDyadic: null });
        continue;
      }
      if (bundle.absent.includes(relation)) throw new Error('Declared absent relation is present');
      const directory = resolve(output, bundle.variant, relation);
      await mkdir(directory, { recursive: true });
      const circuitBytes = Buffer.from(JSON.stringify(circuits[relation]));
      const circuitPath = resolve(directory, 'circuit.json');
      await writeFile(circuitPath, circuitBytes, { flag: 'wx' });
      const circuitSha256 = sha(circuitBytes);
      await new Promise((accept, reject) => {
        const child = spawn(process.execPath,
          [fileURLToPath(new URL('../../experiments/private-accounting/profile.mjs', import.meta.url))],
          { stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env,
            CIRCUIT_PATH: circuitPath, CIRCUIT_SHA256: circuitSha256, PROFILE_ARTIFACT_DIR: directory } });
        const timer = setTimeout(() => child.kill('SIGKILL'), 300000);
        child.once('error', error => { clearTimeout(timer); reject(error); });
        child.once('exit', (code, signal) => {
          clearTimeout(timer);
          if (code !== 0) reject(new Error(`Profile failed: ${bundle.variant}/${relation} (${code ?? signal})`));
          else accept();
        });
      });
      const profile = JSON.parse(await readFile(resolve(directory, 'profile-evidence.json')));
      if (!profile.ok || profile.expectedHash !== circuitSha256
        || profile.dependencyLockSha256 !== bundle.dependencyLockSha256) throw new Error('Profile receipt mismatch');
      evidence.rows.push({ ...row, status: 'profiled', circuitSha256, compiler: profile.compiler,
        backend: profile.backend, backendPackageSha256: profile.backendPackageSha256,
        numGates: profile.stats.numGates, numGatesDyadic: profile.stats.numGatesDyadic,
        byPrimitiveHint: profile.mapping.byPrimitiveHint, totalMinusAttributed: profile.mapping.totalMinusAttributed });
      await writeFile(resolve(output, 'B0.json'), JSON.stringify(evidence, null, 2) + '\n');
    }
  }
  evidence.ok = true;
} catch (error) {
  evidence.ok = false;
  evidence.error = String(error.message);
  process.exitCode = 1;
} finally {
  await writeFile(resolve(output, 'B0.json'), JSON.stringify(evidence, null, 2) + '\n');
}
