// Fixture suite metadata must describe the SDK that really constructs the proof.
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, join} from 'node:path';

const require = createRequire(import.meta.url);
// Third-party dependencies are declared as semver ranges; exactness comes from the
// lockfile. The installed SDK must equal the version the suite lockfile resolved.
const lock = JSON.parse(readFileSync(new URL('../runtime/accounting/package-lock.json', import.meta.url), 'utf8'));
const suite = {dependencies: Object.fromEntries(['@aztec/bb.js', '@noir-lang/noir_js'].map(name => {
  const resolved = lock.packages?.[`node_modules/${name}`]?.version;
  assert.ok(resolved, `${name} missing from the suite lockfile`);
  return [name, resolved];
}))};
for (const origin of [import.meta.url,
  require.resolve('@corbet-labs/czkp/prove'),
  require.resolve('@corbet-labs/cwlt/extensions'),
  new URL('../runtime/accounting/package.json', import.meta.url)]) {
for (const name of ['@aztec/bb.js', '@noir-lang/noir_js']) {
  let directory = dirname(createRequire(origin).resolve(name));
  let found = false;
  for (;;) {
    const path = join(directory, 'package.json');
    if (existsSync(path)) {
      const metadata = JSON.parse(readFileSync(path, 'utf8'));
      if (metadata.name === name) {
        assert.equal(metadata.version, suite.dependencies[name], `${name} fixture suite drift`);
        console.log(`Fixture SDK ${name} ${metadata.version}`);
        found = true;
        break;
      }
    }
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  assert.ok(found, `Missing installed package identity: ${name}`);
}
}
