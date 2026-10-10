// Fixture suite metadata must describe the SDK that really constructs the proof.
import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname, join} from 'node:path';

const require = createRequire(import.meta.url);
const suite = JSON.parse(readFileSync(new URL('../runtime/accounting/package.json', import.meta.url), 'utf8'));
for (const name of ['@aztec/bb.js', '@noir-lang/noir_js']) {
  let directory = dirname(require.resolve(name));
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
