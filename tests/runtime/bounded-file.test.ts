import test from 'node:test';
import assert from 'node:assert/strict';
import {appendFile, mkdtemp, open, rm, truncate, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {boundedFile} from '../../runtime/bounded-file.ts';

test('public artifact reads enforce exact bounds and reject non-files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cblc-artifact-'));
  const path = join(directory, 'public.bin');
  try {
    await writeFile(path, new Uint8Array([1, 2, 3]));
    assert.deepEqual(await boundedFile(path, 3), new Uint8Array([1, 2, 3]));
    await assert.rejects(boundedFile(path, 2), /Artifact file bound/);
    await assert.rejects(boundedFile(directory, 4), /Artifact file bound/);
    await assert.rejects(boundedFile(join(directory, 'missing'), 4), {code: 'ENOENT'});
    for (const bound of [-1, 0.5, NaN, Infinity, 128 * 1024 * 1024 + 1]) {
      await assert.rejects(boundedFile(path, bound), /Artifact file bound/);
    }
    await writeFile(path, new Uint8Array());
    assert.deepEqual(await boundedFile(path, 0), new Uint8Array());
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
});

test('growth and truncation after real fstat refuse without reading unbounded data', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cblc-artifact-race-'));
  const path = join(directory, 'public.bin');
  const handle = await open(path, 'w+');
  const prototype = Object.getPrototypeOf(handle);
  const originalStat = prototype.stat;
  const originalRead = prototype.read;
  await handle.close();
  let mutate: () => Promise<void>, readCapacity = 0;
  const openedHandles: typeof handle[] = [];
  // Instrument only the OS boundary: actual fstat, mutation, read and close run.
  // This test file has its own Node test process, so no other tests see the hooks.
  prototype.stat = async function (...args) {
    openedHandles.push(this);
    const result = await originalStat.apply(this, args);
    await mutate();
    return result;
  };
  prototype.read = async function (buffer, ...args) {
    readCapacity = Math.max(readCapacity, buffer.byteLength);
    return originalRead.call(this, buffer, ...args);
  };
  try {
    await writeFile(path, new Uint8Array([1, 2, 3]));
    mutate = () => appendFile(path, new Uint8Array(1024 * 1024));
    await assert.rejects(boundedFile(path, 3), /Artifact changed while reading/);
    assert.equal(readCapacity, 4);
    assert.equal(openedHandles[0].fd, -1);
    await writeFile(path, new Uint8Array([1, 2, 3]));
    mutate = () => truncate(path, 1);
    await assert.rejects(boundedFile(path, 3), /Artifact changed while reading/);
    assert.equal(readCapacity, 4);
    assert.equal(openedHandles[1].fd, -1);
  } finally {
    prototype.stat = originalStat;
    prototype.read = originalRead;
    await rm(directory, {recursive: true, force: true});
  }
});
