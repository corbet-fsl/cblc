import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactFetcher, DEFAULT_LIMITS } from '../../runtime/accounting/artifacts.mjs';

test('public artifact downloads reject invalid limits before invoking transport', async () => {
  let calls = 0;
  const read = artifactFetcher('https://artifacts.invalid/release/', async () => {
    calls++;
    return new Response(new Uint8Array([1]));
  });
  for (const maximum of [undefined, null, NaN, Infinity, -Infinity, 0, -1, 1.5, '4',
    Number.MAX_SAFE_INTEGER + 1, DEFAULT_LIMITS.maxArtifactBytes + 1]) {
    await assert.rejects(read('vk.bin', maximum), /Artifact download limit/);
  }
  await assert.rejects(read('../secret', 4), /Artifact name/);
  assert.equal(calls, 0);
});

test('artifact downloads preserve exact chunked bytes and fixed transport policy', async () => {
  let calls = 0;
  const read = artifactFetcher('https://artifacts.invalid/release/', async (url: URL, options: RequestInit) => {
    calls++;
    assert.equal(url.href, 'https://artifacts.invalid/release/setup/g1.dat');
    assert.deepEqual(options, { redirect: 'error', credentials: 'omit' });
    return new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3]));
        controller.close();
      },
    }));
  });
  assert.deepEqual(await read('setup/g1.dat', 3), new Uint8Array([1, 2, 3]));
  assert.equal(calls, 1);
  const empty = artifactFetcher('https://artifacts.invalid/', async () => new Response(new Uint8Array()));
  assert.deepEqual(await empty('vk.bin', DEFAULT_LIMITS.maxArtifactBytes), new Uint8Array());
});

test('artifact streams cancel immediately when accumulated bytes exceed the limit', async () => {
  let pulls = 0, cancellations = 0;
  const body = new ReadableStream({
    pull(controller) { pulls++; controller.enqueue(new Uint8Array([1, 2])); },
    cancel() { cancellations++; },
  }, { highWaterMark: 0 });
  const read = artifactFetcher('https://artifacts.invalid/', async () => new Response(body));
  await assert.rejects(read('circuit.json', 3), /Artifact download bound/);
  assert.equal(pulls, 2);
  assert.equal(cancellations, 1);
});

test('artifact transport and stream failures cannot return a partial artifact', async () => {
  for (const response of [new Response('unavailable', { status: 503 }), new Response(null)]) {
    const read = artifactFetcher('https://artifacts.invalid/', async () => response);
    await assert.rejects(read('vk.bin', 10), /Artifact fetch failed/);
  }
  const unavailable = new Error('inert transport failure');
  const failed = artifactFetcher('https://artifacts.invalid/', async () => { throw unavailable; });
  await assert.rejects(failed('vk.bin', 10), error => error === unavailable);
  const interrupted = new Error('inert stream failure');
  let chunks = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (chunks++ === 0) controller.enqueue(new Uint8Array([1]));
      else controller.error(interrupted);
    },
  }, { highWaterMark: 0 });
  const partial = artifactFetcher('https://artifacts.invalid/', async () => new Response(stream));
  await assert.rejects(partial('vk.bin', 10), error => error === interrupted);
  assert.equal(chunks, 2);
});
