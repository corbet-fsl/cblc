// Public conformance outputs from fictional fixed inputs and maintained BB.
// No proof, accepted account, certificate, private opening or secret is retained.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { ExtensionWitness, extensionHashes } from '@corbet-labs/cwlt/extensions';
import {
  IndexedMap, checkpointFromVerified, policyDigest, statePolicyDigest,
} from '@corbet-labs/cwlt/hashes';
import { fieldBytes } from '@corbet-labs/czkp/primitives';
import { hex } from '@corbet-labs/czkp/encoding';
import { STANDING, STANDING_DIGEST, STANDING_TABLES } from '../standing-fixture.mts';

const bytes = (n: number) => new Uint8Array(32).fill(n);
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const encodeField = (n: bigint) => hex(fieldBytes(n));

// Register against the parent test's original bounded native worker. The parent
// retains its original single worker lifetime and destroys it after the suite.
export function registerNativeAccountVectors(hashApi: Parameters<typeof extensionHashes>[0]) {
  test('original BB emits public native account conformance vectors', async () => {
    const hashes = extensionHashes(hashApi);
    const community = new Uint8Array(createHash('sha256').update('community').digest());
    // Maintained Node P-256 projection; this is a fictional public fixture row,
    // not an issuer-verified delegation or an accepted enrollment.
    const key = createECDH('prime256v1');
    const privateKey = bytes(5);
    try { key.setPrivateKey(privateKey); } finally { privateKey.fill(0); }
    const publicKey = new Uint8Array(key.getPublicKey(undefined, 'uncompressed').subarray(1));
    const ownerSecret = bytes(7);
    try {
      const secretHash = await hashes.secretHash(community, ownerSecret);
      const entries = [{
        memberId: Buffer.from(bytes(3)).toString('base64url'),
        accountKey: hex(publicKey), secretHash: hex(secretHash),
        issuedAt: 1, expiresAt: 9000, delegationDigest: hex(bytes(4)),
      }];
      const enrollment = await checkpointFromVerified(community, entries, hashes);
      const policy = {
        initialCredit: 20, maximumAvailable: 100, outgoingReservation: 5,
        incomingReservation: 5, policyRevision: 1, policyValidFrom: 1,
        policyValidUntil: 10000, newcomerPeriod: 100, rateWindow: 100,
        newcomerAdmissions: 2, maximumAdmissions: 10, refillPeriod: 100,
        refillUnits: 2, abandonAfter: 200,
      };
      const extension = {
        revision: 1, publicRecordQuorum: 2, changeTokenCost: 1,
        depositDelaySeconds: 100, minimumDepositBatch: 2,
        standingPolicyDigest: STANDING_DIGEST,
      };
      const genesis = await ExtensionWitness.genesis({
        hashes, community, policy, extension, standing: STANDING, policyTables: STANDING_TABLES, checkpoint: enrollment,
        ownerIndex: 0, ownerSecret, now: 101,
      });
      // Recompute the original private state transcript with a fixed fictional
      // blind. No production constructor, random source or witness is altered.
      const originalBlind = genesis.next.opening.blind;
      const fixedBlind = bytes(6);
      let genesisCommitment: bigint;
      try {
        genesis.next.opening.blind = fixedBlind;
        genesisCommitment = await genesis.next.commit(genesis.next.opening, 0n);
      } finally {
        fixedBlind.fill(0);
        originalBlind.fill(0);
      }
      assert.equal(genesis.next.opening.createdAt, 200n);
      assert.equal(enrollment.entries[0].path.length, 32);
      const empty = await IndexedMap.create(hashes);
      const first = await empty.insert(11n, 22n);
      const second = await first.next.insert(5n, 33n);
      const updated = await second.next.update(11n, 44n);
      assert.equal(empty.count, 1n);
      assert.equal(updated.next.count, 3n);
      assert.equal(first.witness.append_path.length, 32);
      // Only public commitments and paths of this fully public map fixture are
      // emitted. Never serialize genesis.input/opening/ownerSecret or a proof.
      const vectors = {
        community: hex(community), accountPublicKey: hex(publicKey),
        registeredSecretCommitment: hex(secretHash),
        enrollmentLeaf: encodeField(enrollment.entries[0].leaf),
        enrollmentRoot: encodeField(enrollment.root),
        enrollmentPath: enrollment.entries[0].path.map(encodeField),
        policyDigest: hex(await policyDigest(community, policy)),
        statePolicyDigest: hex(await statePolicyDigest(community, policy)),
        extensionDigest: encodeField(await hashes.extension(extension)),
        emptyMapRoot: encodeField(empty.root),
        firstMapRoot: encodeField(first.next.root),
        firstPredecessorPath: first.witness.path.map(encodeField),
        firstAppendPath: first.witness.append_path.map(encodeField),
        secondMapRoot: encodeField(second.next.root),
        updatedMapRoot: encodeField(updated.next.root),
        genesisState30: encodeField(genesisCommitment),
      };
      for (const [name, value] of Object.entries(vectors)) {
        for (const item of Array.isArray(value) ? value : [value]) {
          assert.match(item, name === 'accountPublicKey' ? /^[0-9a-f]{128}$/ : /^[0-9a-f]{64}$/);
        }
      }
      if (process.env.ARTIFACT_ROOT) {
        const commit = process.env.CI_COMMIT_SHA;
        assert.match(commit ?? '', /^[0-9a-f]{40}$/, 'retention requires actual source identity');
        const lock = await readFile('package-lock.json');
        const sdkBytes = await readFile('.ci/native-sdk.json');
        const sdk = JSON.parse(sdkBytes.toString('utf8'));
        assert.match(sdk.version, /^\d+\.\d+\.\d+$/);
        assert.match(sdk.sha256, /^[0-9a-f]{64}$/);
        const sources = [
          'runtime/accounting/hashes.mjs',
          'tests/holder/test/native-account-vectors.test.ts',
          'node_modules/@corbet-labs/cwlt/runtime/account.mjs',
          'node_modules/@corbet-labs/cwlt/runtime/extensions.mjs',
          'node_modules/@corbet-labs/cwlt/runtime/hashes.mjs',
        ];
        const sourceDigests = Object.fromEntries(await Promise.all(
          sources.map(async path => [path, digest(await readFile(path))]),
        ));
        const bb = JSON.parse((await readFile('node_modules/@aztec/bb.js/package.json')).toString('utf8'));
        assert.equal(bb.version, '5.2.1');
        const output = JSON.stringify({
          schema: 'cwlt.native-account-vectors.v1',
          producer: { commit, packageLockSha256: digest(lock), bbPackageVersion: bb.version,
            configuredCblcNativeSdkDeclaration: sdk,
            configuredCblcNativeSdkDeclarationSha256: digest(sdkBytes), sourceDigests },
          vectors,
        }, null, 2) + '\n';
        assert(Buffer.byteLength(output) <= 16384);
        const path = resolve(process.env.ARTIFACT_ROOT, `native-account-vectors-${commit}.json`);
        try { await writeFile(path, output, { flag: 'wx', mode: 0o600 }); }
        catch (error) {
          if (!(error instanceof Error) || !('code' in error) || error.code !== 'EEXIST') throw error;
          assert.equal(await readFile(path, 'utf8'), output, 'retained producer output must be identical');
        }
      }
    } finally { ownerSecret.fill(0); }
  });
}
