# Retained public Wave worker diagnostic

This CI-only selector diagnoses Crow144/11's `CryptoProvider` refusal. It is
based on CBLC1567f77 and CZKP6e8755f. It does not qualify an authenticated
presentation, run the Rust peer, compile a circuit, or generate another proof.
The separate epoch projection product candidates are excluded.

The fixed evidence archive SHA256 is
`31bd9e04a29c84744bed55949d0dd15b78a7d6630ce67f53b97da5260087a543`.
Its eight `public/` files and original receipt are byte-for-byte retained144/11
artifacts. The receipt SHA256 is
`589e2897a7ec816ef760d9de9d6a2490844c2c7694166d09e2727ddabcf2a632`.
The proof is the original14,656-byte public proof, SHA256
`e58d2242c77bdbeb8af3a87bbbf74bdc67685b8e4f15c089e629888ec5479f29`.
The signed COSE payload is extracted without granting it authority. Its raw
signed envelope remains in the retained public policy file. The worker request
is derived public data, not captured original worker stdin or authenticated
authority; the original fixture retained the peer request, not this inner frame.

The projection follows CWLTed86f90 `src/wave.rs::public_input` exactly. The
retained Cargo metadata's serde_json features do not include preserve_order;
Value object keys are therefore sorted. CZKP6e8755f `src/process.rs` serializes
Request fields as statement/proof/proofScope and ProofScope as
circuitDigest/verifyingKeyDigest. The resulting31,795-byte JSON has no newline,
SHA256 `a10f007a5595e3286a1aa639e884bc0da05abbdde581751be045fd1baf45fcb0`.
The adapter independently reconstructs and compares these bytes before use.

The first child repeats the original ProcessVerifier boundary configuration:

```
<first absolute PATH directory containing node>/node
  --max-old-space-size=4096 <original resolved node-verifier.mjs> <absolute config>
```

It inherits the current CI environment except NODE_OPTIONS and NODE_PATH, as
ProcessVerifier does. The thread settings and BB_BINARY_PATH follow the original
fixture adapter. The original full environment was not retained; the receipt
records relevant current values and actual Node/worker identities. The cwd is
the physical source root. Only config.directory changes to the new job-local
public artifact directory; the original config stays immutable. Stdin closes
after the exact JSON bytes, stderr goes to null, stdout is bounded to4097 bytes,
the deadline is180 seconds, and success requires exit0 plus the exact original
true verdict/scope within4096 bytes. Spawn/write/read/timeout/exit/raw stdout
are retained in original-worker-process.json before any second verifier call.

A separate bounded child imports the same worker's exported verify function
and reports its public exception name/message. It uses the same request/config
and a180-second deadline. It cannot replace a failed first boundary result.
Archive-derived source/evidence guards and an npm backend/Node byte snapshot run
before execution, between the two children, and at exit. The job retains a
failure receipt even if only the second diagnostic succeeds. No private state,
witness, issuer action, original acceptance assertion or verifier code changes.

Run only as `g2-wave-worker-replay`, with600 seconds plus15 seconds kill grace,
CI_TIMEOUT660,2 jobs/2 threads/16GiB. The shell parent survives the bounded child
and performs final guards (30 seconds plus5 grace) and receipt hashing. Use the
same eight-consumer/thirteen-owner
closure; only the root CI adapter source changes. Serialize with the separate
product qualification job because ccid uses the same canonical target/source
area. No Cargo or wasm-pack command runs in this selector.
