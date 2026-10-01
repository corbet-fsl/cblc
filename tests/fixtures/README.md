# Public metadata fixture

extension-manifest.json comes from the real native/Wasm extension proof suite at
cblc43a241855f04fa5c41375ed3fbddc7c15e7ad55b, run36918786696. It contains only
public circuit/key/setup digests and the fictional fixture issuer's public key.
No member opening, witness or production authority is present.

The unit cases test bounded parsing and binding of these original bytes. The
separate extension_adversaries executable must additionally activate a fresh
ledger with the actual current public proof, produce its canonical document,
sign/cache it with a separately configured fixture ring, and verify a real
record proof using the recovered authenticated material. That execution is
required in ordinary and instrumented CI; metadata parsing is not proof success.

publication.json emitted into the CI artifact contains the exact signed owner
bytes and a configuredFixtureRing for independent vector reproduction. The ring
is a fixture expectation, never an authority accepted from a network response.
