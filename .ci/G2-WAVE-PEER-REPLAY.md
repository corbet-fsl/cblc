# Retained original Rust peer diagnostic

The current replay is bound to the first expected-valid public Wave refusal in
full-extension run 24. That call returned `verdict_decode`: the child exited
successfully, the input write and bounded output read completed, and the output
was not an exact verdict envelope. Its stdout was not retained. No mathematical
proof rejection or source-level cryptographic defect has been established.

The original Rust verifier is reused unchanged, SHA256
`d52a76228e6022ca77e39a075278cb16b4cb2ca62745dbef4e836eb5abb49e49`.
The five-file peer archive SHA256 is
`e3fedce2d9ebcd9130d6703084428aa3e7cbd5662c8a3985a7bbc40bb9d1e513`.
The original receipt binds compiler metadata, the unique root-package
`wave_verifier` example and its executable digest. CZKP remains the original
`645ed05c81d5c3305cfb6e860d346c6882472237`; no verifier code is changed.

The original public evidence archive SHA256 is
`21365a62b1053b1520d37dea5bc46f465030136ca5aab5044f564c5f24d4a484`.
All original public artifacts, including every setup prefix, match the failed
run's receipt. The included 32,047-byte worker request is a source-derived
comparison, SHA256
`1f4b674aace825cd1f5176452ba1dc9fde8f00e635ad5ec41b661ed6b77dcd5b`.
It includes the public certificate. It is not authority and is not substituted
for the actual Rust request. The signed payload is decoded only for this
comparison; the original Rust peer independently verifies its publication.

First run the retained Rust binary with the original absolute configuration and
policy paths and the resolved neutral worker entry point. Send the original
retained peer request plus one newline, hold stdin until the first reply, then
close it. Accept only its exact `{verified:true,diagnostic:null}` reply together
with successful process and pipe completion. Preserve failure as failure.

The second run adds only a job-local PATH/node capture wrapper. It forwards the
actual Rust request unchanged to the same worker. Capture bounded raw stdin,
stdout, stderr and exit details as private fixture artifacts. Compare actual
stdin against the source-derived frame and fail the replay on disagreement.
Do not print peer content to the workflow log: the console summary contains only
acceptance booleans, frame equality, output byte length and fixed structural
categories. Structural recognition of a JSON suffix never relaxes the original
Rust parser or makes a rejected result pass.

Each peer has a 195-second outer bound; capture has a 160-second lifetime and an
independent 170-second process-group timeout plus five-second kill grace, below
the original Rust 180-second verifier deadline. The entire selector retains its
600+15 child / 660 parent timeout and at most 2 jobs / 2 test threads / 16 GiB.
Source, evidence and installed package snapshots are checked before, between and
after execution. Current runtime and relevant environment are recorded; the
original complete environment was not captured.

Use the existing `g2-wave-peer-replay` selector through an authorized temporary
forge copy. It performs no Cargo invocation, Rust or circuit compilation, issuer
execution or proof generation. A replay success does not prove the original
full-extension fixture passed, nor does it qualify the browser or product.
