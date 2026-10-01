# Dependency security

Storage uses the pinned crlt facade. Its remote transport uses maintained
reqwest/rustls with the repaired certificate verifier; libSQL's old remote
connector is not enabled. No old libSQL TLS advisory exceptions remain.

CI rejects the legacy transport packages and runs cargo-deny against the exact
lockfile. Update dependency locks on the CI-only refresh workflow, review the
artifact, and commit it before consuming the revision downstream.
