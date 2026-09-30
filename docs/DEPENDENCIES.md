# Reviewed transport exceptions

The locked libSQL 0.9.30 client still uses hyper 0.14 and rustls 0.22.
These advisory exceptions preserve the same reviewed transport policy as the
other consumers of crlt; they do not repair the dependencies. CI checks the
exact dependency versions and connector source before accepting an exception.
All other advisories continue to fail. Reassess these exceptions before release.

- RUSTSEC-2026-0258 (h2 0.3.27): the built-in connector enables HTTP/1 only.
- RUSTSEC-2026-0049 and RUSTSEC-2026-0104 (webpki 0.102.8): the built-in connector
  configures no CRLs. This assessment does not cover custom CRL configurations.
- RUSTSEC-2025-0134 (rustls-pemfile 2.2.0): unmaintained native-root parser.
  Replace through an upstream transport upgrade.
- RUSTSEC-2026-0098 and RUSTSEC-2026-0099 (webpki 0.102.8): **open remote TLS
  name-constraint risks** if a trusted CA misissues a certificate. The maintained
  webpki 0.103 fixes are outside libSQL's current compatibility range. Local-file
  storage is unaffected. A trusted endpoint does not eliminate the CA risk.

A green audit means this explicit exception policy passed. It does not mean the
graph is advisory-free or that remote TLS is cleared for production. No local
cryptographic or TLS fork, ignored audit job, or broad crate exemption is used.
