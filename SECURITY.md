# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities through GitHub's private vulnerability reporting for this
repository (`Security` → `Report a vulnerability`). Do not open a public issue for a
vulnerability report.

Include the affected component and version, a reproduction or proof of concept, and the impact
you believe is achievable. We triage reports against the threat model in
`.agents/02-architecture/threat-model.md`; reports that match the residual-risk list below are
expected limitations, not bugs, but we still want to hear about practical exploitation costs that
are lower than the model assumes.

## Scope

CopyLocker is a licensing and anti-tamper toolkit. Its security goal is to make unauthorized use
**expensive and non-reusable**, not impossible. The cryptography (hybrid post-quantum signatures,
X-Wing KEM, AEAD, domain-separated KDFs) is designed to be real; the client-side hardening
(symbol randomization, integrity manifests, two-stage key derivation) is obfuscation and
engineering inseparability, and is documented as such.

## Residual Risk Statement

The following is copied from the threat model (`.agents/02-architecture/threat-model.md` §6) and
is part of the honest security contract of this project:

1. **An attacker with physical control of a machine can eventually extract whatever that machine
   can decrypt.** We raise the cost and reduce reusability; we do not make extraction impossible.
2. **A legitimate buyer leaking decrypted assets** cannot be prevented technically; mitigations
   are per-user watermarking and version rotation.
3. **Fully offline operation combined with clock manipulation** can extend usage up to
   `not_after` in Mode O; deployments needing stronger guarantees should use Mode E.
4. **Browser-environment protection is inherently weaker than native.** The Web SDK raises the
   bar; it is not equivalent to the native SDKs. The ML-KEM private key is software-held on the
   web platform (wrapped by a non-extractable AES-GCM key), which is a known platform limitation.
5. **A private-suite leak** reduces the non-reusability of cracking effort but does not make
   credentials forgeable.
6. **The guard's runtime integrity checks can be removed**; their value comes from the check
   result participating in feature-key derivation, not from reporting.

## Cryptographic Agility and Suites

Algorithm agility is a design property (ADR-0001/ADR-0002). CL-STD-1 uses ML-DSA (44/65/87) in a
hybrid signature, X-Wing (ML-KEM-768 + X25519) key encapsulation, XChaCha20-Poly1305 AEAD, and
HKDF/SHA-2/BLAKE3. Known-answer vectors live in `vectors/CL-STD-1/`. The standard suite keeps its
security independent of any proprietary implementation secrecy.

## Supply Chain

- Dependencies are gated by `cargo-deny` (advisories, bans, licenses, sources) and
  `cargo audit --deny warnings` in CI; exact advisory exceptions with removal conditions are
  recorded in `.cargo/audit.toml`.
- GitHub Actions are pinned by commit SHA.
- Release artifacts are covered by Sigstore signing, SBOM, and npm provenance as part of the GA
  release engineering work (see `.agents/04-roadmap/roadmap.md` M8); until that lands, treat
  locally built artifacts as the only verified form.

## Supported Versions

CopyLocker has not reached v1.0. Only the latest commit on the default branch receives security
fixes. The protocol compatibility promises (N and N-1) are documented in
`.agents/02-architecture/versioning-and-variants.md` and take effect at GA.
