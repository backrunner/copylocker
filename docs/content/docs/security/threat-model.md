---
title: Security & Threat Model
navTitle: Security & Threat Model
order: 31
description: The public security contract of CopyLocker — scope, residual risks, assets, attacker profiles, and how the main attacks fail.
---

# Security & Threat Model

This page is the public security contract. It follows
`.agents/02-architecture/threat-model.md` and the repository's
[SECURITY.md](https://github.com/backrunner/copylocker/blob/main/SECURITY.md).

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting
(**Security → Report a vulnerability**). Do not open a public issue. Include the affected
component and version, a reproduction or proof of concept, and the impact you believe is
achievable. Reports matching the residual-risk list below are expected limitations, not bugs —
but we still want to hear about practical exploitation costs that are lower than the model
assumes. P0 vulnerabilities target a patch within 72 hours, with 90-day coordinated disclosure
(NFR-SEC-014).

## Scope: what CopyLocker is for

CopyLocker is a licensing and anti-tamper toolkit. Its security goal is to make unauthorized use
**expensive and non-reusable**, not impossible. The cryptography (hybrid post-quantum signatures,
X-Wing KEM, AEAD, domain-separated KDFs) is designed to be real; the client-side hardening
(symbol randomization, integrity manifests, two-stage key derivation) is obfuscation and
engineering inseparability, and is documented as such.

## Residual risks

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

## Assets and attacker profiles

| ID | Asset | Impact if compromised |
|---|---|---|
| A1 | Root private key | Total: arbitrary credential forgery; requires bricking all clients and a new root |
| A2 | Epoch private key | Credential forgery until the epoch is revoked (≤ 90-day window) |
| A3 | CredentialSecret (per device) | That device's credential can be copied (if fingerprint binding is bypassed) |
| A4 | Feature keys / sealed-asset plaintext | Protected features extracted permanently (for that version) |
| A5 | Vendor fingerprint salt | Offline fingerprint recomputation; forgery/correlation aid |
| A6 | Admin token | Arbitrary license issuance/revocation within scope |
| A7 | License database | Customer list exposure; enumerable valid keys |
| A8 | Private suite source | Higher crack reusability — but **not** forgery (NFR-SEC-001) |
| A9 | Client availability | Mistaken revocation / server failure locking out legitimate users → reputational loss |

Attackers modeled: **T1** casual users with ready-made patches · **T2** skilled reversers
(IDA/Ghidra/Frida/DevTools, Rust and WASM) · **T3** keygen authors · **T4** malicious insiders
with CI/Cloudflare/repo access · **T5** network attackers (MITM, DNS) · **T6** service abusers
(bots, DoS, seat exhaustion) · **T7** supply-chain attackers · **T8** future CRQC adversaries.

## How the main attacks fail

The full STRIDE tables and attack tree live in the threat-model document. The load-bearing
mechanisms:

- **Forged license server** (T5): application-layer signatures on top of TLS, pinned Root public
  keys, and nonce challenges. **TLS carries no security semantics in this design.**
- **Patching out verification** (T2/T3): productive verification (ADR-0004) — skipping the check
  means never deriving the feature key, so sealed assets stay encrypted. Effective only at
  [L2+](/docs/guide/protection-levels); the docs push L2 as the default for exactly this reason.
- **Stubbed WASM / tampered bundles** (T2): split key derivation (WASM output + build constants +
  the WASM's own digest + the guard's computed root `R`). One-sided replacement derives the wrong
  key; deleting the guard deletes `R` and fails closed under `requireIntegrityProof`.
- **Copied machine credentials** (T2): the credential is KEM-sealed to the device's private key
  with the fingerprint in the AAD — another machine cannot open it.
- **Clock manipulation** (T1/T2): a monotonic high-water mark, server time anchor, and rollback
  thresholds force online revalidation; Mode E uses a hard `not_after`.
- **Downgrade attacks** (T2/T3): `security_floor` is monotonic; clients persist the maximum and
  reject lower-floor credentials.
- **Cross-version crack reuse** (T2/T3): every release is a distinct variant (encoding masks,
  FK info, binders, offline parameters all differ). `release mark-compromised` +
  `force_upgrade` recalls exactly one compromised version without touching other users.
- **Lying about `release_id`**: gets you the old variant's keys, which cannot open the new
  version's assets — the variant mechanism enforces version scope.
- **Repudiation**: the Issuer DO keeps a monotonic sequence and a hash-chained audit log,
  archived immutably through the Queue to R2.
- **Harvest-now-decrypt-later** (T8): the hybrid PQ KEM (X-Wing) protects sensitive fields today.

## Cryptographic agility

Algorithm agility is a design property (ADR-0001/ADR-0002). CL-STD-1 uses ML-DSA (44/65/87) in a
hybrid signature, X-Wing (ML-KEM-768 + X25519) key encapsulation, XChaCha20-Poly1305 AEAD, and
HKDF/SHA-2/BLAKE3. Known-answer vectors live in `vectors/CL-STD-1/`. The standard suite's
security is independent of any proprietary implementation secrecy (NFR-SEC-001: a full private
suite leak degrades the system to CL-STD-1 strength, never below it).

## Supply chain

- Dependencies are gated by `cargo-deny` (advisories, bans, licenses, sources) and
  `cargo audit --deny warnings` in CI; exact advisory exceptions with removal conditions are
  recorded in `.cargo/audit.toml`.
- GitHub Actions are pinned by commit SHA.
- Release artifacts are covered by Sigstore signing, SBOM, and npm provenance as part of the GA
  release engineering work (roadmap M8); until that lands, treat locally built artifacts as the
  only verified form.

## Supported versions

CopyLocker has not reached v1.0. Only the latest commit on the default branch receives security
fixes. The protocol compatibility promises (N and N−1) are documented in
`.agents/02-architecture/versioning-and-variants.md` and take effect at GA.

## Red-team gates (pre-GA)

GA requires passing RT-1 through RT-10, including: forged-validation MITM attempts, cross-machine
credential copies, stub-WASM replacement, single-chunk tampering, one-year clock rollback,
100 concurrent activations against a 3-seat license (exactly 3 succeed), malformed-CBOR floods
(no panic, no 500, no resource exhaustion), credential forgery with leaked private-suite source,
cross-version crack reuse with `security_floor` downgrade attempts, and `release_id` spoofing
against version caps. Status is tracked in `.agents/05-ops/testing-strategy.md`.
