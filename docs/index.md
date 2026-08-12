---
layout: home

hero:
  name: CopyLocker
  text: Licensing that cannot be `if`-ed away
  tagline: Post-quantum hybrid credentials, sealed assets, and honest anti-tamper engineering for desktop and web software.
  actions:
    - theme: brand
      text: 5-Minute Quickstart
      link: /guide/quickstart
    - theme: alt
      text: Threat Model
      link: /security/threat-model

features:
  - title: Productive verification
    details: There is no "license valid?" boolean to patch out. Features stay cryptographically sealed until a valid credential derives their keys — skipping the check means skipping the content.
  - title: Post-quantum by default
    details: CL-STD-1 combines ML-DSA hybrid signatures, X-Wing (ML-KEM-768 + X25519) key encapsulation, and XChaCha20-Poly1305 AEAD with canonical CBOR and domain separation.
  - title: Honest security
    details: The residual risks are written down, in public, in the threat model. We raise the cost of cracking and destroy its reusability; we do not claim impossibility.
  - title: Self-hosted on Cloudflare
    details: "Your licensing server is a Worker you own: D1, Durable Objects, KV, R2, and Queues. CopyLocker the project never sees your customers' data."
---
