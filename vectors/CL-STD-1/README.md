# CL-STD-1 known-answer test vectors

`kat.json` contains the public known-answer test (KAT) vectors for the CL-STD-1 standard
suite. Every key in this directory — including any private/secret scalar — is a **test vector
published deliberately** so independent implementations can verify byte-for-byte
compatibility. These values are never used as production keys, and production deployments
generate their own key material through the documented ceremonies. See
[SECURITY.md](../../SECURITY.md) for the residual-risk statement.
