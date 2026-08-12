---
doc: ropa-entry
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# RoPA Entry Template — GDPR Art. 30 Record of Processing Activities

> ⚠️ **Disclaimer (must appear verbatim at the top of every template)**
>
> All documents in this directory are **technical templates written by the engineering team**
> to reduce the Vendor's cost of drafting compliance documents.
> They are **not legal advice**, do not create a lawyer–client relationship, and do not
> guarantee compliance in any jurisdiction.
> Before use, the Vendor **must** have them reviewed and adapted by qualified legal counsel
> to their own business, data flows, and applicable law.
> The CopyLocker project accepts no liability for legal consequences arising from use of
> these templates.

**Status: DRAFT — must be reviewed by qualified legal counsel / the Vendor's DPO before
filing.**
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08). Row references (A1…F3) point at
that inventory.

**How to use.** One entry per processing purpose. Copy the entry blocks below into the
Vendor's Art. 30 record and replace `{{PLACEHOLDER}}`s. Delete entries for capabilities the
Vendor does not use (Mode E, T1).

---

## Entry 1 — License verification and anti-piracy (T0)

| Art. 30(1) field | Content |
|---|---|
| Controller | {{VENDOR_NAME}}, {{VENDOR_ADDRESS}}, {{DPO_CONTACT}} |
| Purpose | Verifying software licenses; seat management; preventing unauthorized copying; compatibility and version-distribution statistics |
| Categories of data subjects | End users of {{PRODUCT_NAME}} |
| Categories of personal data | Pseudonymous device identifiers (fingerprint digest B1, machine id B2, device keys B4); license identifiers (A1, A3); version/platform strings and activation path (B6, B9); server timestamps (B10); country code (B7); anomaly score (B8); Vendor-defined license metadata (A9 — potentially personal); optional raw device attributes if enabled (B3/B3a/B3b — personal, default off) |
| Recipients | Cloudflare, Inc. (processor, hosting only). No other recipients. The CopyLocker project receives no data. |
| Transfers to third countries | {{TRANSFER_MECHANISM}} [[LEGAL REVIEW: document Cloudflare transfer mechanism; note whether Jurisdictional Restrictions are configured]] |
| Retention | Device records: release + 90 days. License records: license lifetime. Nonces: 48 h. Aggregates (no personal data): 3 years. |
| Technical & organisational measures | TLS; platform encryption at rest; keyed HMAC digests; AEAD-sealed credentials; hash-chained audit logs; no plaintext IP storage |

**Suggested legal basis** [[LEGAL REVIEW — decision belongs to counsel]]: Art. 6(1)(b)
(contract performance) for validation; Art. 6(1)(f) (legitimate interest — anti-piracy) with
a documented balancing test for fingerprinting and anomaly scoring. ePrivacy-type
terminal-access rules may apply independently to local storage (F1–F3) and device-attribute
reads.

## Entry 2 — Consented aggregate usage statistics (T1, optional)

| Art. 30(1) field | Content |
|---|---|
| Controller | {{VENDOR_NAME}} |
| Purpose | Product improvement via pre-aggregated usage counters |
| Categories of data subjects | End users who opted in |
| Categories of personal data | Session count, 4-bucket session-length histogram, allow-listed feature-hit counters, days active (0–28), consent version (C4–C9). All pre-aggregated; no event timestamps, no order, no content. |
| Recipients | Cloudflare, Inc. (processor, hosting only) |
| Transfers | {{TRANSFER_MECHANISM}} |
| Retention | Raw reports 30 days; rollups 3 years (k-anonymity suppression via `sample_n`, C10) |
| TOMs | Consent callback consulted before every upload; 512-byte report cap; server-side clipping; k-anonymity suppression in rollups |

**Suggested legal basis**: Art. 6(1)(a) (consent); withdrawal stops the next upload;
server-side purge of already-uploaded T1 data on request (see `dsr-runbook.md`).

## Entry 3 — Account-based licensing (Mode E, optional)

| Art. 30(1) field | Content |
|---|---|
| Controller | {{VENDOR_NAME}} |
| Purpose | Account registration, authentication, account-bound licenses |
| Categories of data subjects | Registered end users |
| Categories of personal data | Account id, email (A5, A6 — direct identifiers); Argon2id password hash (A7); OAuth subject (A8); session token hashes (A11); login-attempt log with keyed IP hash (A12 — retention TBD, see inventory) |
| Recipients | Cloudflare, Inc. (processor); OAuth identity provider (authentication only, A8) |
| Retention | Account closure + 30 days; sessions until expiry/revocation |
| TOMs | Argon2id; TLS; token hashes only (no plaintext tokens) |

## Entry 4 — Security audit logging

| Art. 30(1) field | Content |
|---|---|
| Purpose | Non-repudiation, security auditing, abuse investigation |
| Categories of data subjects | Vendor administrative staff (`actor`, D2–D4); end users referenced in before/after snapshots (D2) |
| Categories of personal data | Staff identifiers; license/machine ids (pseudonymous); embedded end-user PII possible in admin operation snapshots (A9 edits) |
| Retention | 3 years (configurable) |
| TOMs | Append-only, hash-chained, trigger-enforced immutability; PII tombstoning on deletion with chain preserved |

**Suggested legal basis** [[LEGAL REVIEW]]: Art. 6(1)(f) / Art. 6(1)(c) where retention is
legally required.

## Drafting notes

- Entry 1 exists even when T1/Mode E are unused — every deployment processes T0 data.
- The plaintext IP address (B15) is deliberately **not** a stored category; keep it out of
  the record except as a transient-processing note.
- Payment buyer data is processed by the payment provider as independent controller; record
  it in the Vendor's own sales-processing entry, not here.
