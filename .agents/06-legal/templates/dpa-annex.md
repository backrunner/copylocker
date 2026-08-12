---
doc: dpa-annex
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# DPA Annex Template — Sub-processors and Data Categories

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

**Status: DRAFT — must be reviewed by qualified legal counsel before use.**
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08), especially §3.3 (data flow) of
the legal pack and the inventory's "Shared with" column.

**How to use.** This is an annex a Vendor can attach to (a) their own customer-facing DPA
when selling to enterprise customers, and (b) their internal record of processing
infrastructure. It documents the CopyLocker licensing layer's processing chain.

---

## Annex {{ANNEX_NUMBER}} — Licensing Component (CopyLocker)

### 1. Processing chain

All end-user licensing and analytics data flows **exclusively** into infrastructure operated
within **{{VENDOR_NAME}}'s own Cloudflare account** (Cloudflare Workers, D1, Durable
Objects, KV, R2, Queues). **The CopyLocker project receives, stores, and aggregates no
end-user data.** The only sub-processor engaged by this processing is **Cloudflare, Inc.**,
already covered by the data processing agreement between {{VENDOR_NAME}} and Cloudflare. No
third-party analytics SDK, advertising SDK, or data broker is involved.

### 2. Sub-processor list

| # | Sub-processor | Role | Data categories | Location / transfer mechanism |
|---|---|---|---|---|
| 1 | Cloudflare, Inc. ({{CLOUDFLARE_ENTITY}}) | Edge compute, database, object storage, queues hosting the licensing service | All categories in §3, in transit and at rest | {{CF_REGION_CONFIG}} [[LEGAL REVIEW: state applicable transfer mechanism (e.g. EU–US Data Privacy Framework, SCCs) and whether Jurisdictional Restrictions (`eu`/`fedramp`) are configured for Durable Objects, D1, R2]] |
| 2 | {{PAYMENT_PROVIDER_LIST}} | Independent controller for checkout; source of signed subscription webhooks | None sent by the licensing component; receives only subscription status events (`provider`, event id/timestamps, provider subscription id, license id, event kind/periods — E1–E5) | Payment provider's own checkout pages; buyer relationship governed by provider's own terms |

### 3. Categories of data subjects and data

**Data subjects:** end users of {{PRODUCT_NAME}}; Vendor staff performing administrative
operations (audit-log `actor` fields, D2–D4).

| Category | Fields (inventory rows) | Personal data? | Retention |
|---|---|---|---|
| License identifiers | `license_id`, `key_hmac`, product/policy ids (A1–A4) | Pseudonymous; personal once linked to an order/account | License lifetime |
| Vendor-defined license metadata | `metadata_json` (A9) | Potentially yes — Vendor-controlled free-form JSON | License lifetime |
| Device identification | `fingerprint` (keyed HMAC-SHA256 digest), `machine_id`, device public keys, sealed credential state (B1, B2, B4, B5) | Pseudonymous | Device release + 90 days |
| Optional raw device attributes | hardware serials, hostname, web UA/device hints (B3, B3a, B3b) — **default off** | **Yes** | Device release + 90 days |
| Platform/usage context | versions, OS/arch, activation path, server timestamps, country code, anomaly score (B6–B10) | No / low sensitivity (pseudonymous link) | Device release + 90 days; aggregates 3 years |
| Network data | plaintext IP **never stored** — transient rate-limiting only; keyed IP hash in login-attempt log (B15, A12) | Yes (hence no-store) | Not retained / TBD for hash log |
| Account data (Mode E, if used) | account id, email, Argon2id password hash, OAuth subject, sessions (A5–A8, A11, A12) | **Yes** | Account closure + 30 days |
| Consented usage statistics | session counters, 4-bucket duration histogram, feature-hit counters, days active, consent version (C4–C9) | No (pre-aggregated) | Raw 30 days; rollups 3 years |
| Aggregates | exact-count rollups, HyperLogLog sketches (C1, C2, C10) | No | 3 years |
| Audit & security logs | issuance chain, admin operations, audit chain, security-floor log (D1–D4) | Staff identifiers yes; may embed end-user PII in before/after snapshots | 3 years (configurable) |

**Never collected (design exclusion):** event timestamp sequences, action ordering, user
input content, file names/paths, clipboard, screen content, contacts, GPS/precise location,
browsing history, card or payment-instrument data, buyer name/email/billing address from
payment webhooks.

### 4. Nature and purpose of processing

License validation and anti-piracy (contract performance; legitimate interest); seat
management; optional consented aggregate usage statistics for product improvement; security
auditing (tamper-evident hash-chained logs); fraud/abuse anomaly scoring.

### 5. Technical and organisational measures (summary)

- TLS in transit on all client↔edge and webhook paths; Cloudflare platform encryption at
  rest for D1 / DO / KV / R2.
- Application-layer protections: keyed HMAC for license keys and device fingerprints (no
  plaintext secrets stored); Argon2id for passwords; AEAD-sealed credential state;
  hash-chained, append-only audit logs (D1–D4); replay nonces with 48-hour TTL.
- IP addresses not persisted (B15).
- Optional data localization via Cloudflare Jurisdictional Restrictions (`eu`, `fedramp`)
  for Durable Objects; equivalent regional settings for D1 and R2.
- Deletion procedure with defined boundary: device rows and raw events deleted; audit-log
  PII tombstoned with hash chain preserved; irreversible aggregates (HLL, rollups) not
  retroactively modified.

[[LEGAL REVIEW: align §5 with the TOM schedule of the Vendor's main DPA; this is a summary,
not a substitute for the full TOM document.]]

### 6. Placeholders

`{{ANNEX_NUMBER}}`, `{{VENDOR_NAME}}`, `{{PRODUCT_NAME}}`, `{{CLOUDFLARE_ENTITY}}`,
`{{CF_REGION_CONFIG}}`, `{{PAYMENT_PROVIDER_LIST}}`.
