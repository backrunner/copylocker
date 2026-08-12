---
doc: privacy-policy-section
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# Privacy Policy Section Template — "Software Licensing & Usage Analytics"

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

**Status: DRAFT — must be reviewed by qualified legal counsel before publication.**
**Factual basis:** `data-inventory.md` v0.1.0 (verified against code 2026-08-08). Every
field, retention period, encryption claim, and sharing statement below is taken from that
inventory (row references in parentheses, e.g. `(B1)`). If a statement here cannot be traced
to the inventory, treat it as a drafting error and report it.

**How to use.** This is the "Software Licensing and Usage Analytics" section of the Vendor's
own privacy policy — the Vendor is the controller; this section covers only the processing
performed by the CopyLocker licensing layer running in the Vendor's infrastructure. Merge it
into the Vendor's full policy and replace every `{{PLACEHOLDER}}`.

---

## Template text begins

### {{SECTION_NUMBER}}. Software Licensing and Usage Analytics

{{PRODUCT_NAME}} uses CopyLocker, a software licensing component, to verify that your copy
of the software is properly licensed and to protect it against unauthorized copying. This
section describes what that component processes.

#### {{SECTION_NUMBER}}.1 Data processed for license verification (required)

License verification is a technical precondition for operating the software and cannot be
switched off. For this purpose the software processes the following categories of data and
transmits them to our licensing service over an encrypted connection (TLS):

- **License identifier** — a randomly generated 16-byte id assigned to your license `(A1)`.
  The license key you type is **never stored**; only a keyed hash (HMAC) of it is retained
  `(A2, A3)`.
- **Device fingerprint** — an irreversible keyed hash (HMAC-SHA256) computed over normalized
  hardware attributes of your device `(B1)`. We use it to recognize your device and to
  prevent a license from being copied to additional machines.
- **Server-assigned device id** (`machine_id`) — a random pseudonymous identifier assigned at
  activation `(B2)`.
- **Optional raw device attributes** — only if we have explicitly enabled this for your
  license tier, normalized hardware attributes (e.g. hardware serial, hostname) may be
  transmitted to make the fingerprint tolerant of hardware changes `(B3, B3a, B3b)`.
  This is **off by default**. [[LEGAL REVIEW: if the Vendor enables `report_attrs`, this
  data is personal data — confirm the notice and legal basis are adequate before enabling.]]
- **Device public keys and a sealed credential state** `(B4, B5)` — cryptographic material
  used to sign validation requests.
- **Software and platform information** — app version, SDK version, release id, variant id,
  operating system, CPU architecture `(B6)`, and the activation path used (online / offline /
  offline key / account) `(B9)`.
- **Server-side timestamps** of activation, last validation, and last heartbeat `(B10)`.
- **Country code** derived from the network connection at the edge (country level only; no
  IP address is stored) `(B7, B15)`.
- **An anti-abuse anomaly score** computed server-side from activation counters `(B8)`.
- **If you use an account-based license (Mode E):** account id, email address, a salted
  Argon2id password hash, or an OAuth subject identifier, plus login-session records `(A5–A8,
  A11, A12)`.

Your **IP address is never stored**: it is used transiently at the network edge for rate
limiting only, and at most a keyed hash of it is kept in the login-attempt log `(B15, A12)`.

#### {{SECTION_NUMBER}}.2 Optional usage statistics (consent-gated)

If — and only if — you explicitly opt in, the software additionally reports **pre-aggregated
usage counters** to help us improve the product `(C4–C9)`:

- number of sessions in the reporting window;
- a four-bucket histogram of session lengths (e.g. `<5m / 5–30m / 30m–2h / >2h`) — **never
  exact durations, never timestamps**;
- how often specific, pre-declared product features were used (feature names only, no
  content);
- the number of distinct days you used the software in the window (0–28);
- the version of the privacy notice you consented to (consent evidence).

The software **never** collects: sequences or timestamps of individual actions, the order of
your actions, anything you type, file names or paths, clipboard contents, screen contents,
contacts, GPS or precise location, or browsing history.

You can withdraw your consent at any time in **{{CONSENT_SETTINGS_LOCATION}}**; withdrawal
takes effect on the next report and does not affect any software functionality. License
verification ({{SECTION_NUMBER}}.1) is unaffected. [[LEGAL REVIEW: confirm the withdrawal
path satisfies local consent-withdrawal requirements (e.g. GDPR Art. 7(3) "as easy to
withdraw as to give").]]

#### {{SECTION_NUMBER}}.3 Where the data goes

All licensing and analytics data is sent exclusively to infrastructure operated in
**{{VENDOR_NAME}}'s own Cloudflare account**. **The developer of the CopyLocker component
receives, stores, and aggregates no end-user data whatsoever.** The only sub-processor is
**Cloudflare, Inc.** (Workers / D1 / Durable Objects / KV / R2 / Queues), covered by the data
processing agreement between {{VENDOR_NAME}} and Cloudflare. There are no third-party
analytics SDKs, no advertising SDKs, and no data brokers involved.

Payment processing happens entirely on the payment provider's own checkout pages
({{PAYMENT_PROVIDER_LIST}}); the licensing component receives only signed subscription
status events (no card data, no buyer name, no billing address, no buyer email) `(E1–E5)`.

[[LEGAL REVIEW: insert international-transfer wording appropriate to the Vendor's setup
(e.g. EU SCCs / Cloudflare's Data Localization Suite). Cloudflare region pinning via
Jurisdictional Restrictions is available; state here whether the Vendor uses it.]]

#### {{SECTION_NUMBER}}.4 Retention

| Data | Retention |
|---|---|
| Device records (fingerprint, machine id, device attributes, keys, timestamps) | Deleted 90 days after the device is released or the license is revoked `(B1–B10)` |
| License records | Lifetime of the license `(A1–A4, A9, A10)` |
| Account data (Mode E) | 30 days after account closure `(A5–A8)` |
| Replay-protection nonces | 48 hours `(B11)` |
| Raw analytics events | 90 days `(C3)` |
| Raw usage-statistics reports | 30 days, then only aggregates are kept `(C4–C9)` |
| Aggregated statistics (counters, probabilistic sketches) | 3 years `(C1, C2, C10)` |
| Audit and security logs | 3 years (configurable) `(D1–D4)` |

#### {{SECTION_NUMBER}}.5 Your rights and what deletion means

You may request access to, export of, rectification of, or deletion of your licensing data at
**{{DSR_CONTACT}}**. We respond within 30 days.

When a device record is deleted, the device rows, activation records, and raw event records
are deleted, and personal identifiers in audit logs are replaced with a tombstone marker
(keeping the tamper-evident hash chain of the audit log intact). **Aggregate statistics that
no longer contain personal data — counter rollups and irreversible probabilistic
(HyperLogLog) sketches — are not retroactively modified**: they cannot be traced back to you,
and retroactive edits would destroy the comparability of historical statistics. After
deletion, your device no longer contributes to any future aggregate. [[LEGAL REVIEW: confirm
this deletion-boundary disclosure satisfies local erasure requirements; if the jurisdiction
requires full audit-log erasure, note the `--purge-audit` option and its hash-chain break.]]

License verification itself ({{SECTION_NUMBER}}.1) cannot be disabled while you use the
software, because it is necessary to perform the license agreement. [[LEGAL REVIEW: confirm
the legal basis mapping — suggested starting point: contract performance (GDPR
Art. 6(1)(b)) plus legitimate interest in anti-piracy (Art. 6(1)(f)); usage statistics:
consent (Art. 6(1)(a)). Also assess ePrivacy-type rules on accessing information on the
terminal device, which may independently cover local storage and device-attribute reads.]]

#### {{SECTION_NUMBER}}.6 What we will never do

The licensing component is deliberately designed so that it cannot be used for: cross-app or
cross-vendor tracking or data correlation; advertising profiles or data monetization;
collection of user content (files, typing, clipboard, screen); precise geolocation; or any
collection not publicly listed in this section.

## Template text ends

---

## Drafting notes (delete before publication)

1. **Consistency duty.** The `legal-sync` CI gate regenerates the data inventory from the
   protocol schema. If this section ever contradicts `data-inventory.md`, the inventory wins
   — update this text.
2. **Placeholders:** `{{SECTION_NUMBER}}`, `{{PRODUCT_NAME}}`, `{{VENDOR_NAME}}`,
   `{{CONSENT_SETTINGS_LOCATION}}`, `{{PAYMENT_PROVIDER_LIST}}`, `{{DSR_CONTACT}}`.
3. **Honesty constraint.** Do not soften {{SECTION_NUMBER}}.1 into "we may collect". The
   fields listed there are transmitted on every activation/validation by design; listing them
   accurately is the entire point of this template.
4. If the Vendor does **not** use Mode E accounts, remove the Mode E bullet and the account
   rows of the retention table.
5. If the Vendor does **not** offer T1 usage statistics, remove {{SECTION_NUMBER}}.2 entirely
   rather than leaving it in "just in case" — an unexercised consent claim is a liability.
