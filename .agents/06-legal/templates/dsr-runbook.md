---
doc: dsr-runbook
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# DSR Runbook — Data Subject Requests (Access / Export / Delete / Rectify / Object)

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

**Status: DRAFT — operational runbook for the Vendor's support/engineering team; legal
sign-off required for the external-facing response templates.**
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08), especially its §8 DSR support
matrix and §4 deletion boundary.

> **⚠ Honesty notice for the whole runbook.** The dedicated `copylocker dsr` CLI commands
> and the telemetry purge endpoint are **M6 deliverables that do not exist yet**. Every
> procedure below is split into **"Today"** (verified against code, 2026-08-08) and
> **"After M6"** (target). Do not tell a customer or a regulator that a target-state
> command exists before it ships.

---

## 1. Intake and identity verification

DSR contact: **{{DSR_CONTACT}}**. Response SLA: **30 days** (GDPR Art. 12(3)).

The requester must be mapped to a CopyLocker identifier before any action:

- **By license key** → resolve to `license_id` (A1) via the Admin API license list/lookup.
- **By account email (Mode E)** → resolve to `account_id` (A5).
- **By device** → the end user can trigger `/v1/deactivate` self-service from the app; a
  `machine_id` (B2) can be found via the Admin API machines listing for a license.

[[LEGAL REVIEW: define proportional identity verification — the licensing layer is
pseudonymous by design; over-collecting identity documents to fulfil a DSR is itself a
data-minimisation problem.]]

## 2. Request types

### 2.1 Access / export (Art. 15 / Art. 20 portability)

**After M6 (target):**

```sh
copylocker dsr export --machine <machine_id>   # or: --account <account_id>
# → JSON bundle: machine row (B1–B10), license row (A1–A10), account row (A5–A8)
```

**Today (manual equivalent):**

1. Admin API read endpoints for licenses and machines
   (`crates/copylocker-worker/src/admin.rs`, `admin_resources/licenses.rs`) — export the
   license row and its machine rows to JSON manually.
2. T0/T1 aggregate data (C1, C2, C10) contains no per-device keys — there is nothing
   per-subject to export from aggregates; say so in the response.
3. Raw analytics events (C3, in progress M5) and T1 raw reports (C4–C9, in progress M5) are
   not yet queryable per machine; note this limitation in the response until M6.
4. Assemble the bundle, record the fulfilment in the admin operation log (D2 — automatic
   for Admin API mutations; log manual reads in the Vendor's ticket system).

**Response template (access):** see §4.

### 2.2 Deletion (Art. 17)

**After M6 (target):**

```sh
copylocker dsr delete --machine <machine_id>
# 1. LicenseDO: delete activation row
# 2. D1: delete machines row + projections
# 3. R2: purge raw records
# 4. Audit log: PII fields → tombstone, hash chain preserved
```

**Today (manual equivalent):**

1. Self-service: the end user can release their own seat via `/v1/deactivate` from the app.
2. Admin-side: revoke the license / release the device via the Admin revocation endpoints.
3. Released device rows are purged automatically **90 days after release** by the Durable
   Object alarm (`RELEASED_RETENTION_SECS` — data-inventory B1–B10). Communicate this
   timeline; there is no same-day hard delete today.
4. Audit-log PII tombstoning is **not implemented today** (M6). If a deletion request
   requires it before M6, escalate to engineering — do not improvise SQL against production.

**Deletion boundary (must be stated in the external response and in the privacy policy):**

| Data | On deletion |
|---|---|
| Machine rows, activation records, R2 raw events | Deleted |
| PII fields in audit logs | Replaced with a tombstone; tamper-evident hash chain preserved |
| HLL sketches and rollup counters | **Not retroactively modified** — they contain no personal data and retroactive edits would destroy historical comparability; the device stops contributing to future aggregates |

If the Vendor's counsel determines that the jurisdiction requires full audit-log erasure,
the M6 tooling provides `--purge-audit`, which breaks the hash chain at a recorded break
point. [[LEGAL REVIEW: decide whether/when `--purge-audit` may be used; a broken chain
weakens non-repudiation evidence.]]

### 2.3 Rectification (Art. 16)

**Available today.** License `metadata_json` (A9) is Vendor-defined and editable through the
Admin API mutation path, with before/after snapshots recorded in the audit trail (D2). All
other stored fields are system-generated and not user-correctable by design — explain this
rather than editing them out of band.

### 2.4 Objection / consent withdrawal (Art. 21 / Art. 7(3))

**T1 usage statistics:**

1. The end user switches off usage statistics in the app settings (see
   `consent-ui-copy.md`); the SDK's `consent()` callback returns falsy and the **next**
   report is not sent. Effective immediately.
2. Already-uploaded T1 data (raw 30-day window, C4–C9):
   - **After M6 (target):** `POST /v1/admin/telemetry/purge?machine_id=<id>`.
   - **Today:** the purge endpoint is **not implemented**. T1 raw records expire after
     30 days by design once the pipeline ships; until then, record the request and confirm
     expiry. [[LEGAL REVIEW: assess whether the 30-day expiry is an adequate interim
     measure in the Vendor's jurisdiction.]]

**T0 license verification:** cannot be disabled while the software is in use (contract
performance). Suggested response copy:

> License verification data is processed because it is technically necessary to operate
> your licensed copy of {{PRODUCT_NAME}} and to protect it against unauthorized copying.
> It is not optional while the license is in use. You may end this processing at any time
> by deactivating your license and uninstalling the software; your device record is then
> deleted 90 days after release.

### 2.5 Account deletion (Mode E)

**After M5/M6 (target):** admin cascade delete; account rows (A5–A8, A11–A12) purged 30
days after closure.
**Today:** Mode E endpoints are in progress (schema-only); do not accept account-deletion
commitments until the cascade job lands. Track under the M5/M6 milestone.

## 3. Fulfilment log

Record every DSR in the Vendor's ticket system: request id, date received, identifier
resolution steps, actions taken (commands / API calls), completion date, responder. The
admin audit chain (D3) already covers Admin API mutations automatically.

## 4. External response snippets

- **Access:** "The licensing system stores the following records linked to your license:
  device identifier (random id and irreversible device fingerprint), license identifier,
  software version and platform information, timestamps of activation and last validation,
  and country code. Aggregate statistics contain no reference to your device and are not
  part of this export."
- **Deletion:** state the deletion boundary table (§2.2) verbatim — including that
  aggregate sketches/counters are not retroactively modified and why.
- **Withdrawal:** "Usage statistics were switched off; no further reports are sent.
  Previously sent counters {{PURGE_OUTCOME_STATEMENT}}."

## 5. Placeholders and review points

`{{DSR_CONTACT}}`, `{{PRODUCT_NAME}}`, `{{PURGE_OUTCOME_STATEMENT}}`.

- [[LEGAL REVIEW: confirm 30-day SLA wording and extension handling per jurisdiction.]]
- [[LEGAL REVIEW: approve the T0 objection response copy (§2.4) against local law.]]
- [[LEGAL REVIEW: approve interim handling of T1 purge before M6 ships.]]
