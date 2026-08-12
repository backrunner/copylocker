---
doc: dpia-worksheet
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
---

# DPIA Worksheet Template — CopyLocker Licensing Layer

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

**Status: DRAFT — the DPIA itself is the Vendor's (controller's) obligation; this worksheet
only pre-fills the technical facts. Review by counsel/DPO is mandatory.**
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08).

---

## 0. Do we need a DPIA at all? (screening)

Answer for each processing:

| Processing | Screening indicators | Likely need |
|---|---|---|
| T0 license verification (device fingerprint B1, machine id B2) | Systematic monitoring? Pseudonymous, purpose-limited, short retention (90 days post-release). Not special-category. | Usually **not** mandatory, but [[LEGAL REVIEW: some DPAs treat persistent device fingerprinting as systematic monitoring — confirm per jurisdiction]] |
| Optional raw device attributes (B3, default off) | Hardware serials + hostname are personal data; systematic collection | **Escalates screening — strongly consider DPIA before enabling `report_attrs`** |
| T1 consented aggregates (C4–C9) | Pre-aggregated counters, consent-gated, no events | Unlikely to require DPIA |
| T2 event telemetry | **Does not exist in the product** | n/a — if a Vendor builds event-level analytics via the `onEvent` hook, that Vendor must assess it independently; it is outside CopyLocker's data inventory |
| Anomaly scoring (B8) | Automated scoring attached to a device; can lead to revocation of access | [[LEGAL REVIEW: assess Art. 22 implications — the score informs license enforcement decisions]] |
| Mode E accounts (A5–A8) | Standard account data | Usually not |

**Rule of thumb:** a default CopyLocker deployment (T0 only, `report_attrs` off, T1 off) is
designed to sit below the DPIA threshold in most jurisdictions. Enabling `report_attrs`,
large-scale deployment, or children as data subjects moves the assessment.

## 1. Systematic description of processing (pre-filled)

- **What:** See RoPA entries (`ropa-entry.md`) — device fingerprint digest, machine id,
  license ids, version/platform context, timestamps, country code, anomaly score; optional
  raw device attributes; optional consented usage counters.
- **Where:** Vendor's own Cloudflare account only; sole sub-processor Cloudflare, Inc.; the
  CopyLocker project receives nothing (data-inventory §7 data-flow diagram).
- **How long:** device rows release + 90 days; T1 raw 30 days; aggregates 3 years; audit
  logs 3 years (configurable).
- **Scale / context:** {{DEPLOYMENT_SCALE}}, {{USER_POPULATION}}, {{JURISDICTIONS}}.

## 2. Necessity and proportionality

- License key never stored (keyed HMAC only, A2/A3); fingerprint is an irreversible keyed
  digest (B1); IP never stored (B15); raw attributes off by default (B3); T1 off by default
  and consent-gated with per-upload consent checks; T1 reports are pre-aggregated, capped at
  512 bytes, and clipped server-side; telemetry piggybacks on the validate request (no extra
  network surface).
- **Could less data achieve the purpose?** For pure validation, yes — that is why raw
  attributes are optional and T0 contains no payload beyond the protocol. Document the
  Vendor's justification for any optional field enabled.
- Data minimisation residual: `metadata_json` (A9) is free-form under Vendor control — the
  Vendor must police what they put there. [[LEGAL REVIEW: add internal policy forbidding
  unnecessary PII in license metadata.]]

## 3. Risk assessment (pre-filled hazards)

| # | Risk to data subjects | Source | Likelihood | Severity | Mitigations in design | Residual |
|---|---|---|---|---|---|---|
| R1 | Re-identification via device fingerprint | B1 | Low | Medium | Keyed HMAC, irreversible; 90-day post-release purge | Low |
| R2 | Exposure of raw hardware attributes | B3 (if enabled) | Medium | Medium–High | Default off; DO-only storage, not projected to D1; TLS | Medium — this is why enabling B3 escalates screening |
| R3 | Behavioural profiling via timestamps / check-in cadence | B10, C1–C3 | Medium | Low–Medium | Coarse aggregation; HLL sketches (irreversible, p=14); k-anonymity suppression (`sample_n`) | Low |
| R4 | IP-based tracking | B15 | Low | Medium | No storage; keyed hash only in login log (A12) | Low |
| R5 | Audit-log PII persistence beyond erasure | D2–D3 | Medium | Medium | Tombstoning on deletion, hash chain preserved; optional `--purge-audit` (breaks chain, logged) | Low–Medium — disclose deletion boundary in privacy policy |
| R6 | Automated enforcement from anomaly score | B8 | Medium | Medium | Score is advisory input to Vendor action; [[LEGAL REVIEW: document human-in-the-loop for revocation decisions to manage Art. 22 exposure]] | Medium |
| R7 | Breach of D1/R2/DO storage | all | Low | Medium | Platform encryption, no plaintext secrets, pseudonymous keys | Low |
| R8 | Vendor misuse (function creep) | A9, B3 | Deployment-dependent | — | Published anti-abuse commitments (legal pack §9); all fields public | Governance, not technical |

## 4. Consultation & sign-off

- DPO / counsel consulted: {{DPO_NAME}}, date {{DATE}}.
- Data-subject views sought (if required): {{CONSULTATION_NOTES}}.
- Decision: ☐ proceed ☐ proceed with conditions ☐ do not proceed — {{DECISION_NOTES}}.
- Residual-risk acceptance by: {{CONTROLLER_SIGNATORY}}.

## 5. Review triggers

Re-run this worksheet when: `report_attrs` is enabled; Mode E is enabled; deployment scale
changes materially; a new field is added to the protocol schema (the `legal-sync` CI gate
forces a data-inventory update — treat that as the trigger); the `legal-sync` gate flags
drift; or the sub-processor/region configuration changes.
