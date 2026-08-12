---
doc: eula-clause
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
i18n: i18n/eula-clause.zh-CN.md, i18n/eula-clause.de.md, i18n/eula-clause.ja.md
---

# EULA Clause Template — License Verification & Telemetry

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

**Status: DRAFT — must be reviewed by qualified legal counsel before inclusion in a EULA.**
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08); honesty claims follow the
project's residual-risk statement (`SECURITY.md`, threat model §6).
**Languages:** this file is the English master. zh-CN / de / ja versions live in `i18n/` and
are **machine-assisted drafts requiring professional legal translation review**.

**How to use.** These are clauses for the Vendor's own End User License Agreement covering
the CopyLocker licensing layer. Renumber to fit the host EULA and replace
`{{PLACEHOLDER}}`s.

---

## Clause {{CLAUSE_1}} — License verification

1. The Software includes a license verification component that periodically contacts
   {{VENDOR_NAME}}'s licensing service to confirm that your copy is properly licensed and
   that the number of devices in use does not exceed the seats of your license.
2. For this purpose the Software transmits: a license identifier; a server-assigned random
   device identifier; an irreversible cryptographic hash (fingerprint) derived from hardware
   attributes of your device; device public keys; software version, operating system, and
   architecture information; the activation method used; and a country code inferred at the
   network edge. Your IP address is not stored. The full, authoritative list of transmitted
   fields is published in our privacy policy ({{PRIVACY_POLICY_URL}}).
3. License verification is a condition of using the Software and cannot be disabled. If
   verification fails, the Software may reduce functionality or cease to operate, as
   described in {{GRACE_POLICY_DOC}}.
4. The license key you enter is never stored by the licensing service; only a keyed hash of
   it is retained.

## Clause {{CLAUSE_2}} — Optional usage statistics

1. If you explicitly opt in, the Software may additionally report pre-aggregated usage
   statistics (counts of sessions, a coarse histogram of session lengths, counts of feature
   usage, and the number of days used per period). Reports contain no content, no file
   names, no timestamps of individual actions, and no precise location.
2. You may withdraw consent at any time in the Software's settings with immediate effect for
   future reports. Declining or withdrawing does not reduce any functionality of the
   Software.

## Clause {{CLAUSE_3}} — Restrictions

You may not: (a) circumvent, disable, or tamper with the license verification component;
(b) use the Software on more devices than your license permits; (c) remove or alter
per-user watermarking applied to protected assets; or (d) use the Software's licensing
interfaces to probe, stress, or attack the licensing service. [[LEGAL REVIEW: align with
mandatory local law — e.g. EU Directive 2009/24/EC Art. 5–6 limits contractual restrictions
on interoperability and backup; many jurisdictions void anti-reverse-engineering clauses to
that extent.]]

## Clause {{CLAUSE_4}} — Honest limits of protection

The anti-copying protection in the Software is designed to make unauthorized use expensive
and non-reusable, not impossible. Among other things, an attacker with full physical control
of a device can eventually extract what that device can decrypt, and protection in web
browser environments is inherently weaker than in native applications. Nothing in this
Agreement warrants that unauthorized copying is impossible. (This clause mirrors the
project's public residual-risk statement; keep it consistent with `SECURITY.md`.)

## Clause {{CLAUSE_5}} — Enforcement

If the licensing service detects abuse indicators (for example, activation on an excessive
number of distinct devices), {{VENDOR_NAME}} may suspend or revoke the affected license
{{HUMAN_REVIEW_WORDING}}. [[LEGAL REVIEW: if enforcement can be automated, assess GDPR
Art. 22 / automated-decision constraints and add a human-review commitment here.]]

---

## Placeholders

`{{CLAUSE_1}}`…`{{CLAUSE_5}}`, `{{VENDOR_NAME}}`, `{{PRIVACY_POLICY_URL}}`,
`{{GRACE_POLICY_DOC}}`, `{{HUMAN_REVIEW_WORDING}}`.

## Review points

- [[LEGAL REVIEW: consumer-law conformity of the "verification is a condition" clause in
  each sales jurisdiction (mandatory consumer rights may limit functionality reduction).]]
- [[LEGAL REVIEW: confirm the EULA and privacy policy do not diverge — Clause 1.2 must stay
  byte-equivalent in meaning to the privacy policy section built from
  `privacy-policy-section.md`; the `legal-sync` gate watches the inventory both cite.]]
- [[LEGAL REVIEW: governing law and severability are host-EULA concerns, out of scope here.]]

## Translations

| Language | File | Status |
|---|---|---|
| zh-CN | `i18n/eula-clause.zh-CN.md` | machine-assisted draft — needs professional legal translation review |
| de | `i18n/eula-clause.de.md` | machine-assisted draft — needs professional legal translation review |
| ja | `i18n/eula-clause.ja.md` | machine-assisted draft — needs professional legal translation review |
