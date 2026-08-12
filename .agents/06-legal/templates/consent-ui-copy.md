---
doc: consent-ui-copy
version: 0.1.0
status: draft
language: en
data_source: data-inventory.md v0.1.0 (verified against code 2026-08-08)
i18n: i18n/consent-ui-copy.zh-CN.md, i18n/consent-ui-copy.de.md, i18n/consent-ui-copy.ja.md
---

# Consent UI Copy Template — Usage Statistics Opt-in

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
**Factual basis:** `data-inventory.md` v0.1.0 (2026-08-08) §3.2 (T1 fields C4–C9) and
`.agents/03-modules/90-analytics-telemetry.md` (consent mechanics).
**Languages:** this file is the English master. Translations live in `i18n/` and are
machine-assisted drafts requiring professional legal translation review.

---

## 1. Mechanics this copy must match (do not contradict)

- The SDK calls the Vendor's `consent()` callback **before every upload**; a falsy return
  means no upload. Withdrawal therefore stops the **next** report — the copy must promise
  exactly that, not "within 30 days".
- `tier: 'T1'` without a consent provider is an SDK **initialization error** — the dialog
  must be wired to real state, not a placeholder.
- Every report carries `consent_version`; the dialog copy is part of the Vendor's compliance
  evidence. Bump the version whenever the notice text changes materially.
- License verification (T0) is **not** consent-gated and is not toggled by this dialog.
  Never present it as optional.

## 2. Copy rules (anti-dark-pattern)

1. Clearly separate **license verification** (required, cannot be turned off) from
   **usage statistics** (optional).
2. No pre-ticked boxes; "Accept" and "Decline" equally prominent; no "remind me later" loop.
3. A withdrawal entry point exists at all times, with the same number of steps as consent.
4. The copy must state that declining **does not reduce functionality**.
5. Name the actual fields. Vague words like "anonymous usage data" are not acceptable —
   the report contents are fixed and public (data inventory C4–C9).

## 3. English master copy

### 3.1 First-run dialog

**Title:** Help improve {{PRODUCT_NAME}}?

**Body:**
> {{PRODUCT_NAME}} can send us anonymous usage statistics to help us decide what to improve.
>
> **What is sent, if you agree:**
>
> - how many times you used the app, per reporting period;
> - a rough histogram of session lengths (four ranges — never exact times);
> - how often specific features were used (feature names only);
> - how many days per month the app was used;
> - the version of this notice you agreed to.
>
> **What is never sent:** anything you type, file names or paths, clipboard or screen
> contents, contacts, precise location, browsing history, or the order and timing of
> individual actions.
>
> Statistics are sent to our own servers only (infrastructure: Cloudflare); no third-party
> analytics or advertising service receives them.
>
> Declining changes nothing about how the app works. You can change your choice at any time
> in **Settings → {{SETTINGS_ENTRY}}**; a change takes effect with the next report.
>
> *License verification runs independently of this choice and cannot be turned off — it is
> required to operate your licensed copy. Details: {{PRIVACY_POLICY_URL}}.*

**Buttons:** `[Accept]` `[Decline]` — same visual weight.

**Link:** "Full data list" → the Vendor's privacy policy section (see
`privacy-policy-section.md`).

### 3.2 Settings toggle (persistent withdrawal entry)

> **Usage statistics** `[toggle, default off]`
> Share anonymous usage counters to help improve {{PRODUCT_NAME}}. No content, files, or
> precise behaviour is ever sent. Turning this off stops the next report; previously sent
> counters are deleted on request ({{DSR_CONTACT}}). Details: {{PRIVACY_POLICY_URL}}.

### 3.3 Withdrawal confirmation (optional microcopy)

> Usage statistics are off. No further reports will be sent. This does not affect any
> feature of {{PRODUCT_NAME}}.

## 4. Placeholders

`{{PRODUCT_NAME}}`, `{{SETTINGS_ENTRY}}`, `{{PRIVACY_POLICY_URL}}`, `{{DSR_CONTACT}}`.

## 5. Legal review points

- [[LEGAL REVIEW: confirm the "anonymous usage statistics" phrasing is defensible in the
  Vendor's jurisdictions — T1 fields carry no device id beyond what licensing already sends,
  but the report rides on an authenticated request; some counsel prefer "does not contain
  personal data beyond license verification" over "anonymous".]]
- [[LEGAL REVIEW: confirm whether ePrivacy-type terminal-access rules require consent even
  for the T0 local storage (client-local data F1–F3 in the inventory). If so, this dialog
  needs an additional required-processing notice.]]
- [[LEGAL REVIEW: age-gating / children's data — if {{PRODUCT_NAME}} may be used by minors,
  consent copy and flows need jurisdiction-specific adjustments.]]

## 6. Translations

| Language | File | Status |
|---|---|---|
| zh-CN | `i18n/consent-ui-copy.zh-CN.md` | machine-assisted draft — needs professional legal translation review |
| de | `i18n/consent-ui-copy.de.md` | machine-assisted draft — needs professional legal translation review |
| ja | `i18n/consent-ui-copy.ja.md` | machine-assisted draft — needs professional legal translation review |
