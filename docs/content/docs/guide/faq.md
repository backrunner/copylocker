---
title: FAQ
navTitle: FAQ
order: 9
description: Frequently asked questions about CopyLocker, answered honestly against the shipped implementation and the threat model.
---

# FAQ

Answers are aligned with the shipped implementation and the threat model. Where the honest answer
is "no" or "not yet", that is the answer.

## Using the SDK

**Can users keep working offline?**
Mode O: yes, until the grace window ends. Mode E: yes, until `refresh_after + grace` elapses. A
full server outage does not lock out Mode O clients inside their grace period — that is a
deliberate design decision (NFR-REL-002), not an accident.

**Does changing a disk or NIC invalidate the license?**
Usually no. Fingerprint matching has a tolerance (default 70/100, set per policy as
`fpr_tolerance`). Beyond tolerance, the machine transfer flow applies (`max_transfers` /
`transfer_window_secs` on the policy's seat spec).

**How do I run licensing in CI?**
Issue a development license bound to the CI build fingerprint. Note: the dedicated
`copylocker-cli dev-license` helper named in the internal docs is **not implemented yet**; use
`copylocker license issue` against your development backend today.

**How expensive is decryption?**
XChaCha20-Poly1305 runs at roughly 1–2 GB/s on the desktop path — a 100 MB asset costs tens of
milliseconds and the result can be cached. Local credential verification (including ML-DSA-65)
targets < 5 ms desktop / < 15 ms browser WASM (NFR-PERF-004).

**What happens if my licensing server goes down?**
Clients enter grace and keep working (Mode O). Your availability problem stays an availability
problem; it does not become a licensing incident. See the [Runbook](/docs/operations/runbook).

## Security, answered honestly

**Can CopyLocker stop all cracking?**
No. An attacker with physical control of a machine can eventually extract whatever that machine
can decrypt. CopyLocker raises the cost and — just as important — destroys the *reusability* of
the work: per-release variants mean a crack for v1.2 does not carry to v1.5. The full residual
risk list is in the [Threat Model](/docs/security/threat-model#residual-risks) and in
`SECURITY.md`, verbatim.

**A legitimate customer can just share the decrypted content, right?**
Yes — the "one buyer leaks" problem has no technical fix. Mitigations are per-user watermarking
(on the v1.1+ backlog) and version rotation.

**What stops someone from patching out the check?**
At L2+, there is no boolean check to patch: the content is encrypted, and the key only exists
after the credential chain verifies. Patching the guard or stubbing the WASM changes the derived
key and sealed assets simply fail to open. At L0/L1, patching works — which is why those levels
are demos and cheap tools only. See [Protection Levels](/docs/guide/protection-levels).

**Could CopyLocker itself forge my users' credentials or see their data?**
No. Clients never hold key material that can sign credentials (NFR-SEC-002). And the project
receives no end-user data at all (NFR-COMP-010): you self-host the server on your own Cloudflare
account; the only subprocessor in the data path is Cloudflare.

**What if my Root private key leaks?**
That is the disaster case: rotate to the pre-provisioned `root_next`, revoke affected epochs with
the two-actor flow, and ship a client update. The full procedure is in the
[Runbook](/docs/operations/runbook#root-key-compromise). This is why Root keys are generated and
kept offline.

## Operating it

**Will CopyLocker lock out paying customers by mistake?**
This is the risk we optimize against hardest. Defaults are conservative: long grace windows,
dunning grace on top of `current_period_end` (never equal to it), report-only guard observation
before enforcement, dry-run-first revocation, and staged rollouts. The
[go-live checklist](/docs/guide/protection-levels#go-live-checklist) exists because of this question.

**What does it cost to run?**
The design target is under $20/month at 100,000 active devices validating daily
(NFR-COST-001). The [cost model](/docs/operations/cost-estimation) gives the formulas.

**Which payment providers are supported for subscriptions?**
The server template binds webhook secrets for Stripe, Paddle, and LemonSqueezy
(`STRIPE_WEBHOOK_SECRET`, `PADDLE_WEBHOOK_SECRET`, `LEMONSQUEEZY_WEBHOOK_SECRET` in
`wrangler.jsonc`). Webhook processing is idempotent by `(provider, event_id)`.

**Can I self-host somewhere other than Cloudflare?**
Server logic is decoupled from Cloudflare behind a `Storage` trait (NFR-PORT-004), so porting is
possible but not promised or supported. The shipped, tested target is Cloudflare.

**Is there an admin console?**
Yes — `apps/console` is a SvelteKit app you deploy alongside the API Worker. It covers licenses,
epochs, catalogs, telemetry, and DSR operations, and it is an untrusted frontend: authorization
always happens in the API Worker. Before any production deployment, complete the Cloudflare
Access JWKS verification noted in [Deployment → The admin
console](/docs/guide/deployment#the-admin-console).

**What license is CopyLocker under?**
The public repository is GPL-3.0-only. Proprietary suite code lives in a separate commercial
repository. Combined proprietary distribution requires a commercial license, process/service
isolation, or GPL-compliant source distribution — see `LICENSING.md`, and get qualified legal
review for your distribution model.
