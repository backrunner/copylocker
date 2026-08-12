/**
 * `@copylocker/admin-sdk` — typed client for the CopyLocker Admin API
 * (`/v1/admin/*` on the CopyLocker Worker).
 *
 * Covers every admin route: releases, licenses, accounts, asset-keks,
 * integrity (signer keys + remote manifest signing), offline-key issuance,
 * catalog, policies, epochs, license/machine revocation, the product alert
 * webhook, analytics (definitions/metrics/export/subscriptions), DSR
 * export/delete, the telemetry retention purge, cross-license machine
 * listing, the GDPR machine delete, and the Admin audit chain query/verify.
 */

export { createAdminClient } from './client.js'
export type {
  AdminClient,
  AdminClientOptions,
  FetchLike,
  ListAdminAuditQuery,
  ListAdminMachinesQuery,
  ListAssetKeksQuery,
  ListLicensesQuery,
  MutationOptions,
  RevokeEpochOptions,
  RevokeOptions,
  TransitionOptions,
} from './client.js'
export { AdminApiError } from './errors.js'
export type * from './types.js'
