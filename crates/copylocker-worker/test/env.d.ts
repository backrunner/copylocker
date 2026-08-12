/// <reference types="@cloudflare/vitest-pool-workers/types" />
/// <reference path="../worker-configuration.d.ts" />

declare namespace Cloudflare {
  interface Env {
    TEST_EPOCH_SIGNING_KEY: string;
    TEST_EPOCH_FAST_SIGNING_KEY: string;
    TEST_SERVER_PEPPER: string;
    TEST_ADMIN_TOKEN_PEPPER: string;
    TEST_VARIANT_PARAMS_KEY: string;
    TEST_ASSET_KEK_KEY: string;
    TEST_BUILD_SIGNING_KEY: string;
    INTEGRITY_OIDC_AUDIENCE: string;
    INTEGRITY_OIDC_REPOSITORIES: string;
    INTEGRITY_OIDC_JWKS: string;
    TEST_DEVICE_KEM_EK: string;
    TEST_MIGRATIONS: Array<{ name: string; queries: string[] }>;
  }
}
