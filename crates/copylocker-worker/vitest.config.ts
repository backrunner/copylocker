import {
  cloudflareTest,
  readD1Migrations,
} from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import kat from "../../vectors/CL-STD-1/kat.json";

const migrations = await readD1Migrations(
  new URL("./migrations", import.meta.url).pathname,
);

const hexBytes = (value: string): number[] =>
  value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [];

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        queueProducers: {
          EVENTS: {
            queueName: "copylocker-events-test-sink",
          },
        },
        bindings: {
          ENVIRONMENT: "test",
          TEST_EPOCH_SIGNING_KEY: JSON.stringify({
            schema_version: 1,
            epoch_id: new Array<number>(8).fill(3),
            suite_id: [1, 0, 0, 1],
            signing_key: new Array<number>(64).fill(7),
          }),
          TEST_EPOCH_FAST_SIGNING_KEY: JSON.stringify({
            schema_version: 1,
            epoch_id: new Array<number>(8).fill(3),
            suite_id: [1, 0, 0, 1],
            signing_key: hexBytes(
              "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            ),
          }),
          TEST_SERVER_PEPPER: JSON.stringify(new Array<number>(32).fill(9)),
          TEST_ADMIN_TOKEN_PEPPER: JSON.stringify(new Array<number>(32).fill(4)),
          TEST_VARIANT_PARAMS_KEY: JSON.stringify(new Array<number>(32).fill(1)),
          TEST_ASSET_KEK_KEY: JSON.stringify(new Array<number>(32).fill(2)),
          TEST_STRIPE_WEBHOOK_SECRET: "stripe-test-secret",
          TEST_PADDLE_WEBHOOK_SECRET: "paddle-test-secret",
          TEST_LEMONSQUEEZY_WEBHOOK_SECRET: "lemon-test-secret",
          TEST_DEVICE_KEM_EK: kat.kem[0].encapsulation_key,
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  ],
});
