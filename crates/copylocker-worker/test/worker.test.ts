import { exports } from "cloudflare:workers";
import WorkerEntrypoint from "../build/worker/shim.mjs";
import kat from "../../../vectors/CL-STD-1/kat.json";
import {
  applyD1Migrations,
  createExecutionContext,
  createMessageBatch,
  createScheduledController,
  env,
  getQueueResult,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";

type ReserveResult = {
  ok: boolean;
  machine_id: number[];
  reused_existing: boolean;
  status: string;
};

type RevokeResult = {
  ok: boolean;
  changed: boolean;
  revocation_epoch: number;
};

type ProjectionEvent = {
  event: "license_projection";
  schema_version: 1;
  license_id: number[];
  license_status: "active" | "suspended" | "expired" | "revoked";
  seats_used: number;
  last_seen_at: number | null;
  machine: {
    machine_id: number[];
    fingerprint: number[];
    status: "active" | "pending" | "released" | "revoked";
    activation_path: "online" | "offline_ar" | "olk" | "account";
    first_seen_at: number;
    last_seen_at: number | null;
    os: string | null;
    arch: string | null;
    app_version: string | null;
    sdk_version: string | null;
    release_id: string | null;
    variant_id: number | null;
    build_fp: string | null;
    geo_country: string | null;
    suspicion: number;
  } | null;
  proj_version: number;
  occurred_at: number;
};

type MachineStatus = NonNullable<ProjectionEvent["machine"]>["status"];

type AuditArchiveEvent = {
  event: "audit_archive";
  schema_version: 1;
  shard: number;
  seq: number;
  occurred_at: number;
  kind: number;
  product_id: string;
  subject: number[];
  epoch_id: number[];
  digest: number[];
  prev_hash: number[];
  hash: number[];
  envelope: number[];
  r2_key: string;
};

type AdminRevocationSnapshot = {
  kind: "license" | "machine";
  target: string;
  license_id: string;
  product_id: string;
  status: string;
  seats: number;
  heartbeat_sec: number | null;
  expires_at: number | null;
  affected_machines: number;
  revocation_epoch: number;
};

type AdminAuditEvent = {
  event: "admin_audit_archive";
  schema_version: 1 | 2;
  seq: number;
  occurred_at: number;
  vendor_id: string;
  actor: string;
  action: string;
  target: string;
  reason?: number;
  request_id: string;
  before: AdminRevocationSnapshot | Record<string, unknown>;
  after: AdminRevocationSnapshot | Record<string, unknown>;
  prev_hash: number[];
  hash: number[];
  r2_key: string;
};

type IssueResult = {
  ok: boolean;
  seq: number;
  epoch_id: number[];
  envelope: number[];
  digest: number[];
  prev_hash: number[];
  hash: number[];
};

type AdminRevokeResult = {
  ok: boolean;
  dry_run: boolean;
  kind: "license" | "machine";
  target: string;
  revocation_epoch?: number;
  affected_machines?: number;
  already_revoked?: boolean;
};

type AdminLicenseIssueResult = {
  ok: boolean;
  product_id: string;
  policy_id: string;
  catalog_version: number;
  count: number;
  license_ids: string[];
  licenses: Array<{ license_id: string; license_key: string }>;
};

type AdminLicenseMutationResult = {
  ok: boolean;
  version: number;
  license: {
    license_id: string;
    product_id: string;
    policy_id: string;
    status: string;
    seats_override: number | null;
    entitlement_override: { tier: string } | null;
    expires_at: number | null;
    updated_at: number;
  };
};

type BillingWebhookEvent = {
  event: "billing_webhook";
  schema_version: 1;
  provider: "stripe" | "paddle" | "lemon_squeezy";
  event_id: string;
  event_ts: number;
  external_id: string;
  event_kind:
    | {
        kind: "started";
        license_id: number[];
        period_start: number;
        period_end: number;
        billing_period: string;
      }
    | { kind: "renewed"; period_start: number; period_end: number }
    | {
        kind:
          | "payment_failed"
          | "dunning_lapsed"
          | "payment_recovered"
          | "cancel_at_period_end"
          | "period_ended"
          | "refund_reported";
      };
};

const textEncoder = new TextEncoder();
const uint64Mask = (1n << 64n) - 1n;
const suiteId = [0x01, 0x00, 0x00, 0x01];
const productId = "product_1";
const activationLicenseKey = "CL1-NC0G4-0R40M-30E20-91AEX";
const activationLicenseKeyBytes = hexBytes("ab0102030405060708090a");
const fastEpochVerifyingKey = hexBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);
const encryptedVariantParams = hexBytes(
  "1111111111111111111111111111111111111111111111119fbeed727c61e88d5cd7a900c4f760e4dbef61be3ddd92807518ddf3a9a13921ff35412196b2fa55292a5089d3c165ed79043547f024d786cf57963dc8fe75d5d1ec544b35944e3fa889514f3fed57a4733c803506d60dd8d6ae698619",
);
const encryptedAssetKek = hexBytes(
  "222222222222222222222222222222222222222222222222d00c7450c7c4129282e1e98b2957b9c8213b933581c971562869592cf7b78176e1952d4f09847b3a96ba196733528fe1",
);
const encryptedCredentialState = hexBytes(
  "3333333333333333333333333333333333333333333333339fe424f62de2ef6a5c7fc383b5ca8f77a7ad46907bfd2db77721b8ba9e23304cc3d289668317f62684e5b91c2ebb197a",
);
const licenseKeyAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

type TestCborValue =
  | number
  | string
  | Uint8Array
  | TestCborValue[]
  | Map<number, TestCborValue>;

type DeviceKeys = {
  privateKey: CryptoKey;
  verifyingKey: number[];
};

function hexBytes(value: string): number[] {
  return value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [];
}

async function hmacHex(secret: string, payload: string | Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const source = typeof payload === "string" ? textEncoder.encode(payload) : payload;
  const payloadBytes = new Uint8Array(source.byteLength);
  payloadBytes.set(source);
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, payloadBytes),
  );
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function postSignedWebhook(
  provider: "stripe" | "paddle" | "lemonsqueezy",
  payload: unknown,
  secret: string,
): Promise<Response> {
  const body = JSON.stringify(payload);
  const timestamp = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (provider === "stripe") {
    headers["Stripe-Signature"] = `t=${timestamp},v1=${await hmacHex(secret, `${timestamp}.${body}`)}`;
  } else if (provider === "paddle") {
    headers["Paddle-Signature"] = `ts=${timestamp};h1=${await hmacHex(secret, `${timestamp}:${body}`)}`;
  } else {
    headers["X-Signature"] = await hmacHex(secret, body);
  }
  return exports.default.fetch(`https://copylocker.test/webhooks/${provider}`, {
    method: "POST",
    headers,
    body,
  });
}

function hexId(value: number[]): string {
  return value.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function testAdminToken(value: number): string {
  const encoded = btoa(String.fromCharCode(...new Array<number>(32).fill(value)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return `clat_${encoded}`;
}

function testLicenseKey(lastRandomByte: number): {
  value: string;
  bytes: number[];
} {
  const bytes = [0xab, 1, 2, 3, 4, 5, 6, 7, 8, 9, lastRandomByte];
  let checked = 0n;
  for (const byte of bytes) checked = (checked << 8n) | BigInt(byte);

  let crc = 0;
  for (let bitIndex = 87; bitIndex >= 0; bitIndex -= 1) {
    const bit = Number((checked >> BigInt(bitIndex)) & 1n);
    const top = (crc >> 11) & 1;
    crc = (crc << 1) & 0x0fff;
    if ((top ^ bit) === 1) crc ^= 0x0f13;
  }

  const payload = (checked << 12n) | BigInt(crc);
  let encoded = "";
  for (let index = 0; index < 20; index += 1) {
    const shift = BigInt(100 - 5 * (index + 1));
    encoded += licenseKeyAlphabet[Number((payload >> shift) & 0x1fn)];
  }
  return {
    value: `CL1-${encoded.slice(0, 5)}-${encoded.slice(5, 10)}-${encoded.slice(10, 15)}-${encoded.slice(15)}`,
    bytes,
  };
}

function licenseKeyBytes(value: string): number[] {
  const encoded = value.replace(/^CL1-/, "").replaceAll("-", "");
  if (encoded.length !== 20) throw new Error("invalid test license key length");
  let payload = 0n;
  for (const character of encoded) {
    const digit = licenseKeyAlphabet.indexOf(character);
    if (digit < 0) throw new Error("invalid test license key character");
    payload = (payload << 5n) | BigInt(digit);
  }
  let checked = payload >> 12n;
  const bytes = new Array<number>(11).fill(0);
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(checked & 0xffn);
    checked >>= 8n;
  }
  return bytes;
}

function machineBytes(value: number): number[] {
  const bytes = new Array<number>(16).fill(0);
  bytes[14] = Math.floor(value / 256);
  bytes[15] = value % 256;
  return bytes;
}

function licenseBytes(value: number): number[] {
  const bytes = machineBytes(value);
  bytes[0] = 0xc1;
  return bytes;
}

function issuerShard(routingKey: number[]): number {
  let hash = 0xcbf29ce484222325n;
  for (const byte of routingKey) {
    hash = ((hash ^ BigInt(byte)) * 0x100000001b3n) & uint64Mask;
  }
  return Number(hash % 8n);
}

function signedInt64(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigInt64(0, BigInt(value));
  return bytes;
}

function unsignedInt64(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function cborHead(major: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("test CBOR only supports safe unsigned integers");
  }
  if (value < 24) return new Uint8Array([(major << 5) | value]);
  if (value <= 0xff) return new Uint8Array([(major << 5) | 24, value]);
  if (value <= 0xffff) {
    const encoded = new Uint8Array(3);
    encoded[0] = (major << 5) | 25;
    new DataView(encoded.buffer).setUint16(1, value);
    return encoded;
  }
  if (value <= 0xffff_ffff) {
    const encoded = new Uint8Array(5);
    encoded[0] = (major << 5) | 26;
    new DataView(encoded.buffer).setUint32(1, value);
    return encoded;
  }
  return concatBytes([
    new Uint8Array([(major << 5) | 27]),
    unsignedInt64(value),
  ]);
}

function encodeTestCbor(value: TestCborValue): Uint8Array {
  if (typeof value === "number") return cborHead(0, value);
  if (typeof value === "string") {
    const encoded = textEncoder.encode(value);
    return concatBytes([cborHead(3, encoded.length), encoded]);
  }
  if (value instanceof Uint8Array) {
    return concatBytes([cborHead(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concatBytes([cborHead(4, value.length), ...value.map(encodeTestCbor)]);
  }
  const entries = [...value.entries()].map(([key, entryValue]) => ({
    key: encodeTestCbor(key),
    value: encodeTestCbor(entryValue),
  }));
  entries.sort(({ key: a }, { key: b }) => {
    const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
      if (a[index] !== b[index]) return a[index] - b[index];
    }
    return a.length - b.length;
  });
  return concatBytes([
    cborHead(5, entries.length),
    ...entries.flatMap(({ key, value: entryValue }) => [key, entryValue]),
  ]);
}

function decodeTestCbor(bytes: Uint8Array): unknown {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const parseLength = (
    additional: number,
    offset: number,
  ): { length: number; offset: number } => {
    if (additional < 24) return { length: additional, offset };
    if (additional === 24) return { length: bytes[offset], offset: offset + 1 };
    if (additional === 25) {
      return { length: view.getUint16(offset), offset: offset + 2 };
    }
    if (additional === 26) {
      return { length: view.getUint32(offset), offset: offset + 4 };
    }
    if (additional === 27) {
      const value = view.getBigUint64(offset);
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("test CBOR integer is too large");
      }
      return { length: Number(value), offset: offset + 8 };
    }
    throw new Error("unsupported test CBOR length");
  };
  const parse = (start: number): { value: unknown; offset: number } => {
    const initial = bytes[start];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (major === 7 && (additional === 20 || additional === 21)) {
      return { value: additional === 21, offset: start + 1 };
    }
    if (major === 7 && additional === 22) {
      return { value: null, offset: start + 1 };
    }
    const decoded = parseLength(additional, start + 1);
    if (major === 0) return { value: decoded.length, offset: decoded.offset };
    if (major === 1) return { value: -1 - decoded.length, offset: decoded.offset };
    if (major === 2) {
      const end = decoded.offset + decoded.length;
      return { value: bytes.slice(decoded.offset, end), offset: end };
    }
    if (major === 3) {
      const end = decoded.offset + decoded.length;
      return {
        value: new TextDecoder().decode(bytes.slice(decoded.offset, end)),
        offset: end,
      };
    }
    if (major === 4) {
      const value: unknown[] = [];
      let offset = decoded.offset;
      for (let index = 0; index < decoded.length; index += 1) {
        const item = parse(offset);
        value.push(item.value);
        offset = item.offset;
      }
      return { value, offset };
    }
    if (major === 5) {
      const value = new Map<unknown, unknown>();
      let offset = decoded.offset;
      for (let index = 0; index < decoded.length; index += 1) {
        const key = parse(offset);
        const entry = parse(key.offset);
        value.set(key.value, entry.value);
        offset = entry.offset;
      }
      return { value, offset };
    }
    throw new Error("unsupported test CBOR value");
  };
  const decoded = parse(0);
  if (decoded.offset !== bytes.length) throw new Error("trailing test CBOR bytes");
  return decoded.value;
}

function cborMap(value: unknown): Map<unknown, unknown> {
  if (!(value instanceof Map)) throw new Error("expected a CBOR map");
  return value;
}

function cborBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error("expected CBOR bytes");
  return value;
}

function katEpochFixture(): {
  certificate: Uint8Array;
  epochId: string;
  epochIdBytes: number[];
  productId: string;
  rootVerifyingKeyHex: string;
} {
  const chain = kat.chains[0];
  const certificate = new Uint8Array(hexBytes(chain.epoch_envelope));
  const envelope = cborMap(decodeTestCbor(certificate));
  const certificateBody = cborMap(decodeTestCbor(cborBytes(envelope.get(3))));
  const epochIdBytes = [...cborBytes(certificateBody.get(2))];
  return {
    certificate,
    epochId: hexId(epochIdBytes),
    epochIdBytes,
    productId: chain.product_id,
    rootVerifyingKeyHex: chain.root_verifying_key,
  };
}

function u32(value: number): Uint8Array {
  const encoded = new Uint8Array(4);
  new DataView(encoded.buffer).setUint32(0, value);
  return encoded;
}

async function generateDeviceKeys(): Promise<DeviceKeys> {
  const keys = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return {
    privateKey: keys.privateKey,
    verifyingKey: [...new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey))],
  };
}

async function signDeviceProof(
  domain: "ar" | "validate-request" | "heartbeat-request" | "deactivate-request",
  proofInput: Uint8Array,
  privateKey: CryptoKey,
): Promise<number[]> {
  const context = concatBytes([
    textEncoder.encode(`copylocker/v1/${domain}`),
    new Uint8Array([0]),
    new Uint8Array(suiteId),
    textEncoder.encode(productId),
  ]);
  const toBeSigned = concatBytes([
    textEncoder.encode("copylocker/hybrid-sig/v1"),
    u32(context.length),
    context,
    await sha256(proofInput),
  ]);
  const message = new Uint8Array(toBeSigned.byteLength);
  message.set(toBeSigned);
  return [
    ...new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, message)),
  ];
}

function activationRequestWithoutProof(
  deviceKemEk: number[],
  deviceSigVk: number[],
  nonce: number[],
  licenseKey = activationLicenseKey,
): Map<number, TestCborValue> {
  const credential = new Map<number, TestCborValue>([[0, licenseKey]]);
  const clientInfo = new Map<number, TestCborValue>([
    [0, "1.2.3"],
    [1, "0.1.0"],
    [2, "macos"],
    [3, "arm64"],
    [4, "build-validate"],
    [5, "rel_1"],
    [6, 1],
    [7, [new Uint8Array(suiteId)]],
    [8, [1]],
  ]);
  return new Map<number, TestCborValue>([
    [0, 1],
    [1, new Uint8Array(suiteId)],
    [2, productId],
    [3, credential],
    [4, new Uint8Array(32).fill(7)],
    [6, new Uint8Array(deviceKemEk)],
    [7, new Uint8Array(nonce)],
    [8, 1_700_000_000],
    [9, clientInfo],
    [11, new Uint8Array(deviceSigVk)],
  ]);
}

async function activationRequestCbor(
  deviceKemEk: number[],
  keys: DeviceKeys,
  fingerprintByte = 7,
  licenseKey = activationLicenseKey,
): Promise<Uint8Array> {
  const nonce = new Array<number>(32).fill(71);
  const request = activationRequestWithoutProof(
    deviceKemEk,
    keys.verifyingKey,
    nonce,
    licenseKey,
  );
  request.set(4, new Uint8Array(32).fill(fingerprintByte));
  const proofInput = encodeTestCbor(request);
  request.set(
    12,
    new Uint8Array(await signDeviceProof("ar", proofInput, keys.privateKey)),
  );
  return encodeTestCbor(request);
}

function postActivation(
  body: Uint8Array,
  idempotencyKey?: string,
): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/cbor",
    "X-CL-Proto": "1",
  };
  if (idempotencyKey !== undefined) {
    headers["Idempotency-Key"] = idempotencyKey;
  }
  return exports.default.fetch("https://copylocker.test/v1/activate", {
    method: "POST",
    headers,
    body: body.slice(),
  });
}

async function protocolErrorCode(response: Response): Promise<unknown> {
  const body = cborMap(
    decodeTestCbor(new Uint8Array(await response.arrayBuffer())),
  );
  return body.get(0);
}

async function verifyFastArtifact(
  domain: "validation-ticket" | "kill-order",
  tbs: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const verifyingKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(fastEpochVerifyingKey),
    "Ed25519",
    false,
    ["verify"],
  );
  const context = concatBytes([
    textEncoder.encode(`copylocker/v1/${domain}`),
    new Uint8Array([0]),
    new Uint8Array(suiteId),
    textEncoder.encode(productId),
  ]);
  const signed = concatBytes([
    textEncoder.encode("copylocker/hybrid-sig/v1"),
    u32(context.length),
    context,
    await sha256(tbs),
  ]);
  const signatureCopy = new Uint8Array(signature.byteLength);
  signatureCopy.set(signature);
  const signedCopy = new Uint8Array(signed.byteLength);
  signedCopy.set(signed);
  return crypto.subtle.verify("Ed25519", verifyingKey, signatureCopy, signedCopy);
}

function lifecycleProofInput(
  licenseId: number[],
  machineId: number[],
  nonce: number[],
): Uint8Array {
  return encodeTestCbor(
    new Map<number, TestCborValue>([
      [0, 1],
      [1, new Uint8Array(suiteId)],
      [2, new Uint8Array(licenseId)],
      [3, new Uint8Array(machineId)],
      [4, new Uint8Array(nonce)],
      [5, 1_700_000_000],
    ]),
  );
}

function lifecycleRequestCbor(
  licenseId: number[],
  machineId: number[],
  nonce: number[],
  proof: number[],
): Uint8Array {
  return encodeTestCbor(
    new Map<number, TestCborValue>([
      [0, 1],
      [1, new Uint8Array(suiteId)],
      [2, new Uint8Array(licenseId)],
      [3, new Uint8Array(machineId)],
      [4, new Uint8Array(nonce)],
      [5, 1_700_000_000],
      [6, new Uint8Array(proof)],
    ]),
  );
}

async function lifecycleAuthentication(
  domain: "heartbeat-request" | "deactivate-request",
  licenseId: number[],
  machineId: number[],
  nonce: number[],
  privateKey: CryptoKey,
) {
  const proofInput = lifecycleProofInput(licenseId, machineId, nonce);
  return {
    license_id: licenseId,
    machine_id: machineId,
    suite_id: suiteId,
    nonce,
    proof_input: [...proofInput],
    proof: await signDeviceProof(domain, proofInput, privateKey),
  };
}

function validateProofInput(
  licenseId: number[],
  machineId: number[],
  nonce: number[],
  knownRevocationEpoch = 0,
): Uint8Array {
  const clientInfo = new Map<number, TestCborValue>([
    [0, "1.2.3"],
    [1, "0.1.0"],
    [2, "macos"],
    [3, "arm64"],
    [4, "build-validate"],
    [5, "rel_1"],
    [6, 1],
    [7, [new Uint8Array(suiteId)]],
    [8, [1]],
  ]);
  return encodeTestCbor(
    new Map<number, TestCborValue>([
      [0, 1],
      [1, new Uint8Array(suiteId)],
      [2, new Uint8Array(machineId)],
      [3, new Uint8Array(32).fill(7)],
      [4, new Uint8Array(nonce)],
      [5, 1_700_000_000],
      [6, knownRevocationEpoch],
      [7, clientInfo],
      [10, 0],
      [12, new Uint8Array(licenseId)],
    ]),
  );
}

function validateRequestCbor(
  licenseId: number[],
  machineId: number[],
  nonce: number[],
  proof: number[],
  knownRevocationEpoch = 0,
): Uint8Array {
  const clientInfo = new Map<number, TestCborValue>([
    [0, "1.2.3"],
    [1, "0.1.0"],
    [2, "macos"],
    [3, "arm64"],
    [4, "build-validate"],
    [5, "rel_1"],
    [6, 1],
    [7, [new Uint8Array(suiteId)]],
    [8, [1]],
  ]);
  return encodeTestCbor(
    new Map<number, TestCborValue>([
      [0, 1],
      [1, new Uint8Array(suiteId)],
      [2, new Uint8Array(machineId)],
      [3, new Uint8Array(32).fill(7)],
      [4, new Uint8Array(nonce)],
      [5, 1_700_000_000],
      [6, knownRevocationEpoch],
      [7, clientInfo],
      [8, new Uint8Array(proof)],
      [10, 0],
      [12, new Uint8Array(licenseId)],
    ]),
  );
}

function licenseObject(value: number): {
  licenseId: number[];
  stub: DurableObjectStub;
} {
  const licenseId = licenseBytes(value);
  const name = licenseId.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return { licenseId, stub: env.LICENSE.getByName(name) };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy));
}

async function activationKeyHmac(
  keyBytes: number[] = activationLicenseKeyBytes,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(32).fill(9),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new Uint8Array(keyBytes),
    ),
  );
}

async function seedAdminToken(
  token: string,
  scopes: string[] = ["revoke"],
  vendorId = "vendor_1",
  actor = "admin@example.test",
): Promise<void> {
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(32).fill(4),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const tokenHmac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, textEncoder.encode(token)),
  );
  await env.DB.prepare(
    "INSERT INTO admin_tokens(\
       id, vendor_id, token_hmac, actor, scopes_json, not_before, expires_at, created_at\
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      `token_${token.slice(-8)}`,
      vendorId,
      tokenHmac,
      actor,
      JSON.stringify(scopes),
      0,
      4_000_000_000,
      1,
    )
    .run();
}

async function seedEpochProduct(vendorId = "vendor_epoch_api"): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
    ).bind(vendorId, "Epoch API Vendor", "epoch_salt", 1),
    env.DB.prepare(
      "INSERT INTO products(\
         id, vendor_id, name, min_suite_id, min_proto_ver, min_sdk_version, created_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      kat.chains[0].product_id,
      vendorId,
      "KAT Product",
      new Uint8Array(suiteId),
      1,
      "0.1.0",
      1,
    ),
  ]);
}

async function sha256Parts(parts: Uint8Array[]): Promise<Uint8Array> {
  const framed = parts.flatMap((part) => [unsignedInt64(part.length), part]);
  return sha256(concatBytes(framed));
}

function auditR2Key(occurredAt: number, shard: number, seq: number): string {
  const [date] = new Date(occurredAt * 1000).toISOString().split("T");
  const [year, month, day] = date.split("-");
  return `audit/${year}/${month}/${day}/${shard}/${seq}.cbor`;
}

async function auditEvent(
  shard: number,
  seq: number,
  envelope: number[],
): Promise<AuditArchiveEvent> {
  const occurredAt = 1_700_000_000;
  const kind = 4;
  const productId = "product_1";
  const subject = machineBytes(900 + seq);
  const epochId = new Array<number>(8).fill(3);
  const prevHash = seq === 1 ? new Array<number>(32).fill(0) : new Array<number>(32).fill(seq - 1);
  const digest = await sha256(new Uint8Array(envelope));
  const hash = await sha256Parts([
    textEncoder.encode("copylocker/issuer-audit/v1"),
    new Uint8Array([shard]),
    signedInt64(seq),
    signedInt64(occurredAt),
    new Uint8Array([kind]),
    textEncoder.encode(productId),
    new Uint8Array(subject),
    new Uint8Array(epochId),
    digest,
    new Uint8Array(prevHash),
  ]);
  return {
    event: "audit_archive",
    schema_version: 1,
    shard,
    seq,
    occurred_at: occurredAt,
    kind,
    product_id: productId,
    subject,
    epoch_id: epochId,
    digest: [...digest],
    prev_hash: prevHash,
    hash: [...hash],
    envelope,
    r2_key: auditR2Key(occurredAt, shard, seq),
  };
}

function killOrderTbs(machineId: number[]): number[] {
  return [
    0xa7,
    0x00,
    0x01,
    0x01,
    0x44,
    0x01,
    0x00,
    0x00,
    0x01,
    0x02,
    0x50,
    ...machineId,
    0x03,
    0x58,
    0x20,
    ...new Array<number>(32).fill(5),
    0x04,
    0x01,
    0x05,
    0x01,
    0x07,
    0x01,
  ];
}

function revocationBatchTbs(
  fromEpoch: number,
  toEpoch: number,
  revokedLicenseIds: number[][],
  revokedMachineIds: number[][],
  protoVer = 1,
): number[] {
  return [
    ...encodeTestCbor(
      new Map<number, TestCborValue>([
        [0, protoVer],
        [1, new Uint8Array(suiteId)],
        [2, fromEpoch],
        [3, toEpoch],
        [4, 1_700_000_000],
        [5, revokedLicenseIds.map((id) => new Uint8Array(id))],
        [6, revokedMachineIds.map((id) => new Uint8Array(id))],
        [7, []],
      ]),
    ),
  ];
}

function reserveBody(
  value: number,
  idempotencyKey = `reserve-${value}`,
  deviceSigVk: number[] = [4, 5, 6],
) {
  return {
    idempotency_key: idempotencyKey,
    machine_id: machineBytes(value),
    fingerprint: new Array<number>(32).fill(value),
    device_kem_ek: [1, 2, 3],
    device_sig_vk: deviceSigVk,
    activation_path: "online",
    release_id: "rel_1",
    variant_id: 1,
    refresh_after: 2_000_000_000,
    not_after: 0,
    build_fp: `build-${value}`,
    app_version: "1.2.3",
    os: "macos",
    arch: "arm64",
    sdk_version: "0.1.0",
    geo: "SG",
  };
}

function postJson(
  stub: DurableObjectStub,
  path: string,
  value: unknown,
): Promise<Response> {
  return stub.fetch(`https://durable.test${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  });
}

function postAdminRevoke(
  collection: "licenses" | "machines",
  target: number[],
  token: string | undefined,
  dryRun?: boolean,
  idempotencyKey?: string,
  body: unknown = {},
): Promise<Response> {
  const query = dryRun === undefined ? "" : `?dry_run=${String(dryRun)}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  if (idempotencyKey !== undefined) headers["Idempotency-Key"] = idempotencyKey;
  return exports.default.fetch(
    `https://copylocker.test/v1/admin/${collection}/${hexId(target)}/revoke${query}`,
    { method: "POST", headers, body: JSON.stringify(body) },
  );
}

function adminJson(
  path: string,
  method: "GET" | "POST" | "PATCH",
  token: string,
  body?: unknown,
  idempotencyKey?: string,
): Promise<Response> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (idempotencyKey !== undefined) headers["Idempotency-Key"] = idempotencyKey;
  return exports.default.fetch(`https://copylocker.test/v1/admin${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function postEpochRevoke(
  epochId: string,
  token: string,
  dryRun?: boolean,
  idempotencyKey?: string,
  body: unknown = {},
): Promise<Response> {
  const query = dryRun === undefined ? "" : `?dry_run=${String(dryRun)}`;
  return adminJson(
    `/epochs/${epochId}/revoke${query}`,
    "POST",
    token,
    body,
    idempotencyKey,
  );
}

async function seedProjectedMachine(
  licenseId: number[],
  machineId: number[],
  status: "active" | "pending" | "released" | "revoked" = "active",
): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO machines(\
       id, license_id, fingerprint, status, activation_path, first_seen_at, proj_version\
     ) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      new Uint8Array(machineId),
      new Uint8Array(licenseId),
      new Uint8Array(32).fill(machineId.at(-1) ?? 0),
      status,
      "online",
      1,
      1,
    )
    .run();
}

async function clearAdminRevocationState(licenseId: number[]): Promise<void> {
  await env.DB.exec("DELETE FROM audit_index WHERE seq < 0");
  await env.DB.exec("DELETE FROM admin_audit_events");
  await env.DB.exec("DELETE FROM revocations");
  await env.DB.exec("DELETE FROM sqlite_sequence WHERE name = 'revocations'");
  await env.CACHE.delete("rev:epoch");
  const keys = await env.CACHE.list({ prefix: "rev:batch:" });
  await Promise.all(keys.keys.map(({ name }) => env.CACHE.delete(name)));
  const auditObjects = await env.ARCHIVE.list({ prefix: "audit-admin/" });
  await Promise.all(auditObjects.objects.map(({ key }) => env.ARCHIVE.delete(key)));
  const issuer = env.ISSUER.getByName(`issuer-${issuerShard(licenseId)}`);
  await runInDurableObject(issuer, async (_instance, state) => {
    state.storage.sql.exec("DELETE FROM issuance_log");
    state.storage.sql.exec("DELETE FROM outbox");
    state.storage.sql.exec("DELETE FROM idem");
  });
  await clearAdminAuditDo();
}

async function clearAdminAuditDo(): Promise<void> {
  const adminAudit = env.ADMIN_AUDIT.getByName("global");
  await runInDurableObject(adminAudit, async (_instance, state) => {
    state.storage.sql.exec("DELETE FROM events");
    state.storage.sql.exec("DELETE FROM chain_base");
  });
}

async function initLicense(
  stub: DurableObjectStub,
  licenseId: number[],
  seats: number,
): Promise<void> {
  const response = await postJson(stub, "/init", {
    license_id: licenseId,
    product_id: productId,
    suite_id: suiteId,
    seats,
  });
  expect(response.status).toBe(200);
}

function projectionEvent(
  licenseId: number[],
  version: number,
  status: MachineStatus,
  seatsUsed: number,
): ProjectionEvent {
  return {
    event: "license_projection",
    schema_version: 1,
    license_id: licenseId,
    license_status: "active",
    seats_used: seatsUsed,
    last_seen_at: 1_700_000_000 + version,
    machine: {
      machine_id: machineBytes(42),
      fingerprint: new Array<number>(32).fill(version),
      status,
      activation_path: "online",
      first_seen_at: 1_700_000_000,
      last_seen_at: 1_700_000_000 + version,
      os: "macos",
      arch: "arm64",
      app_version: `1.0.${version}`,
      sdk_version: "0.1.0",
      release_id: "rel_1",
      variant_id: 1,
      build_fp: `build-${version}`,
      geo_country: "SG",
      suspicion: version,
    },
    proj_version: version,
    occurred_at: 1_700_000_000 + version,
  };
}

async function dispatchEvents(events: unknown[], idPrefix: string) {
  const batch = createMessageBatch(
    "copylocker-events",
    events.map((body, index) => ({
      id: `${idPrefix}-${index}`,
      timestamp: new Date(1_700_000_000_000 + index),
      attempts: 1,
      body,
    })),
  );
  const context = createExecutionContext();
  const worker = new WorkerEntrypoint(context, env);

  await worker.queue(batch);
  return getQueueResult(batch, context);
}

async function dispatchProjectionEvents(events: unknown[]) {
  return dispatchEvents(events, "projection");
}

async function runScheduledReconciliation(): Promise<void> {
  const context = createExecutionContext();
  const worker = new WorkerEntrypoint(context, env);
  await worker.scheduled(createScheduledController());
}

async function seedProjectedLicense(
  licenseId: number[],
  keyHmac: Uint8Array = new Uint8Array(licenseId),
  seats = 3,
): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
    ).bind("vendor_1", "Vendor", "salt_ref", 1),
    env.DB.prepare(
      "INSERT OR IGNORE INTO products(\
         id, vendor_id, name, min_suite_id, min_proto_ver, min_sdk_version, created_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind("product_1", "vendor_1", "Product", new Uint8Array([1]), 1, "0.1.0", 1),
    env.DB.prepare(
      "INSERT OR IGNORE INTO policies(\
         id, product_id, name, entitlement_json, validity_json, version_scope_json, \
         seats, mode, refresh_after_sec, grace_seconds, created_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      "policy_1",
      "product_1",
      "Policy",
      '{"tier":"pro"}',
      '{"kind":"perpetual"}',
      '{"kind":"unlimited"}',
      3,
      0,
      3600,
      3600,
      1,
      1,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO features(product_id, id, label, created_at) VALUES (?, ?, ?, ?)",
    ).bind("product_1", "feature.alpha", "Alpha", 1),
    env.DB.prepare(
      "INSERT OR IGNORE INTO tiers(\
         product_id, id, label, rank, groups_json, features_json, limits_json\
       ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind("product_1", "pro", "Pro", 1, "[]", '["feature.alpha"]', "{}"),
    env.DB.prepare(
      "INSERT INTO licenses(\
         id, product_id, policy_id, key_hmac, status, seats_override, catalog_version, \
         created_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      new Uint8Array(licenseId),
      "product_1",
      "policy_1",
      keyHmac,
      "active",
      seats,
      1,
      1,
      1,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO releases(\
         id, product_id, app_version, variant_id, variant_params, build_fingerprint, \
         channel, status, min_sdk_version, proto_ver, suite_id, published_at, created_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      "rel_1",
      "product_1",
      "1.2.3",
      1,
      new Uint8Array(encryptedVariantParams),
      "build-validate",
      "stable",
      "active",
      "0.1.0",
      1,
      new Uint8Array(suiteId),
      1,
      1,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO release_feature_keks(\
         release_id, product_id, feature_id, key_version, encrypted_kek, created_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      "rel_1",
      "product_1",
      "feature.alpha",
      1,
      new Uint8Array(encryptedAssetKek),
      1,
      1,
    ),
    env.DB.prepare(
      "INSERT OR IGNORE INTO epochs(\
         id, product_scope, suite_id, vk_pq, vk_trad, vk_fast, cert, \
         not_before, not_after, created_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      new Uint8Array(8).fill(3),
      null,
      new Uint8Array(suiteId),
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array(fastEpochVerifyingKey),
      new Uint8Array([3]),
      0,
      4_000_000_000,
      1,
    ),
  ]);
}

async function seedBillingLicense(licenseId: number[]): Promise<void> {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
  const suffix = String(licenseId.at(-1) ?? 0);
  const policyId = `policy_billing_${suffix}`;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT OR IGNORE INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
    ).bind("vendor_1", "Vendor", "salt_ref", 1),
    env.DB.prepare(
      "INSERT OR IGNORE INTO products(\
         id, vendor_id, name, min_suite_id, min_proto_ver, min_sdk_version, created_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind("product_1", "vendor_1", "Product", new Uint8Array([1]), 1, "0.1.0", 1),
    env.DB.prepare(
      "INSERT INTO policies(\
         id, product_id, name, entitlement_json, validity_json, version_scope_json, \
         seats, mode, refresh_after_sec, grace_seconds, created_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      policyId,
      "product_1",
      "Billing policy",
      '{"tier":"pro"}',
      '{"kind":"subscription","period_secs":2592000,"dunning_grace_secs":604800,"fallback":null}',
      '{"kind":"unlimited"}',
      1,
      0,
      604800,
      604800,
      1,
      1,
    ),
    env.DB.prepare(
      "INSERT INTO licenses(\
         id, product_id, policy_id, key_hmac, status, catalog_version, created_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      new Uint8Array(licenseId),
      "product_1",
      policyId,
      new Uint8Array(licenseId),
      "active",
      1,
      1,
      1,
    ),
  ]);
}

describe("worker runtime", () => {
  it("serves the health endpoint", async () => {
    const response = await exports.default.fetch("https://copylocker.test/health");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({
      ok: true,
      service: "copylocker",
      version: "0.1.0",
    });
  });

  it("verifies and accepts Stripe, Paddle, and Lemon Squeezy webhooks", async () => {
    const now = Math.floor(Date.now() / 1000);
    const fixtures = [
      {
        provider: "stripe" as const,
        secret: "stripe-test-secret",
        payload: {
          id: "evt_stripe_signature",
          type: "invoice.payment_failed",
          created: now,
          data: { object: { subscription: "sub_signature_stripe" } },
        },
      },
      {
        provider: "paddle" as const,
        secret: "paddle-test-secret",
        payload: {
          event_id: "evt_paddle_signature",
          event_type: "subscription.past_due",
          occurred_at: now,
          data: { id: "sub_signature_paddle" },
        },
      },
      {
        provider: "lemonsqueezy" as const,
        secret: "lemon-test-secret",
        payload: {
          meta: {
            webhook_id: "evt_lemon_signature",
            event_name: "subscription_payment_failed",
            event_created_at: now,
          },
          data: { id: "sub_signature_lemon", attributes: {} },
        },
      },
    ];

    for (const fixture of fixtures) {
      const response = await postSignedWebhook(
        fixture.provider,
        fixture.payload,
        fixture.secret,
      );
      expect(response.status, fixture.provider).toBe(202);
      await expect(response.json()).resolves.toEqual({ ok: true, accepted: true });
    }

    const rejected = await exports.default.fetch(
      "https://copylocker.test/webhooks/stripe",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Stripe-Signature": `t=${now},v1=${"00".repeat(32)}`,
        },
        body: JSON.stringify(fixtures[0]?.payload),
      },
    );
    expect(rejected.status).toBe(401);
    expect(rejected.headers.get("cache-control")).toBe("no-store");
  });

  it("applies billing events once and ignores stale state transitions", async () => {
    const licenseId = new Array<number>(16).fill(73);
    const externalId = "sub_billing_e2e";
    const start = 1_800_000_000;
    const month = 30 * 86_400;
    const dunning = 7 * 86_400;
    await seedBillingLicense(licenseId);

    const started: BillingWebhookEvent = {
      event: "billing_webhook",
      schema_version: 1,
      provider: "stripe",
      event_id: "evt_billing_started",
      event_ts: start,
      external_id: externalId,
      event_kind: {
        kind: "started",
        license_id: licenseId,
        period_start: start,
        period_end: start + month,
        billing_period: "monthly",
      },
    };
    const startedResult = await dispatchEvents(
      [started, started, started],
      "billing-started",
    );
    expect(startedResult.retryMessages).toEqual([]);

    const initial = await env.DB.prepare(
      "SELECT state, continuous_paid_months, current_period_end FROM subscriptions \
       WHERE provider = ? AND external_id = ?",
    )
      .bind("stripe", externalId)
      .first<{
        state: string;
        continuous_paid_months: number;
        current_period_end: number;
      }>();
    expect(initial).toEqual({
      state: "active",
      continuous_paid_months: 0,
      current_period_end: start + month,
    });

    const renewed: BillingWebhookEvent = {
      ...started,
      event_id: "evt_billing_renewed",
      event_ts: start + month,
      event_kind: {
        kind: "renewed",
        period_start: start + month,
        period_end: start + 2 * month,
      },
    };
    const renewedResult = await dispatchEvents(
      [renewed, renewed, renewed],
      "billing-renewed",
    );
    expect(renewedResult.retryMessages).toEqual([]);

    const staleFailure: BillingWebhookEvent = {
      ...started,
      event_id: "evt_billing_stale_failure",
      event_ts: start + 1,
      event_kind: { kind: "payment_failed" },
    };
    expect((await dispatchEvents([staleFailure], "billing-stale")).retryMessages).toEqual([]);

    const afterStale = await env.DB.prepare(
      "SELECT state, continuous_paid_months, current_period_end FROM subscriptions \
       WHERE provider = ? AND external_id = ?",
    )
      .bind("stripe", externalId)
      .first<{
        state: string;
        continuous_paid_months: number;
        current_period_end: number;
      }>();
    expect(afterStale).toEqual({
      state: "active",
      continuous_paid_months: 1,
      current_period_end: start + 2 * month,
    });

    const failed: BillingWebhookEvent = {
      ...started,
      event_id: "evt_billing_failed",
      event_ts: start + month + 1,
      event_kind: { kind: "payment_failed" },
    };
    expect((await dispatchEvents([failed], "billing-failed")).retryMessages).toEqual([]);
    const pastDue = await env.DB.prepare(
      "SELECT state, dunning_until FROM subscriptions WHERE license_id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{ state: string; dunning_until: number }>();
    expect(pastDue).toEqual({
      state: "past_due",
      dunning_until: failed.event_ts + dunning,
    });

    const refunded: BillingWebhookEvent = {
      ...started,
      event_id: "evt_billing_refunded",
      event_ts: failed.event_ts + 1,
      event_kind: { kind: "refund_reported" },
    };
    expect((await dispatchEvents([refunded], "billing-refunded")).retryMessages).toEqual([]);
    const review = await env.DB.prepare(
      "SELECT s.state, s.refund_observe_until, l.status AS license_status \
       FROM subscriptions s JOIN licenses l ON l.id = s.license_id \
       WHERE s.license_id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{
        state: string;
        refund_observe_until: number;
        license_status: string;
      }>();
    expect(review).toEqual({
      state: "suspended",
      refund_observe_until: refunded.event_ts + 7 * 86_400,
      license_status: "suspended",
    });

    const eventCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM billing_events WHERE provider = ?",
    )
      .bind("stripe")
      .first<{ count: number }>();
    expect(eventCount?.count).toBe(5);
    const license = await env.DB.prepare(
      "SELECT expires_at FROM licenses WHERE id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{ expires_at: number }>();
    expect(license?.expires_at).toBe(start + 2 * month + dunning);
  });

  it("reconciles elapsed dunning and cancellation deadlines", async () => {
    const now = Math.floor(Date.now() / 1000);
    const month = 30 * 86_400;
    const dunning = 7 * 86_400;
    const dunningLicense = new Array<number>(16).fill(74);
    const cancelLicense = new Array<number>(16).fill(75);
    await seedBillingLicense(dunningLicense);
    await seedBillingLicense(cancelLicense);

    const dunningStart = now - 40 * 86_400;
    const dunningExternal = "sub_due_dunning";
    const dunningStarted: BillingWebhookEvent = {
      event: "billing_webhook",
      schema_version: 1,
      provider: "stripe",
      event_id: "evt_due_dunning_start",
      event_ts: dunningStart,
      external_id: dunningExternal,
      event_kind: {
        kind: "started",
        license_id: dunningLicense,
        period_start: dunningStart,
        period_end: dunningStart + month,
        billing_period: "monthly",
      },
    };
    const dunningFailed: BillingWebhookEvent = {
      ...dunningStarted,
      event_id: "evt_due_dunning_failure",
      event_ts: dunningStart + month,
      event_kind: { kind: "payment_failed" },
    };

    const cancelStart = now - 35 * 86_400;
    const cancelExternal = "sub_due_cancel";
    const cancelStarted: BillingWebhookEvent = {
      ...dunningStarted,
      event_id: "evt_due_cancel_start",
      event_ts: cancelStart,
      external_id: cancelExternal,
      event_kind: {
        kind: "started",
        license_id: cancelLicense,
        period_start: cancelStart,
        period_end: cancelStart + month,
        billing_period: "monthly",
      },
    };
    const canceled: BillingWebhookEvent = {
      ...cancelStarted,
      event_id: "evt_due_cancel",
      event_ts: cancelStart + 10 * 86_400,
      event_kind: { kind: "cancel_at_period_end" },
    };

    const seeded = await dispatchEvents(
      [dunningStarted, dunningFailed, cancelStarted, canceled],
      "billing-due",
    );
    expect(seeded.retryMessages).toEqual([]);
    await runScheduledReconciliation();

    const states = await env.DB.prepare(
      "SELECT external_id, state FROM subscriptions WHERE external_id IN (?, ?) \
       ORDER BY external_id",
    )
      .bind(cancelExternal, dunningExternal)
      .all<{ external_id: string; state: string }>();
    expect(states.results).toEqual([
      { external_id: cancelExternal, state: "expired" },
      { external_id: dunningExternal, state: "suspended" },
    ]);
    const syntheticEvents = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM billing_events WHERE event_id LIKE 'system:%'",
    ).first<{ count: number }>();
    expect(syntheticEvents?.count).toBe(2);
    expect(dunningStart + month + dunning).toBeLessThan(now);
  });

  it("finalizes a refund through the signed Admin revocation path", async () => {
    const licenseId = new Array<number>(16).fill(76);
    const now = Math.floor(Date.now() / 1000);
    await seedProjectedLicense(licenseId);
    await env.DB.prepare(
      "UPDATE policies SET validity_json = ? WHERE id = 'policy_1'",
    )
      .bind(
        '{"kind":"subscription","period_secs":2592000,"dunning_grace_secs":604800,"fallback":{"after_months":12,"scope_at":"earned_at"}}',
      )
      .run();
    await env.DB.prepare(
      "INSERT INTO subscriptions(\
         license_id, provider, external_id, state, billing_period, current_period_start, \
         current_period_end, continuous_paid_months, fallback_earned_at, updated_at, \
         refund_observe_until\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(
        new Uint8Array(licenseId),
        "stripe",
        "sub_refund_finalize",
        "suspended",
        "monthly",
        now - 40 * 86_400,
        now - 10 * 86_400,
        12,
        now - 20 * 86_400,
        now - 8 * 86_400,
        now - 1,
      )
      .run();

    await runScheduledReconciliation();

    const subscription = await env.DB.prepare(
      "SELECT state, fallback_earned_at, refund_observe_until FROM subscriptions \
       WHERE license_id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{
        state: string;
        fallback_earned_at: number | null;
        refund_observe_until: number | null;
      }>();
    expect(subscription).toEqual({
      state: "expired",
      fallback_earned_at: null,
      refund_observe_until: null,
    });
    const revocation = await env.DB.prepare(
      "SELECT reason, applied_at IS NOT NULL AS applied, published_at IS NOT NULL AS published \
       FROM revocations WHERE kind = 'license' AND target = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{ reason: number; applied: number; published: number }>();
    expect(revocation).toEqual({ reason: 5, applied: 1, published: 1 });
    expect(await env.CACHE.get("rev:epoch")).toBe("1");
    await clearAdminRevocationState(licenseId);
  });

  it("streams the signed key set from KV", async () => {
    const payload = new Uint8Array([0xa2, 0x00, 0x80, 0x01, 0x07]);
    await env.CACHE.put("keys:current", payload);

    const response = await exports.default.fetch("https://copylocker.test/v1/keys", {
      headers: { "X-CL-Proto": "1" },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/cbor");
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(payload);
  });

  it("streams the requested signed revocation batch from KV", async () => {
    const payload = new Uint8Array([0xa1, 0x00, 0x07]);
    await env.CACHE.put("rev:batch:7", payload);

    const response = await exports.default.fetch(
      "https://copylocker.test/v1/revocations?since=7",
      { headers: { "X-CL-Proto": "1" } },
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe(
      "public, max-age=31536000, immutable",
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(payload);
  });

  it("rejects a missing protocol version before binding access", async () => {
    const response = await exports.default.fetch("https://copylocker.test/v1/keys");

    expect(response.status).toBe(426);
    expect(response.headers.get("content-type")).toBe("application/cbor");
  });

  it("rejects an invalid revocation cursor", async () => {
    const response = await exports.default.fetch(
      "https://copylocker.test/v1/revocations?since=not-a-number",
      { headers: { "X-CL-Proto": "1" } },
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("serializes, replays, and verifies the unified Admin audit chain", async () => {
    await clearAdminAuditDo();
    const stub = env.ADMIN_AUDIT.getByName("global");
    const append = (requestId: string, target: string, status: string) => ({
      operation_id: `vendor_1/${requestId}`,
      occurred_at: 1_700_000_000,
      vendor_id: "vendor_1",
      actor: "admin@example.test",
      action: "license:suspend",
      target,
      request_id: requestId,
      before: { status: "active", version: 1 },
      after: { status, version: 2 },
      bootstrap_seq: 0,
      bootstrap_hash: new Array<number>(32).fill(0),
    });
    const firstInput = append("audit-append-first", "01".repeat(16), "suspended");
    const secondInput = append("audit-append-second", "02".repeat(16), "suspended");

    const responses = await Promise.all([
      postJson(stub, "/append", firstInput),
      postJson(stub, "/append", secondInput),
    ]);
    expect(responses.map(({ status }) => status).sort()).toEqual([201, 409]);
    const winnerIndex = responses.findIndex(({ status }) => status === 201);
    if (winnerIndex < 0) throw new Error("one append must win the initial chain head");
    const firstEvent = await responses[winnerIndex].json<AdminAuditEvent>();
    const loserInput = winnerIndex === 0 ? secondInput : firstInput;
    const retried = await postJson(stub, "/append", {
      ...loserInput,
      bootstrap_seq: firstEvent.seq,
      bootstrap_hash: firstEvent.hash,
    });
    expect(retried.status).toBe(201);
    const events = [firstEvent, await retried.json<AdminAuditEvent>()];
    events.sort((left, right) => left.seq - right.seq);
    expect(events.map(({ seq }) => seq)).toEqual([1, 2]);
    expect(events[0].schema_version).toBe(2);
    expect(events[0].prev_hash).toEqual(new Array<number>(32).fill(0));
    expect(events[1].prev_hash).toEqual(events[0].hash);

    const replay = await postJson(stub, "/append", firstInput);
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toEqual(
      events.find(({ request_id }) => request_id === "audit-append-first"),
    );
    const conflict = await postJson(stub, "/append", {
      ...firstInput,
      after: { status: "active", version: 2 },
    });
    expect(conflict.status).toBe(409);

    const verified = await postJson(stub, "/verify", events[0]);
    expect(verified.status).toBe(200);
    const tampered = await postJson(stub, "/verify", {
      ...events[0],
      actor: "other@example.test",
    });
    expect(tampered.status).toBe(400);
    await clearAdminAuditDo();
  });

  it("versions catalog and policy mutations through the recoverable Admin audit journal", async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    const product = "product_admin_api";
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
      ).bind("vendor_admin_api", "Admin API Vendor", "salt", 1),
      env.DB.prepare(
        "INSERT INTO products(\
           id, vendor_id, name, min_suite_id, min_proto_ver, min_sdk_version, created_at\
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        product,
        "vendor_admin_api",
        "Admin API Product",
        new Uint8Array(suiteId),
        1,
        "0.1.0",
        1,
      ),
    ]);
    const token = testAdminToken(31);
    await seedAdminToken(
      token,
      ["catalog:rw", "policies:rw"],
      "vendor_admin_api",
      "catalog-admin@example.test",
    );

    const feature = {
      product_id: product,
      id: "export.pdf",
      label: "PDF export",
      description: "Export a PDF document",
    };
    const featureResponse = await adminJson(
      "/catalog/features",
      "POST",
      token,
      feature,
      "catalog-feature-create",
    );
    expect(featureResponse.status).toBe(201);
    const featureResult = (await featureResponse.json()) as {
      catalog_version: number;
    };
    expect(featureResult.catalog_version).toBe(1);

    const replay = await adminJson(
      "/catalog/features",
      "POST",
      token,
      feature,
      "catalog-feature-create",
    );
    expect(replay.status).toBe(201);
    await expect(replay.json()).resolves.toEqual(featureResult);
    const conflict = await adminJson(
      "/catalog/features",
      "POST",
      token,
      { ...feature, label: "Different" },
      "catalog-feature-create",
    );
    expect(conflict.status).toBe(409);

    const groupResponse = await adminJson(
      "/catalog/groups",
      "POST",
      token,
      {
        product_id: product,
        id: "exports",
        label: "Exports",
        members: { includes: [], features: ["export.*"] },
      },
      "catalog-group-create",
    );
    expect(groupResponse.status).toBe(201);
    const tierResponse = await adminJson(
      "/catalog/tiers",
      "POST",
      token,
      {
        product_id: product,
        id: "pro",
        label: "Pro",
        rank: 10,
        groups: ["exports"],
        features: [],
        limits: { projects: 25 },
      },
      "catalog-tier-create",
    );
    expect(tierResponse.status).toBe(201);
    await expect(tierResponse.json()).resolves.toMatchObject({ catalog_version: 3 });

    const resolved = await adminJson("/catalog/resolve", "POST", token, {
      product_id: product,
      catalog_version: 3,
      entitlement: { tier: "pro" },
      at: 1_700_000_000,
    });
    expect(resolved.status).toBe(200);
    await expect(resolved.json()).resolves.toMatchObject({
      catalog_version: 3,
      entitlements: {
        features: ["export.pdf"],
        limits: { projects: 25 },
        tier_id: "pro",
      },
    });

    const policy = {
      id: "policy_admin_api",
      product_id: product,
      name: "Admin API policy",
      preset: null,
      entitlement: { tier: "pro" },
      validity: { kind: "perpetual" },
      version_scope: { kind: "unlimited" },
      seats: {
        seats: 1,
        max_transfers: null,
        transfer_window_secs: null,
        heartbeat_secs: null,
      },
      mode: "offline_hybrid",
      runtime: {
        refresh_after_secs: 604800,
        grace_secs: 1209600,
        fpr_tolerance: 70,
        allow_vm: true,
        allow_olk: false,
        allow_unbound_olk: false,
        vt_signature: "fast",
        offline_upgrade_policy: "require_online",
        preload_variants_n: 3,
        report_attrs: false,
      },
    };
    const createdPolicy = await adminJson(
      "/policies",
      "POST",
      token,
      policy,
      "policy-create",
    );
    expect(createdPolicy.status).toBe(201);
    await expect(createdPolicy.json()).resolves.toMatchObject({
      version: 1,
      policy: { id: "policy_admin_api", name: "Admin API policy" },
    });

    const updatedPolicy = await adminJson(
      "/policies/policy_admin_api",
      "PATCH",
      token,
      { ...policy, name: "Renamed policy" },
      "policy-update",
    );
    expect(updatedPolicy.status).toBe(200);
    await expect(updatedPolicy.json()).resolves.toMatchObject({
      version: 2,
      policy: { id: "policy_admin_api", name: "Renamed policy" },
    });
    const fetchedPolicy = await adminJson(
      "/policies/policy_admin_api",
      "GET",
      token,
    );
    expect(fetchedPolicy.status).toBe(200);
    await expect(fetchedPolicy.json()).resolves.toMatchObject({
      version: 2,
      policy: { name: "Renamed policy" },
    });

    const operations = await env.DB.prepare(
      "SELECT operation_id, completed_at FROM admin_operations ORDER BY created_at, operation_id",
    ).all<{ operation_id: string; completed_at: number | null }>();
    expect(operations.results).toHaveLength(5);
    expect(operations.results.every(({ completed_at }) => typeof completed_at === "number")).toBe(
      true,
    );
    const auditRows = await env.DB.prepare(
      "SELECT seq, event_json FROM admin_audit_events ORDER BY seq",
    ).all<{ seq: number; event_json: string }>();
    expect(auditRows.results.map(({ seq }) => seq)).toEqual([1, 2, 3, 4, 5]);
    const events = auditRows.results.map(
      ({ event_json }) => JSON.parse(event_json) as AdminAuditEvent,
    );
    expect(events[0].prev_hash).toEqual(new Array<number>(32).fill(0));
    for (let index = 1; index < events.length; index += 1) {
      expect(events[index].prev_hash).toEqual(events[index - 1].hash);
    }
    await env.DB.exec("DELETE FROM admin_audit_events");
    await clearAdminAuditDo();
  });

  it("uploads a verified Epoch and enforces replacement plus two-person revocation", async () => {
    const vendor = "vendor_epoch_api";
    const otherVendor = "vendor_epoch_other";
    const fixture = katEpochFixture();
    const replacementId = new Array<number>(8).fill(3);
    const replacementCertificate = new Uint8Array([0xa0]);
    await seedEpochProduct(vendor);
    await clearAdminAuditDo();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO epochs(\
         id, product_scope, suite_id, vk_pq, vk_trad, vk_fast, cert, \
         not_before, not_after, revoked_at, created_at\
       ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(
        new Uint8Array(replacementId),
        new Uint8Array(suiteId),
        new Uint8Array([1]),
        new Uint8Array([2]),
        new Uint8Array(fastEpochVerifyingKey),
        replacementCertificate,
        0,
        4_000_000_000,
        1,
        2,
      )
      .run();
    await env.DB.prepare("UPDATE epochs SET revoked_at = 1 WHERE id = ?")
      .bind(new Uint8Array(replacementId))
      .run();
    const token = testAdminToken(34);
    await seedAdminToken(
      token,
      ["epochs:rw", "revoke"],
      vendor,
      "first-epoch-admin@example.test",
    );

    const uploadBody = {
      certificate_hex: kat.chains[0].epoch_envelope,
      root_verifying_key_hex: fixture.rootVerifyingKeyHex,
    };
    const lastRootByte = Number.parseInt(fixture.rootVerifyingKeyHex.slice(-2), 16) ^ 1;
    const invalidRoot = `${fixture.rootVerifyingKeyHex.slice(0, -2)}${lastRootByte
      .toString(16)
      .padStart(2, "0")}`;
    const invalid = await adminJson(
      "/epochs",
      "POST",
      token,
      { ...uploadBody, root_verifying_key_hex: invalidRoot },
      "epoch-upload-invalid-root",
    );
    expect(invalid.status).toBe(422);
    await expect(invalid.json()).resolves.toMatchObject({
      error: { code: "invalid_epoch" },
    });

    const response = await adminJson(
      "/epochs",
      "POST",
      token,
      uploadBody,
      "epoch-upload-kat",
    );
    expect(response.status, await response.clone().text()).toBe(201);
    const uploaded = await response.json<{
      ok: boolean;
      version: number;
      epoch: {
        epoch_id: string;
        product_id: string;
        status: string;
        suite_id: string;
      };
    }>();
    expect(uploaded).toMatchObject({
      ok: true,
      version: 1,
      epoch: {
        epoch_id: fixture.epochId,
        product_id: fixture.productId,
        status: "expired",
        suite_id: "01000001",
      },
    });

    const replay = await adminJson(
      "/epochs",
      "POST",
      token,
      uploadBody,
      "epoch-upload-kat",
    );
    expect(replay.status).toBe(201);
    await expect(replay.json()).resolves.toEqual(uploaded);
    const conflictingReplay = await adminJson(
      "/epochs",
      "POST",
      token,
      {
        ...uploadBody,
        root_verifying_key_hex: fixture.rootVerifyingKeyHex.toUpperCase(),
      },
      "epoch-upload-kat",
    );
    expect(conflictingReplay.status).toBe(409);
    await expect(conflictingReplay.json()).resolves.toMatchObject({
      error: { code: "idempotency_conflict" },
    });

    const stored = await env.DB.prepare(
      "SELECT lower(hex(id)) AS id, length(vk_pq) AS pq_length, \
              length(vk_trad) AS trad_length, length(vk_fast) AS fast_length, cert \
       FROM epochs WHERE id = ?",
    )
      .bind(new Uint8Array(fixture.epochIdBytes))
      .first<{
        id: string;
        pq_length: number;
        trad_length: number;
        fast_length: number;
        cert: ArrayBuffer;
      }>();
    expect(stored).not.toBeNull();
    expect(stored).toMatchObject({
      id: fixture.epochId,
      trad_length: 32,
      fast_length: 32,
    });
    expect(stored?.pq_length).toBeGreaterThan(1_000);
    expect(new Uint8Array(stored?.cert ?? new ArrayBuffer(0))).toEqual(fixture.certificate);

    const list = await adminJson(`/epochs?product_id=${fixture.productId}`, "GET", token);
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      product_id: fixture.productId,
      items: [{ epoch_id: fixture.epochId, status: "expired" }],
    });
    const show = await adminJson(`/epochs/${fixture.epochId}`, "GET", token);
    expect(show.status).toBe(200);
    await expect(show.json()).resolves.toMatchObject({
      epoch: { epoch_id: fixture.epochId, product_id: fixture.productId },
      replacement_ready: false,
      replacement_epoch_ids: [],
    });

    const keysetBytes = await env.CACHE.get("keys:current", "arrayBuffer");
    expect(keysetBytes).not.toBeNull();
    const keyset = cborMap(
      decodeTestCbor(new Uint8Array(keysetBytes ?? new ArrayBuffer(0))),
    );
    expect(keyset.get(0)).toBe(1);
    expect(keyset.get(2)).toBe(0);
    const certificates = keyset.get(1);
    if (!Array.isArray(certificates)) throw new Error("keyset certificates must be an array");
    expect(certificates).toHaveLength(1);
    expect(cborBytes(certificates[0])).toEqual(fixture.certificate);

    await env.DB.prepare(
      "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
    )
      .bind(otherVendor, "Other Epoch Vendor", "other_epoch_salt", 1)
      .run();
    const otherToken = testAdminToken(35);
    await seedAdminToken(otherToken, ["epochs:rw"], otherVendor, "other-epoch-admin");
    expect(
      (await adminJson(`/epochs?product_id=${fixture.productId}`, "GET", otherToken)).status,
    ).toBe(404);
    expect((await adminJson(`/epochs/${fixture.epochId}`, "GET", otherToken)).status).toBe(404);

    const journal = await env.DB.prepare(
      "SELECT o.source_kind, o.side_effect_at, o.completed_at, a.enqueued_at \
       FROM admin_operations o JOIN admin_audit_events a ON a.operation_id = o.operation_id \
       WHERE o.request_id = ?",
    )
      .bind("epoch-upload-kat")
      .first<{
        source_kind: string;
        side_effect_at: number | null;
        completed_at: number | null;
        enqueued_at: number | null;
      }>();
    expect(journal?.source_kind).toBe("epoch");
    expect(journal?.side_effect_at).toBeTypeOf("number");
    expect(journal?.completed_at).toBeTypeOf("number");
    expect(journal?.enqueued_at).toBeTypeOf("number");

    const secondToken = testAdminToken(37);
    await seedAdminToken(
      secondToken,
      ["epochs:rw", "revoke"],
      vendor,
      "second-epoch-admin@example.test",
    );

    const initialPreview = await postEpochRevoke(fixture.epochId, token);
    expect(initialPreview.status).toBe(200);
    await expect(initialPreview.json()).resolves.toMatchObject({
      dry_run: true,
      epoch: { epoch_id: fixture.epochId },
      replacement_ready: false,
      replacement_epoch_ids: [],
      already_revoked: false,
      requires_distinct_actors: 2,
    });
    const withoutReplacement = await postEpochRevoke(
      fixture.epochId,
      token,
      false,
      "epoch-revoke-without-replacement",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(withoutReplacement.status).toBe(409);
    await expect(withoutReplacement.json()).resolves.toMatchObject({
      error: { code: "replacement_epoch_required" },
    });
    const untouched = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM revocations",
    ).first<{ count: number }>();
    expect(untouched?.count).toBe(0);

    await env.DB.prepare("UPDATE epochs SET revoked_at = NULL WHERE id = ?")
      .bind(new Uint8Array(replacementId))
      .run();
    const readyPreview = await postEpochRevoke(fixture.epochId, token);
    expect(readyPreview.status).toBe(200);
    await expect(readyPreview.json()).resolves.toMatchObject({
      dry_run: true,
      replacement_ready: true,
      replacement_epoch_ids: [hexId(replacementId)],
      already_revoked: false,
    });
    expect(
      (
        await env.DB.prepare("SELECT revoked_at FROM epochs WHERE id = ?")
          .bind(new Uint8Array(fixture.epochIdBytes))
          .first<{ revoked_at: number | null }>()
      )?.revoked_at,
    ).toBeNull();

    const firstApprovalResponse = await postEpochRevoke(
      fixture.epochId,
      token,
      false,
      "epoch-revoke-first-approval",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(firstApprovalResponse.status, await firstApprovalResponse.clone().text()).toBe(202);
    const firstApproval = await firstApprovalResponse.json<{
      approval_pending: boolean;
      epoch_id: string;
      first_actor: string;
      received_confirmations: number;
    }>();
    expect(firstApproval).toMatchObject({
      approval_pending: true,
      epoch_id: fixture.epochId,
      first_actor: "first-epoch-admin@example.test",
      received_confirmations: 1,
    });
    const firstReplay = await postEpochRevoke(
      fixture.epochId,
      token,
      false,
      "epoch-revoke-first-approval",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(firstReplay.status).toBe(202);
    await expect(firstReplay.json()).resolves.toEqual(firstApproval);

    const sameActor = await postEpochRevoke(
      fixture.epochId,
      token,
      false,
      "epoch-revoke-same-actor",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(sameActor.status).toBe(409);
    await expect(sameActor.json()).resolves.toMatchObject({
      error: { code: "second_actor_required" },
    });

    const secondApprovalResponse = await postEpochRevoke(
      fixture.epochId,
      secondToken,
      false,
      "epoch-revoke-second-approval",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(secondApprovalResponse.status, await secondApprovalResponse.clone().text()).toBe(200);
    const secondApproval = await secondApprovalResponse.json<{
      approval_pending: boolean;
      epoch_id: string;
      revocation_epoch: number;
      first_actor: string;
      second_actor: string;
      received_confirmations: number;
    }>();
    expect(secondApproval).toMatchObject({
      approval_pending: false,
      epoch_id: fixture.epochId,
      revocation_epoch: 1,
      first_actor: "first-epoch-admin@example.test",
      second_actor: "second-epoch-admin@example.test",
      received_confirmations: 2,
    });
    const secondReplay = await postEpochRevoke(
      fixture.epochId,
      secondToken,
      false,
      "epoch-revoke-second-approval",
      { confirm_epoch_id: fixture.epochId },
    );
    expect(secondReplay.status).toBe(200);
    await expect(secondReplay.json()).resolves.toEqual(secondApproval);

    const approval = await env.DB.prepare(
      "SELECT first_actor, second_actor, revocation_seq \
       FROM epoch_revocation_approvals WHERE epoch_id = ?",
    )
      .bind(new Uint8Array(fixture.epochIdBytes))
      .first<{
        first_actor: string;
        second_actor: string;
        revocation_seq: number;
      }>();
    expect(approval).toEqual({
      first_actor: "first-epoch-admin@example.test",
      second_actor: "second-epoch-admin@example.test",
      revocation_seq: 1,
    });
    const revoked = await env.DB.prepare(
      "SELECT revoked_at FROM epochs WHERE id = ?",
    )
      .bind(new Uint8Array(fixture.epochIdBytes))
      .first<{ revoked_at: number | null }>();
    expect(revoked?.revoked_at).toBeTypeOf("number");
    const revocation = await env.DB.prepare(
      "SELECT seq, kind, target, applied_at, published_at \
       FROM revocations WHERE request_id = ?",
    )
      .bind("epoch-revoke-second-approval")
      .first<{
        seq: number;
        kind: string;
        target: ArrayBuffer;
        applied_at: number | null;
        published_at: number | null;
      }>();
    expect(revocation).toMatchObject({ seq: 1, kind: "epoch" });
    expect(new Uint8Array(revocation?.target ?? new ArrayBuffer(0))).toEqual(
      new Uint8Array(fixture.epochIdBytes),
    );
    expect(revocation?.applied_at).toBeTypeOf("number");
    expect(revocation?.published_at).toBeTypeOf("number");

    const batchBytes = await env.CACHE.get("rev:batch:0", "arrayBuffer");
    expect(batchBytes).not.toBeNull();
    const envelope = cborMap(
      decodeTestCbor(new Uint8Array(batchBytes ?? new ArrayBuffer(0))),
    );
    expect(envelope.get(2)).toBe(5);
    expect(cborBytes(envelope.get(5))).toEqual(new Uint8Array(replacementId));
    const batch = cborMap(decodeTestCbor(cborBytes(envelope.get(3))));
    const revokedEpochs = batch.get(7);
    if (!Array.isArray(revokedEpochs)) throw new Error("revoked epochs must be an array");
    expect(revokedEpochs).toHaveLength(1);
    expect(cborBytes(revokedEpochs[0])).toEqual(new Uint8Array(fixture.epochIdBytes));
    expect(await env.CACHE.get("rev:epoch")).toBe("1");

    const revokedKeysetBytes = await env.CACHE.get("keys:current", "arrayBuffer");
    expect(revokedKeysetBytes).not.toBeNull();
    const revokedKeyset = cborMap(
      decodeTestCbor(new Uint8Array(revokedKeysetBytes ?? new ArrayBuffer(0))),
    );
    expect(revokedKeyset.get(2)).toBe(1);
    const activeCertificates = revokedKeyset.get(1);
    if (!Array.isArray(activeCertificates)) {
      throw new Error("keyset certificates must be an array");
    }
    expect(activeCertificates).toHaveLength(1);
    expect(cborBytes(activeCertificates[0])).not.toEqual(fixture.certificate);

    const versions = await env.DB.prepare(
      "SELECT entity_kind, version, operation_id \
       FROM admin_entity_versions WHERE entity_id = ? ORDER BY created_at, entity_kind, version",
    )
      .bind(fixture.epochId)
      .all<{ entity_kind: string; version: number; operation_id: string }>();
    expect(versions.results).toEqual(
      expect.arrayContaining([
        {
          entity_kind: "epoch",
          version: 1,
          operation_id: `${vendor}/epoch-upload-kat`,
        },
        {
          entity_kind: "epoch_approval",
          version: 1,
          operation_id: `${vendor}/epoch-revoke-first-approval`,
        },
        {
          entity_kind: "epoch",
          version: 2,
          operation_id: `${vendor}/epoch-revoke-second-approval`,
        },
      ]),
    );
    const duplicateVersions = await env.DB.prepare(
      "SELECT operation_id FROM admin_entity_versions \
       GROUP BY operation_id HAVING COUNT(*) > 1",
    ).all<{ operation_id: string }>();
    expect(duplicateVersions.results).toEqual([]);
    const journals = await env.DB.prepare(
      "SELECT o.request_id, o.source_kind, o.completed_at, a.enqueued_at \
       FROM admin_operations o JOIN admin_audit_events a ON a.operation_id = o.operation_id \
       WHERE o.request_id IN (?, ?) ORDER BY o.request_id",
    )
      .bind("epoch-revoke-first-approval", "epoch-revoke-second-approval")
      .all<{
        request_id: string;
        source_kind: string;
        completed_at: number | null;
        enqueued_at: number | null;
      }>();
    expect(journals.results).toHaveLength(2);
    expect(journals.results.map(({ source_kind }) => source_kind).sort()).toEqual([
      "epoch",
      "epoch_approval",
    ]);
    expect(journals.results.every(({ completed_at }) => typeof completed_at === "number")).toBe(
      true,
    );
    expect(journals.results.every(({ enqueued_at }) => typeof enqueued_at === "number")).toBe(
      true,
    );
    await env.DB.exec("DELETE FROM audit_index WHERE seq < 0");
    await env.DB.exec("DELETE FROM admin_audit_events");
    await env.DB.exec("DELETE FROM revocations");
    await env.DB.exec("DELETE FROM sqlite_sequence WHERE name = 'revocations'");
    await env.CACHE.delete("rev:epoch");
    await env.CACHE.delete("rev:batch:0");
    await env.CACHE.delete("keys:current");
    await clearAdminAuditDo();
  });

  it("issues and updates tenant-scoped licenses through the recoverable Admin journal", async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    await clearAdminAuditDo();
    const vendor = "vendor_license_api";
    const otherVendor = "vendor_license_other";
    const product = "product_license_api";
    const policy = "policy_license_api";
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
      ).bind(vendor, "License API Vendor", "salt", 1),
      env.DB.prepare(
        "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
      ).bind(otherVendor, "Other License Vendor", "salt", 1),
      env.DB.prepare(
        "INSERT INTO products(\
           id, vendor_id, name, min_suite_id, min_proto_ver, min_sdk_version, created_at\
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        product,
        vendor,
        "License API Product",
        new Uint8Array(suiteId),
        1,
        "0.1.0",
        1,
      ),
      env.DB.prepare(
        "INSERT INTO features(product_id, id, label, created_at) VALUES (?, ?, ?, ?)",
      ).bind(product, "feature.alpha", "Alpha", 1),
      env.DB.prepare(
        "INSERT INTO tiers(\
           product_id, id, label, rank, groups_json, features_json, limits_json\
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(product, "pro", "Pro", 1, "[]", '["feature.alpha"]', "{}"),
      env.DB.prepare(
        "INSERT INTO tiers(\
           product_id, id, label, rank, groups_json, features_json, limits_json\
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(product, "enterprise", "Enterprise", 2, "[]", '["feature.alpha"]', "{}"),
      env.DB.prepare(
        "INSERT INTO policies(\
           id, product_id, name, entitlement_json, validity_json, version_scope_json, \
           seats, heartbeat_sec, mode, refresh_after_sec, grace_seconds, created_at, updated_at\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        policy,
        product,
        "License API Policy",
        '{"tier":"pro"}',
        '{"kind":"subscription","period_secs":2592000,"dunning_grace_secs":604800,"fallback":{"after_months":12,"scope_at":"earned_at"}}',
        '{"kind":"unlimited"}',
        3,
        120,
        0,
        604800,
        604800,
        1,
        1,
      ),
    ]);
    const token = testAdminToken(32);
    await seedAdminToken(token, ["licenses:rw"], vendor, "license-admin@example.test");

    const issueBody = {
      product_id: product,
      policy_id: policy,
      count: 2,
      metadata: { source: "integration-test" },
    };
    const issueResponse = await adminJson(
      "/licenses",
      "POST",
      token,
      issueBody,
      "license-issue-batch",
    );
    expect(issueResponse.status, await issueResponse.clone().text()).toBe(201);
    const issued = await issueResponse.json<AdminLicenseIssueResult>();
    expect(issued).toMatchObject({
      ok: true,
      product_id: product,
      policy_id: policy,
      catalog_version: 0,
      count: 2,
    });
    expect(issued.license_ids).toHaveLength(2);
    expect(issued.licenses.map(({ license_id }) => license_id)).toEqual(issued.license_ids);
    expect(new Set(issued.licenses.map(({ license_key }) => license_key)).size).toBe(2);
    for (const { license_key } of issued.licenses) {
      expect(license_key).toMatch(/^CL1-[0-9A-HJKMNP-TV-Z]{5}(?:-[0-9A-HJKMNP-TV-Z]{5}){3}$/);
    }

    const replayResponse = await adminJson(
      "/licenses",
      "POST",
      token,
      issueBody,
      "license-issue-batch",
    );
    expect(replayResponse.status).toBe(201);
    await expect(replayResponse.json()).resolves.toEqual(issued);
    const issueConflict = await adminJson(
      "/licenses",
      "POST",
      token,
      { ...issueBody, count: 1 },
      "license-issue-batch",
    );
    expect(issueConflict.status).toBe(409);

    const stored = await env.DB.prepare(
      "SELECT lower(hex(id)) AS id, key_hmac FROM licenses WHERE product_id = ? ORDER BY id",
    )
      .bind(product)
      .all<{ id: string; key_hmac: ArrayBuffer }>();
    expect(stored.results).toHaveLength(2);
    const issuedById = new Map(
      issued.licenses.map((entry) => [entry.license_id, entry.license_key]),
    );
    for (const row of stored.results) {
      const licenseKey = issuedById.get(row.id);
      expect(licenseKey).toBeTypeOf("string");
      expect(new Uint8Array(row.key_hmac)).toEqual(
        await activationKeyHmac(licenseKeyBytes(licenseKey ?? "")),
      );
    }
    const operationPayloads = await env.DB.prepare(
      "SELECT before_json || after_json || result_json || COALESCE(side_effect_json, '') AS payload \
       FROM admin_operations",
    ).all<{ payload: string }>();
    const auditPayloads = await env.DB.prepare(
      "SELECT event_json AS payload FROM admin_audit_events",
    ).all<{ payload: string }>();
    for (const { license_key } of issued.licenses) {
      expect(operationPayloads.results.every(({ payload }) => !payload.includes(license_key))).toBe(
        true,
      );
      expect(auditPayloads.results.every(({ payload }) => !payload.includes(license_key))).toBe(
        true,
      );
    }

    const listResponse = await adminJson(
      `/licenses?product_id=${product}&status=active&limit=10`,
      "GET",
      token,
    );
    expect(listResponse.status).toBe(200);
    const listed = await listResponse.json<{ items: Array<{ license_id: string }> }>();
    expect(new Set(listed.items.map(({ license_id }) => license_id))).toEqual(
      new Set(issued.license_ids),
    );
    const licenseId = issued.license_ids[0];
    const licenseBytesValue = hexBytes(licenseId);
    const showResponse = await adminJson(`/licenses/${licenseId}`, "GET", token);
    expect(showResponse.status).toBe(200);
    const shownText = await showResponse.clone().text();
    expect(shownText).not.toContain("key_hmac");
    for (const { license_key } of issued.licenses) expect(shownText).not.toContain(license_key);

    const suspendResponse = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { status: "suspended" },
      "license-suspend",
    );
    expect(suspendResponse.status, await suspendResponse.clone().text()).toBe(200);
    const suspended = await suspendResponse.json<AdminLicenseMutationResult>();
    expect(suspended).toMatchObject({ version: 1, license: { status: "suspended" } });
    const suspendReplay = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { status: "suspended" },
      "license-suspend",
    );
    expect(suspendReplay.status).toBe(200);
    await expect(suspendReplay.json()).resolves.toEqual(suspended);

    const licenseStub = env.LICENSE.getByName(licenseId);
    const pending = await runInDurableObject(licenseStub, async (_instance, state) =>
      state.storage.sql
        .exec<{ status: string; version: number; initialized: number }>(
          "SELECT \
             CAST((SELECT v FROM meta WHERE k = 'pending_admin_status') AS TEXT) AS status, \
             CAST((SELECT v FROM meta WHERE k = 'admin_version') AS INTEGER) AS version, \
             (SELECT COUNT(*) FROM meta WHERE k = 'license_id') AS initialized",
        )
        .one(),
    );
    expect(pending).toEqual({ status: "suspended", version: 1, initialized: 0 });
    const initialized = await postJson(licenseStub, "/init", {
      license_id: licenseBytesValue,
      product_id: product,
      suite_id: suiteId,
      seats: 3,
    });
    expect(initialized.status).toBe(200);
    await runInDurableObject(licenseStub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: string; seats: number; version: number; pending: number }>(
          "SELECT \
             CAST((SELECT v FROM meta WHERE k = 'status') AS TEXT) AS status, \
             CAST((SELECT v FROM meta WHERE k = 'seats') AS INTEGER) AS seats, \
             CAST((SELECT v FROM meta WHERE k = 'admin_version') AS INTEGER) AS version, \
             (SELECT COUNT(*) FROM meta WHERE k LIKE 'pending_admin_%') AS pending",
        )
        .one();
      expect(row).toEqual({ status: "suspended", seats: 3, version: 1, pending: 0 });
    });

    const resumeResponse = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { status: "active" },
      "license-resume",
    );
    expect(resumeResponse.status).toBe(200);
    const resumed = await resumeResponse.json<AdminLicenseMutationResult>();
    expect(resumed).toMatchObject({ version: 2, license: { status: "active" } });
    expect(resumed.license.expires_at).toBeTypeOf("number");

    const extendResponse = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { extend_by_seconds: 3600 },
      "license-extend",
    );
    expect(extendResponse.status).toBe(200);
    const extended = await extendResponse.json<AdminLicenseMutationResult>();
    expect(extended.license.expires_at).toBe((resumed.license.expires_at ?? 0) + 3600);
    const extendReplay = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { extend_by_seconds: 3600 },
      "license-extend",
    );
    expect(extendReplay.status).toBe(200);
    await expect(extendReplay.json()).resolves.toEqual(extended);
    const expiryAfterReplay = await env.DB.prepare(
      "SELECT expires_at FROM licenses WHERE id = ?",
    )
      .bind(new Uint8Array(licenseBytesValue))
      .first<{ expires_at: number }>();
    expect(expiryAfterReplay?.expires_at).toBe(extended.license.expires_at);

    const seatsResponse = await adminJson(
      `/licenses/${licenseId}`,
      "PATCH",
      token,
      { seats_override: 7 },
      "license-seats",
    );
    expect(seatsResponse.status).toBe(200);
    const seatsChanged = await seatsResponse.json<AdminLicenseMutationResult>();
    expect(seatsChanged).toMatchObject({ version: 4, license: { seats_override: 7 } });
    const tierResponse = await adminJson(
      `/licenses/${licenseId}/change-tier`,
      "POST",
      token,
      { tier: "enterprise" },
      "license-change-tier",
    );
    expect(tierResponse.status).toBe(200);
    const tierChanged = await tierResponse.json<AdminLicenseMutationResult>();
    expect(tierChanged).toMatchObject({
      version: 5,
      license: { entitlement_override: { tier: "enterprise" } },
    });
    const tierReplay = await adminJson(
      `/licenses/${licenseId}/change-tier`,
      "POST",
      token,
      { tier: "enterprise" },
      "license-change-tier",
    );
    expect(tierReplay.status).toBe(200);
    await expect(tierReplay.json()).resolves.toEqual(tierChanged);

    const staleUpdate = await postJson(licenseStub, "/admin-update", {
      license_id: licenseBytesValue,
      operation_id: "stale-license-operation",
      version: 1,
      status: "suspended",
      seats: 1,
      heartbeat_sec: null,
      expires_at: null,
    });
    expect(staleUpdate.status).toBe(200);
    await runInDurableObject(licenseStub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: string; seats: number; version: number }>(
          "SELECT \
             CAST((SELECT v FROM meta WHERE k = 'status') AS TEXT) AS status, \
             CAST((SELECT v FROM meta WHERE k = 'seats') AS INTEGER) AS seats, \
             CAST((SELECT v FROM meta WHERE k = 'admin_version') AS INTEGER) AS version",
        )
        .one();
      expect(row).toEqual({ status: "active", seats: 7, version: tierChanged.version });
    });

    const machineId = machineBytes(2_090);
    await seedProjectedMachine(licenseBytesValue, machineId);
    const machinesResponse = await adminJson(`/licenses/${licenseId}/machines`, "GET", token);
    expect(machinesResponse.status).toBe(200);
    await expect(machinesResponse.json()).resolves.toMatchObject({
      license_id: licenseId,
      items: [{ machine_id: hexId(machineId), status: "active" }],
    });

    const periodStart = 1_700_000_000;
    const fallbackEarnedAt = periodStart + 12 * 30 * 86_400;
    await env.DB.prepare(
      "INSERT INTO subscriptions(\
         license_id, provider, external_id, state, billing_period, current_period_start, \
         current_period_end, continuous_paid_months, fallback_earned_at, updated_at\
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(
        new Uint8Array(licenseBytesValue),
        "stripe",
        "sub_license_admin_preview",
        "canceling",
        "monthly",
        periodStart,
        periodStart + 30 * 86_400,
        12,
        fallbackEarnedAt,
        periodStart,
      )
      .run();
    const fallbackResponse = await adminJson(
      `/licenses/${licenseId}/preview-fallback`,
      "GET",
      token,
    );
    expect(fallbackResponse.status).toBe(200);
    await expect(fallbackResponse.json()).resolves.toMatchObject({
      license_id: licenseId,
      current_state: "canceling",
      end_state: "perpetual_fallback",
      version_cutoff: fallbackEarnedAt,
      continuous_paid_months: 12,
    });

    const otherToken = testAdminToken(33);
    await seedAdminToken(otherToken, ["licenses:rw"], otherVendor, "other-admin@example.test");
    expect((await adminJson(`/licenses/${licenseId}`, "GET", otherToken)).status).toBe(404);
    expect(
      (await adminJson(`/licenses/${licenseId}/machines`, "GET", otherToken)).status,
    ).toBe(404);

    const updatedRow = await env.DB.prepare(
      "SELECT status, seats_override, expires_at, updated_at FROM licenses WHERE id = ?",
    )
      .bind(new Uint8Array(licenseBytesValue))
      .first<{
        status: string;
        seats_override: number;
        expires_at: number;
        updated_at: number;
      }>();
    expect(updatedRow).toMatchObject({
      status: "active",
      seats_override: 7,
      expires_at: extended.license.expires_at,
      updated_at: tierChanged.license.updated_at,
    });
    const completed = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM admin_operations WHERE completed_at IS NULL",
    ).first<{ count: number }>();
    expect(completed?.count).toBe(0);
    await env.DB.exec("DELETE FROM admin_audit_events");
    await clearAdminAuditDo();
  });

  it("authenticates tenant-scoped Admin revocation dry-runs without mutating state", async () => {
    const licenseId = licenseBytes(2_001);
    await seedProjectedLicense(licenseId);
    await seedProjectedMachine(licenseId, machineBytes(2_001));
    await seedProjectedMachine(licenseId, machineBytes(2_002), "released");

    const missing = await postAdminRevoke("licenses", licenseId, undefined);
    expect(missing.status).toBe(401);
    expect(missing.headers.get("cache-control")).toBe("no-store");
    expect(missing.headers.get("www-authenticate")).toContain("Bearer");

    const token = testAdminToken(41);
    await seedAdminToken(token);
    const preview = await postAdminRevoke("licenses", licenseId, token);
    expect(preview.status, await preview.clone().text()).toBe(200);
    expect(preview.headers.get("content-type")).toContain("application/json");
    expect(preview.headers.get("cache-control")).toBe("no-store");
    await expect(preview.json<AdminRevokeResult>()).resolves.toEqual({
      ok: true,
      dry_run: true,
      kind: "license",
      target: hexId(licenseId),
      affected_machines: 1,
      already_revoked: false,
    });
    const untouched = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM revocations",
    ).first<{ count: number }>();
    expect(untouched?.count).toBe(0);

    const noScope = testAdminToken(42);
    await seedAdminToken(noScope, ["licenses:rw"], "vendor_1", "read-only");
    const forbidden = await postAdminRevoke("licenses", licenseId, noScope);
    expect(forbidden.status).toBe(403);
    expect(forbidden.headers.get("cache-control")).toBe("no-store");

    await env.DB.prepare(
      "INSERT INTO vendors(id, name, fpr_salt_ref, created_at) VALUES (?, ?, ?, ?)",
    )
      .bind("vendor_2", "Other Vendor", "other_salt", 1)
      .run();
    const otherVendor = testAdminToken(43);
    await seedAdminToken(otherVendor, ["revoke"], "vendor_2", "other-admin");
    const hidden = await postAdminRevoke("licenses", licenseId, otherVendor);
    expect(hidden.status).toBe(404);
  });

  it("classifies Admin revocation body failures without mutating state", async () => {
    const licenseId = licenseBytes(2_003);
    await seedProjectedLicense(licenseId);
    const token = testAdminToken(44);
    await seedAdminToken(token);
    const url = `https://copylocker.test/v1/admin/licenses/${hexId(licenseId)}/revoke`;
    const request = (
      contentType: string,
      body: BodyInit,
      contentEncoding?: string,
    ): Promise<Response> => {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        "Content-Type": contentType,
      };
      if (contentEncoding !== undefined) {
        headers["Content-Encoding"] = contentEncoding;
      }
      return exports.default.fetch(url, { method: "POST", headers, body });
    };

    const unsupportedType = await request("text/plain", "{}");
    expect(unsupportedType.status).toBe(415);
    expect(unsupportedType.headers.get("cache-control")).toBe("no-store");
    await expect(unsupportedType.json()).resolves.toMatchObject({
      error: { code: "unsupported_media_type" },
    });

    const unsupportedEncoding = await request("application/json", "{}", "gzip");
    expect(unsupportedEncoding.status).toBe(415);
    await expect(unsupportedEncoding.json()).resolves.toMatchObject({
      error: { code: "unsupported_content_encoding" },
    });

    const tooLarge = await request(
      "application/json",
      JSON.stringify({ padding: "x".repeat(4 * 1024) }),
    );
    expect(tooLarge.status).toBe(413);
    await expect(tooLarge.json()).resolves.toMatchObject({
      error: { code: "payload_too_large" },
    });

    const malformed = await request("application/json", "{");
    expect(malformed.status).toBe(400);
    await expect(malformed.json()).resolves.toMatchObject({
      error: { code: "invalid_request" },
    });

    const untouched = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM revocations",
    ).first<{ count: number }>();
    expect(untouched?.count).toBe(0);
  });

  it("publishes a signed license RevocationBatch idempotently and advances other licenses", async () => {
    const revokedLicense = licenseObject(2_015);
    const unaffectedLicense = licenseObject(2_012);
    await seedProjectedLicense(revokedLicense.licenseId);
    await seedProjectedLicense(unaffectedLicense.licenseId);
    await env.DB.exec("DELETE FROM release_feature_keks");
    const token = testAdminToken(51);
    await seedAdminToken(token);

    const unaffectedKeys = await generateDeviceKeys();
    await initLicense(unaffectedLicense.stub, unaffectedLicense.licenseId, 1);
    const unaffectedReservationResponse = await postJson(
      unaffectedLicense.stub,
      "/reserve",
      {
        ...reserveBody(72, "unaffected-reserve", unaffectedKeys.verifyingKey),
        fingerprint: new Array<number>(32).fill(7),
        build_fp: "build-validate",
      },
    );
    expect(unaffectedReservationResponse.status).toBe(201);
    const unaffectedReservation =
      await unaffectedReservationResponse.json<ReserveResult>();
    expect(
      (
        await postJson(unaffectedLicense.stub, "/commit", {
          machine_id: unaffectedReservation.machine_id,
        })
      ).status,
    ).toBe(200);

    const first = await postAdminRevoke(
      "licenses",
      revokedLicense.licenseId,
      token,
      false,
      "admin-license-revoke",
    );
    expect(first.status, await first.clone().text()).toBe(200);
    const firstBody = await first.json<AdminRevokeResult>();
    expect(firstBody).toEqual({
      ok: true,
      dry_run: false,
      kind: "license",
      target: hexId(revokedLicense.licenseId),
      revocation_epoch: 1,
    });

    const logged = await env.DB.prepare(
      "SELECT seq, kind, target, reason, actor, applied_at, published_at \
       FROM revocations WHERE request_id = ?",
    )
      .bind("admin-license-revoke")
      .first<{
        seq: number;
        kind: string;
        target: ArrayBuffer;
        reason: number;
        actor: string;
        applied_at: number;
        published_at: number;
      }>();
    expect(logged).toMatchObject({
      seq: 1,
      kind: "license",
      reason: 1,
      actor: "admin@example.test",
    });
    expect(new Uint8Array(logged?.target ?? new ArrayBuffer(0))).toEqual(
      new Uint8Array(revokedLicense.licenseId),
    );
    expect(logged?.applied_at).toBeTypeOf("number");
    expect(logged?.published_at).toBeTypeOf("number");

    const auditRow = await env.DB.prepare(
      "SELECT event_json, enqueued_at, archived_at \
       FROM admin_audit_events WHERE operation_id = ?",
    )
      .bind("vendor_1/admin-license-revoke")
      .first<{
        event_json: string;
        enqueued_at: number;
        archived_at: number | null;
      }>();
    expect(auditRow?.enqueued_at).toBeTypeOf("number");
    expect(auditRow?.archived_at).toBeNull();
    const adminAudit = JSON.parse(auditRow?.event_json ?? "null") as AdminAuditEvent;
    expect(adminAudit).toMatchObject({
      event: "admin_audit_archive",
      schema_version: 2,
      seq: 1,
      vendor_id: "vendor_1",
      actor: "admin@example.test",
      action: "revoke:license",
      target: hexId(revokedLicense.licenseId),
      reason: 1,
      request_id: "admin-license-revoke",
      before: {
        kind: "license",
        target: hexId(revokedLicense.licenseId),
        license_id: hexId(revokedLicense.licenseId),
        product_id: "product_1",
        status: "active",
        affected_machines: 0,
        revocation_epoch: 0,
      },
      after: {
        status: "revoked",
        affected_machines: 0,
        revocation_epoch: 1,
      },
      prev_hash: new Array<number>(32).fill(0),
    });
    expect(adminAudit.hash).toHaveLength(32);

    const archived = await dispatchEvents([adminAudit], "admin-audit");
    expect(archived.explicitAcks).toEqual(["admin-audit-0"]);
    expect(archived.retryMessages).toEqual([]);
    const replayed = await dispatchEvents([adminAudit], "admin-audit-replay");
    expect(replayed.explicitAcks).toEqual(["admin-audit-replay-0"]);
    expect(replayed.retryMessages).toEqual([]);
    const archiveObject = await env.ARCHIVE.get(adminAudit.r2_key);
    expect(archiveObject).not.toBeNull();
    if (archiveObject === null) throw new Error("Admin audit archive was not written");
    const archive = cborMap(
      decodeTestCbor(new Uint8Array(await archiveObject.arrayBuffer())),
    );
    expect(archive.get(5)).toBe("revoke:license");
    expect(archive.get(6)).toBe(hexId(revokedLicense.licenseId));
    const before = cborMap(archive.get(9));
    const after = cborMap(archive.get(10));
    expect(before.get("status")).toBe("active");
    expect(before.get("revocation_epoch")).toBe(0);
    expect(after.get("status")).toBe("revoked");
    expect(after.get("revocation_epoch")).toBe(1);
    const auditIndex = await env.DB.prepare(
      "SELECT ts, actor, action, target, r2_key FROM audit_index WHERE seq = ?",
    )
      .bind(-adminAudit.seq)
      .first<{
        ts: number;
        actor: string;
        action: string;
        target: string;
        r2_key: string;
      }>();
    expect(auditIndex).toEqual({
      ts: adminAudit.occurred_at,
      actor: "admin@example.test",
      action: "revoke:license",
      target: hexId(revokedLicense.licenseId),
      r2_key: adminAudit.r2_key,
    });
    const auditCheckpoint = await env.DB.prepare(
      "SELECT archived_at FROM admin_audit_events WHERE seq = ?",
    )
      .bind(adminAudit.seq)
      .first<{ archived_at: number }>();
    expect(auditCheckpoint?.archived_at).toBeTypeOf("number");

    await runInDurableObject(revokedLicense.stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: string; epoch: number }>(
          "SELECT CAST((SELECT v FROM meta WHERE k = 'status') AS TEXT) AS status, \
                  CAST((SELECT v FROM meta WHERE k = 'revocation_epoch') AS INTEGER) AS epoch",
        )
        .one();
      expect(row).toEqual({ status: "revoked", epoch: 1 });
    });

    const encodedBatch = await env.CACHE.get("rev:batch:0", "arrayBuffer");
    expect(encodedBatch).not.toBeNull();
    const envelope = cborMap(
      decodeTestCbor(new Uint8Array(encodedBatch ?? new ArrayBuffer(0))),
    );
    expect(envelope.get(2)).toBe(5);
    expect(cborBytes(envelope.get(4)).byteLength).toBeGreaterThan(1_000);
    expect(cborBytes(envelope.get(5))).toEqual(new Uint8Array(8).fill(3));
    const batch = cborMap(decodeTestCbor(cborBytes(envelope.get(3))));
    expect(batch.get(2)).toBe(1);
    expect(batch.get(3)).toBe(1);
    const revokedLicenseIds = batch.get(5);
    if (!Array.isArray(revokedLicenseIds)) {
      throw new Error("revoked license ids must be an array");
    }
    expect(revokedLicenseIds).toHaveLength(1);
    expect(cborBytes(revokedLicenseIds[0])).toEqual(
      new Uint8Array(revokedLicense.licenseId),
    );
    expect(await env.CACHE.get("rev:epoch")).toBe("1");

    const replay = await postAdminRevoke(
      "licenses",
      revokedLicense.licenseId,
      token,
      false,
      "admin-license-revoke",
    );
    expect(replay.status).toBe(200);
    await expect(replay.json()).resolves.toEqual(firstBody);
    const conflictingReplay = await postAdminRevoke(
      "licenses",
      revokedLicense.licenseId,
      token,
      false,
      "admin-license-revoke",
      { reason: 4 },
    );
    expect(conflictingReplay.status).toBe(409);
    const duplicate = await postAdminRevoke(
      "licenses",
      revokedLicense.licenseId,
      token,
      false,
      "admin-license-revoke-again",
    );
    expect(duplicate.status).toBe(409);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM revocations",
    ).first<{ count: number }>();
    expect(count?.count).toBe(1);

    const nonce = new Array<number>(32).fill(91);
    const proofInput = validateProofInput(
      unaffectedLicense.licenseId,
      unaffectedReservation.machine_id,
      nonce,
      1,
    );
    const proof = await signDeviceProof(
      "validate-request",
      proofInput,
      unaffectedKeys.privateKey,
    );
    const validation = await exports.default.fetch(
      "https://copylocker.test/v1/validate",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/cbor",
          "X-CL-Proto": "1",
        },
        body: validateRequestCbor(
          unaffectedLicense.licenseId,
          unaffectedReservation.machine_id,
          nonce,
          proof,
          1,
        ),
      },
    );
    const validationStatus = validation.status;
    const validationBytes = new Uint8Array(await validation.arrayBuffer());
    await clearAdminRevocationState(revokedLicense.licenseId);
    expect(validationStatus).toBe(200);
    const ticketEnvelope = cborMap(
      decodeTestCbor(validationBytes),
    );
    const ticket = cborMap(decodeTestCbor(cborBytes(ticketEnvelope.get(3))));
    expect(ticket.get(8)).toBe(1);
  });

  it("rejects a valid Admin audit message after its D1 source disappears", async () => {
    const licenseId = licenseBytes(2_019);
    await seedProjectedLicense(licenseId);
    const token = testAdminToken(52);
    await seedAdminToken(token);
    const revoked = await postAdminRevoke(
      "licenses",
      licenseId,
      token,
      false,
      "admin-audit-missing-source",
    );
    expect(revoked.status, await revoked.clone().text()).toBe(200);
    const row = await env.DB.prepare(
      "SELECT event_json FROM admin_audit_events WHERE operation_id = ?",
    )
      .bind("vendor_1/admin-audit-missing-source")
      .first<{ event_json: string }>();
    const event = JSON.parse(row?.event_json ?? "null") as AdminAuditEvent;
    await env.DB.prepare("DELETE FROM admin_audit_events WHERE seq = ?")
      .bind(event.seq)
      .run();

    const result = await dispatchEvents([event], "admin-audit-missing-source");
    expect(result.explicitAcks).toEqual([]);
    expect(result.retryMessages).toEqual([
      { msgId: "admin-audit-missing-source-0" },
    ]);
    expect(await env.ARCHIVE.get(event.r2_key)).toBeNull();
    const index = await env.DB.prepare(
      "SELECT seq FROM audit_index WHERE seq = ?",
    )
      .bind(-event.seq)
      .first<{ seq: number }>();
    expect(index).toBeNull();
    await clearAdminRevocationState(licenseId);
  });

  it("recovers a machine revocation with the same epoch after a KV publication failure", async () => {
    const { licenseId, stub } = licenseObject(2_021);
    await seedProjectedLicense(licenseId);
    const token = testAdminToken(61);
    await seedAdminToken(token);
    await initLicense(stub, licenseId, 2);
    const reservationResponse = await postJson(
      stub,
      "/reserve",
      reserveBody(81, "admin-machine-reserve"),
    );
    expect(reservationResponse.status).toBe(201);
    const reservation = await reservationResponse.json<ReserveResult>();
    expect(
      (await postJson(stub, "/commit", { machine_id: reservation.machine_id })).status,
    ).toBe(200);
    await seedProjectedMachine(licenseId, reservation.machine_id);

    await env.DB.exec(
      "CREATE TRIGGER fail_revocation_publish \
       BEFORE UPDATE OF published_at ON revocations \
       BEGIN SELECT RAISE(FAIL, 'injected publication failure'); END",
    );
    const failed = await postAdminRevoke(
      "machines",
      reservation.machine_id,
      token,
      false,
      "admin-machine-revoke",
    );
    expect(failed.status, await failed.clone().text()).toBe(500);
    expect(failed.headers.get("cache-control")).toBe("no-store");
    await env.DB.exec("DROP TRIGGER fail_revocation_publish");
    const pending = await env.DB.prepare(
      "SELECT seq, applied_at, published_at FROM revocations WHERE request_id = ?",
    )
      .bind("admin-machine-revoke")
      .first<{ seq: number; applied_at: number; published_at: number | null }>();
    expect(pending?.seq).toBe(1);
    expect(pending?.applied_at).toBeTypeOf("number");
    expect(pending?.published_at).toBeNull();
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: number; epoch: number }>(
          "SELECT status, CAST((SELECT v FROM meta WHERE k = 'revocation_epoch') AS INTEGER) \
             AS epoch FROM activations WHERE machine_id = ?",
          new Uint8Array(reservation.machine_id),
        )
        .one();
      expect(row).toEqual({ status: 2, epoch: 1 });
    });

    const blocked = await postAdminRevoke(
      "licenses",
      licenseId,
      token,
      false,
      "blocked-by-pending",
    );
    expect(blocked.status).toBe(409);
    await expect(blocked.json()).resolves.toMatchObject({
      error: { code: "revocation_in_progress" },
    });

    const recovered = await postAdminRevoke(
      "machines",
      reservation.machine_id,
      token,
      false,
      "admin-machine-revoke",
    );
    expect(recovered.status, await recovered.clone().text()).toBe(200);
    await expect(recovered.json<AdminRevokeResult>()).resolves.toMatchObject({
      ok: true,
      kind: "machine",
      revocation_epoch: 1,
    });
    const machineEnvelopeBytes = await env.CACHE.get("rev:batch:0", "arrayBuffer");
    const machineEnvelope = cborMap(
      decodeTestCbor(new Uint8Array(machineEnvelopeBytes ?? new ArrayBuffer(0))),
    );
    const machineBatch = cborMap(
      decodeTestCbor(cborBytes(machineEnvelope.get(3))),
    );
    const revokedMachineIds = machineBatch.get(6);
    if (!Array.isArray(revokedMachineIds)) {
      throw new Error("revoked machine ids must be an array");
    }
    expect(cborBytes(revokedMachineIds[0])).toEqual(
      new Uint8Array(reservation.machine_id),
    );

    const license = await postAdminRevoke(
      "licenses",
      licenseId,
      token,
      false,
      "admin-license-after-machine",
    );
    expect(license.status, await license.clone().text()).toBe(200);
    await expect(license.json<AdminRevokeResult>()).resolves.toMatchObject({
      ok: true,
      kind: "license",
      revocation_epoch: 2,
    });
    expect(await env.CACHE.get("rev:epoch")).toBe("2");
    expect(await env.CACHE.get("rev:batch:1", "arrayBuffer")).not.toBeNull();
    const rows = await env.DB.prepare(
      "SELECT seq, applied_at, published_at FROM revocations ORDER BY seq",
    ).all<{ seq: number; applied_at: number; published_at: number }>();
    expect(rows.results).toHaveLength(2);
    expect(rows.results.map(({ seq }) => seq)).toEqual([1, 2]);
    const auditRows = await env.DB.prepare(
      "SELECT seq, event_json, enqueued_at FROM admin_audit_events ORDER BY seq",
    ).all<{ seq: number; event_json: string; enqueued_at: number }>();
    expect(auditRows.results.map(({ seq }) => seq)).toEqual([1, 2]);
    const firstAudit = JSON.parse(auditRows.results[0].event_json) as AdminAuditEvent;
    const secondAudit = JSON.parse(auditRows.results[1].event_json) as AdminAuditEvent;
    expect(firstAudit.prev_hash).toEqual(new Array<number>(32).fill(0));
    expect(secondAudit.prev_hash).toEqual(firstAudit.hash);
    expect(auditRows.results.every(({ enqueued_at }) => typeof enqueued_at === "number")).toBe(
      true,
    );

    const issuer = env.ISSUER.getByName(`issuer-${issuerShard(licenseId)}`);
    await runInDurableObject(issuer, async (_instance, state) => {
      const issued = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM issuance_log")
        .one();
      expect(issued.count).toBe(2);
    });
    await clearAdminRevocationState(licenseId);
  });

  it("reconciles a pending revocation after an apply checkpoint failure", async () => {
    const licenseId = licenseBytes(2_025);
    await seedProjectedLicense(licenseId);
    const token = testAdminToken(62);
    await seedAdminToken(token);

    await env.DB.exec(
      "CREATE TRIGGER ignore_revocation_apply \
       BEFORE UPDATE OF applied_at ON revocations \
       BEGIN SELECT RAISE(IGNORE); END",
    );
    const failed = await postAdminRevoke(
      "licenses",
      licenseId,
      token,
      false,
      "ignored-apply-checkpoint",
    );
    await env.DB.exec("DROP TRIGGER ignore_revocation_apply");

    expect(failed.status, await failed.clone().text()).toBe(500);
    expect(failed.headers.get("cache-control")).toBe("no-store");
    const pending = await env.DB.prepare(
      "SELECT seq, applied_at, published_at FROM revocations WHERE request_id = ?",
    )
      .bind("ignored-apply-checkpoint")
      .first<{ seq: number; applied_at: number | null; published_at: number | null }>();
    expect(pending).toEqual({ seq: 1, applied_at: null, published_at: null });
    expect(await env.CACHE.get("rev:epoch")).toBeNull();
    expect(await env.CACHE.get("rev:batch:0", "arrayBuffer")).toBeNull();

    await runScheduledReconciliation();
    await runScheduledReconciliation();
    const completed = await env.DB.prepare(
      "SELECT seq, applied_at, published_at FROM revocations WHERE request_id = ?",
    )
      .bind("ignored-apply-checkpoint")
      .first<{ seq: number; applied_at: number | null; published_at: number | null }>();
    expect(completed?.seq).toBe(1);
    expect(completed?.applied_at).toBeTypeOf("number");
    expect(completed?.published_at).toBeTypeOf("number");
    expect(await env.CACHE.get("rev:epoch")).toBe("1");
    expect(await env.CACHE.get("rev:batch:0", "arrayBuffer")).not.toBeNull();
    const issuer = env.ISSUER.getByName(`issuer-${issuerShard(licenseId)}`);
    await runInDurableObject(issuer, async (_instance, state) => {
      const issued = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM issuance_log")
        .one();
      expect(issued.count).toBe(1);
    });
    await clearAdminRevocationState(licenseId);
  });

  it("serializes concurrent Admin revocations without allocating an epoch gap", async () => {
    const firstLicenseId = licenseBytes(2_031);
    const secondLicenseId = licenseBytes(2_032);
    await seedProjectedLicense(firstLicenseId);
    await seedProjectedLicense(secondLicenseId);
    const token = testAdminToken(63);
    await seedAdminToken(token);
    const attempts = [
      { target: firstLicenseId, requestId: "concurrent-revoke-first" },
      { target: secondLicenseId, requestId: "concurrent-revoke-second" },
    ];

    await env.DB.exec(
      "CREATE TRIGGER fail_concurrent_revocation_publish \
       BEFORE UPDATE OF published_at ON revocations \
       BEGIN SELECT RAISE(FAIL, 'injected concurrent publication failure'); END",
    );
    const responses = await Promise.all(
      attempts.map(({ target, requestId }) =>
        postAdminRevoke("licenses", target, token, false, requestId),
      ),
    );
    await env.DB.exec("DROP TRIGGER fail_concurrent_revocation_publish");

    expect(responses.map(({ status }) => status).sort((a, b) => a - b)).toEqual([
      409, 500,
    ]);
    const reservedIndex = responses.findIndex(({ status }) => status === 500);
    if (reservedIndex < 0) throw new Error("one concurrent request must reserve the epoch");
    const blockedIndex = reservedIndex === 0 ? 1 : 0;
    const reserved = attempts[reservedIndex];
    const blocked = attempts[blockedIndex];
    const pending = await env.DB.prepare(
      "SELECT seq, request_id, target FROM revocations",
    ).first<{ seq: number; request_id: string; target: ArrayBuffer }>();
    expect(pending?.seq).toBe(1);
    expect(pending?.request_id).toBe(reserved.requestId);
    expect(new Uint8Array(pending?.target ?? new ArrayBuffer(0))).toEqual(
      new Uint8Array(reserved.target),
    );
    const sequence = await env.DB.prepare(
      "SELECT seq FROM sqlite_sequence WHERE name = 'revocations'",
    ).first<{ seq: number }>();
    expect(sequence?.seq).toBe(1);

    const recovered = await postAdminRevoke(
      "licenses",
      reserved.target,
      token,
      false,
      reserved.requestId,
    );
    expect(recovered.status, await recovered.clone().text()).toBe(200);
    await expect(recovered.json<AdminRevokeResult>()).resolves.toMatchObject({
      revocation_epoch: 1,
    });
    const retried = await postAdminRevoke(
      "licenses",
      blocked.target,
      token,
      false,
      blocked.requestId,
    );
    expect(retried.status, await retried.clone().text()).toBe(200);
    await expect(retried.json<AdminRevokeResult>()).resolves.toMatchObject({
      revocation_epoch: 2,
    });

    const rows = await env.DB.prepare(
      "SELECT seq, request_id FROM revocations ORDER BY seq",
    ).all<{ seq: number; request_id: string }>();
    expect(rows.results).toEqual([
      { seq: 1, request_id: reserved.requestId },
      { seq: 2, request_id: blocked.requestId },
    ]);
    expect(await env.CACHE.get("rev:epoch")).toBe("2");
    expect(await env.CACHE.get("rev:batch:0", "arrayBuffer")).not.toBeNull();
    expect(await env.CACHE.get("rev:batch:1", "arrayBuffer")).not.toBeNull();
    await clearAdminRevocationState(firstLicenseId);
    await clearAdminRevocationState(secondLicenseId);
  });

  it("rejects an identity body larger than 16 KiB", async () => {
    const response = await exports.default.fetch("https://copylocker.test/v1/activate", {
      method: "POST",
      headers: {
        "Content-Type": "application/cbor",
        "X-CL-Proto": "1",
      },
      body: "x".repeat(16 * 1024 + 1),
    });

    expect(response.status).toBe(413);
  });

  it("bounds the decompressed size of gzip request bodies", async () => {
    const source = new Blob(["x".repeat(16 * 1024 + 1)]).stream();
    const compressed = await new Response(
      source.pipeThrough(new CompressionStream("gzip")),
    ).arrayBuffer();
    const response = await exports.default.fetch("https://copylocker.test/v1/activate", {
      method: "POST",
      headers: {
        "Content-Encoding": "gzip",
        "Content-Type": "application/cbor",
        "X-CL-Proto": "1",
      },
      body: compressed,
    });

    expect(response.status).toBe(413);
  });

  it("rejects unsupported request encodings", async () => {
    const response = await exports.default.fetch("https://copylocker.test/v1/activate", {
      method: "POST",
      headers: {
        "Content-Encoding": "deflate",
        "Content-Type": "application/cbor",
        "X-CL-Proto": "1",
      },
      body: new Uint8Array([0xa0]),
    });

    expect(response.status).toBe(415);
  });

  it("does not return 500 for malformed input across every routed endpoint", async () => {
    const corpus = Array.from({ length: 32 }, (_, corpusIndex) => {
      let state = (0x9e3779b9 ^ corpusIndex) >>> 0;
      const body = new Uint8Array(1 + ((corpusIndex * 37) % 255));
      for (let index = 0; index < body.length; index += 1) {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        state >>>= 0;
        body[index] = state & 0xff;
      }
      return body;
    });
    corpus.push(
      new Uint8Array([0xff]),
      new Uint8Array([0x5a, 0xff, 0xff, 0xff, 0xff]),
      new Uint8Array([...new Array<number>(64).fill(0x81), 0x00]),
    );
    const edgeCases = corpus.slice(-3);
    const assertNoInternalErrors = async (
      requests: Array<() => Promise<Response>>,
    ): Promise<void> => {
      for (let offset = 0; offset < requests.length; offset += 8) {
        const responses: Response[] = await Promise.all(
          requests.slice(offset, offset + 8).map((request) => request()),
        );
        expect(responses.some(({ status }) => status === 500)).toBe(false);
        await Promise.all(responses.map((response) => response.arrayBuffer()));
      }
    };

    const publicPaths = [
      "/v1/activate",
      "/v1/validate",
      "/v1/heartbeat",
      "/v1/deactivate",
    ];
    await assertNoInternalErrors(
      publicPaths.flatMap((path) =>
        corpus.map(
          (body, corpusIndex) => () =>
            exports.default.fetch(`https://copylocker.test${path}`, {
              method: "POST",
              headers: {
                "Content-Type": "application/cbor",
                "Idempotency-Key": `malformed-${corpusIndex}`,
                "X-CL-Proto": "1",
              },
              body: body.slice(),
            }),
        ),
      ),
    );

    const licenseId = licenseBytes(2_041);
    await seedProjectedLicense(licenseId);
    const token = testAdminToken(55);
    await seedAdminToken(token, [
      "catalog:rw",
      "policies:rw",
      "licenses:rw",
      "epochs:rw",
      "revoke",
    ]);
    const epochId = hexId(licenseId.slice(0, 8));
    const adminRoutes = [
      { method: "POST", path: "/v1/admin/catalog/features" },
      { method: "PATCH", path: "/v1/admin/catalog/features" },
      { method: "POST", path: "/v1/admin/catalog/groups" },
      { method: "PATCH", path: "/v1/admin/catalog/groups" },
      { method: "POST", path: "/v1/admin/catalog/tiers" },
      { method: "PATCH", path: "/v1/admin/catalog/tiers" },
      { method: "POST", path: "/v1/admin/catalog/resolve" },
      { method: "POST", path: "/v1/admin/policies" },
      { method: "PATCH", path: "/v1/admin/policies/policy_1" },
      { method: "POST", path: "/v1/admin/licenses" },
      { method: "PATCH", path: `/v1/admin/licenses/${hexId(licenseId)}` },
      { method: "POST", path: `/v1/admin/licenses/${hexId(licenseId)}/change-tier` },
      { method: "POST", path: `/v1/admin/licenses/${hexId(licenseId)}/revoke` },
      { method: "POST", path: `/v1/admin/machines/${hexId(machineBytes(2_041))}/revoke` },
      { method: "POST", path: "/v1/admin/epochs" },
      { method: "POST", path: `/v1/admin/epochs/${epochId}/revoke?dry_run=true` },
    ];
    await assertNoInternalErrors(
      adminRoutes.flatMap(({ method, path }, routeIndex) =>
        edgeCases.map(
          (body, corpusIndex) => () =>
            exports.default.fetch(`https://copylocker.test${path}`, {
              method,
              headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
                "Idempotency-Key": `malformed-admin-${routeIndex}-${corpusIndex}`,
              },
              body: body.slice(),
            }),
        ),
      ),
    );

    const webhookRoutes = [
      { provider: "stripe", secret: "stripe-test-secret" },
      { provider: "paddle", secret: "paddle-test-secret" },
      { provider: "lemonsqueezy", secret: "lemon-test-secret" },
    ] as const;
    await assertNoInternalErrors(
      webhookRoutes.flatMap(({ provider, secret }) =>
        edgeCases.map((body) => async () => {
          const timestamp = Math.floor(Date.now() / 1000);
          const headers: Record<string, string> = { "Content-Type": "application/json" };
          if (provider === "stripe") {
            const signed = concatBytes([textEncoder.encode(`${timestamp}.`), body]);
            headers["Stripe-Signature"] = `t=${timestamp},v1=${await hmacHex(secret, signed)}`;
          } else if (provider === "paddle") {
            const signed = concatBytes([textEncoder.encode(`${timestamp}:`), body]);
            headers["Paddle-Signature"] = `ts=${timestamp};h1=${await hmacHex(secret, signed)}`;
          } else {
            headers["X-Signature"] = await hmacHex(secret, body);
          }
          return exports.default.fetch(`https://copylocker.test/webhooks/${provider}`, {
            method: "POST",
            headers,
            body: body.slice(),
          });
        }),
      ),
    );

    await assertNoInternalErrors([
      () => exports.default.fetch("https://copylocker.test/health"),
      () =>
        exports.default.fetch("https://copylocker.test/v1/keys", {
          headers: { "X-CL-Proto": "1" },
        }),
      () =>
        exports.default.fetch(
          "https://copylocker.test/v1/revocations?since=%ff",
          { headers: { "X-CL-Proto": "1" } },
        ),
      () => exports.default.fetch("https://copylocker.test/v1/admin"),
      () =>
        exports.default.fetch("https://copylocker.test/v1/not-a-route", {
          method: "PATCH",
        }),
      () =>
        exports.default.fetch("https://copylocker.test/not-a-route", {
          method: "POST",
        }),
    ]);
  }, 30_000);

  it("activates with a signed MachineCredential and replays it byte-for-byte", async () => {
    const { licenseId, stub } = licenseObject(1_013);
    await seedProjectedLicense(licenseId, await activationKeyHmac());
    const keys = await generateDeviceKeys();
    const requestBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      keys,
    );
    const activate = () => postActivation(requestBody, "public-activate");

    const first = await activate();
    expect(first.status).toBe(200);
    expect(first.headers.get("content-type")).toBe("application/cbor");
    const firstBytes = new Uint8Array(await first.arrayBuffer());
    const envelope = cborMap(decodeTestCbor(firstBytes));
    expect(envelope.get(2)).toBe(2);
    const credential = cborMap(decodeTestCbor(cborBytes(envelope.get(3))));
    expect(credential.get(0)).toBe(1);
    expect(cborBytes(credential.get(1))).toEqual(new Uint8Array(suiteId));
    expect(credential.get(2)).toBe(productId);
    expect(cborBytes(credential.get(3))).toEqual(new Uint8Array(licenseId));
    const machineId = cborBytes(credential.get(4));
    expect(machineId).toHaveLength(16);
    expect(cborBytes(credential.get(5))).toEqual(new Uint8Array(32).fill(7));
    expect(cborBytes(credential.get(6)).length).toBeGreaterThan(0);
    expect(cborBytes(credential.get(7))).toHaveLength(72);
    expect(cborBytes(credential.get(8))).toHaveLength(32);
    expect(credential.get(14)).toBe(0);
    expect(credential.get(20)).toBe(1);
    const wrappedKeks = cborMap(credential.get(21));
    expect(cborBytes(wrappedKeks.get("feature.alpha"))).toHaveLength(72);

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: number; credential_state: ArrayBuffer }>(
          "SELECT status, credential_state FROM activations WHERE machine_id = ?",
          machineId,
        )
        .one();
      expect(row.status).toBe(0);
      expect(new Uint8Array(row.credential_state)).toHaveLength(72);
    });

    const replay = await activate();
    expect(replay.status).toBe(200);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(firstBytes);
  });

  it("requires an idempotency key before reserving an activation seat", async () => {
    const { licenseId, stub } = licenseObject(1_014);
    const licenseKey = testLicenseKey(11);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
    );
    const keys = await generateDeviceKeys();
    const requestBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      keys,
      7,
      licenseKey.value,
    );

    const response = await postActivation(requestBody);

    expect(response.status).toBe(400);
    expect(await protocolErrorCode(response)).toBe(1000);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM activations")
        .one();
      expect(row.count).toBe(0);
    });
  });

  it("rejects a forged activation proof before reserving its idempotency key", async () => {
    const { licenseId } = licenseObject(1_102);
    const licenseKey = testLicenseKey(12);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
    );
    const keys = await generateDeviceKeys();
    const requestBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      keys,
      7,
      licenseKey.value,
    );
    const forged = requestBody.slice();
    forged[forged.length - 1] ^= 0x01;

    const rejected = await postActivation(forged, "activation-proof");
    expect(rejected.status).toBe(403);
    expect(await protocolErrorCode(rejected)).toBe(1000);

    const accepted = await postActivation(requestBody, "activation-proof");
    expect(accepted.status).toBe(200);
  });

  it("rejects an activation idempotency key reused for a different request", async () => {
    const { licenseId, stub } = licenseObject(1_016);
    const licenseKey = testLicenseKey(13);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
    );
    const firstKeys = await generateDeviceKeys();
    const secondKeys = await generateDeviceKeys();
    const firstBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      firstKeys,
      7,
      licenseKey.value,
    );
    const secondBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      secondKeys,
      8,
      licenseKey.value,
    );

    const first = await postActivation(firstBody, "activation-conflict");
    expect(first.status).toBe(200);
    const firstBytes = new Uint8Array(await first.arrayBuffer());

    const conflict = await postActivation(secondBody, "activation-conflict");
    expect(conflict.status).toBe(409);
    expect(await protocolErrorCode(conflict)).toBe(1000);

    const replay = await postActivation(firstBody, "activation-conflict");
    expect(replay.status).toBe(200);
    expect(new Uint8Array(await replay.arrayBuffer())).toEqual(firstBytes);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM activations")
        .one();
      expect(row.count).toBe(1);
    });
  });

  it("returns one completed envelope to concurrent activation retries", async () => {
    const { licenseId, stub } = licenseObject(1_105);
    const licenseKey = testLicenseKey(15);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
    );
    const keys = await generateDeviceKeys();
    const requestBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      keys,
      7,
      licenseKey.value,
    );

    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        postActivation(requestBody, "activation-concurrent"),
      ),
    );
    expect(responses.every(({ status }) => status === 200)).toBe(true);
    const envelopes = await Promise.all(
      responses.map(async (response) =>
        new Uint8Array(await response.arrayBuffer()),
      ),
    );
    for (const envelope of envelopes.slice(1)) {
      expect(envelope).toEqual(envelopes[0]);
    }

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ active: number; total: number }>(
          "SELECT \
             SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) AS active, \
             COUNT(*) AS total FROM activations",
        )
        .one();
      expect(row).toEqual({ active: 1, total: 1 });
    });
  });

  it("grants exactly 3 seats through 100 concurrent public activations", async () => {
    const { licenseId, stub } = licenseObject(1_108);
    const licenseKey = testLicenseKey(16);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
      3,
    );
    const requests = await Promise.all(
      Array.from({ length: 100 }, async (_, index) => {
        const keys = await generateDeviceKeys();
        return activationRequestCbor(
          hexBytes(env.TEST_DEVICE_KEM_EK),
          keys,
          index,
          licenseKey.value,
        );
      }),
    );

    const responses = await Promise.all(
      requests.map((body, index) =>
        postActivation(body, `public-activation-${index}`),
      ),
    );
    const accepted = responses.filter(({ status }) => status === 200);
    const exhausted = responses.filter(({ status }) => status === 409);

    expect(accepted).toHaveLength(3);
    expect(exhausted).toHaveLength(97);
    await expect(
      Promise.all(exhausted.map((response) => protocolErrorCode(response))),
    ).resolves.toEqual(new Array<unknown>(97).fill(1001));

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ active: number; total: number }>(
          "SELECT \
             SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) AS active, \
             COUNT(*) AS total FROM activations",
        )
        .one();
      expect(row).toEqual({ active: 3, total: 3 });
    });
  });

  it("returns seat exhausted after activation capacity is full", async () => {
    const { licenseId, stub } = licenseObject(1_017);
    const licenseKey = testLicenseKey(14);
    await seedProjectedLicense(
      licenseId,
      await activationKeyHmac(licenseKey.bytes),
      1,
    );
    const firstKeys = await generateDeviceKeys();
    const secondKeys = await generateDeviceKeys();
    const firstBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      firstKeys,
      7,
      licenseKey.value,
    );
    const secondBody = await activationRequestCbor(
      hexBytes(env.TEST_DEVICE_KEM_EK),
      secondKeys,
      8,
      licenseKey.value,
    );

    expect((await postActivation(firstBody, "activation-seat-1")).status).toBe(200);
    const exhausted = await postActivation(secondBody, "activation-seat-2");
    expect(exhausted.status).toBe(409);
    expect(await protocolErrorCode(exhausted)).toBe(1001);

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM activations WHERE status IN (0, 3)",
        )
        .one();
      expect(row.count).toBe(1);
    });
  });

  it("requires a 16-byte license identifier", async () => {
    const stub = env.LICENSE.getByName("invalid-license-id");
    const response = await postJson(stub, "/init", {
      license_id: [1, 2, 3],
      product_id: productId,
      suite_id: suiteId,
      seats: 1,
    });

    expect(response.status).toBe(400);
  });

  it("grants exactly 3 seats under 100 concurrent reservations", async () => {
    const { licenseId, stub } = licenseObject(1_001);
    await initLicense(stub, licenseId, 3);

    const responses = await Promise.all(
      Array.from({ length: 100 }, (_, value) =>
        postJson(stub, "/reserve", reserveBody(value)),
      ),
    );

    expect(responses.filter(({ status }) => status === 201)).toHaveLength(3);
    expect(responses.filter(({ status }) => status === 409)).toHaveLength(97);

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM activations WHERE status IN (0, 3)",
        )
        .one();
      expect(row.count).toBe(3);
    });
  });

  it("replays a reservation idempotently", async () => {
    const { licenseId, stub } = licenseObject(1_002);
    await initLicense(stub, licenseId, 1);
    const body = reserveBody(1, "same-request");

    const first = await postJson(stub, "/reserve", body);
    const second = await postJson(stub, "/reserve", body);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(await first.json<ReserveResult>()).toEqual(await second.json<ReserveResult>());
    expect(
      (
        await postJson(stub, "/reserve", {
          ...body,
          fingerprint: new Array<number>(32).fill(99),
        })
      ).status,
    ).toBe(409);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM activations")
        .one();
      expect(row.count).toBe(1);
    });
  });

  it("commits, heartbeats, and deactivates a seat", async () => {
    const { licenseId, stub } = licenseObject(1_003);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(1, "lifecycle-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();

    expect(
      (
        await postJson(stub, "/commit", {
          machine_id: reservation.machine_id,
        })
      ).status,
    ).toBe(200);
    const heartbeat = await lifecycleAuthentication(
      "heartbeat-request",
      licenseId,
      reservation.machine_id,
      new Array<number>(32).fill(11),
      keys.privateKey,
    );
    expect((await postJson(stub, "/heartbeat", heartbeat)).status).toBe(200);

    const deactivation = {
      ...(await lifecycleAuthentication(
        "deactivate-request",
        licenseId,
        reservation.machine_id,
        new Array<number>(32).fill(12),
        keys.privateKey,
      )),
      idempotency_key: "lifecycle-deactivate",
    };
    const firstDeactivation = await postJson(stub, "/deactivate", deactivation);
    expect(firstDeactivation.status, await firstDeactivation.clone().text()).toBe(200);
    expect((await postJson(stub, "/deactivate", deactivation)).status).toBe(200);
    expect(
      (
        await postJson(stub, "/deactivate", {
          ...deactivation,
          nonce: new Array<number>(32).fill(13),
        })
      ).status,
    ).toBe(409);
    expect((await postJson(stub, "/reserve", reserveBody(2))).status).toBe(201);
  });

  it("routes authenticated heartbeat and deactivate CBOR requests through LicenseDO", async () => {
    const { licenseId, stub } = licenseObject(1_010);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(10, "public-lifecycle-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();
    await postJson(stub, "/commit", { machine_id: reservation.machine_id });

    const heartbeatNonce = new Array<number>(32).fill(41);
    const heartbeatInput = lifecycleProofInput(
      licenseId,
      reservation.machine_id,
      heartbeatNonce,
    );
    const heartbeatProof = await signDeviceProof(
      "heartbeat-request",
      heartbeatInput,
      keys.privateKey,
    );
    const heartbeat = await exports.default.fetch(
      "https://copylocker.test/v1/heartbeat",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/cbor",
          "X-CL-Proto": "1",
        },
        body: lifecycleRequestCbor(
          licenseId,
          reservation.machine_id,
          heartbeatNonce,
          heartbeatProof,
        ),
      },
    );
    expect(heartbeat.status).toBe(200);
    expect(heartbeat.headers.get("content-type")).toBe("application/cbor");
    expect(
      [...new Uint8Array(await heartbeat.arrayBuffer()).slice(0, 4)],
    ).toEqual([0xa2, 0x00, 0xf5, 0x01]);

    const deactivateNonce = new Array<number>(32).fill(42);
    const deactivateInput = lifecycleProofInput(
      licenseId,
      reservation.machine_id,
      deactivateNonce,
    );
    const deactivateProof = await signDeviceProof(
      "deactivate-request",
      deactivateInput,
      keys.privateKey,
    );
    const deactivateBody = lifecycleRequestCbor(
      licenseId,
      reservation.machine_id,
      deactivateNonce,
      deactivateProof,
    );
    const deactivateRequest = () =>
      exports.default.fetch("https://copylocker.test/v1/deactivate", {
        method: "POST",
        headers: {
          "Content-Type": "application/cbor",
          "Idempotency-Key": "public-deactivate",
          "X-CL-Proto": "1",
        },
        body: deactivateBody,
      });
    const deactivation = await deactivateRequest();
    expect(deactivation.status).toBe(200);
    expect(new Uint8Array(await deactivation.arrayBuffer())).toEqual(
      new Uint8Array([0xa1, 0x00, 0xf5]),
    );
    expect((await deactivateRequest()).status).toBe(200);

    const conflictNonce = new Array<number>(32).fill(43);
    const conflictInput = lifecycleProofInput(
      licenseId,
      reservation.machine_id,
      conflictNonce,
    );
    const conflict = await exports.default.fetch(
      "https://copylocker.test/v1/deactivate",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/cbor",
          "Idempotency-Key": "public-deactivate",
          "X-CL-Proto": "1",
        },
        body: lifecycleRequestCbor(
          licenseId,
          reservation.machine_id,
          conflictNonce,
          await signDeviceProof("deactivate-request", conflictInput, keys.privateKey),
        ),
      },
    );
    expect(conflict.status).toBe(409);
  });

  it("returns signed tickets and kill orders after machine and license revocation", async () => {
    const { licenseId, stub } = licenseObject(1_012);
    const keys = await generateDeviceKeys();
    await seedProjectedLicense(licenseId);
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(stub, "/reserve", {
      ...reserveBody(12, "public-validate-reserve", keys.verifyingKey),
      fingerprint: new Array<number>(32).fill(7),
      build_fp: "build-validate",
      credential_state: encryptedCredentialState,
    });
    expect(reserved.status).toBe(201);
    const reservation = await reserved.json<ReserveResult>();
    expect((await postJson(stub, "/commit", { machine_id: reservation.machine_id })).status).toBe(
      200,
    );

    const validatePublic = async (
      machineId: number[],
      privateKey: CryptoKey,
      nonceByte: number,
    ): Promise<Response> => {
      const nonce = new Array<number>(32).fill(nonceByte);
      const proofInput = validateProofInput(licenseId, machineId, nonce);
      const proof = await signDeviceProof("validate-request", proofInput, privateKey);
      return exports.default.fetch("https://copylocker.test/v1/validate", {
        method: "POST",
        headers: {
          "Content-Type": "application/cbor",
          "X-CL-Proto": "1",
        },
        body: validateRequestCbor(licenseId, machineId, nonce, proof),
      });
    };

    const ticketResponse = await validatePublic(
      reservation.machine_id,
      keys.privateKey,
      61,
    );
    expect(ticketResponse.status).toBe(200);
    expect(ticketResponse.headers.get("content-type")).toBe("application/cbor");
    const ticketEnvelope = cborMap(
      decodeTestCbor(new Uint8Array(await ticketResponse.arrayBuffer())),
    );
    expect(ticketEnvelope.get(2)).toBe(3);
    expect(cborBytes(ticketEnvelope.get(5))).toEqual(new Uint8Array(8).fill(3));
    const ticketTbs = cborBytes(ticketEnvelope.get(3));
    expect(
      await verifyFastArtifact(
        "validation-ticket",
        ticketTbs,
        cborBytes(ticketEnvelope.get(4)),
      ),
    ).toBe(true);
    const ticket = cborMap(decodeTestCbor(ticketTbs));
    expect(cborBytes(ticket.get(2))).toEqual(new Uint8Array(reservation.machine_id));
    expect(cborBytes(ticket.get(3))).toEqual(new Uint8Array(32).fill(61));
    expect(cborBytes(ticket.get(4))).toHaveLength(32);
    expect(ticket.get(9)).toBe(0);
    expect(cborBytes(ticket.get(11))).toEqual(new Uint8Array(8).fill(3));
    const wrappedKeks = cborMap(ticket.get(15));
    expect(cborBytes(wrappedKeks.get("feature.alpha"))).toHaveLength(72);

    const revokeMachine = await postJson(stub, "/revoke", {
      license_id: licenseId,
      kind: "machine",
      machine_id: reservation.machine_id,
      revocation_epoch: 1,
    });
    expect(revokeMachine.status, await revokeMachine.clone().text()).toBe(200);
    await expect(revokeMachine.json<RevokeResult>()).resolves.toEqual({
      ok: true,
      changed: true,
      revocation_epoch: 1,
    });
    const replayMachine = await postJson(stub, "/revoke", {
      license_id: licenseId,
      kind: "machine",
      machine_id: reservation.machine_id,
      revocation_epoch: 1,
    });
    await expect(replayMachine.json<RevokeResult>()).resolves.toEqual({
      ok: true,
      changed: false,
      revocation_epoch: 1,
    });
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: number; revocation_epoch: number }>(
          "SELECT status, (SELECT CAST(v AS INTEGER) FROM meta \
             WHERE k = 'revocation_epoch') AS revocation_epoch \
           FROM activations WHERE machine_id = ?",
          new Uint8Array(reservation.machine_id),
        )
        .one();
      expect(row).toEqual({ status: 2, revocation_epoch: 1 });
      const outbox = state.storage.sql
        .exec<{ payload: ArrayBuffer }>(
          "SELECT payload FROM outbox ORDER BY id DESC LIMIT 1",
        )
        .one();
      const event = JSON.parse(
        new TextDecoder().decode(outbox.payload),
      ) as ProjectionEvent;
      expect(event.machine?.status).toBe("revoked");
      expect(event.seats_used).toBe(0);
    });

    const killResponse = await validatePublic(
      reservation.machine_id,
      keys.privateKey,
      62,
    );
    expect(killResponse.status).toBe(200);
    const killEnvelope = cborMap(
      decodeTestCbor(new Uint8Array(await killResponse.arrayBuffer())),
    );
    expect(killEnvelope.get(2)).toBe(4);
    const killTbs = cborBytes(killEnvelope.get(3));
    expect(
      await verifyFastArtifact("kill-order", killTbs, cborBytes(killEnvelope.get(4))),
    ).toBe(true);
    const kill = cborMap(decodeTestCbor(killTbs));
    expect(cborBytes(kill.get(2))).toEqual(new Uint8Array(reservation.machine_id));
    expect(cborBytes(kill.get(3))).toEqual(new Uint8Array(32).fill(62));
    expect(kill.get(5)).toBe(2);
    expect(kill.get(7)).toBe(1);

    const secondKeys = await generateDeviceKeys();
    const secondReserved = await postJson(
      stub,
      "/reserve",
      reserveBody(13, "license-revoke-reserve", secondKeys.verifyingKey),
    );
    expect(secondReserved.status).toBe(201);
    const secondReservation = await secondReserved.json<ReserveResult>();
    expect(
      (
        await postJson(stub, "/commit", {
          machine_id: secondReservation.machine_id,
        })
      ).status,
    ).toBe(200);

    const staleRevoke = await postJson(stub, "/revoke", {
      license_id: licenseId,
      kind: "machine",
      machine_id: secondReservation.machine_id,
      revocation_epoch: 1,
    });
    expect(staleRevoke.status).toBe(409);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ status: number; revocation_epoch: number }>(
          "SELECT status, (SELECT CAST(v AS INTEGER) FROM meta \
             WHERE k = 'revocation_epoch') AS revocation_epoch \
           FROM activations WHERE machine_id = ?",
          new Uint8Array(secondReservation.machine_id),
        )
        .one();
      expect(row).toEqual({ status: 0, revocation_epoch: 1 });
    });

    const revokeLicense = await postJson(stub, "/revoke", {
      license_id: licenseId,
      kind: "license",
      revocation_epoch: 2,
    });
    expect(revokeLicense.status).toBe(200);
    await expect(revokeLicense.json<RevokeResult>()).resolves.toEqual({
      ok: true,
      changed: true,
      revocation_epoch: 2,
    });

    const licenseProjection = await runInDurableObject(
      stub,
      async (_instance, state) => {
        const row = state.storage.sql
          .exec<{ status: string; revocation_epoch: number }>(
            "SELECT CAST((SELECT v FROM meta WHERE k = 'status') AS TEXT) AS status, \
                    CAST((SELECT v FROM meta WHERE k = 'revocation_epoch') AS INTEGER) \
                      AS revocation_epoch",
          )
          .one();
        expect(row).toEqual({ status: "revoked", revocation_epoch: 2 });
        const outbox = state.storage.sql
          .exec<{ payload: ArrayBuffer }>(
            "SELECT payload FROM outbox ORDER BY id DESC LIMIT 1",
          )
          .one();
        return JSON.parse(
          new TextDecoder().decode(outbox.payload),
        ) as ProjectionEvent;
      },
    );
    expect(licenseProjection.license_status).toBe("revoked");
    expect(licenseProjection.machine).toBeNull();
    const projectionResult = await dispatchProjectionEvents([licenseProjection]);
    expect(projectionResult.explicitAcks).toEqual(["projection-0"]);
    const projected = await env.DB.prepare(
      "SELECT status FROM licenses WHERE id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{ status: string }>();
    expect(projected?.status).toBe("revoked");

    const licenseKillResponse = await validatePublic(
      secondReservation.machine_id,
      secondKeys.privateKey,
      63,
    );
    expect(licenseKillResponse.status).toBe(200);
    const licenseKillEnvelope = cborMap(
      decodeTestCbor(new Uint8Array(await licenseKillResponse.arrayBuffer())),
    );
    expect(licenseKillEnvelope.get(2)).toBe(4);
    const licenseKillTbs = cborBytes(licenseKillEnvelope.get(3));
    expect(
      await verifyFastArtifact(
        "kill-order",
        licenseKillTbs,
        cborBytes(licenseKillEnvelope.get(4)),
      ),
    ).toBe(true);
    const licenseKill = cborMap(decodeTestCbor(licenseKillTbs));
    expect(cborBytes(licenseKill.get(2))).toEqual(
      new Uint8Array(secondReservation.machine_id),
    );
    expect(cborBytes(licenseKill.get(3))).toEqual(new Uint8Array(32).fill(63));
    expect(licenseKill.get(5)).toBe(1);
    expect(licenseKill.get(7)).toBe(2);
  });

  it("rejects forged public lifecycle proofs without consuming their nonce", async () => {
    const { licenseId, stub } = licenseObject(1_011);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(11, "public-proof-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();
    await postJson(stub, "/commit", { machine_id: reservation.machine_id });

    const nonce = new Array<number>(32).fill(51);
    const proofInput = lifecycleProofInput(licenseId, reservation.machine_id, nonce);
    const proof = await signDeviceProof("heartbeat-request", proofInput, keys.privateKey);
    proof[0] ^= 0x01;
    const forged = await exports.default.fetch("https://copylocker.test/v1/heartbeat", {
      method: "POST",
      headers: {
        "Content-Type": "application/cbor",
        "X-CL-Proto": "1",
      },
      body: lifecycleRequestCbor(licenseId, reservation.machine_id, nonce, proof),
    });
    expect(forged.status).toBe(403);
    expect(forged.headers.get("content-type")).toBe("application/cbor");

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ nonces: number; last_hb_at: number | null }>(
          "SELECT (SELECT COUNT(*) FROM nonces) AS nonces, last_hb_at " +
            "FROM activations WHERE machine_id = ?",
          new Uint8Array(reservation.machine_id),
        )
        .one();
      expect(row).toEqual({ nonces: 0, last_hb_at: null });
    });

    const validProof = await signDeviceProof(
      "heartbeat-request",
      proofInput,
      keys.privateKey,
    );
    const valid = await exports.default.fetch("https://copylocker.test/v1/heartbeat", {
      method: "POST",
      headers: {
        "Content-Type": "application/cbor",
        "X-CL-Proto": "1",
      },
      body: lifecycleRequestCbor(licenseId, reservation.machine_id, nonce, validProof),
    });
    expect(valid.status).toBe(200);
  });

  it("does not consume a nonce or mutate state for forged or cross-domain proofs", async () => {
    const { licenseId, stub } = licenseObject(1_004);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(4, "proof-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();
    expect(
      (
        await postJson(stub, "/commit", {
          machine_id: reservation.machine_id,
        })
      ).status,
    ).toBe(200);

    const heartbeat = await lifecycleAuthentication(
      "heartbeat-request",
      licenseId,
      reservation.machine_id,
      new Array<number>(32).fill(21),
      keys.privateKey,
    );
    heartbeat.proof[0] ^= 0x01;
    expect((await postJson(stub, "/heartbeat", heartbeat)).status).toBe(401);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ nonces: number; status: number; last_hb_at: number | null }>(
          "SELECT (SELECT COUNT(*) FROM nonces) AS nonces, status, last_hb_at " +
            "FROM activations WHERE machine_id = ?",
          new Uint8Array(reservation.machine_id),
        )
        .one();
      expect(row).toEqual({ nonces: 0, status: 0, last_hb_at: null });
    });

    const validHeartbeat = await lifecycleAuthentication(
      "heartbeat-request",
      licenseId,
      reservation.machine_id,
      new Array<number>(32).fill(21),
      keys.privateKey,
    );
    expect((await postJson(stub, "/heartbeat", validHeartbeat)).status).toBe(200);

    const crossDomain = {
      ...(await lifecycleAuthentication(
        "heartbeat-request",
        licenseId,
        reservation.machine_id,
        new Array<number>(32).fill(22),
        keys.privateKey,
      )),
      idempotency_key: "cross-domain",
    };
    expect((await postJson(stub, "/deactivate", crossDomain)).status).toBe(401);
    const validDeactivation = {
      ...(await lifecycleAuthentication(
        "deactivate-request",
        licenseId,
        reservation.machine_id,
        new Array<number>(32).fill(22),
        keys.privateKey,
      )),
      idempotency_key: "cross-domain-valid",
    };
    expect((await postJson(stub, "/deactivate", validDeactivation)).status).toBe(200);
  });

  it("returns ticket and kill plans only after authenticating validate requests", async () => {
    const { licenseId, stub } = licenseObject(1_005);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(5, "validate-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();
    await postJson(stub, "/commit", { machine_id: reservation.machine_id });

    const validate = async (nonceByte: number) => {
      const nonce = new Array<number>(32).fill(nonceByte);
      const proofInput = validateProofInput(licenseId, reservation.machine_id, nonce);
      return postJson(stub, "/validate", {
        auth: {
          license_id: licenseId,
          machine_id: reservation.machine_id,
          suite_id: suiteId,
          nonce,
          proof_input: [...proofInput],
          proof: await signDeviceProof("validate-request", proofInput, keys.privateKey),
        },
        known_revocation_epoch: 0,
        authoritative_revocation_epoch: 0,
        known_security_floor: 0,
        next_refresh_after: 2_000_000_000,
        not_after: 0,
        variant_id: 1,
      });
    };

    const ticket = await validate(31);
    expect(ticket.status).toBe(200);
    await expect(ticket.json()).resolves.toEqual({
      ok: true,
      outcome: "ticket",
      kill_reason: null,
      revocation_epoch: 0,
      security_floor: 0,
      suspicion: 0,
      fingerprint: new Array<number>(32).fill(5),
      credential_state: null,
    });

    const revoked = await postJson(stub, "/revoke", {
      license_id: licenseId,
      kind: "machine",
      machine_id: reservation.machine_id,
      revocation_epoch: 1,
    });
    expect(revoked.status).toBe(200);
    const kill = await validate(32);
    expect(kill.status).toBe(200);
    await expect(kill.json()).resolves.toMatchObject({
      ok: true,
      outcome: "kill",
      kill_reason: 2,
      revocation_epoch: 1,
    });
  });

  it("rejects a replayed nonce", async () => {
    const { licenseId, stub } = licenseObject(1_006);
    const keys = await generateDeviceKeys();
    await initLicense(stub, licenseId, 1);
    const reserved = await postJson(
      stub,
      "/reserve",
      reserveBody(6, "nonce-reserve", keys.verifyingKey),
    );
    const reservation = await reserved.json<ReserveResult>();
    await postJson(stub, "/commit", { machine_id: reservation.machine_id });
    const heartbeat = await lifecycleAuthentication(
      "heartbeat-request",
      licenseId,
      reservation.machine_id,
      new Array<number>(32).fill(7),
      keys.privateKey,
    );

    expect((await postJson(stub, "/heartbeat", heartbeat)).status).toBe(200);
    expect((await postJson(stub, "/heartbeat", heartbeat)).status).toBe(409);
  });

  it("reclaims an expired pending reservation when its alarm runs", async () => {
    const { licenseId, stub } = licenseObject(1_007);
    await initLicense(stub, licenseId, 1);
    expect((await postJson(stub, "/reserve", reserveBody(1))).status).toBe(201);

    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec("UPDATE activations SET created_at = 0 WHERE status = 3");
      await state.storage.setAlarm(Date.now() + 60_000);
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    expect((await postJson(stub, "/reserve", reserveBody(2))).status).toBe(201);
  });

  it("delivers durable outbox rows and marks them sent", async () => {
    const { licenseId, stub } = licenseObject(1_008);
    await initLicense(stub, licenseId, 1);
    expect((await postJson(stub, "/reserve", reserveBody(1))).status).toBe(201);

    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM outbox WHERE sent_at IS NULL",
        )
        .one();
      expect(row.count).toBe(1);
      await state.storage.setAlarm(Date.now() + 60_000);
    });

    expect(await runDurableObjectAlarm(stub)).toBe(true);
    await runInDurableObject(stub, async (_instance, state) => {
      const row = state.storage.sql
        .exec<{ pending: number; sent: number }>(
          "SELECT \
             SUM(CASE WHEN sent_at IS NULL THEN 1 ELSE 0 END) AS pending, \
             SUM(CASE WHEN sent_at IS NOT NULL THEN 1 ELSE 0 END) AS sent \
           FROM outbox",
        )
        .one();
      expect(row).toEqual({ pending: 0, sent: 1 });
    });
  });

  it("signs idempotently and extends the issuer audit chain", async () => {
    const routingKey = licenseBytes(501);
    const shard = issuerShard(routingKey);
    const stub = env.ISSUER.getByName(`issuer-${shard}`);
    const firstSubject = machineBytes(501);
    const firstBody = {
      idempotency_key: "issue-first",
      shard,
      routing_key: routingKey,
      kind: 4,
      product_id: "product_1",
      subject: firstSubject,
      tbs: killOrderTbs(firstSubject),
    };

    const firstResponse = await postJson(stub, "/sign", firstBody);
    expect(firstResponse.status).toBe(201);
    const first = await firstResponse.json<IssueResult>();
    expect(first.ok).toBe(true);
    expect(first.seq).toBe(1);
    expect(first.epoch_id).toEqual(new Array<number>(8).fill(3));
    expect(first.envelope.length).toBeGreaterThan(firstBody.tbs.length);
    expect(first.prev_hash).toEqual(new Array<number>(32).fill(0));

    const replayResponse = await postJson(stub, "/sign", firstBody);
    expect(replayResponse.status).toBe(200);
    await expect(replayResponse.json()).resolves.toEqual(first);

    const conflictingResponse = await postJson(stub, "/sign", {
      ...firstBody,
      tbs: [...firstBody.tbs, 0x00],
    });
    expect(conflictingResponse.status).toBe(409);

    const secondSubject = machineBytes(502);
    const secondResponse = await postJson(stub, "/sign", {
      idempotency_key: "issue-second",
      shard,
      routing_key: routingKey,
      kind: 4,
      product_id: "product_1",
      subject: secondSubject,
      tbs: killOrderTbs(secondSubject),
    });
    expect(secondResponse.status).toBe(201);
    const second = await secondResponse.json<IssueResult>();
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toEqual(first.hash);

    await runInDurableObject(stub, async (_instance, state) => {
      const issued = state.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM issuance_log")
        .one();
      const outbox = state.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM outbox",
        )
        .one();
      expect(issued.count).toBe(2);
      expect(outbox.count).toBe(2);
    });
  });

  it("rejects semantically invalid RevocationBatch signing requests without writes", async () => {
    const routingKey = licenseBytes(504);
    const shard = issuerShard(routingKey);
    const stub = env.ISSUER.getByName(`issuer-${shard}`);
    const subject = machineBytes(504);
    const invalidBatches = [
      revocationBatchTbs(2, 1, [], [subject]),
      revocationBatchTbs(0, 0, [], [subject]),
      revocationBatchTbs(1, 1, [], [machineBytes(505)]),
      revocationBatchTbs(1, 1, [], [subject], 2),
    ];

    for (const [index, tbs] of invalidBatches.entries()) {
      const response = await postJson(stub, "/sign", {
        idempotency_key: `invalid-revocation-batch-${index}`,
        shard,
        routing_key: routingKey,
        kind: 5,
        product_id: "product_1",
        subject,
        tbs,
      });
      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toEqual({
        ok: false,
        error: "invalid_artifact",
      });
    }

    await runInDurableObject(stub, async (_instance, state) => {
      const counts = state.storage.sql
        .exec<{ issued: number; outbox: number; idem: number }>(
          "SELECT \
             (SELECT COUNT(*) FROM issuance_log) AS issued, \
             (SELECT COUNT(*) FROM outbox) AS outbox, \
             (SELECT COUNT(*) FROM idem) AS idem",
        )
        .one();
      expect(counts).toEqual({ issued: 0, outbox: 0, idem: 0 });
    });
  });

  it("rejects a signing request routed to the wrong issuer shard without writes", async () => {
    const routingKey = licenseBytes(503);
    const shard = issuerShard(routingKey);
    const wrongShard = (shard + 1) % 8;
    const stub = env.ISSUER.getByName(`issuer-${wrongShard}`);
    const subject = machineBytes(503);

    const response = await postJson(stub, "/sign", {
      idempotency_key: "issue-wrong-shard",
      shard,
      routing_key: routingKey,
      kind: 4,
      product_id: "product_1",
      subject,
      tbs: killOrderTbs(subject),
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      error: "wrong_issuer_shard",
    });
    await runInDurableObject(stub, async (_instance, state) => {
      const counts = state.storage.sql
        .exec<{ issued: number; outbox: number; idem: number }>(
          "SELECT \
             (SELECT COUNT(*) FROM issuance_log) AS issued, \
             (SELECT COUNT(*) FROM outbox) AS outbox, \
             (SELECT COUNT(*) FROM idem) AS idem",
        )
        .one();
      expect(counts).toEqual({ issued: 0, outbox: 0, idem: 0 });
    });
  });

  it("archives audit events to R2 and indexes replays idempotently", async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    const event = await auditEvent(2, 101, [0xa1, 0x00, 0x01]);

    const first = await dispatchEvents([event], "audit");
    expect(first.explicitAcks).toEqual(["audit-0"]);
    expect(first.retryMessages).toEqual([]);

    const object = await env.ARCHIVE.get(event.r2_key);
    expect(object).not.toBeNull();
    if (object === null) {
      throw new Error("audit archive was not written");
    }
    const archived = new Uint8Array(await object.arrayBuffer());
    expect(archived.byteLength).toBeGreaterThan(event.envelope.length);

    const index = await env.DB.prepare(
      "SELECT ts, actor, action, target, r2_key FROM audit_index WHERE seq = ?",
    )
      .bind(803)
      .first<{
        ts: number;
        actor: string;
        action: string;
        target: string;
        r2_key: string;
      }>();
    expect(index).toEqual({
      ts: event.occurred_at,
      actor: "issuer:2",
      action: "issue:kill-order",
      target: event.subject.map((byte) => byte.toString(16).padStart(2, "0")).join(""),
      r2_key: event.r2_key,
    });

    const replay = await dispatchEvents([event], "audit-replay");
    expect(replay.explicitAcks).toEqual(["audit-replay-0"]);
    expect(replay.retryMessages).toEqual([]);
  });

  it("retries an audit event that conflicts with an immutable R2 key", async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    const original = await auditEvent(3, 102, [0xa1, 0x00, 0x01]);
    const conflicting = await auditEvent(3, 102, [0xa1, 0x00, 0x02]);

    const first = await dispatchEvents([original], "audit-original");
    expect(first.explicitAcks).toEqual(["audit-original-0"]);

    const conflict = await dispatchEvents([conflicting], "audit-conflict");
    expect(conflict.explicitAcks).toEqual([]);
    expect(conflict.retryMessages).toEqual([{ msgId: "audit-conflict-0" }]);
  });

  it("projects queue messages idempotently across replay and reordering", async () => {
    const licenseId = licenseBytes(77);
    await seedProjectedLicense(licenseId);
    const newest = projectionEvent(licenseId, 2, "active", 1);
    const older = projectionEvent(licenseId, 1, "pending", 2);

    const firstResult = await dispatchProjectionEvents([newest, older]);
    expect(firstResult.explicitAcks).toEqual(["projection-0", "projection-1"]);
    expect(firstResult.retryMessages).toEqual([]);

    const replay = structuredClone(newest);
    if (replay.machine) {
      replay.machine.app_version = "should-not-overwrite";
      replay.machine.suspicion = 99;
    }
    const replayResult = await dispatchProjectionEvents([replay]);
    expect(replayResult.explicitAcks).toEqual(["projection-0"]);
    expect(replayResult.retryMessages).toEqual([]);

    const machine = await env.DB.prepare(
      "SELECT status, app_version, suspicion, proj_version FROM machines WHERE id = ?",
    )
      .bind(new Uint8Array(machineBytes(42)))
      .first<{
        status: string;
        app_version: string;
        suspicion: number;
        proj_version: number;
      }>();
    expect(machine).toEqual({
      status: "active",
      app_version: "1.0.2",
      suspicion: 2,
      proj_version: 2,
    });

    const license = await env.DB.prepare(
      "SELECT status, seats_used, proj_version FROM licenses WHERE id = ?",
    )
      .bind(new Uint8Array(licenseId))
      .first<{ status: string; seats_used: number; proj_version: number }>();
    expect(license).toEqual({ status: "active", seats_used: 1, proj_version: 2 });
  });

  it("acks malformed projection messages without touching D1", async () => {
    const result = await dispatchProjectionEvents([
      {
        event: "license_projection",
        schema_version: 1,
        license_id: [1, 2, 3],
      },
    ]);

    expect(result.explicitAcks).toEqual(["projection-0"]);
    expect(result.retryMessages).toEqual([]);
  });

  it("retries a valid projection when D1 rejects the write", async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
    await env.DB.exec(
      "CREATE TRIGGER fail_projection \
       BEFORE INSERT ON machines \
       BEGIN SELECT RAISE(FAIL, 'injected projection failure'); END",
    );

    try {
      const result = await dispatchProjectionEvents([
        projectionEvent(licenseBytes(88), 1, "active", 1),
      ]);

      expect(result.explicitAcks).toEqual([]);
      expect(result.retryMessages).toEqual([{ msgId: "projection-0" }]);
    } finally {
      await env.DB.exec("DROP TRIGGER fail_projection");
    }
  });

  const schemas = [
    {
      className: "LicenseDO",
      namespace: () => env.LICENSE,
      schemaVersion: 4,
      tables: [
        "_sql_schema_migrations",
        "activations",
        "idem",
        "meta",
        "nonces",
        "outbox",
        "transfers",
      ],
    },
    {
      className: "AccountDO",
      namespace: () => env.ACCOUNT,
      schemaVersion: 1,
      tables: ["_sql_schema_migrations", "login_attempts", "sessions"],
    },
    {
      className: "IssuerDO",
      namespace: () => env.ISSUER,
      schemaVersion: 2,
      tables: ["_sql_schema_migrations", "idem", "issuance_log", "outbox"],
    },
  ] as const;

  for (const schema of schemas) {
    it(`initializes ${schema.className} schema`, async () => {
      const stub = schema.namespace().getByName(`schema-${schema.className}`);
      const response = await stub.fetch("https://durable.test/health");

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        ok: true,
        class: schema.className,
        schema_version: schema.schemaVersion,
      });

      const tables = await runInDurableObject(stub, async (_instance, state) =>
        state.storage.sql
          .exec<{ name: string }>(
            "SELECT name FROM sqlite_master " +
              "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
          )
          .toArray()
          .map(({ name }) => name),
      );

      expect(tables).toEqual([...schema.tables].sort());
    });
  }
});
