import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type ServerOptions } from 'node:https';

import {
  deriveDeviceAuthorizationIdV2,
  deriveDeviceIdV2,
  deriveDeviceOperationIdV2,
  deriveGenesisHash,
  deriveSubject,
  signProtocolPayload,
  verifyProtocolPayload,
} from '../../packages/crypto/src/index.js';
import {
  base64Url32Schema,
  decodeBase64UrlExact,
  deviceActivationRequestV2Schema,
  deviceRegistryReceiptV2Schema,
  deviceRegistryStatusV2Schema,
  deviceStatusRequestV2Schema,
  deviceStatusStatementV2Schema,
  encodeBase64Url,
  registerIdentityRequestV1Schema,
  registryReceiptV1Schema,
  registryStatusV1Schema,
  revokeRequestV1Schema,
  serviceKeySetSchema,
  statusRequestV1Schema,
  statusStatementV1Schema,
  type Base64Url32,
  type DeviceRegistryReceiptV2,
  type IdentityGenesisV1,
  type NexusDeviceAuthorizationIdV2,
  type NexusDeviceIdV2,
  type NexusSubject,
  type RegistryReceiptV1,
  type ServiceKeySet,
} from '../../packages/protocol/src/index.js';
import {
  verifyRevocationSecret,
  verifyRevokeBySignature,
} from '../../packages/verifier/src/index.js';

import { REGISTRY_ORIGIN, WALLET_ORIGIN } from './origins.js';

const SIGNER_KID = 'e2e-registry-key';
const MAX_BODY_BYTES = 64 * 1024;

interface StoredIdentity {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  genesisHash: Base64Url32;
  registeredAt: number;
  revokedAt?: number;
  registrationReceipt: RegistryReceiptV1;
  revocationReceipt?: RegistryReceiptV1;
  deviceLedgerSequence: number;
  devices: Map<NexusDeviceIdV2, StoredDevice>;
}

interface StoredDevice {
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  activatedAt: number;
  authorizationExpiresAt: number;
  receipt: DeviceRegistryReceiptV2;
}

export interface StartedRegistryFixture {
  readonly serviceKeyset: ServiceKeySet;
  readonly stop: () => Promise<void>;
}

export async function startRegistryFixture(tls: ServerOptions): Promise<StartedRegistryFixture> {
  const registry = await TestRegistry.create();
  const server = createServer(tls, (request, response) => {
    void registry.route(request, response);
  });
  const port = Number(new URL(REGISTRY_ORIGIN).port);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    serviceKeyset: registry.serviceKeyset,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      }),
  };
}

class TestRegistry {
  readonly #identities = new Map<NexusSubject, StoredIdentity>();

  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly keyset: ServiceKeySet,
  ) {}

  public get serviceKeyset(): ServiceKeySet {
    return this.keyset;
  }

  public static async create(): Promise<TestRegistry> {
    const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const keyset = serviceKeySetSchema.parse({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: SIGNER_KID,
          x: encodeBase64Url(rawPublicKey),
          use: 'sig',
        },
      ],
    });
    return new TestRegistry(pair.privateKey, keyset);
  }

  public async route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    setApiHeaders(request, response);
    try {
      const url = new URL(request.url ?? '/', REGISTRY_ORIGIN);
      if (request.method === 'OPTIONS') {
        response.statusCode = 204;
        response.end();
        return;
      }
      if (request.method === 'GET' && url.pathname === '/.well-known/jwks.json') {
        sendJson(response, 200, this.keyset, 'application/json');
        return;
      }
      if (request.method === 'GET' && url.pathname === '/health') {
        sendJson(response, 200, { ok: true });
        return;
      }
      if (request.method !== 'POST') {
        sendError(response, 405, 'METHOD_NOT_ALLOWED');
        return;
      }
      const mediaType = request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
      if (mediaType !== 'application/nexus+json') {
        sendError(response, 415, 'UNSUPPORTED_MEDIA_TYPE');
        return;
      }
      if (url.pathname === '/v1/identity/register') {
        await this.#register(await readJson(request), response);
        return;
      }
      if (url.pathname === '/v1/identity/status') {
        await this.#status(await readJson(request), response);
        return;
      }
      if (url.pathname === '/v1/identity/revoke') {
        await this.#revoke(await readJson(request), response);
        return;
      }
      if (url.pathname === '/v2/device/activate') {
        await this.#activateDevice(await readJson(request), response);
        return;
      }
      if (url.pathname === '/v2/device/status') {
        await this.#deviceStatus(
          await readJson(request),
          response,
          request.headers.origin === WALLET_ORIGIN,
        );
        return;
      }
      sendError(response, 404, 'NOT_FOUND');
    } catch (error) {
      sendError(response, 400, error instanceof Error ? error.name : 'BAD_REQUEST');
    }
  }

  async #register(value: unknown, response: ServerResponse): Promise<void> {
    const request = registerIdentityRequestV1Schema.parse(value);
    const computedSubject = await deriveSubject(request.genesis);
    if (computedSubject !== request.subject) throw new TypeError('INVALID_SUBJECT');

    const existing = this.#identities.get(request.subject);
    if (existing !== undefined) {
      sendJson(response, 200, { receipt: existing.registrationReceipt });
      return;
    }

    const acceptedAt = nowSeconds();
    const genesisHash = base64Url32Schema.parse(
      encodeBase64Url(await deriveGenesisHash(request.genesis)),
    );
    const registrationReceipt = await this.#receipt({
      eventId: await eventId(`registered:${request.subject}`),
      subject: request.subject,
      genesisHash,
      eventType: 'registered',
      sequence: 0,
      state: 'active',
      acceptedAt,
    });
    this.#identities.set(request.subject, {
      subject: request.subject,
      genesis: request.genesis,
      genesisHash,
      registeredAt: acceptedAt,
      registrationReceipt,
      deviceLedgerSequence: 0,
      devices: new Map(),
    });
    sendJson(response, 201, { receipt: registrationReceipt });
  }

  async #status(value: unknown, response: ServerResponse): Promise<void> {
    const request = statusRequestV1Schema.parse(value);
    const identity = this.#identities.get(request.subject);
    if (identity === undefined) {
      sendError(response, 404, 'IDENTITY_NOT_FOUND');
      return;
    }
    const iat = nowSeconds();
    const revoked = identity.revokedAt !== undefined;
    const statusStatement = statusStatementV1Schema.parse({
      payload: {
        protocol: 'nexus.status-statement.v1',
        subject: identity.subject,
        state: revoked ? 'revoked' : 'active',
        sequence: revoked ? 1 : 0,
        registeredAt: identity.registeredAt,
        ...(identity.revokedAt === undefined ? {} : { revokedAt: identity.revokedAt }),
        iat,
        exp: iat + 60,
        signerKid: SIGNER_KID,
      },
      signature: await signProtocolPayload(
        {
          protocol: 'nexus.status-statement.v1',
          subject: identity.subject,
          state: revoked ? 'revoked' : 'active',
          sequence: revoked ? 1 : 0,
          registeredAt: identity.registeredAt,
          ...(identity.revokedAt === undefined ? {} : { revokedAt: identity.revokedAt }),
          iat,
          exp: iat + 60,
          signerKid: SIGNER_KID,
        },
        this.privateKey,
      ),
    });
    const status = registryStatusV1Schema.parse({
      subject: identity.subject,
      state: revoked ? 'revoked' : 'active',
      sequence: revoked ? 1 : 0,
      registeredAt: identity.registeredAt,
      revokedAt: identity.revokedAt ?? null,
      genesis: identity.genesis,
      statusStatement,
    });
    sendJson(response, 200, status);
  }

  async #revoke(value: unknown, response: ServerResponse): Promise<void> {
    const request = revokeRequestV1Schema.parse(value);
    const identity = this.#identities.get(request.payload.subject);
    if (identity === undefined) {
      sendError(response, 404, 'IDENTITY_NOT_FOUND');
      return;
    }
    if (identity.revocationReceipt !== undefined) {
      sendJson(response, 200, { receipt: identity.revocationReceipt });
      return;
    }
    if (request.mode === 'signature') {
      await verifyRevokeBySignature(request, identity.genesis, {
        subject: identity.subject,
        expectedSequence: 0,
        nonce: request.payload.nonce,
        now: nowSeconds(),
        maxClockSkewSeconds: 30,
      });
    } else {
      await verifyRevocationSecret(request, identity.genesis, {
        subject: identity.subject,
        expectedSequence: 0,
      });
    }

    const acceptedAt = nowSeconds();
    const receipt = await this.#receipt({
      eventId: await eventId(`revoked:${identity.subject}`),
      subject: identity.subject,
      genesisHash: identity.genesisHash,
      eventType: 'revoked',
      sequence: 1,
      state: 'revoked',
      acceptedAt,
    });
    identity.revokedAt = acceptedAt;
    identity.revocationReceipt = receipt;
    sendJson(response, 200, { receipt });
  }

  async #activateDevice(value: unknown, response: ServerResponse): Promise<void> {
    const request = deviceActivationRequestV2Schema.parse(value);
    const authorization = request.authorization.payload;
    const identity = this.#identities.get(authorization.subject);
    if (identity === undefined) {
      sendError(response, 404, 'IDENTITY_NOT_FOUND');
      return;
    }
    if (identity.revokedAt !== undefined) {
      sendError(response, 409, 'IDENTITY_REVOKED');
      return;
    }
    const [deviceId, authorizationId] = await Promise.all([
      deriveDeviceIdV2({ subject: authorization.subject, signingKey: authorization.signingKey }),
      deriveDeviceAuthorizationIdV2(authorization),
    ]);
    if (
      authorization.genesisHash !== identity.genesisHash ||
      authorization.deviceId !== deviceId ||
      request.payload.deviceId !== deviceId ||
      request.payload.authorizationId !== authorizationId
    ) {
      sendError(response, 400, 'BAD_REQUEST');
      return;
    }
    const rootKey = await importEd25519PublicKey(identity.genesis.signingKey.publicKey);
    const deviceKey = await importEd25519PublicKey(authorization.signingKey.publicKey);
    const [validRoot, validDevice] = await Promise.all([
      verifyProtocolPayload(authorization, request.authorization.rootSignature, rootKey),
      verifyProtocolPayload(request.payload, request.deviceSignature, deviceKey),
    ]);
    if (!validRoot || !validDevice) {
      sendError(response, 403, 'INVALID_SIGNATURE');
      return;
    }
    const now = nowSeconds();
    if (
      now < authorization.validFrom - 30 ||
      now > authorization.activationDeadline + 30 ||
      now >= authorization.expiresAt ||
      now < request.payload.iat - 30 ||
      now > request.payload.exp + 30 ||
      request.payload.exp - request.payload.iat > 300
    ) {
      sendError(response, 400, 'BAD_REQUEST');
      return;
    }
    const existing = identity.devices.get(deviceId);
    if (existing !== undefined) {
      if (existing.authorizationId !== authorizationId) {
        sendError(response, 409, 'DEVICE_AUTHORIZATION_CONFLICT');
        return;
      }
      sendJson(response, 200, { receipt: existing.receipt });
      return;
    }

    const acceptedAt = now;
    identity.deviceLedgerSequence += 1;
    const operationId = await deriveDeviceOperationIdV2(request.payload);
    const receipt = await this.#deviceReceipt({
      eventId: await deviceEventId(`activated:${identity.subject}:${deviceId}`),
      operationId,
      eventType: 'activated',
      subject: identity.subject,
      genesisHash: identity.genesisHash,
      identitySequence: 0,
      identityState: 'active',
      deviceLedgerSequence: identity.deviceLedgerSequence,
      deviceId,
      authorizationId,
      deviceState: 'active',
      authorizationExpiresAt: authorization.expiresAt,
      acceptedAt,
    });
    identity.devices.set(deviceId, {
      deviceId,
      authorizationId,
      activatedAt: acceptedAt,
      authorizationExpiresAt: authorization.expiresAt,
      receipt,
    });
    sendJson(response, 201, { receipt });
  }

  async #deviceStatus(
    value: unknown,
    response: ServerResponse,
    exerciseWalletClockSkew: boolean,
  ): Promise<void> {
    const request = deviceStatusRequestV2Schema.parse(value);
    const identity = this.#identities.get(request.subject);
    const device = identity?.devices.get(request.deviceId);
    if (
      identity === undefined ||
      device === undefined ||
      device.authorizationId !== request.authorizationId
    ) {
      sendError(response, 404, 'DEVICE_NOT_FOUND');
      return;
    }
    // Exercise the wallet's bounded clock-skew handling without changing the RP fixture's clock.
    const issuedAt = nowSeconds() + (exerciseWalletClockSkew ? 5 : 0);
    const identityRevoked = identity.revokedAt !== undefined;
    const expired = issuedAt >= device.authorizationExpiresAt;
    const deviceState = identityRevoked ? 'revoked' : expired ? 'expired' : 'active';
    const statusPayload = {
      protocol: 'nexus.device-status-statement.v2' as const,
      subject: identity.subject,
      genesisHash: identity.genesisHash,
      identityState: identityRevoked ? ('revoked' as const) : ('active' as const),
      identitySequence: identityRevoked ? 1 : 0,
      deviceLedgerSequence: identity.deviceLedgerSequence,
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      deviceState,
      activatedAt: device.activatedAt,
      ...(identity.revokedAt === undefined ? {} : { revokedAt: identity.revokedAt }),
      authorizationExpiresAt: device.authorizationExpiresAt,
      iat: issuedAt,
      exp: expired ? issuedAt + 60 : Math.min(issuedAt + 60, device.authorizationExpiresAt),
      signerKid: SIGNER_KID,
    };
    const statusStatement = deviceStatusStatementV2Schema.parse({
      payload: statusPayload,
      signature: await signProtocolPayload(statusPayload, this.privateKey),
    });
    const status = deviceRegistryStatusV2Schema.parse({
      subject: identity.subject,
      genesisHash: identity.genesisHash,
      identityState: statusPayload.identityState,
      identitySequence: statusPayload.identitySequence,
      deviceLedgerSequence: identity.deviceLedgerSequence,
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      deviceState,
      activatedAt: device.activatedAt,
      revokedAt: identity.revokedAt ?? null,
      authorizationExpiresAt: device.authorizationExpiresAt,
      statusStatement,
    });
    sendJson(response, 200, status);
  }

  async #receipt(
    payload: Omit<RegistryReceiptV1['payload'], 'protocol' | 'signerKid'>,
  ): Promise<RegistryReceiptV1> {
    const signedPayload = {
      protocol: 'nexus.registry-receipt.v1' as const,
      ...payload,
      signerKid: SIGNER_KID,
    };
    return registryReceiptV1Schema.parse({
      payload: signedPayload,
      signature: await signProtocolPayload(signedPayload, this.privateKey),
    });
  }

  async #deviceReceipt(
    payload: Omit<DeviceRegistryReceiptV2['payload'], 'protocol' | 'signerKid'>,
  ): Promise<DeviceRegistryReceiptV2> {
    const signedPayload = {
      protocol: 'nexus.device-registry-receipt.v2' as const,
      ...payload,
      signerKid: SIGNER_KID,
    };
    return deviceRegistryReceiptV2Schema.parse({
      payload: signedPayload,
      signature: await signProtocolPayload(signedPayload, this.privateKey),
    });
  }
}

function setApiHeaders(request: IncomingMessage, response: ServerResponse): void {
  const origin = request.headers.origin;
  response.setHeader('Access-Control-Allow-Origin', origin === WALLET_ORIGIN ? origin : '*');
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'accept, content-type');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buffer.byteLength;
    if (size > MAX_BODY_BYTES) throw new TypeError('BODY_TOO_LARGE');
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: unknown,
  contentType = 'application/nexus+json',
): void {
  if (response.writableEnded) return;
  response.statusCode = status;
  response.setHeader('Content-Type', `${contentType}; charset=utf-8`);
  response.end(JSON.stringify(value));
}

function sendError(response: ServerResponse, status: number, code: string): void {
  sendJson(response, status, {
    error: { code, message: 'The test registry rejected the request.' },
  });
}

async function eventId(label: string): Promise<`nxe1_${string}`> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label));
  return `nxe1_${encodeBase64Url(new Uint8Array(digest))}`;
}

async function deviceEventId(label: string): Promise<`nxde2_${string}`> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label));
  return `nxde2_${encodeBase64Url(new Uint8Array(digest))}`;
}

async function importEd25519PublicKey(encoded: string): Promise<CryptoKey> {
  const publicKey = Uint8Array.from(decodeBase64UrlExact(encoded, 32));
  return crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
