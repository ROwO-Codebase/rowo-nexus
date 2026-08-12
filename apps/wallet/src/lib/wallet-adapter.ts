import {
  registryReceiptV1Schema,
  registryStatusV1Schema,
  deviceRegistryStatusV2Schema,
  serviceKeySetSchema,
  type ContinuityLinkV1,
  type DeviceActivationRequestV2,
  type DeviceRegistryReceiptV2,
  type DeviceRegistryStatusV2,
  type DeviceRootRevokeRequestV2,
  type DeviceSelfRevokeRequestV2,
  type DeviceStatusRequestV2,
  type OwnershipProofV1,
  type OwnershipProofV2,
  type ProofRequest,
  type RegistryReceiptV1,
  type RevokeBySecretRequestV1,
  type RevokeBySignatureRequestV1,
  type ServiceKeySet,
} from '@nexus/protocol';
import {
  verifyDeviceRegistryReceipt,
  verifyDeviceStatusStatement,
  verifyRegistryReceipt,
} from '@nexus/verifier';
import {
  IndexedDbIdentityStore,
  WalletCore,
  WebCryptoIndexedDbKeyVault,
  type CreatedLocalIdentity,
  type DeviceTransferEnvelopeV2,
  type ImportedDeviceV2,
  type IssueDeviceTransferOptions,
  type IssuedDeviceTransferV2,
  type LocalIdentitySummary,
  type RegistryClient,
  type RegistryIdentityStatus,
  type RegistryRegisterRequest,
  type TrustedWalletEventBoundary,
} from '@nexus/wallet-core';

import { retryIdentityRegistration } from './registration-recovery';
import type { NexusOwnershipProofProtocol } from './popup-protocol';

const API_MEDIA_TYPE = 'application/nexus+json';
const DATABASE_NAME = 'rowo-nexus-wallet-v1';
const DEVICE_STATUS_MAX_CLOCK_SKEW_SECONDS = 60;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function configuredApiUrl(): URL {
  const raw =
    import.meta.env.VITE_NEXUS_API_URL?.trim() ||
    (import.meta.env.DEV ? 'http://localhost:8787' : 'https://nexus.rowo.link');
  const parsed = new URL(raw);
  const localHttp =
    parsed.protocol === 'http:' &&
    (parsed.hostname === 'localhost' ||
      parsed.hostname === '127.0.0.1' ||
      parsed.hostname === '[::1]');
  if (parsed.protocol !== 'https:' && !localHttp) {
    throw new Error('VITE_NEXUS_API_URL must use HTTPS outside local development.');
  }
  if (
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    (parsed.pathname !== '' && parsed.pathname !== '/')
  ) {
    throw new Error('VITE_NEXUS_API_URL must be an origin without credentials, query, or path.');
  }
  return new URL(parsed.origin);
}

export const nexusApiUrl = configuredApiUrl();

async function parseJsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim();
  if (contentType !== API_MEDIA_TYPE && contentType !== 'application/json') {
    throw new Error('The Nexus registry returned an unsupported response type.');
  }
  const value = (await response.json()) as unknown;
  if (!response.ok) {
    const code =
      isRecord(value) && isRecord(value.error) && typeof value.error.code === 'string'
        ? value.error.code
        : `HTTP_${String(response.status)}`;
    throw new Error(`The Nexus registry rejected the request (${code}).`);
  }
  return value;
}

async function postRegistry(path: string, body: unknown): Promise<unknown> {
  const response = await fetch(new URL(path, nexusApiUrl), {
    method: 'POST',
    headers: { 'Content-Type': API_MEDIA_TYPE, Accept: API_MEDIA_TYPE },
    body: JSON.stringify(body),
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
  });
  return parseJsonResponse(response);
}

let keysetPromise: Promise<ServiceKeySet> | undefined;

async function loadServiceKeyset(): Promise<ServiceKeySet> {
  keysetPromise ??= fetch(new URL('/.well-known/jwks.json', nexusApiUrl), {
    cache: 'no-store',
    credentials: 'omit',
    headers: { Accept: 'application/json' },
    referrerPolicy: 'no-referrer',
  })
    .then(parseJsonResponse)
    .then((value) => serviceKeySetSchema.parse(value))
    .catch((error: unknown) => {
      keysetPromise = undefined;
      throw error;
    });
  return keysetPromise;
}

class HttpRegistryClient implements RegistryClient {
  public async register(request: RegistryRegisterRequest): Promise<RegistryReceiptV1> {
    const value = await postRegistry('/v1/identity/register', request);
    if (!isRecord(value)) throw new Error('The registration response is malformed.');
    return registryReceiptV1Schema.parse(value.receipt);
  }

  public async getStatus(
    subject: RegistryRegisterRequest['subject'],
  ): Promise<RegistryIdentityStatus> {
    const value = registryStatusV1Schema.parse(
      await postRegistry('/v1/identity/status', { subject }),
    );
    return {
      subject: value.subject,
      state: value.state,
      sequence: value.sequence,
      registeredAt: value.registeredAt,
      ...(value.revokedAt === null ? {} : { revokedAt: value.revokedAt }),
    };
  }

  public async revoke(
    request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1,
  ): Promise<RegistryReceiptV1> {
    const value = await postRegistry('/v1/identity/revoke', request);
    if (!isRecord(value)) throw new Error('The revocation response is malformed.');
    return registryReceiptV1Schema.parse(value.receipt);
  }

  public async activateDevice(
    request: DeviceActivationRequestV2,
  ): Promise<DeviceRegistryReceiptV2> {
    return this.#deviceMutation('/v2/device/activate', request);
  }

  public async revokeDeviceSelf(
    request: DeviceSelfRevokeRequestV2,
  ): Promise<DeviceRegistryReceiptV2> {
    return this.#deviceMutation('/v2/device/revoke-self', request);
  }

  public async revokeDeviceRoot(
    request: DeviceRootRevokeRequestV2,
  ): Promise<DeviceRegistryReceiptV2> {
    return this.#deviceMutation('/v2/device/revoke-root', request);
  }

  public async getDeviceStatus(request: DeviceStatusRequestV2): Promise<DeviceRegistryStatusV2> {
    return deviceRegistryStatusV2Schema.parse(await postRegistry('/v2/device/status', request));
  }

  async #deviceMutation(path: string, request: unknown): Promise<DeviceRegistryReceiptV2> {
    const value = await postRegistry(path, request);
    if (!isRecord(value)) throw new Error('The device registry response is malformed.');
    return verifyDeviceRegistryReceipt(value.receipt, await loadServiceKeyset());
  }
}

const identityStore = new IndexedDbIdentityStore({ databaseName: DATABASE_NAME });
const walletCore = new WalletCore({
  keyVault: new WebCryptoIndexedDbKeyVault({ databaseName: DATABASE_NAME }),
  identityStore,
  registryClient: new HttpRegistryClient(),
  verifyRegistryReceipt: async (receipt) =>
    verifyRegistryReceipt(receipt, await loadServiceKeyset()),
  verifyDeviceRegistryReceipt: async (receipt) =>
    verifyDeviceRegistryReceipt(receipt, await loadServiceKeyset()),
  verifyDeviceRegistryStatus: async (status, expected) => {
    const parsed = deviceRegistryStatusV2Schema.parse(status);
    await verifyDeviceStatusStatement(
      parsed.statusStatement,
      await loadServiceKeyset(),
      Math.floor(Date.now() / 1_000),
      { ...expected, maxClockSkewSeconds: DEVICE_STATUS_MAX_CLOCK_SKEW_SECONDS },
    );
    return parsed;
  },
});

export interface CreateIdentityInput {
  label?: string;
  withAgreementKey?: boolean;
}

export interface RotateIdentityInput extends CreateIdentityInput {
  revokeOld: boolean;
}

export const walletAdapter = {
  async listIdentities(): Promise<LocalIdentitySummary[]> {
    const identities = await walletCore.listIdentitySummaries();
    return identities.sort((a, b) => {
      if (a.localState !== b.localState) return a.localState === 'active' ? -1 : 1;
      return (a.label ?? a.subject).localeCompare(b.label ?? b.subject);
    });
  },

  createIdentity(input: CreateIdentityInput): Promise<CreatedLocalIdentity> {
    return walletCore.createIdentity({
      ...(input.label === undefined ? {} : { label: input.label }),
      ...(input.withAgreementKey === undefined ? {} : { withAgreementKey: input.withAgreementKey }),
      register: true,
    });
  },

  retryRegistration(localId: string): Promise<RegistryReceiptV1> {
    return retryIdentityRegistration(walletCore, localId);
  },

  async prove(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
    addScope: boolean,
  ): Promise<OwnershipProofV1> {
    return walletCore.proveAndRecordAuthorization(localId, boundary, request, addScope);
  },

  async proveForProtocol(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
    addScope: boolean,
    proofProtocol: NexusOwnershipProofProtocol,
  ): Promise<OwnershipProofV1 | OwnershipProofV2> {
    if (proofProtocol === 'nexus.ownership-proof.v2') {
      const proof = await walletCore.proveDevice(localId, boundary, request);
      if (addScope) await walletCore.addScope(localId, boundary);
      return proof;
    }
    return walletCore.proveAndRecordAuthorization(localId, boundary, request, addScope);
  },

  clearAuthorizationHistory(localId: string): Promise<void> {
    return walletCore.clearAuthorizationHistory(localId);
  },

  issueDeviceTransfer(
    rootLocalId: string,
    options: IssueDeviceTransferOptions = {},
  ): Promise<IssuedDeviceTransferV2> {
    return walletCore.issueDeviceTransfer(rootLocalId, options);
  },

  importDeviceTransfer(
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ): Promise<ImportedDeviceV2> {
    return walletCore.importDeviceTransfer(bundle, transferKey);
  },

  activateDevice(localId: string): Promise<DeviceRegistryReceiptV2> {
    return walletCore.activateDevice(localId);
  },

  revokeDeviceSelf(localId: string): Promise<DeviceRegistryReceiptV2> {
    return walletCore.revokeDeviceSelf(localId, { reasonCode: 'replaced' });
  },

  revokeDeviceRoot(
    rootLocalId: string,
    deviceId: LocalIdentitySummary['issuedDevices'][number]['deviceId'],
  ): Promise<DeviceRegistryReceiptV2> {
    return walletCore.revokeDeviceRoot(rootLocalId, deviceId, { reasonCode: 'replaced' });
  },

  refreshDeviceStatus(
    localId: string,
    deviceId?: LocalIdentitySummary['issuedDevices'][number]['deviceId'],
  ): Promise<DeviceRegistryStatusV2> {
    return walletCore.refreshDeviceStatus(localId, deviceId);
  },

  dispose(localId: string): Promise<RegistryReceiptV1> {
    return walletCore.dispose(localId, {
      method: 'signature',
      reasonCode: 'dispose',
      retainPublicRecord: true,
    });
  },

  removeLocalIdentity(localId: string): Promise<void> {
    return walletCore.removeLocalIdentity(localId);
  },

  async rotate(oldLocalId: string, input: RotateIdentityInput): Promise<CreatedLocalIdentity> {
    // Independent create + optional disposal deliberately emits no old/new link.
    const created = await walletCore.createIdentity({
      ...(input.label === undefined ? {} : { label: input.label }),
      ...(input.withAgreementKey === undefined ? {} : { withAgreementKey: input.withAgreementKey }),
      register: true,
    });
    if (input.revokeOld) {
      await walletCore.dispose(oldLocalId, {
        method: 'signature',
        reasonCode: 'dispose',
        retainPublicRecord: true,
      });
    }
    return created;
  },

  async createContinuityLink(
    localIdA: string,
    localIdB: string,
    scope?: string,
  ): Promise<ContinuityLinkV1> {
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    let binary = '';
    for (const byte of nonceBytes) binary += String.fromCharCode(byte);
    const nonce = btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
    return walletCore.createContinuityLink(localIdA, localIdB, {
      nonce,
      ...(scope === undefined ? {} : { scope }),
    });
  },

  setLabel(localId: string, label?: string): Promise<void> {
    return walletCore.setLabel(localId, label);
  },
};

export type WalletAdapter = typeof walletAdapter;
