import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';

import {
  createProtocolSignaturePreimage,
  getDefaultCryptoProvider,
  WebCryptoProvider,
} from '@nexus/crypto';
import {
  createDeviceIdHashPreimageV2,
  base64Url64Schema,
  decodeBase64Url,
  decodeBase64UrlExact,
  deviceRegistryReceiptV2Schema,
  encodeBase64Url,
  formatDeviceIdV2,
  proofRequestSchema,
  type DeviceActivationRequestV2,
  type DeviceAuthorizationPayloadV2,
  type DeviceRegistryReceiptV2,
  type DeviceRootRevokeRequestV2,
  type DeviceSelfRevokeRequestV2,
  type NexusDeviceAuthorizationIdV2,
  type NexusDeviceIdV2,
  type NexusSubject,
  type RevokeBySecretRequestV1,
  type RevokeBySignatureRequestV1,
} from '@nexus/protocol';

import {
  acceptUnsignedInMemoryRegistryReceipt,
  captureWalletEventBoundary,
  InMemoryIdentityStore,
  InMemoryKeyVault,
  InMemoryRegistryClient,
  IndexedDbIdentityStore,
  WalletCore,
  WebCryptoIndexedDbKeyVault,
  type DeviceTransferEnvelopeV2,
  type IdentityStore,
  type KeyVault,
  type RegistryClient,
  type RegistryIdentityStatus,
  type RegistryRegisterRequest,
} from '../src/index.js';
import { decryptDeviceTransferPlaintext, encryptDeviceTransfer } from '../src/device-transfer.js';
import { getManagedKeyVaultCapabilities, signManagedProtocolPayload } from '../src/key-vault.js';

const NOW = 1_786_400_000;

function boundary(origin: string) {
  return captureWalletEventBoundary(new MessageEvent('message', { origin }));
}

function createHarness() {
  const keyVault = new InMemoryKeyVault();
  const identityStore = new InMemoryIdentityStore();
  const wallet = new WalletCore({
    keyVault,
    identityStore,
    registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
    verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
    clock: { now: () => NOW },
  });
  return { wallet, keyVault, identityStore };
}

function deviceReceipt(
  eventType: 'activated' | 'revoked',
  subject: NexusSubject,
  deviceId: NexusDeviceIdV2,
  genesisHash: string,
  authorizationId?: NexusDeviceAuthorizationIdV2,
  authorizationExpiresAt?: number,
): DeviceRegistryReceiptV2 {
  return deviceRegistryReceiptV2Schema.parse({
    payload: {
      protocol: 'nexus.device-registry-receipt.v2',
      eventId: `nxde2_${encodeBase64Url(new Uint8Array(32).fill(eventType === 'activated' ? 1 : 2))}`,
      operationId: `nxo2_${encodeBase64Url(new Uint8Array(32).fill(eventType === 'activated' ? 3 : 4))}`,
      eventType,
      subject,
      genesisHash,
      identitySequence: 0,
      identityState: 'active',
      deviceLedgerSequence: eventType === 'activated' ? 1 : 2,
      deviceId,
      ...(authorizationId === undefined ? {} : { authorizationId }),
      ...(authorizationExpiresAt === undefined ? {} : { authorizationExpiresAt }),
      deviceState: eventType === 'activated' ? 'active' : 'revoked',
      ...(eventType === 'revoked'
        ? { revokedBy: authorizationId === undefined ? ('root' as const) : ('device' as const) }
        : {}),
      acceptedAt: NOW,
      signerKid: 'test-device-registry',
    },
    signature: encodeBase64Url(new Uint8Array(64).fill(5)),
  });
}

class DeviceRegistryClient implements RegistryClient {
  readonly #delegate = new InMemoryRegistryClient({ clock: { now: () => NOW } });
  #terminalReceipt: DeviceRegistryReceiptV2 | undefined;

  public register(request: RegistryRegisterRequest): Promise<unknown> {
    return this.#delegate.register(request);
  }

  public getStatus(subject: NexusSubject): Promise<RegistryIdentityStatus> {
    return this.#delegate.getStatus(subject);
  }

  public revoke(request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1): Promise<unknown> {
    return this.#delegate.revoke(request);
  }

  public activateDevice(request: DeviceActivationRequestV2): Promise<unknown> {
    return Promise.resolve(
      deviceReceipt(
        'activated',
        request.payload.subject,
        request.payload.deviceId,
        request.authorization.payload.genesisHash,
        request.payload.authorizationId,
        request.authorization.payload.expiresAt,
      ),
    );
  }

  public revokeDeviceSelf(request: DeviceSelfRevokeRequestV2): Promise<unknown> {
    this.#terminalReceipt ??= deviceReceipt(
      'revoked',
      request.payload.subject,
      request.payload.deviceId,
      request.payload.genesisHash,
      request.payload.authorizationId,
    );
    return Promise.resolve(this.#terminalReceipt);
  }

  public revokeDeviceRoot(request: DeviceRootRevokeRequestV2): Promise<unknown> {
    this.#terminalReceipt ??= deviceReceipt(
      'revoked',
      request.payload.subject,
      request.payload.deviceId,
      request.payload.genesisHash,
    );
    return Promise.resolve(this.#terminalReceipt);
  }
}

class FlakyDeleteKeyVault extends InMemoryKeyVault {
  public failDeletes = false;

  public override deleteKey(ref: Parameters<InMemoryKeyVault['deleteKey']>[0]): Promise<void> {
    if (this.failDeletes) return Promise.reject(new Error('simulated key deletion failure'));
    return super.deleteKey(ref);
  }
}

class FailAfterDeviceImportStore extends InMemoryIdentityStore {
  public failFinalization = true;

  public override update(
    localId: string,
    mutate: Parameters<InMemoryIdentityStore['update']>[1],
  ): ReturnType<InMemoryIdentityStore['update']> {
    const current = this.get(localId);
    return current.then((record) => {
      if (this.failFinalization && record?.deviceV2?.localState === 'pending-import') {
        return Promise.reject(new Error('simulated device-import finalization failure'));
      }
      return super.update(localId, mutate);
    });
  }
}

class RejectCatalogueAppendStore extends InMemoryIdentityStore {
  public override appendIssuedDevice(): Promise<void> {
    return Promise.reject(new Error('simulated catalogue append failure'));
  }
}

class TrackingCryptoProvider extends WebCryptoProvider {
  public readonly randomOutputs: Uint8Array[] = [];

  public override randomBytes(length: number): Uint8Array {
    const bytes = super.randomBytes(length);
    this.randomOutputs.push(bytes);
    return bytes;
  }
}

class PausingImportFinalizationStore extends InMemoryIdentityStore {
  readonly paused: Promise<void>;
  #signalPaused: (() => void) | undefined;
  #release: (() => void) | undefined;
  #pauseOnce = true;

  public constructor() {
    super();
    this.paused = new Promise((resolve) => {
      this.#signalPaused = resolve;
    });
  }

  public release(): void {
    this.#release?.();
  }

  public override async update(
    localId: string,
    mutate: Parameters<InMemoryIdentityStore['update']>[1],
  ): ReturnType<InMemoryIdentityStore['update']> {
    const current = await this.get(localId);
    if (this.#pauseOnce && current?.deviceV2?.localState === 'pending-import') {
      this.#pauseOnce = false;
      this.#signalPaused?.();
      await new Promise<void>((resolve) => {
        this.#release = resolve;
      });
    }
    return super.update(localId, mutate);
  }
}

class PausingFalseKeyObservationVault extends InMemoryKeyVault {
  readonly falseObserved: Promise<void>;
  #signalFalseObserved: (() => void) | undefined;
  #releaseObservation: (() => void) | undefined;
  #pauseOnce = true;

  public constructor(options: ConstructorParameters<typeof InMemoryKeyVault>[0]) {
    super(options);
    this.falseObserved = new Promise((resolve) => {
      this.#signalFalseObserved = resolve;
    });
  }

  public releaseObservation(): void {
    this.#releaseObservation?.();
  }

  public override async hasKey(ref: Parameters<InMemoryKeyVault['hasKey']>[0]): Promise<boolean> {
    const observed = await super.hasKey(ref);
    if (this.#pauseOnce && !observed) {
      this.#pauseOnce = false;
      this.#signalFalseObserved?.();
      await new Promise<void>((resolve) => {
        this.#releaseObservation = resolve;
      });
    }
    return observed;
  }
}

describe('v2 root-authorized devices', () => {
  it('issues only an encrypted transfer and records the device in the root catalogue', async () => {
    const { wallet, identityStore } = createHarness();
    const root = await wallet.createIdentity();

    const first = await wallet.issueDeviceTransfer(root.localId, { label: 'Travel laptop' });
    const second = await wallet.issueDeviceTransfer(root.localId);

    expect(first.transferKey).toHaveLength(32);
    expect(first.bundle.protocol).toBe('nexus.device-transfer.v2');
    expect(first.bundle.ciphertext).not.toContain(root.subject);
    expect(JSON.stringify(first.bundle)).not.toContain('privateKey');
    expect(first.authorization.payload.subject).toBe(root.subject);
    expect(second.authorization.payload.deviceId).not.toBe(first.authorization.payload.deviceId);

    const record = await identityStore.get(root.localId);
    expect(record?.issuedDevicesV2).toHaveLength(2);
    expect(record?.issuedDevicesV2?.[0]).toMatchObject({
      deviceId: first.authorization.payload.deviceId,
      label: 'Travel laptop',
      localState: 'issued',
    });
    expect(
      await wallet.createDeviceRootRevokeRequest(
        root.localId,
        first.authorization.payload.deviceId,
      ),
    ).toMatchObject({
      payload: {
        protocol: 'nexus.device-root-revoke.v2',
        subject: root.subject,
        deviceId: first.authorization.payload.deviceId,
      },
    });
  });

  it('encrypts an exact device-only transfer shape with no root private material', async () => {
    const { wallet } = createHarness();
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const plaintext = await decryptDeviceTransferPlaintext(
      issued.bundle,
      issued.transferKey,
      getDefaultCryptoProvider(),
    );

    expect(Object.keys(plaintext).sort()).toEqual([
      'authorization',
      'devicePrivateKey',
      'genesis',
      'protocol',
      'subject',
    ]);
    expect(Object.keys(plaintext.devicePrivateKey).sort()).toEqual(['alg', 'bytes', 'format']);
    expect(plaintext.devicePrivateKey).toMatchObject({ alg: 'Ed25519', format: 'pkcs8' });
    expect(plaintext.genesis.signingKey).toEqual(root.genesis.signingKey);
    expect(JSON.stringify(plaintext)).not.toContain('rootPrivate');
    expect(JSON.stringify(plaintext)).not.toContain('revocationSecret');
    expect(JSON.stringify(plaintext)).not.toContain('authorizationHistory');
    expect(JSON.stringify(plaintext)).not.toContain('localScopes');
  });

  it('atomically preserves every catalogue entry during concurrent issuance', async () => {
    const { wallet, identityStore } = createHarness();
    const root = await wallet.createIdentity();

    const issued = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        wallet.issueDeviceTransfer(root.localId, { label: `Device ${String(index)}` }),
      ),
    );

    const record = await identityStore.get(root.localId);
    const catalog = record?.issuedDevicesV2 ?? [];
    expect(catalog).toHaveLength(20);
    expect(new Set(catalog.map((device) => device.deviceId)).size).toBe(20);
    expect(new Set(issued.map((entry) => entry.authorization.payload.deviceId))).toEqual(
      new Set(catalog.map((device) => device.deviceId)),
    );
  });

  it('bounds the root-local issued-device catalogue', async () => {
    const { wallet, identityStore } = createHarness();
    const root = await wallet.createIdentity();
    const first = await wallet.issueDeviceTransfer(root.localId);
    const record = await identityStore.get(root.localId);
    const issuedEntry = record?.issuedDevicesV2?.[0];
    if (issuedEntry === undefined) throw new Error('Expected an issued-device catalogue entry.');
    await identityStore.update(root.localId, (latest) => ({
      ...latest,
      issuedDevicesV2: Array.from({ length: 256 }, () => structuredClone(issuedEntry)),
    }));

    await expect(wallet.issueDeviceTransfer(root.localId)).rejects.toMatchObject({
      code: 'STORAGE_ERROR',
    });
    expect(first.transferKey).toHaveLength(32);
  });

  it('zeros the generated transfer key if catalogue persistence fails', async () => {
    const crypto = new TrackingCryptoProvider();
    const identityStore = new RejectCatalogueAppendStore();
    const wallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      crypto,
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();
    crypto.randomOutputs.length = 0;

    await expect(wallet.issueDeviceTransfer(root.localId)).rejects.toThrow(
      'simulated catalogue append failure',
    );
    const thirtyTwoByteOutputs = crypto.randomOutputs.filter((bytes) => bytes.byteLength === 32);
    // authorization nonce, transfer key, bundle ID, and HKDF salt
    expect(thirtyTwoByteOutputs).toHaveLength(4);
    expect(thirtyTwoByteOutputs[1]).toEqual(new Uint8Array(32));
  });

  it('preserves issuance, label, and scope across concurrent transactional updates', async () => {
    const indexedDB = new IDBFactory();
    const databaseName = 'wallet-v2-concurrent-mutations';
    const registryClient = new InMemoryRegistryClient({ clock: { now: () => NOW } });
    const createWallet = () =>
      new WalletCore({
        keyVault: new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB }),
        identityStore: new IndexedDbIdentityStore({ databaseName, indexedDB }),
        registryClient,
        verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
        clock: { now: () => NOW },
      });
    const first = createWallet();
    const second = createWallet();
    const root = await first.createIdentity();
    const rp = boundary('https://rp-a.test');

    const [issued] = await Promise.all([
      first.issueDeviceTransfer(root.localId),
      second.setLabel(root.localId, 'Concurrent root'),
      second.addScope(root.localId, rp),
    ]);

    const summary = (await first.listIdentitySummaries()).find(
      (entry) => entry.localId === root.localId,
    );
    expect(summary).toMatchObject({ label: 'Concurrent root' });
    expect(summary?.localScopes).toContain('https://rp-a.test');
    expect(summary?.issuedDevices.map((entry) => entry.deviceId)).toContain(
      issued.authorization.payload.deviceId,
    );
  });

  it('imports a device non-extractably, proves possession, and preserves the v1 subject', async () => {
    const { wallet, identityStore, keyVault } = createHarness();
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const imported = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);

    expect(imported.subject).toBe(root.subject);
    expect(imported.deviceId).toBe(issued.authorization.payload.deviceId);
    const record = await identityStore.get(imported.localId);
    expect(record?.signingPrivateKeyRef).toBeUndefined();
    expect(record?.deviceV2?.localState).toBe('pending-activation');
    expect(record?.deviceV2?.signingPrivateKeyRef).toBeDefined();
    const importedSummary = (await wallet.listIdentitySummaries()).find(
      (summary) => summary.localId === imported.localId,
    );
    expect(importedSummary?.hasAgreementKey).toBe(false);

    const proofRequest = proofRequestSchema.parse({
      action: 'post.edit',
      resource: 'post:01JABC',
      nonce: 'AQEBAQEBAQEBAQEBAQEBAQ',
      expiresAt: NOW + 60,
    });
    await expect(
      wallet.proveDevice(imported.localId, boundary('https://rp-a.test'), proofRequest),
    ).rejects.toMatchObject({ code: 'IDENTITY_NOT_REGISTERED' });

    const activation = await wallet.createDeviceActivationRequest(imported.localId);
    const crypto = getDefaultCryptoProvider();
    const publicKey = await crypto.importEd25519PublicKey(
      decodeBase64UrlExact(issued.authorization.payload.signingKey.publicKey, 32),
    );
    expect(
      await crypto.verifyEd25519(
        publicKey,
        decodeBase64UrlExact(activation.deviceSignature, 64),
        createProtocolSignaturePreimage(activation.payload),
      ),
    ).toBe(true);

    const deviceRef = record?.deviceV2?.signingPrivateKeyRef;
    if (deviceRef === undefined) throw new Error('Expected imported device key reference.');
    expect(await keyVault.hasKey(deviceRef)).toBe(true);

    if (record?.deviceV2 === undefined) throw new Error('Expected imported device metadata.');
    await identityStore.put({
      ...record,
      deviceV2: { ...record.deviceV2, localState: 'active' },
    });
    const proof = await wallet.proveDevice(
      imported.localId,
      boundary('https://rp-a.test'),
      proofRequest,
    );
    expect(proof.payload.subject).toBe(root.subject);
    expect(proof.payload.deviceId).toBe(imported.deviceId);
    expect(
      await crypto.verifyEd25519(
        publicKey,
        decodeBase64UrlExact(proof.deviceSignature, 64),
        createProtocolSignaturePreimage(proof.payload),
      ),
    ).toBe(true);

    const expiredWallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => issued.authorization.payload.expiresAt },
    });
    expect(
      (await expiredWallet.listIdentitySummaries()).find(
        (summary) => summary.localId === imported.localId,
      )?.proofReady,
    ).toBe(false);
  });

  it('atomically permits only one concurrent installation of the same device key', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const keyVault = new InMemoryKeyVault();
    const identityStore = new InMemoryIdentityStore();
    const target = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });

    const results = await Promise.allSettled([
      target.importDeviceTransfer(issued.bundle, issued.transferKey),
      target.importDeviceTransfer(issued.bundle, issued.transferKey),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(
      (await identityStore.list()).filter((record) => record.deviceV2 !== undefined),
    ).toHaveLength(1);
  });

  it('atomically reserves one device ID across two IndexedDB store instances', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const indexedDB = new IDBFactory();
    const databaseName = 'wallet-v2-cross-instance-reservation';
    const createTarget = () =>
      new WalletCore({
        keyVault: new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB }),
        identityStore: new IndexedDbIdentityStore({ databaseName, indexedDB }),
        registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
        verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
        clock: { now: () => NOW },
      });
    const results = await Promise.allSettled([
      createTarget().importDeviceTransfer(issued.bundle, issued.transferKey),
      createTarget().importDeviceTransfer(issued.bundle, issued.transferKey),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const records = await new IndexedDbIdentityStore({ databaseName, indexedDB }).list();
    expect(
      records.filter(
        (record) => record.deviceV2?.deviceId === issued.authorization.payload.deviceId,
      ),
    ).toHaveLength(1);
  });

  it('durably tracks a key when import finalization and cleanup both fail', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const keyVault = new FlakyDeleteKeyVault();
    keyVault.failDeletes = true;
    const identityStore = new FailAfterDeviceImportStore();
    const target = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });

    await expect(
      target.importDeviceTransfer(issued.bundle, issued.transferKey),
    ).rejects.toMatchObject({ code: 'STORAGE_ERROR' });
    const pending = (await identityStore.list()).find(
      (record) => record.deviceV2?.deviceId === issued.authorization.payload.deviceId,
    );
    expect(pending?.deviceV2).toMatchObject({ localState: 'pending-import' });
    expect(pending?.deviceV2?.signingPrivateKeyRef).toBeDefined();
    if (pending?.deviceV2?.signingPrivateKeyRef === undefined) {
      throw new Error('Expected a durable pending-import key reference.');
    }
    expect(await keyVault.hasKey(pending.deviceV2.signingPrivateKeyRef)).toBe(true);
  });

  it('keeps the key when lease recovery promotes an import before its original finalizer resumes', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const keyVault = new InMemoryKeyVault();
    const identityStore = new PausingImportFinalizationStore();
    const registryClient = new InMemoryRegistryClient({ clock: { now: () => NOW } });
    const importer = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const recovery = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW + 301 },
    });

    const importing = importer.importDeviceTransfer(issued.bundle, issued.transferKey);
    await identityStore.paused;
    const pending = (await identityStore.list()).find(
      (record) => record.deviceV2?.deviceId === issued.authorization.payload.deviceId,
    );
    const ref = pending?.deviceV2?.signingPrivateKeyRef;
    if (ref === undefined) throw new Error('Expected pending import reference.');
    if (pending === undefined) throw new Error('Expected pending import record.');
    expect(await keyVault.hasKey(ref)).toBe(true);

    await recovery.listIdentitySummaries();
    expect((await identityStore.get(pending.localId))?.deviceV2?.localState).toBe(
      'pending-activation',
    );
    identityStore.release();
    const imported = await importing;
    expect(imported.localId).toBe(pending.localId);
    expect(await keyVault.hasKey(ref)).toBe(true);
    expect((await identityStore.get(imported.localId))?.deviceV2?.signingPrivateKeyRef).toBe(ref);
    await expect(importer.createDeviceActivationRequest(imported.localId)).resolves.toMatchObject({
      payload: { deviceId: imported.deviceId },
    });
  });

  it('removes a late-inserted key when lease recovery deleted its reservation first', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    let signalPaused: (() => void) | undefined;
    let release: (() => void) | undefined;
    const paused = new Promise<void>((resolve) => {
      signalPaused = resolve;
    });
    const keyVault = new InMemoryKeyVault({
      beforeDeviceKeyImport: async () => {
        signalPaused?.();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      },
    });
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new InMemoryRegistryClient({ clock: { now: () => NOW } });
    const importer = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const recovery = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW + 301 },
    });

    const importing = importer.importDeviceTransfer(issued.bundle, issued.transferKey);
    await paused;
    const pending = (await identityStore.list()).find(
      (record) => record.deviceV2?.deviceId === issued.authorization.payload.deviceId,
    );
    const ref = pending?.deviceV2?.signingPrivateKeyRef;
    if (pending === undefined || ref === undefined) {
      throw new Error('Expected a pending import reservation with a key reference.');
    }
    expect(await keyVault.hasKey(ref)).toBe(false);

    await recovery.listIdentitySummaries();
    expect(await identityStore.get(pending.localId)).toBeUndefined();

    release?.();
    await expect(importing).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    expect(await keyVault.hasKey(ref)).toBe(false);
    expect(await identityStore.get(pending.localId)).toBeUndefined();
  });

  it('durably rejects a late key insertion after recovery cancels its reference', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const plaintext = await decryptDeviceTransferPlaintext(
      issued.bundle,
      issued.transferKey,
      getDefaultCryptoProvider(),
    );
    const sourceRecord = await source.identityStore.get(root.localId);
    const issuedRecord = sourceRecord?.issuedDevicesV2?.find(
      (device) => device.deviceId === issued.authorization.payload.deviceId,
    );
    if (issuedRecord === undefined) throw new Error('Expected issued-device catalogue record.');

    const keyVault = new InMemoryKeyVault();
    const managed = getManagedKeyVaultCapabilities(keyVault);
    if (managed === undefined) throw new Error('Expected managed key-vault capability.');
    const ref = managed.createDeviceSigningKeyRef();
    const identityStore = new InMemoryIdentityStore();
    const localId = '00000000-0000-4000-8000-000000000001';
    await identityStore.reserveDeviceRecord({
      localId,
      subject: root.subject,
      genesis: root.genesis,
      localScopes: [],
      authorizationHistory: [],
      localState: 'active',
      deviceV2: {
        deviceId: issued.authorization.payload.deviceId,
        authorizationId: issuedRecord.authorizationId,
        authorization: issued.authorization,
        signingPrivateKeyRef: ref,
        localState: 'pending-import',
        importStartedAt: NOW,
      },
    });
    const recovery = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW + 301 },
    });

    await recovery.listIdentitySummaries();
    expect(await identityStore.get(localId)).toBeUndefined();
    await expect(
      managed.importDeviceSigningKeyAtRef(
        ref,
        decodeBase64Url(plaintext.devicePrivateKey.bytes),
        decodeBase64UrlExact(issued.authorization.payload.signingKey.publicKey, 32),
      ),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    expect(await keyVault.hasKey(ref)).toBe(false);
    await keyVault.deleteKey(ref);
    await keyVault.deleteSecret(ref as unknown as Parameters<InMemoryKeyVault['deleteSecret']>[0]);
    await expect(
      managed.importDeviceSigningKeyAtRef(
        ref,
        decodeBase64Url(plaintext.devicePrivateKey.bytes),
        decodeBase64UrlExact(issued.authorization.payload.signingKey.publicKey, 32),
      ),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    expect(await keyVault.hasKey(ref)).toBe(false);
  });

  it('persists canceled refs across IndexedDB vault instances and rejects late insertion', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const plaintext = await decryptDeviceTransferPlaintext(
      issued.bundle,
      issued.transferKey,
      getDefaultCryptoProvider(),
    );
    const issuedRecord = (await source.identityStore.get(root.localId))?.issuedDevicesV2?.find(
      (device) => device.deviceId === issued.authorization.payload.deviceId,
    );
    if (issuedRecord === undefined) throw new Error('Expected issued-device catalogue record.');

    const indexedDB = new IDBFactory();
    const databaseName = 'wallet-v2-cancelled-device-key-ref';
    const recoveryVault = new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB });
    const lateVault = new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB });
    const managedRecovery = getManagedKeyVaultCapabilities(recoveryVault);
    const managedLate = getManagedKeyVaultCapabilities(lateVault);
    if (managedRecovery === undefined || managedLate === undefined) {
      throw new Error('Expected managed IndexedDB key-vault capabilities.');
    }
    const ref = managedRecovery.createDeviceSigningKeyRef();
    const identityStore = new IndexedDbIdentityStore({ databaseName, indexedDB });
    const localId = '00000000-0000-4000-8000-000000000002';
    await identityStore.reserveDeviceRecord({
      localId,
      subject: root.subject,
      genesis: root.genesis,
      localScopes: [],
      authorizationHistory: [],
      localState: 'active',
      deviceV2: {
        deviceId: issued.authorization.payload.deviceId,
        authorizationId: issuedRecord.authorizationId,
        authorization: issued.authorization,
        signingPrivateKeyRef: ref,
        localState: 'pending-import',
        importStartedAt: NOW,
      },
    });
    const recovery = new WalletCore({
      keyVault: recoveryVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW + 301 },
    });

    await recovery.listIdentitySummaries();
    expect(await identityStore.get(localId)).toBeUndefined();
    const privateKey = decodeBase64Url(plaintext.devicePrivateKey.bytes);
    const publicKey = decodeBase64UrlExact(issued.authorization.payload.signingKey.publicKey, 32);
    await expect(
      managedLate.importDeviceSigningKeyAtRef(ref, privateKey, publicKey),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    expect(await lateVault.hasKey(ref)).toBe(false);
    await lateVault.deleteKey(ref);
    await lateVault.deleteSecret(
      ref as unknown as Parameters<WebCryptoIndexedDbKeyVault['deleteSecret']>[0],
    );
    await expect(
      managedLate.importDeviceSigningKeyAtRef(ref, privateKey, publicKey),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });

    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(databaseName);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Failed to reopen wallet DB.'));
    });
    const transaction = database.transaction('key-material', 'readonly');
    const stored = await new Promise<unknown>((resolve, reject) => {
      const request = transaction.objectStore('key-material').get(ref);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Failed to read tombstone.'));
    });
    expect(stored).toEqual({ ref, kind: 'cancelled-device-key-ref' });
    database.close();

    const concurrentRef = managedRecovery.createDeviceSigningKeyRef();
    await Promise.all([
      lateVault.deleteKey(concurrentRef),
      managedRecovery.cancelDeviceSigningKeyRef(concurrentRef),
    ]);
    await lateVault.deleteSecret(
      concurrentRef as unknown as Parameters<WebCryptoIndexedDbKeyVault['deleteSecret']>[0],
    );
    await expect(
      managedLate.importDeviceSigningKeyAtRef(concurrentRef, privateKey, publicKey),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    expect(await lateVault.hasKey(concurrentRef)).toBe(false);
  });

  it('preserves an import that finalizes after recovery observes no key', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    let signalInsertionPaused: (() => void) | undefined;
    let releaseInsertion: (() => void) | undefined;
    const insertionPaused = new Promise<void>((resolve) => {
      signalInsertionPaused = resolve;
    });
    const keyVault = new PausingFalseKeyObservationVault({
      beforeDeviceKeyImport: async () => {
        signalInsertionPaused?.();
        await new Promise<void>((resolve) => {
          releaseInsertion = resolve;
        });
      },
    });
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new InMemoryRegistryClient({ clock: { now: () => NOW } });
    const importer = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const recovery = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW + 301 },
    });

    const importing = importer.importDeviceTransfer(issued.bundle, issued.transferKey);
    await insertionPaused;
    const recovering = recovery.listIdentitySummaries();
    await keyVault.falseObserved;

    releaseInsertion?.();
    const imported = await importing;
    const importedRecord = await identityStore.get(imported.localId);
    const ref = importedRecord?.deviceV2?.signingPrivateKeyRef;
    if (ref === undefined) throw new Error('Expected finalized device signing-key reference.');
    expect(importedRecord?.deviceV2?.localState).toBe('pending-activation');

    keyVault.releaseObservation();
    await recovering;
    expect((await identityStore.get(imported.localId))?.deviceV2?.localState).toBe(
      'pending-activation',
    );
    expect(await keyVault.hasKey(ref)).toBe(true);
  });

  it('stores an imported device private key as non-extractable in IndexedDB', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);

    const indexedDB = new IDBFactory();
    const databaseName = 'wallet-v2-device-nonextractable';
    const keyVault = new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB });
    const identityStore = new IndexedDbIdentityStore({ databaseName, indexedDB });
    const target = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const imported = await target.importDeviceTransfer(issued.bundle, issued.transferKey);
    const record = await identityStore.get(imported.localId);
    const ref = record?.deviceV2?.signingPrivateKeyRef;
    if (ref === undefined) throw new Error('Expected imported device key reference.');

    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(databaseName);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new Error('Unable to open the test wallet database.', { cause: request.error }));
    });
    const stored = await new Promise<{ privateKey: CryptoKey }>((resolve, reject) => {
      const request = database.transaction('key-material').objectStore('key-material').get(ref);
      request.onsuccess = () => resolve(request.result as { privateKey: CryptoKey });
      request.onerror = () =>
        reject(new Error('Unable to read the imported device key.', { cause: request.error }));
    });
    expect(stored.privateKey.extractable).toBe(false);
    database.close();
    await keyVault.close();
    await identityStore.close();
  });

  it('deletes device keys only after a cryptographically accepted revocation receipt', async () => {
    const keyVault = new InMemoryKeyVault();
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new DeviceRegistryClient();
    let rejectDeviceReceipt = false;
    const wallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt: (receipt) => {
        if (rejectDeviceReceipt) throw new Error('bad device registry signature');
        return Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
      },
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const imported = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    await wallet.activateDevice(imported.localId);
    const active = await identityStore.get(imported.localId);
    const ref = active?.deviceV2?.signingPrivateKeyRef;
    if (ref === undefined) throw new Error('Expected active device key reference.');

    rejectDeviceReceipt = true;
    await expect(wallet.revokeDeviceSelf(imported.localId)).rejects.toMatchObject({
      code: 'INVALID_REGISTRY_RECEIPT',
    });
    expect(await keyVault.hasKey(ref)).toBe(true);

    rejectDeviceReceipt = false;
    await wallet.revokeDeviceSelf(imported.localId);
    expect(await keyVault.hasKey(ref)).toBe(false);
    expect((await identityStore.get(imported.localId))?.deviceV2?.localState).toBe('revoked');
  });

  it('persists terminal state before deletion and retries failed key cleanup safely', async () => {
    const keyVault = new FlakyDeleteKeyVault();
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new DeviceRegistryClient();
    const wallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt: (receipt) =>
        Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt)),
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const imported = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    await wallet.activateDevice(imported.localId);
    keyVault.failDeletes = true;

    await expect(wallet.revokeDeviceSelf(imported.localId)).rejects.toMatchObject({
      code: 'STORAGE_ERROR',
    });
    const pendingCleanup = await identityStore.get(imported.localId);
    expect(pendingCleanup?.deviceV2).toMatchObject({ localState: 'revoked' });
    expect(pendingCleanup?.deviceV2?.revocationReceipt).toBeDefined();
    expect(pendingCleanup?.deviceV2?.signingPrivateKeyRef).toBeDefined();
    await expect(
      wallet.proveDevice(
        imported.localId,
        boundary('https://rp-a.test'),
        proofRequestSchema.parse({
          action: 'post.edit',
          resource: 'post:01JABC',
          nonce: 'AQEBAQEBAQEBAQEBAQEBAQ',
          expiresAt: NOW + 60,
        }),
      ),
    ).rejects.toMatchObject({ code: 'IDENTITY_NOT_REGISTERED' });

    keyVault.failDeletes = false;
    await wallet.revokeDeviceSelf(imported.localId);
    expect(
      (await identityStore.get(imported.localId))?.deviceV2?.signingPrivateKeyRef,
    ).toBeUndefined();
  });

  it('root revocation is receipt-gated and updates the issued-device catalogue', async () => {
    const keyVault = new InMemoryKeyVault();
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new DeviceRegistryClient();
    let rejectDeviceReceipt = false;
    const wallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt: (receipt) => {
        if (rejectDeviceReceipt) throw new Error('bad device registry signature');
        return Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
      },
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const imported = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    const deviceRecord = await identityStore.get(imported.localId);
    const ref = deviceRecord?.deviceV2?.signingPrivateKeyRef;
    if (ref === undefined) throw new Error('Expected installed device key reference.');

    rejectDeviceReceipt = true;
    await expect(wallet.revokeDeviceRoot(root.localId, imported.deviceId)).rejects.toMatchObject({
      code: 'INVALID_REGISTRY_RECEIPT',
    });
    expect(await keyVault.hasKey(ref)).toBe(true);
    expect((await identityStore.get(root.localId))?.issuedDevicesV2?.[0]?.localState).toBe(
      'issued',
    );

    rejectDeviceReceipt = false;
    await wallet.revokeDeviceRoot(root.localId, imported.deviceId);
    expect(await keyVault.hasKey(ref)).toBe(false);
    expect((await identityStore.get(root.localId))?.issuedDevicesV2?.[0]?.localState).toBe(
      'revoked',
    );
  });

  it('converges self-revocation after a root pre-activation tombstone', async () => {
    const registryClient = new DeviceRegistryClient();
    const verifyDeviceRegistryReceipt = (receipt: unknown) =>
      Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
    const rootStore = new InMemoryIdentityStore();
    const rootWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: rootStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const deviceKeyVault = new InMemoryKeyVault();
    const deviceStore = new InMemoryIdentityStore();
    const deviceWallet = new WalletCore({
      keyVault: deviceKeyVault,
      identityStore: deviceStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const root = await rootWallet.createIdentity();
    const issued = await rootWallet.issueDeviceTransfer(root.localId);
    const imported = await deviceWallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    const deviceRef = (await deviceStore.get(imported.localId))?.deviceV2?.signingPrivateKeyRef;
    if (deviceRef === undefined) throw new Error('Expected imported device key reference.');

    const rootReceipt = await rootWallet.revokeDeviceRoot(root.localId, imported.deviceId);
    expect(rootReceipt.payload.revokedBy).toBe('root');
    expect(rootReceipt.payload.authorizationId).toBeUndefined();
    expect(await deviceKeyVault.hasKey(deviceRef)).toBe(true);

    const converged = await deviceWallet.revokeDeviceSelf(imported.localId);
    expect(converged).toEqual(rootReceipt);
    expect(await deviceKeyVault.hasKey(deviceRef)).toBe(false);
    expect((await deviceStore.get(imported.localId))?.deviceV2?.localState).toBe('revoked');
  });

  it('converges root revocation after an existing device-authored revocation', async () => {
    const registryClient = new DeviceRegistryClient();
    const verifyDeviceRegistryReceipt = (receipt: unknown) =>
      Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
    const rootStore = new InMemoryIdentityStore();
    const rootWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: rootStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const deviceWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: new InMemoryIdentityStore(),
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const root = await rootWallet.createIdentity();
    const issued = await rootWallet.issueDeviceTransfer(root.localId);
    const imported = await deviceWallet.importDeviceTransfer(issued.bundle, issued.transferKey);

    const selfReceipt = await deviceWallet.revokeDeviceSelf(imported.localId);
    expect(selfReceipt.payload.revokedBy).toBe('device');
    expect(selfReceipt.payload.authorizationId).toBe(imported.authorizationId);

    const converged = await rootWallet.revokeDeviceRoot(root.localId, imported.deviceId);
    expect(converged).toEqual(selfReceipt);
    expect((await rootStore.get(root.localId))?.issuedDevicesV2?.[0]?.localState).toBe('revoked');
  });

  it('converges concurrent root and device revocation without state rollback', async () => {
    const registryClient = new DeviceRegistryClient();
    const verifyDeviceRegistryReceipt = (receipt: unknown) =>
      Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
    const rootStore = new InMemoryIdentityStore();
    const deviceStore = new InMemoryIdentityStore();
    const rootWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: rootStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const deviceWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: deviceStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const root = await rootWallet.createIdentity();
    const issued = await rootWallet.issueDeviceTransfer(root.localId);
    const imported = await deviceWallet.importDeviceTransfer(issued.bundle, issued.transferKey);

    const [rootReceipt, selfReceipt] = await Promise.all([
      rootWallet.revokeDeviceRoot(root.localId, imported.deviceId),
      deviceWallet.revokeDeviceSelf(imported.localId),
    ]);
    expect(rootReceipt).toEqual(selfReceipt);
    expect((await rootStore.get(root.localId))?.issuedDevicesV2?.[0]?.localState).toBe('revoked');
    expect((await deviceStore.get(imported.localId))?.deviceV2?.localState).toBe('revoked');
  });

  it('lets two independent device keys prove the same subject while revoking only one', async () => {
    const keyVault = new InMemoryKeyVault();
    const identityStore = new InMemoryIdentityStore();
    const registryClient = new DeviceRegistryClient();
    const wallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt: (receipt) =>
        Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt)),
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();
    const [issuedA, issuedB] = await Promise.all([
      wallet.issueDeviceTransfer(root.localId),
      wallet.issueDeviceTransfer(root.localId),
    ]);
    const [deviceA, deviceB] = await Promise.all([
      wallet.importDeviceTransfer(issuedA.bundle, issuedA.transferKey),
      wallet.importDeviceTransfer(issuedB.bundle, issuedB.transferKey),
    ]);
    await Promise.all([
      wallet.activateDevice(deviceA.localId),
      wallet.activateDevice(deviceB.localId),
    ]);
    const request = proofRequestSchema.parse({
      action: 'post.edit',
      resource: 'post:01JABC',
      nonce: 'AQEBAQEBAQEBAQEBAQEBAQ',
      expiresAt: NOW + 60,
    });
    const [proofA, proofB] = await Promise.all([
      wallet.proveDevice(deviceA.localId, boundary('https://rp-a.test'), request),
      wallet.proveDevice(deviceB.localId, boundary('https://rp-a.test'), request),
    ]);
    expect(proofA.payload.subject).toBe(root.subject);
    expect(proofB.payload.subject).toBe(root.subject);
    expect(proofA.payload.deviceId).not.toBe(proofB.payload.deviceId);

    await wallet.revokeDeviceRoot(root.localId, deviceA.deviceId);
    await expect(
      wallet.proveDevice(deviceA.localId, boundary('https://rp-a.test'), request),
    ).rejects.toMatchObject({ code: 'IDENTITY_REVOKED' });
    expect(
      (await wallet.proveDevice(deviceB.localId, boundary('https://rp-a.test'), request)).payload
        .deviceId,
    ).toBe(deviceB.deviceId);
  });

  it('treats two installations of one copied bundle as the same revocable device', async () => {
    const registryClient = new DeviceRegistryClient();
    const verifyDeviceRegistryReceipt = (receipt: unknown) =>
      Promise.resolve(deviceRegistryReceiptV2Schema.parse(receipt));
    const rootWallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: new InMemoryIdentityStore(),
      registryClient,
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      verifyDeviceRegistryReceipt,
      clock: { now: () => NOW },
    });
    const createCloneWallet = () =>
      new WalletCore({
        keyVault: new InMemoryKeyVault(),
        identityStore: new InMemoryIdentityStore(),
        registryClient,
        verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
        verifyDeviceRegistryReceipt,
        clock: { now: () => NOW },
      });
    const root = await rootWallet.createIdentity();
    const issued = await rootWallet.issueDeviceTransfer(root.localId);
    const cloneA = createCloneWallet();
    const cloneB = createCloneWallet();
    const [deviceA, deviceB] = await Promise.all([
      cloneA.importDeviceTransfer(issued.bundle, issued.transferKey),
      cloneB.importDeviceTransfer(issued.bundle, issued.transferKey),
    ]);
    expect(deviceA.deviceId).toBe(deviceB.deviceId);

    const rootReceipt = await rootWallet.revokeDeviceRoot(root.localId, deviceA.deviceId);
    const [receiptA, receiptB] = await Promise.all([
      cloneA.revokeDeviceSelf(deviceA.localId),
      cloneB.revokeDeviceSelf(deviceB.localId),
    ]);
    expect(receiptA).toEqual(rootReceipt);
    expect(receiptB).toEqual(rootReceipt);
  });

  it('rejects a tampered bundle, wrong key, duplicate install, and device delegation', async () => {
    const { wallet } = createHarness();
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const wrongKey = new Uint8Array(32).fill(7);
    await expect(wallet.importDeviceTransfer(issued.bundle, wrongKey)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });

    const ciphertext = decodeBase64Url(issued.bundle.ciphertext);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    const tampered: DeviceTransferEnvelopeV2 = {
      ...issued.bundle,
      ciphertext: encodeBase64Url(ciphertext),
    };
    await expect(wallet.importDeviceTransfer(tampered, issued.transferKey)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });

    const installed = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    await expect(
      wallet.importDeviceTransfer(issued.bundle, issued.transferKey),
    ).rejects.toMatchObject({ code: 'REGISTRY_CONFLICT' });
    await expect(wallet.issueDeviceTransfer(installed.localId)).rejects.toMatchObject({
      code: 'IDENTITY_NOT_REGISTERED',
    });
  });

  it('rejects certified public/private mismatch and every authenticated header mutation', async () => {
    const { wallet } = createHarness();
    const root = await wallet.createIdentity();
    const [issuedA, issuedB] = await Promise.all([
      wallet.issueDeviceTransfer(root.localId),
      wallet.issueDeviceTransfer(root.localId),
    ]);
    const [plainA, plainB] = await Promise.all([
      decryptDeviceTransferPlaintext(
        issuedA.bundle,
        issuedA.transferKey,
        getDefaultCryptoProvider(),
      ),
      decryptDeviceTransferPlaintext(
        issuedB.bundle,
        issuedB.transferKey,
        getDefaultCryptoProvider(),
      ),
    ]);
    const mismatched = await encryptDeviceTransfer(
      {
        subject: plainA.subject,
        genesis: plainA.genesis,
        authorization: plainA.authorization,
        devicePrivateKey: plainB.devicePrivateKey,
      },
      getDefaultCryptoProvider(),
    );
    await expect(
      wallet.importDeviceTransfer(mismatched.bundle, mismatched.transferKey),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });

    const alternate32 = encodeBase64Url(new Uint8Array(32).fill(0x72));
    const alternate12 = encodeBase64Url(new Uint8Array(12).fill(0x73));
    const mutations: DeviceTransferEnvelopeV2[] = [
      { ...issuedA.bundle, bundleId: alternate32 },
      { ...issuedA.bundle, salt: alternate32 },
      { ...issuedA.bundle, iv: alternate12 },
      { ...issuedA.bundle, protocol: 'nexus.device-transfer.v3' as never },
      { ...issuedA.bundle, suite: 'NX-UNKNOWN-v2' as never },
    ];
    for (const mutation of mutations) {
      await expect(
        wallet.importDeviceTransfer(mutation, issuedA.transferKey),
      ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    }
  });

  it('rejects a root signing key reused as a device key before storing key material', async () => {
    const source = createHarness();
    const root = await source.wallet.createIdentity();
    const issued = await source.wallet.issueDeviceTransfer(root.localId);
    const plaintext = await decryptDeviceTransferPlaintext(
      issued.bundle,
      issued.transferKey,
      getDefaultCryptoProvider(),
    );
    const rootRecord = await source.identityStore.get(root.localId);
    const rootRef = rootRecord?.signingPrivateKeyRef;
    if (rootRecord === undefined || rootRef === undefined) {
      throw new Error('Expected a root signing-key reference.');
    }
    const crypto = getDefaultCryptoProvider();
    const signingKey = rootRecord.genesis.signingKey;
    const deviceId = formatDeviceIdV2(
      await crypto.sha256(
        createDeviceIdHashPreimageV2({
          subject: root.subject,
          signingKey,
        }),
      ),
    );
    const payload = {
      ...plaintext.authorization.payload,
      deviceId,
      signingKey,
    } satisfies DeviceAuthorizationPayloadV2;
    const rootKeyDeviceTransfer = await encryptDeviceTransfer(
      {
        subject: plaintext.subject,
        genesis: plaintext.genesis,
        authorization: {
          payload,
          rootSignature: base64Url64Schema.parse(
            encodeBase64Url(await signManagedProtocolPayload(source.keyVault, rootRef, payload)),
          ),
        },
        devicePrivateKey: plaintext.devicePrivateKey,
      },
      crypto,
    );
    let importCalls = 0;
    const keyVault = new InMemoryKeyVault({
      beforeDeviceKeyImport: () => {
        importCalls += 1;
        return Promise.resolve();
      },
    });
    const identityStore = new InMemoryIdentityStore();
    const target = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });

    await expect(
      target.importDeviceTransfer(rootKeyDeviceTransfer.bundle, rootKeyDeviceTransfer.transferKey),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect(importCalls).toBe(0);
    expect(await identityStore.list()).toEqual([]);
  });

  it('rejects an oversized ciphertext string before attempting base64 decoding', async () => {
    const { wallet } = createHarness();
    const root = await wallet.createIdentity();
    const issued = await wallet.issueDeviceTransfer(root.localId);
    const oversized = { ...issued.bundle, ciphertext: 'A'.repeat(87_383) };
    await expect(wallet.importDeviceTransfer(oversized, issued.transferKey)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });
  });

  it('keeps existing v1-only custom vault and store implementations compatible', async () => {
    const vaultDelegate = new InMemoryKeyVault();
    const storeDelegate = new InMemoryIdentityStore();
    const keyVault: KeyVault = {
      createSigningKey: () => vaultDelegate.createSigningKey(),
      sign: (ref, data) =>
        signManagedProtocolPayload(vaultDelegate, ref, {
          protocol: 'nexus.ownership-proof.v1',
          legacyPreimage: encodeBase64Url(data),
        }),
      createAgreementKey: () => vaultDelegate.createAgreementKey(),
      deleteKey: (ref) => vaultDelegate.deleteKey(ref),
      storeRevocationSecret: (secret) => vaultDelegate.storeRevocationSecret(secret),
      readRevocationSecret: (ref) => vaultDelegate.readRevocationSecret(ref),
      deleteSecret: (ref) => vaultDelegate.deleteSecret(ref),
      readPublicKey: (ref) => vaultDelegate.readPublicKey(ref),
      hasKey: (ref) => vaultDelegate.hasKey(ref),
      hasSecret: (ref) => vaultDelegate.hasSecret(ref),
    };
    const identityStore: IdentityStore = {
      get: (localId) => storeDelegate.get(localId),
      list: () => storeDelegate.list(),
      put: (record) => storeDelegate.put(record),
      delete: (localId) => storeDelegate.delete(localId),
    };
    const wallet = new WalletCore({
      keyVault,
      identityStore,
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const identity = await wallet.createIdentity();
    expect(identity.subject).toMatch(/^nx1_/u);
    await expect(wallet.issueDeviceTransfer(identity.localId)).rejects.toMatchObject({
      code: 'INVALID_REQUEST',
    });
  });

  it('does not offer any raw root or device private-key export API', () => {
    const { wallet, keyVault } = createHarness();
    const indexedVault = new WebCryptoIndexedDbKeyVault({ indexedDB: new IDBFactory() });
    expect('exportIdentity' in wallet).toBe(false);
    for (const vault of [keyVault, indexedVault]) {
      expect('sign' in vault).toBe(false);
      expect('exportPrivateKey' in vault).toBe(false);
      expect('importDeviceSigningKey' in vault).toBe(false);
      expect('importDeviceSigningKeyAtRef' in vault).toBe(false);
      expect('createDeviceSigningKeyRef' in vault).toBe(false);
      expect('cancelDeviceSigningKeyRef' in vault).toBe(false);
      expect('createDeviceSigningKeyForTransfer' in vault).toBe(false);
    }
  });

  it('enforces protocol allowlists for managed root and device signing keys', async () => {
    const { wallet, keyVault, identityStore } = createHarness();
    const root = await wallet.createIdentity();
    const rootRecord = await identityStore.get(root.localId);
    const rootRef = rootRecord?.signingPrivateKeyRef;
    if (rootRef === undefined) throw new Error('Expected root signing-key reference.');
    await expect(
      signManagedProtocolPayload(keyVault, rootRef, {
        protocol: 'nexus.device-activation.v2',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });

    const issued = await wallet.issueDeviceTransfer(root.localId);
    const imported = await wallet.importDeviceTransfer(issued.bundle, issued.transferKey);
    const deviceRecord = await identityStore.get(imported.localId);
    const deviceRef = deviceRecord?.deviceV2?.signingPrivateKeyRef;
    if (deviceRef === undefined) throw new Error('Expected device signing-key reference.');
    await expect(
      signManagedProtocolPayload(keyVault, deviceRef, {
        protocol: 'nexus.device-root-revoke.v2',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
  });
});
