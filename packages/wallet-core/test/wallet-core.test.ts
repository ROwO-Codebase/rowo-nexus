import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';

import {
  base64Url32Schema,
  decodeBase64UrlExact,
  encodeBase64Url,
  formatSubject,
  proofRequestSchema,
  type NexusSubject,
  type RevokeBySecretRequestV1,
  type RevokeBySignatureRequestV1,
} from '@nexus/protocol';

import {
  acceptUnsignedInMemoryRegistryReceipt,
  captureWalletEventBoundary,
  IndexedDbIdentityStore,
  InMemoryIdentityStore,
  InMemoryKeyVault,
  InMemoryRegistryClient,
  WalletCore,
  WebCryptoIndexedDbKeyVault,
  type RegistryClient,
  type RegistryIdentityStatus,
  type RegistryRegisterRequest,
  type RegistryReceiptVerifier,
  type TrustedWalletEventBoundary,
} from '../src/index.js';
import { signManagedProtocolPayload } from '../src/key-vault.js';

const NOW = 1_786_400_000;

function walletEvent(origin: string): MessageEvent<unknown> {
  return new MessageEvent('message', { origin });
}

function boundary(origin: string): TrustedWalletEventBoundary {
  return captureWalletEventBoundary(walletEvent(origin));
}

function createHarness(
  verifyRegistryReceipt: RegistryReceiptVerifier = acceptUnsignedInMemoryRegistryReceipt,
) {
  const keyVault = new InMemoryKeyVault();
  const identityStore = new InMemoryIdentityStore();
  const registryClient = new InMemoryRegistryClient({ clock: { now: () => NOW } });
  const wallet = new WalletCore({
    keyVault,
    identityStore,
    registryClient,
    verifyRegistryReceipt,
    clock: { now: () => NOW },
  });
  return { wallet, keyVault, identityStore, registryClient };
}

class DroppedRevocationResponseRegistry implements RegistryClient {
  readonly #delegate: InMemoryRegistryClient;
  #dropNextResponse = true;
  readonly attempts: Array<{ mode: 'signature' | 'secret'; expectedSequence: number }> = [];

  public constructor(delegate: InMemoryRegistryClient) {
    this.#delegate = delegate;
  }

  public register(request: RegistryRegisterRequest): Promise<unknown> {
    return this.#delegate.register(request);
  }

  public async getStatus(subject: NexusSubject): Promise<RegistryIdentityStatus> {
    const status = await this.#delegate.getStatus(subject);
    const productionStatus = { ...status };
    delete productionStatus.terminalReceipt;
    return productionStatus;
  }

  public async revoke(
    request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1,
  ): Promise<unknown> {
    this.attempts.push({
      mode: request.mode,
      expectedSequence: request.payload.expectedSequence,
    });
    const receipt = await this.#delegate.revoke(request);
    if (this.#dropNextResponse) {
      this.#dropNextResponse = false;
      throw new Error('simulated dropped revocation response');
    }
    return receipt;
  }
}

function createDroppedResponseHarness() {
  const keyVault = new InMemoryKeyVault();
  const identityStore = new InMemoryIdentityStore();
  const delegate = new InMemoryRegistryClient({ clock: { now: () => NOW } });
  const registryClient = new DroppedRevocationResponseRegistry(delegate);
  const wallet = new WalletCore({
    keyVault,
    identityStore,
    registryClient,
    verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
    clock: { now: () => NOW },
  });
  return { wallet, keyVault, identityStore, registryClient };
}

describe('WebCrypto IndexedDB vault', () => {
  it('persists non-extractable keys and secrets, then deletes them', async () => {
    const indexedDB = new IDBFactory();
    const options = {
      databaseName: 'wallet-vault-persistence',
      indexedDB,
      crypto: globalThis.crypto,
    };
    const first = new WebCryptoIndexedDbKeyVault(options);
    const signingRef = await first.createSigningKey();
    const agreementRef = await first.createAgreementKey();
    const secretRef = await first.storeRevocationSecret(new Uint8Array(32).fill(0x5a));
    const publicKey = await first.readPublicKey(signingRef);
    const agreementPublicKey = await first.readPublicKey(agreementRef);
    const firstSignature = await signManagedProtocolPayload(first, signingRef, {
      protocol: 'nexus.ownership-proof.v1',
      nonce: 'first',
    });
    expect(publicKey).toHaveLength(32);
    expect(agreementPublicKey).toHaveLength(32);
    expect(firstSignature).toHaveLength(64);
    await first.close();

    const reopened = new WebCryptoIndexedDbKeyVault(options);
    expect(await reopened.readPublicKey(signingRef)).toEqual(publicKey);
    expect(await reopened.readPublicKey(agreementRef)).toEqual(agreementPublicKey);
    expect(await reopened.readRevocationSecret(secretRef)).toEqual(new Uint8Array(32).fill(0x5a));
    expect(
      await signManagedProtocolPayload(reopened, signingRef, {
        protocol: 'nexus.ownership-proof.v1',
        nonce: 'reopened',
      }),
    ).toHaveLength(64);

    await reopened.deleteKey(signingRef);
    await reopened.deleteKey(agreementRef);
    await reopened.deleteSecret(secretRef);
    expect(await reopened.hasKey(signingRef)).toBe(false);
    expect(await reopened.hasKey(agreementRef)).toBe(false);
    expect(await reopened.hasSecret(secretRef)).toBe(false);
    await reopened.close();
  });

  it('persists structured identity records independently from key material', async () => {
    const indexedDB = new IDBFactory();
    const databaseName = 'wallet-record-persistence';
    const vault = new WebCryptoIndexedDbKeyVault({ databaseName, indexedDB });
    const signingPrivateKeyRef = await vault.createSigningKey();
    const revocationSecretRef = await vault.storeRevocationSecret(new Uint8Array(32).fill(7));
    const store = new IndexedDbIdentityStore({ databaseName, indexedDB });
    const record = {
      localId: '4f444ba9-c84a-4da2-83aa-56d3badbc001',
      subject: formatSubject(new Uint8Array(32).fill(1)),
      genesis: {
        protocol: 'nexus.identity.v1' as const,
        suite: 'NX-25519-SHA256-JCS-v1' as const,
        signingKey: {
          alg: 'Ed25519' as const,
          publicKey: base64Url32Schema.parse(encodeBase64Url(new Uint8Array(32).fill(2))),
        },
        revocationCommitment: base64Url32Schema.parse(encodeBase64Url(new Uint8Array(32).fill(3))),
      },
      signingPrivateKeyRef,
      revocationSecretRef,
      localScopes: ['https://rp-a.test'],
      authorizationHistory: [
        {
          authorizationId: 'b7273ce1-f2aa-439c-9538-c56c2ba279b1',
          approvedAt: NOW,
          audience: 'https://rp-a.test',
          action: 'post.create',
          resource: 'post:01JABC',
          introducedScope: true,
          contextBound: false,
        },
      ],
      localState: 'active' as const,
    };
    await store.put(record);
    await store.close();

    const reopened = new IndexedDbIdentityStore({ databaseName, indexedDB });
    expect(await reopened.get(record.localId)).toEqual(record);
    await reopened.delete(record.localId);
    expect(await reopened.get(record.localId)).toBeUndefined();
    await reopened.close();
    await vault.close();
  });
});

describe('identity lifecycle', () => {
  it('creates independent identities with unrelated keys and revocation secrets', async () => {
    const { wallet, identityStore, keyVault } = createHarness();
    const identityA = await wallet.createIdentity({ withAgreementKey: true });
    const identityB = await wallet.createIdentity({ withAgreementKey: true });
    const recordA = await identityStore.get(identityA.localId);
    const recordB = await identityStore.get(identityB.localId);

    expect(identityA.subject).not.toBe(identityB.subject);
    expect(identityA.genesis.signingKey.publicKey).not.toBe(identityB.genesis.signingKey.publicKey);
    expect(identityA.genesis.agreementKey?.publicKey).not.toBe(
      identityB.genesis.agreementKey?.publicKey,
    );
    expect(identityA.genesis.revocationCommitment).not.toBe(identityB.genesis.revocationCommitment);
    expect(recordA?.revocationSecretRef).toBeDefined();
    expect(recordB?.revocationSecretRef).toBeDefined();
    expect(
      await keyVault.readRevocationSecret(recordA?.revocationSecretRef ?? fail('missing secret A')),
    ).not.toEqual(
      await keyVault.readRevocationSecret(recordB?.revocationSecretRef ?? fail('missing secret B')),
    );
  });

  it('preserves every private item when terminal receipt verification fails', async () => {
    const verifier: RegistryReceiptVerifier = async (rawReceipt) => {
      const receipt = await acceptUnsignedInMemoryRegistryReceipt(rawReceipt);
      if (receipt.payload.eventType === 'revoked') throw new Error('invalid service signature');
      return receipt;
    };
    const { wallet, identityStore, keyVault } = createHarness(verifier);
    const identity = await wallet.createIdentity({ withAgreementKey: true });
    const before = await identityStore.get(identity.localId);
    if (
      before?.signingPrivateKeyRef === undefined ||
      before.agreementPrivateKeyRef === undefined ||
      before.revocationSecretRef === undefined
    ) {
      throw new Error('test identity is missing active private references');
    }

    await expect(wallet.dispose(identity.localId)).rejects.toMatchObject({
      code: 'INVALID_REGISTRY_RECEIPT',
    });

    const after = await identityStore.get(identity.localId);
    expect(after?.localState).toBe('active');
    expect(await keyVault.hasKey(before.signingPrivateKeyRef)).toBe(true);
    expect(await keyVault.hasKey(before.agreementPrivateKeyRef)).toBe(true);
    expect(await keyVault.hasSecret(before.revocationSecretRef)).toBe(true);
  });

  it('deletes all active material only after a verified terminal receipt', async () => {
    const { wallet, identityStore, keyVault } = createHarness();
    const identity = await wallet.createIdentity({ withAgreementKey: true });
    const before = await identityStore.get(identity.localId);
    if (
      before?.signingPrivateKeyRef === undefined ||
      before.agreementPrivateKeyRef === undefined ||
      before.revocationSecretRef === undefined
    ) {
      throw new Error('test identity is missing active private references');
    }

    const receipt = await wallet.dispose(identity.localId);
    expect(receipt.payload.state).toBe('revoked');
    expect(await keyVault.hasKey(before.signingPrivateKeyRef)).toBe(false);
    expect(await keyVault.hasKey(before.agreementPrivateKeyRef)).toBe(false);
    expect(await keyVault.hasSecret(before.revocationSecretRef)).toBe(false);

    const retained = await identityStore.get(identity.localId);
    expect(retained).toMatchObject({ localState: 'revoked', subject: identity.subject });
    expect(retained?.signingPrivateKeyRef).toBeUndefined();
    expect(retained?.agreementPrivateKeyRef).toBeUndefined();
    expect(retained?.revocationSecretRef).toBeUndefined();
  });

  it.each(['signature', 'secret'] as const)(
    'recovers %s disposal after the registry commits but its response is dropped',
    async (method) => {
      const { wallet, identityStore, keyVault, registryClient } = createDroppedResponseHarness();
      const identity = await wallet.createIdentity({ withAgreementKey: true });
      const before = await identityStore.get(identity.localId);
      if (
        before?.signingPrivateKeyRef === undefined ||
        before.agreementPrivateKeyRef === undefined ||
        before.revocationSecretRef === undefined
      ) {
        throw new Error('test identity is missing active private references');
      }

      await expect(wallet.dispose(identity.localId, { method })).rejects.toThrow(
        'simulated dropped revocation response',
      );
      expect(await keyVault.hasKey(before.signingPrivateKeyRef)).toBe(true);
      expect(await keyVault.hasKey(before.agreementPrivateKeyRef)).toBe(true);
      expect(await keyVault.hasSecret(before.revocationSecretRef)).toBe(true);

      const receipt = await wallet.dispose(identity.localId, { method });
      expect(receipt.payload.state).toBe('revoked');
      expect(registryClient.attempts).toEqual([
        { mode: method, expectedSequence: 0 },
        { mode: method, expectedSequence: 0 },
      ]);
      expect(await keyVault.hasKey(before.signingPrivateKeyRef)).toBe(false);
      expect(await keyVault.hasKey(before.agreementPrivateKeyRef)).toBe(false);
      expect(await keyVault.hasSecret(before.revocationSecretRef)).toBe(false);

      const retained = await identityStore.get(identity.localId);
      expect(retained).toMatchObject({ localState: 'revoked', subject: identity.subject });
      expect(retained?.signingPrivateKeyRef).toBeUndefined();
      expect(retained?.revocationSecretRef).toBeUndefined();

      expect((await wallet.dispose(identity.localId, { method })).payload.state).toBe('revoked');
      expect(registryClient.attempts).toHaveLength(2);
    },
  );
});

describe('scope, proof, rotation, and explicit continuity', () => {
  it('keeps identity selection isolated by exact wallet event origin', async () => {
    const { wallet } = createHarness();
    const identityA = await wallet.createIdentity();
    const identityB = await wallet.createIdentity();
    const rpA = boundary('https://rp-a.test');
    const rpB = boundary('https://rp-b.test');
    await wallet.addScope(identityA.localId, rpA);
    await wallet.addScope(identityB.localId, rpB);

    expect(
      (await wallet.listIdentitySummariesForBoundary(rpA)).map((item) => item.localId),
    ).toEqual([identityA.localId]);
    expect(
      (await wallet.listIdentitySummariesForBoundary(rpB)).map((item) => item.localId),
    ).toEqual([identityB.localId]);
  });

  it('accepts a proof audience only through the captured MessageEvent boundary', async () => {
    const { wallet } = createHarness();
    const identity = await wallet.createIdentity();
    const rpA = boundary('https://rp-a.test');
    const request = proofRequestSchema.parse({
      action: 'post.edit',
      resource: 'post:01JABC',
      nonce: 'AQEBAQEBAQEBAQEBAQEBAQ',
      expiresAt: NOW + 60,
    });
    const proof = await wallet.prove(identity.localId, rpA, request);
    expect(proof.payload.aud).toBe('https://rp-a.test');
    expect(decodeBase64UrlExact(proof.signature, 64)).toHaveLength(64);

    const forged = { audience: 'https://rp-b.test' } as TrustedWalletEventBoundary;
    await expect(wallet.prove(identity.localId, forged, request)).rejects.toMatchObject({
      code: 'UNTRUSTED_WALLET_EVENT',
    });
  });

  it('stores a bounded, metadata-only authorization history and clears it independently', async () => {
    const { wallet } = createHarness();
    const identity = await wallet.createIdentity();
    const rpA = boundary('https://rp-a.test');
    const request = proofRequestSchema.parse({
      action: 'post.edit',
      resource: 'post:01JABC',
      nonce: 'AQEBAQEBAQEBAQEBAQEBAQ',
      expiresAt: NOW + 60,
      contextHash: encodeBase64Url(new Uint8Array(32).fill(0x04)),
    });

    const proof = await wallet.proveAndRecordAuthorization(identity.localId, rpA, request, true);
    expect(proof.payload).toMatchObject({
      aud: 'https://rp-a.test',
      act: 'post.edit',
      resource: 'post:01JABC',
    });
    let summary = (await wallet.listIdentitySummaries())[0];
    const first = summary?.authorizationHistory[0];
    expect(first).toBeDefined();
    if (first === undefined) throw new Error('Expected a recorded authorization.');
    expect(first).toMatchObject({
      approvedAt: NOW,
      audience: 'https://rp-a.test',
      action: 'post.edit',
      resource: 'post:01JABC',
      introducedScope: true,
      contextBound: true,
    });
    expect(Object.keys(first).sort()).toEqual([
      'action',
      'approvedAt',
      'audience',
      'authorizationId',
      'contextBound',
      'introducedScope',
      'resource',
    ]);
    expect(JSON.stringify(first)).not.toContain(request.nonce);
    expect(JSON.stringify(first)).not.toContain(request.contextHash);

    await wallet.proveAndRecordAuthorization(identity.localId, rpA, request, true);
    summary = (await wallet.listIdentitySummaries())[0];
    expect(summary?.localScopes).toEqual(['https://rp-a.test']);
    expect(summary?.authorizationHistory).toHaveLength(2);
    expect(summary?.authorizationHistory[0]?.introducedScope).toBe(false);
    expect(summary?.authorizationHistory[1]?.introducedScope).toBe(true);

    for (let index = 0; index < 200; index += 1) {
      await wallet.proveAndRecordAuthorization(identity.localId, rpA, request, false);
    }
    summary = (await wallet.listIdentitySummaries())[0];
    expect(summary?.authorizationHistory).toHaveLength(200);

    await wallet.clearAuthorizationHistory(identity.localId);
    summary = (await wallet.listIdentitySummaries())[0];
    expect(summary?.authorizationHistory).toEqual([]);
    expect(summary?.localScopes).toEqual(['https://rp-a.test']);

    const forged = { audience: 'https://rp-b.test' } as TrustedWalletEventBoundary;
    await expect(
      wallet.proveAndRecordAuthorization(identity.localId, forged, request, true),
    ).rejects.toMatchObject({ code: 'UNTRUSTED_WALLET_EVENT' });
  });

  it('rotates through independent create and local scoping without a registry link', async () => {
    const { wallet, registryClient } = createHarness();
    const oldIdentity = await wallet.createIdentity({ withAgreementKey: true });
    const rpA = boundary('https://rp-a.test');
    await wallet.addScope(oldIdentity.localId, rpA);

    const rotated = await wallet.rotate(oldIdentity.localId, rpA);
    expect(rotated.identity.subject).not.toBe(oldIdentity.subject);
    expect(rotated.identity.genesis.signingKey.publicKey).not.toBe(
      oldIdentity.genesis.signingKey.publicKey,
    );
    const registrations = registryClient.registerRequests;
    expect(registrations).toHaveLength(2);
    expect(Object.keys(registrations[1] ?? {}).sort()).toEqual(['genesis', 'subject']);
    expect(JSON.stringify(registrations[1])).not.toContain(oldIdentity.subject);
    expect(
      (await wallet.listIdentitySummariesForBoundary(rpA)).some(
        (summary) => summary.localId === rotated.identity.localId,
      ),
    ).toBe(true);
  });

  it('creates an explicitly dual-signed continuity link only when requested', async () => {
    const { wallet } = createHarness();
    const identityA = await wallet.createIdentity();
    const identityB = await wallet.createIdentity();
    const link = await wallet.createContinuityLink(identityA.localId, identityB.localId, {
      nonce: 'AgICAgICAgICAgICAgICAg',
      scope: 'forum-profile',
      expiresAt: NOW + 120,
    });

    expect(link.payload.subjectA).toBe(identityA.subject);
    expect(link.payload.subjectB).toBe(identityB.subject);
    expect(decodeBase64UrlExact(link.signatureA, 64)).toHaveLength(64);
    expect(decodeBase64UrlExact(link.signatureB, 64)).toHaveLength(64);
    expect(link.signatureA).not.toBe(link.signatureB);
  });
});

function fail(message: string): never {
  throw new Error(message);
}
