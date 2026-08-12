import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { NEXUS_POPUP_CHANNEL, parseWalletMessage } from '../../packages/sdk-browser/src/index.js';
import {
  acceptUnsignedInMemoryRegistryReceipt,
  InMemoryIdentityStore,
  InMemoryKeyVault,
  InMemoryRegistryClient,
  WalletCore,
  WebCryptoIndexedDbKeyVault,
} from '../../packages/wallet-core/src/index.js';
import {
  NEXUS_POPUP_CHANNEL_V2,
  parseProofRequestMessage,
} from '../../apps/wallet/src/lib/popup-protocol.js';

const NOW = 1_788_000_000;
const REQUEST_ID = 'BBBBBBBBBBBBBBBBBBBBBB';
const NONCE = 'AAAAAAAAAAAAAAAAAAAAAA';

function parseWorkspaceSource(path: string): ts.SourceFile {
  const absolutePath = join(process.cwd(), ...path.split('/'));
  return ts.createSourceFile(
    path,
    readFileSync(absolutePath, 'utf8'),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
}

function namedInterface(source: ts.SourceFile, name: string): ts.InterfaceDeclaration {
  const declaration = source.statements.find(
    (statement): statement is ts.InterfaceDeclaration =>
      ts.isInterfaceDeclaration(statement) && statement.name.text === name,
  );
  if (declaration === undefined) throw new Error(`Missing interface ${name}`);
  return declaration;
}

function memberName(member: ts.TypeElement): string | undefined {
  const name = member.name;
  if (name === undefined) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return undefined;
}

function interfaceMemberNames(source: ts.SourceFile, name: string): readonly string[] {
  return namedInterface(source, name)
    .members.map(memberName)
    .filter((member): member is string => member !== undefined);
}

function visitCalls(source: ts.SourceFile): readonly ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) calls.push(node);
    ts.forEachChild(node, visit);
  };
  visit(source);
  return calls;
}

function publicMethodNames(prototype: object): readonly string[] {
  return Object.getOwnPropertyNames(prototype).filter(
    (name) => name !== 'constructor' && typeof Reflect.get(prototype, name) === 'function',
  );
}

function popupEvent(data: unknown): { event: MessageEvent<unknown>; source: Window } {
  const channel = new MessageChannel();
  const source = channel.port1 as unknown as Window;
  return {
    event: new MessageEvent('message', {
      source,
      origin: 'https://rp.example',
      data,
    }),
    source,
  };
}

function validProofRequest(): Record<string, unknown> {
  return {
    action: 'note.create',
    resource: 'note:example',
    nonce: NONCE,
    expiresAt: NOW + 120,
  };
}

describe('v2 device-delegation security guardrails', () => {
  it('keeps every private key created by the wallet vault non-extractable', () => {
    const source = parseWorkspaceSource('packages/wallet-core/src/key-vault.ts');
    const generateKeyCalls = visitCalls(source).filter(
      (call) =>
        ts.isPropertyAccessExpression(call.expression) &&
        call.expression.name.text === 'generateKey',
    );

    expect(generateKeyCalls.length).toBeGreaterThan(0);
    for (const call of generateKeyCalls) {
      expect(call.arguments[1]?.kind).toBe(ts.SyntaxKind.FalseKeyword);
    }

    const privateKeyImports = visitCalls(source).filter((call) => {
      if (!ts.isPropertyAccessExpression(call.expression)) return false;
      if (call.expression.name.text !== 'importKey') return false;
      const format = call.arguments[0];
      return format !== undefined && ts.isStringLiteral(format) && format.text === 'pkcs8';
    });
    expect(privateKeyImports.length).toBeGreaterThan(0);
    for (const call of privateKeyImports) {
      expect(call.arguments[3]?.kind).toBe(ts.SyntaxKind.FalseKeyword);
    }
  });

  it('does not expose raw identity or root-key extraction through wallet public APIs', () => {
    const source = parseWorkspaceSource('packages/wallet-core/src/types.ts');
    const interfaceMethods = [
      ...interfaceMemberNames(source, 'KeyVault'),
      ...interfaceMemberNames(source, 'WalletCoreApi'),
    ];
    const runtimeMethods = [
      ...publicMethodNames(InMemoryKeyVault.prototype),
      ...publicMethodNames(WebCryptoIndexedDbKeyVault.prototype),
      ...publicMethodNames(WalletCore.prototype),
    ];
    const forbiddenPrivateExport =
      /(?:export|extract|backup|dump|serialize|restore).*(?:identity|root|private|secret)|(?:identity|root|private|secret).*(?:export|extract|backup|dump|serialize|restore)/iu;

    expect(
      [...interfaceMethods, ...runtimeMethods].filter((name) => forbiddenPrivateExport.test(name)),
    ).toEqual([]);
  });

  it('permits only authenticated encrypted device-key transfer output', async () => {
    const wallet = new WalletCore({
      keyVault: new InMemoryKeyVault(),
      identityStore: new InMemoryIdentityStore(),
      registryClient: new InMemoryRegistryClient({ clock: { now: () => NOW } }),
      verifyRegistryReceipt: acceptUnsignedInMemoryRegistryReceipt,
      clock: { now: () => NOW },
    });
    const root = await wallet.createIdentity();

    const transfer = await wallet.issueDeviceTransfer(root.localId);

    expect(Object.keys(transfer).sort()).toEqual(['authorization', 'bundle', 'transferKey']);
    expect(transfer.transferKey).toBeInstanceOf(Uint8Array);
    expect(transfer.transferKey).toHaveLength(32);
    expect(Object.keys(transfer.bundle).sort()).toEqual([
      'bundleId',
      'ciphertext',
      'iv',
      'protocol',
      'salt',
      'suite',
    ]);
    expect(transfer.bundle).toMatchObject({
      protocol: 'nexus.device-transfer.v2',
      suite: 'NX-HKDF-SHA256-AES256GCM-v2',
    });
    expect(transfer.bundle.ciphertext).not.toContain(root.genesis.signingKey.publicKey);
    expect(Object.keys(transfer.bundle)).not.toContain('devicePrivateKey');
    expect(Object.keys(transfer.bundle)).not.toContain('rootPrivateKey');
  });

  it('does not expose device management or root authorization to an RP popup', () => {
    const managementTypes = [
      'NEXUS_DEVICE_AUTHORIZE_REQUEST',
      'NEXUS_DEVICE_EXPORT_REQUEST',
      'NEXUS_DEVICE_ROOT_REVOKE_REQUEST',
      'NEXUS_ROOT_SIGN_REQUEST',
    ];
    for (const type of managementTypes) {
      const { event, source } = popupEvent({
        channel: NEXUS_POPUP_CHANNEL_V2,
        type,
        requestId: REQUEST_ID,
        deviceId: 'nxd2_attacker',
      });
      expect(parseProofRequestMessage(event, source, NOW)).toBeUndefined();
    }

    const { event, source } = popupEvent({
      channel: NEXUS_POPUP_CHANNEL_V2,
      type: 'NEXUS_PROOF_REQUEST',
      requestId: REQUEST_ID,
      request: validProofRequest(),
      acceptedProofProtocols: ['nexus.ownership-proof.v2'],
      rootOperation: { type: 'revoke-device', deviceId: 'nxd2_attacker' },
    });
    expect(parseProofRequestMessage(event, source, NOW)).toBeUndefined();
  });

  it('preserves the exact v1 popup request and ready-message behavior', () => {
    const { event, source } = popupEvent({
      channel: NEXUS_POPUP_CHANNEL,
      type: 'NEXUS_PROOF_REQUEST',
      requestId: REQUEST_ID,
      request: validProofRequest(),
    });
    expect(parseProofRequestMessage(event, source, NOW)).toMatchObject({
      popupProtocol: NEXUS_POPUP_CHANNEL,
      acceptedProofProtocols: ['nexus.ownership-proof.v1'],
      origin: 'https://rp.example',
    });

    expect(parseWalletMessage({ channel: NEXUS_POPUP_CHANNEL, type: 'NEXUS_READY' })).toEqual({
      channel: 'nexus.popup.v1',
      type: 'NEXUS_READY',
    });
    expect(
      parseWalletMessage({
        channel: NEXUS_POPUP_CHANNEL,
        type: 'NEXUS_READY',
        supportedProofProtocols: ['nexus.ownership-proof.v2', 'nexus.ownership-proof.v1'],
      }),
    ).toBeUndefined();
    expect(publicMethodNames(WalletCore.prototype)).toContain('prove');
  });
});
