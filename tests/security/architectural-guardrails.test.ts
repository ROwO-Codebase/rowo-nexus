import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import { describe, expect, it } from 'vitest';

interface WorkspaceFile {
  readonly path: string;
  readonly source: string;
}

const WORKSPACE_ROOT = process.cwd();
const IMPLEMENTATION_EXTENSION = /\.(?:[cm]?[jt]sx?|jsonc|sql)$/u;

function workspacePath(path: string): string {
  return path.split('/').join(sep);
}

function normalizePath(path: string): string {
  return path.split(sep).join('/');
}

function walk(root: string): WorkspaceFile[] {
  const absoluteRoot = join(WORKSPACE_ROOT, workspacePath(root));
  if (!existsSync(absoluteRoot)) return [];

  const files: WorkspaceFile[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'coverage') {
          visit(absolute);
        }
        continue;
      }
      if (!entry.isFile() || !IMPLEMENTATION_EXTENSION.test(entry.name)) continue;
      const path = normalizePath(relative(WORKSPACE_ROOT, absolute));
      files.push({ path, source: readFileSync(absolute, 'utf8') });
    }
  };

  visit(absoluteRoot);
  return files;
}

function isImplementation(file: WorkspaceFile): boolean {
  const path = file.path.toLowerCase();
  return (
    !path.includes('/test/') &&
    !path.includes('/tests/') &&
    !path.includes('/fixtures/') &&
    !path.endsWith('/fixtures.ts') &&
    !/\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(path) &&
    !/\/(?:vitest|playwright)(?:\.[^/]+)?\.[cm]?[jt]s$/u.test(path) &&
    !path.endsWith('/wrangler.test.jsonc')
  );
}

function implementationFiles(roots: readonly string[]): WorkspaceFile[] {
  return roots.flatMap((root) => walk(root)).filter(isImplementation);
}

/**
 * Static guardrails intentionally ignore comments so normative prose and
 * blocked-scaffold explanations do not become false positives.
 */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//gu, '')
    .replace(/(^|[^:])\/\/.*$/gmu, '$1')
    .replace(/^\s*--.*$/gmu, '');
}

function matchingFiles(files: readonly WorkspaceFile[], pattern: RegExp): readonly string[] {
  return files
    .filter((file) => {
      pattern.lastIndex = 0;
      return pattern.test(withoutComments(file.source));
    })
    .map((file) => file.path)
    .sort();
}

function extractNamedBlock(source: string, declarationName: string): string | undefined {
  const declaration = new RegExp(`\\b(?:interface|type)\\s+${declarationName}\\b[^\\{]*\\{`, 'u');
  const match = declaration.exec(source);
  if (match === null) return undefined;

  const openingBrace = source.indexOf('{', match.index);
  let depth = 0;
  for (let index = openingBrace; index < source.length; index += 1) {
    const character = source[index];
    if (character === '{') depth += 1;
    if (character === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(openingBrace, index + 1);
    }
  }
  return undefined;
}

describe('architectural security guardrails', () => {
  it('does not use Math.random in security-sensitive implementation source', () => {
    const securitySource = implementationFiles(['apps', 'packages', 'workers', 'scripts']).filter(
      (file) => file.path.includes('/src/') || file.path.startsWith('scripts/'),
    );

    expect(matchingFiles(securitySource, /\bMath\s*\.\s*random\s*\(/u)).toEqual([]);
  });

  it('does not create users, controller, or vault tables', () => {
    const schemaFiles = implementationFiles(['apps', 'migrations', 'workers']).filter(
      (file) => file.path.endsWith('.sql') || file.path.includes('/src/'),
    );
    const violations: string[] = [];
    const createTable =
      /\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+["\x60[]?([A-Za-z][A-Za-z0-9_]*)/giu;
    const forbiddenTable = /(?:^|_)(?:users?|controllers?|vaults?)(?:_|$)/iu;

    for (const file of schemaFiles) {
      const source = withoutComments(file.source);
      for (const match of source.matchAll(createTable)) {
        const table = match[1];
        if (table !== undefined && forbiddenTable.test(table)) {
          violations.push(`${file.path}: ${table}`);
        }
      }
    }

    expect(violations.sort()).toEqual([]);
  });

  it('keeps D1, KV, and projection authorization dependencies out of edge and registry', () => {
    const authorityBoundary = implementationFiles(['workers/edge-api', 'workers/registry']);
    const forbiddenBinding =
      /\b(?:D1Database|KVNamespace|INDEX_DB)\b|["'](?:d1_databases|kv_namespaces)["']\s*:/iu;
    const violations = [...matchingFiles(authorityBoundary, forbiddenBinding)];
    const forbiddenImport =
      /(?:^|\/)(?:projector|projection|d1|kv|lifecycle-cache|authorization-cache)(?:\/|$)/iu;
    const importSpecifier = /\bfrom\s+['"]([^'"]+)['"]/gu;

    for (const file of authorityBoundary.filter((candidate) => candidate.path.endsWith('.ts'))) {
      const source = withoutComments(file.source);
      for (const match of source.matchAll(importSpecifier)) {
        const specifier = match[1];
        if (specifier !== undefined && forbiddenImport.test(specifier)) {
          violations.push(`${file.path}: ${specifier}`);
        }
      }
    }

    expect([...new Set(violations)].sort()).toEqual([]);
  });

  it('never sends proof or result messages to a wildcard postMessage target', () => {
    const browserTransport = implementationFiles(['apps/wallet/src', 'packages/sdk-browser/src']);
    const violations: string[] = [];
    const wildcardCall = /\bpostMessage\s*\(\s*([\s\S]{0,600}?),\s*(['"])\*\2\s*\)/giu;
    const wildcardOption = /\btargetOrigin\s*:\s*['"]\*['"]/iu;

    for (const file of browserTransport) {
      const source = withoutComments(file.source);
      for (const match of source.matchAll(wildcardCall)) {
        const payload = match[1] ?? '';
        const readyOnly =
          /\bNEXUS_READY\b/u.test(payload) || /^\s*[A-Za-z_$][\w$]*ready[\w$]*\s*$/iu.test(payload);
        if (!readyOnly) violations.push(`${file.path}: wildcard postMessage payload`);
      }
      if (wildcardOption.test(source)) {
        violations.push(`${file.path}: wildcard targetOrigin option`);
      }
    }

    expect(violations.sort()).toEqual([]);
  });

  it('keeps wallet-core off localStorage, cookies, and direct network transports', () => {
    const walletCore = implementationFiles(['packages/wallet-core/src']);
    const browserPersistence =
      /\blocalStorage\b|\bdocument\s*\.\s*cookie\b|\bcookieStore\b|['"](?:Cookie|Set-Cookie)['"]/iu;
    const directNetwork =
      /\bfetch\s*\(|\bnew\s+XMLHttpRequest\b|\bnew\s+WebSocket\b|\bnew\s+EventSource\b|\bnavigator\s*\.\s*sendBeacon\s*\(/iu;

    expect(matchingFiles(walletCore, browserPersistence)).toEqual([]);
    expect(matchingFiles(walletCore, directNetwork)).toEqual([]);
  });

  it('does not expose private-key material through wallet registry payload contracts', () => {
    const typesFile = requiredFile('packages/wallet-core/src/types.ts');
    const requestBlock = extractNamedBlock(typesFile.source, 'RegistryRegisterRequest');
    const clientBlock = extractNamedBlock(typesFile.source, 'RegistryClient');
    expect(requestBlock).toBeDefined();
    expect(clientBlock).toBeDefined();

    const publicRegistryContract = `${requestBlock ?? ''}\n${clientBlock ?? ''}`;
    expect(publicRegistryContract).not.toMatch(
      /\b(?:privateKey|signingPrivateKeyRef|agreementPrivateKeyRef)\b/u,
    );

    const walletCore = implementationFiles(['packages/wallet-core/src']);
    const registryCallWithPrivateKey =
      /#registryClient\s*\.\s*(?:register|getStatus|revoke)\s*\([\s\S]{0,800}?\b(?:privateKey|signingPrivateKeyRef|agreementPrivateKeyRef)\b/iu;
    expect(matchingFiles(walletCore, registryCallWithPrivateKey)).toEqual([]);
  });

  it('keeps identity-key backup, export, and restore outside the product', () => {
    expect(existsSync(join(WORKSPACE_ROOT, 'workers', 'backup'))).toBe(false);
    expect(existsSync(join(WORKSPACE_ROOT, 'docs', 'adr', '0011-backup-security.md'))).toBe(false);

    const implementation = implementationFiles(['apps', 'packages', 'workers']);
    const retiredBackupSurface =
      /\b(?:BACKUP_SERVICE|NEXUS_BACKUP_ENABLED|EncryptedVaultBackupV\d*|backupId|backupSecret|exportIdentity|importIdentity|restoreIdentity|createBackup|restoreBackup|deriveBackupKey|encryptVault|decryptVault|backup_read|backup_write|backup_delete)\b|['"]\/v\d+\/(?:backup|vault-backup)(?:\/|['"])/iu;

    expect(matchingFiles(implementation, retiredBackupSurface)).toEqual([]);
  });

  it('keeps default rotation and registry wire state free of old/new linkage', () => {
    const registryWire = implementationFiles([
      'packages/protocol/src',
      'workers/edge-api/src',
      'workers/registry/src',
      'migrations',
    ]);
    const linkageField =
      /\b(?:oldSubject|newSubject|previousSubject|nextSubject|replacementSubject|predecessorSubject|successorSubject|rotatedFrom|rotatedTo|old_subject|new_subject|previous_subject|next_subject|replacement_subject|rotated_from|rotated_to)\b/iu;
    const combinedRotationEndpoint = /['"]\/v1\/identity\/(?:rotate|rotation)['"]/iu;

    expect(matchingFiles(registryWire, linkageField)).toEqual([]);
    expect(matchingFiles(registryWire, combinedRotationEndpoint)).toEqual([]);
  });

  it('keeps routine log calls and metric dimensions free of sensitive values', () => {
    const implementation = implementationFiles(['apps', 'packages', 'workers']);
    const forbiddenDimension =
      /\b(?:subject|ipAddress|userAgent|rpOrigin|audience|nonce|proofId|proof|privateKey|revocationSecret|genesis)\b/iu;
    const violations: string[] = [];
    const logCall =
      /\b(?:console\s*\.\s*(?:log|info|warn|error|debug)|(?:logger|log)\s*\.\s*(?:log|info|warn|error|debug))\s*\(([\s\S]{0,1000}?)\)\s*;?/giu;

    for (const file of implementation) {
      const source = withoutComments(file.source);
      for (const match of source.matchAll(logCall)) {
        const argumentsSource = match[1] ?? '';
        if (forbiddenDimension.test(argumentsSource)) {
          violations.push(`${file.path}: sensitive value in routine log call`);
        }
      }

      if (/(?:logging|metrics?|analytics)/iu.test(basename(file.path))) {
        const declaredDimension =
          /\b(subject|ipAddress|userAgent|rpOrigin|audience|nonce|proofId|proof|privateKey|revocationSecret|genesis)\??\s*:/giu;
        for (const match of source.matchAll(declaredDimension)) {
          violations.push(`${file.path}: forbidden metric field ${match[1] ?? 'unknown'}`);
        }
      }
    }

    expect(violations.sort()).toEqual([]);
  });
});

function requiredFile(path: string): WorkspaceFile {
  const absolute = join(WORKSPACE_ROOT, workspacePath(path));
  if (!existsSync(absolute)) throw new Error(`Required guardrail input is missing: ${path}`);
  return { path, source: readFileSync(absolute, 'utf8') };
}
