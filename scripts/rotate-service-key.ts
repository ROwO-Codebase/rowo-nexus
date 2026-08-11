#!/usr/bin/env node

import { pathToFileURL } from 'node:url';

import { WebCryptoProvider, type CryptoProvider } from '../packages/crypto/src/index.js';
import {
  ed25519PublicJwkSchema,
  encodeBase64Url,
  signerKidSchema,
  type Ed25519PublicJwk,
} from '../packages/protocol/src/index.js';

export const SERVICE_KEY_PURPOSES = [
  'registry-receipt',
  'registry-status',
  'transparency-checkpoint',
  'notary',
] as const;

export type ServiceKeyPurpose = (typeof SERVICE_KEY_PURPOSES)[number];

interface ServiceKeyTarget {
  readonly privateKeyBinding: string;
  readonly kidBinding: string;
}

const SERVICE_KEY_TARGETS: Readonly<Record<ServiceKeyPurpose, ServiceKeyTarget>> = {
  'registry-receipt': {
    privateKeyBinding: 'RECEIPT_SIGNING_PRIVATE_KEY',
    kidBinding: 'RECEIPT_SIGNING_KID',
  },
  'registry-status': {
    privateKeyBinding: 'STATUS_SIGNING_PRIVATE_KEY',
    kidBinding: 'STATUS_SIGNING_KID',
  },
  'transparency-checkpoint': {
    privateKeyBinding: 'TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL',
    kidBinding: 'TRANSPARENCY_SIGNING_KID',
  },
  notary: {
    privateKeyBinding: 'NOTARY_SIGNING_KEY_PKCS8_B64URL',
    kidBinding: 'NOTARY_SIGNING_KID',
  },
};

export interface GenerateServiceKeyOptions {
  readonly purpose: ServiceKeyPurpose;
  readonly kid: string;
  readonly provider?: CryptoProvider;
}

export interface GeneratedServiceKeyMaterial {
  readonly purpose: ServiceKeyPurpose;
  readonly kid: string;
  readonly privateKey: {
    readonly binding: string;
    readonly format: 'PKCS#8';
    readonly encoding: 'base64url';
    readonly value: string;
  };
  readonly kidBinding: {
    readonly binding: string;
    readonly value: string;
  };
  readonly publicJwk: Ed25519PublicJwk;
}

export interface RotateServiceKeyArguments {
  readonly help: boolean;
  readonly purpose?: ServiceKeyPurpose;
  readonly kid?: string;
}

export class OperationalScriptError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OperationalScriptError';
  }
}

function parseServiceKeyPurpose(value: string): ServiceKeyPurpose {
  if ((SERVICE_KEY_PURPOSES as readonly string[]).includes(value)) {
    return value as ServiceKeyPurpose;
  }
  throw new OperationalScriptError(`--purpose must be one of: ${SERVICE_KEY_PURPOSES.join(', ')}.`);
}

function requireSingleValue(arguments_: readonly string[], index: number, option: string): string {
  const value = arguments_[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new OperationalScriptError(`${option} requires a value.`);
  }
  return value;
}

/** Strict CLI parsing is exported so callers can test it without generating a key. */
export function parseRotateServiceKeyArguments(
  arguments_: readonly string[],
): RotateServiceKeyArguments {
  if (arguments_.includes('--help') || arguments_.includes('-h')) {
    if (arguments_.length !== 1) {
      throw new OperationalScriptError('--help cannot be combined with other arguments.');
    }
    return { help: true };
  }

  let purpose: ServiceKeyPurpose | undefined;
  let kid: string | undefined;

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--purpose') {
      if (purpose !== undefined) {
        throw new OperationalScriptError('--purpose may be supplied only once.');
      }
      purpose = parseServiceKeyPurpose(requireSingleValue(arguments_, index, '--purpose'));
      index += 1;
      continue;
    }
    if (argument === '--kid') {
      if (kid !== undefined) {
        throw new OperationalScriptError('--kid may be supplied only once.');
      }
      const candidate = requireSingleValue(arguments_, index, '--kid');
      const parsedKid = signerKidSchema.safeParse(candidate);
      if (!parsedKid.success) {
        throw new OperationalScriptError(
          '--kid must be a non-empty printable ASCII service key identifier.',
        );
      }
      kid = parsedKid.data;
      index += 1;
      continue;
    }
    throw new OperationalScriptError('Unknown or positional argument. See --help.');
  }

  if (purpose === undefined) {
    throw new OperationalScriptError('--purpose is required.');
  }
  if (kid === undefined) {
    throw new OperationalScriptError('--kid is required.');
  }
  return { help: false, purpose, kid };
}

/**
 * Creates a new, non-derived Ed25519 key pair for exactly one service purpose.
 * The private key is extractable only long enough to transfer its PKCS#8 bytes.
 */
export async function generateServiceKeyMaterial(
  options: GenerateServiceKeyOptions,
): Promise<GeneratedServiceKeyMaterial> {
  const parsedKid = signerKidSchema.safeParse(options.kid);
  if (!parsedKid.success) {
    throw new OperationalScriptError(
      'kid must be a non-empty printable ASCII service key identifier.',
    );
  }
  if (!(options.purpose in SERVICE_KEY_TARGETS)) {
    throw new OperationalScriptError('Unsupported service key purpose.');
  }

  const provider = options.provider ?? new WebCryptoProvider();
  const keyPair = await provider.generateEd25519KeyPair({
    privateKeyExtractable: true,
  });
  const [pkcs8, rawPublicKey] = await Promise.all([
    provider.exportEd25519PrivateKey(keyPair.privateKey),
    provider.exportEd25519PublicKey(keyPair.publicKey),
  ]);

  try {
    const target = SERVICE_KEY_TARGETS[options.purpose];
    const publicJwk = ed25519PublicJwkSchema.parse({
      kty: 'OKP',
      crv: 'Ed25519',
      alg: 'EdDSA',
      kid: parsedKid.data,
      x: encodeBase64Url(rawPublicKey),
      use: 'sig',
    });

    return {
      purpose: options.purpose,
      kid: parsedKid.data,
      privateKey: {
        binding: target.privateKeyBinding,
        format: 'PKCS#8',
        encoding: 'base64url',
        value: encodeBase64Url(pkcs8),
      },
      kidBinding: {
        binding: target.kidBinding,
        value: parsedKid.data,
      },
      publicJwk,
    };
  } finally {
    pkcs8.fill(0);
    rawPublicKey.fill(0);
  }
}

export const ROTATE_SERVICE_KEY_HELP = `Usage:
  pnpm tsx scripts/rotate-service-key.ts --purpose <purpose> --kid <kid>

Generate one new Ed25519 service key pair and print a single JSON transfer object
to stdout. This command never writes the private key to disk.

Required options:
  --purpose  ${SERVICE_KEY_PURPOSES.join(' | ')}
  --kid      New, unique public key identifier (printable ASCII)

Other options:
  -h, --help Show this help without generating a key

Handle stdout as secret material. Transfer privateKey.value into the named
Cloudflare secret binding and publish only publicJwk. Generate a separate key
for every environment and purpose; never reuse a registry key for checkpoints.`;

export async function runRotateServiceKeyCli(
  arguments_: readonly string[],
  stdout: (text: string) => void = (text) => process.stdout.write(text),
): Promise<void> {
  const parsed = parseRotateServiceKeyArguments(arguments_);
  if (parsed.help) {
    stdout(`${ROTATE_SERVICE_KEY_HELP}\n`);
    return;
  }
  const material = await generateServiceKeyMaterial({
    purpose: parsed.purpose as ServiceKeyPurpose,
    kid: parsed.kid as string,
  });
  stdout(`${JSON.stringify(material, null, 2)}\n`);
}

function safeErrorMessage(error: unknown): string {
  return error instanceof OperationalScriptError ? error.message : 'Service key generation failed.';
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runRotateServiceKeyCli(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`Error: ${safeErrorMessage(error)}\n`);
    process.exitCode = 1;
  });
}
