export const FIXTURE_WARNING =
  'NON-PRODUCTION TEST FIXTURE: public RFC 8032 key material; never use for real identities or services.';

export interface Ed25519Fixture {
  readonly id: 'identity-a' | 'identity-b' | 'service-registry' | 'service-transparency';
  readonly rfc8032Section: string;
  readonly seedHex: string;
  readonly pkcs8Hex: string;
  readonly publicKeyHex: string;
}

const ED25519_PKCS8_SEED_PREFIX_HEX = '302e020100300506032b657004220420';

function ed25519Fixture(
  id: Ed25519Fixture['id'],
  rfc8032Section: string,
  seedHex: string,
  publicKeyHex: string,
): Ed25519Fixture {
  return {
    id,
    rfc8032Section,
    seedHex,
    pkcs8Hex: `${ED25519_PKCS8_SEED_PREFIX_HEX}${seedHex}`,
    publicKeyHex,
  };
}

export const ED25519_FIXTURES = {
  identityA: ed25519Fixture(
    'identity-a',
    'RFC 8032 section 7.1, TEST 1',
    '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  ),
  identityB: ed25519Fixture(
    'identity-b',
    'RFC 8032 section 7.1, TEST 2',
    '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  ),
  serviceRegistry: ed25519Fixture(
    'service-registry',
    'RFC 8032 section 7.1, TEST 3',
    'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
  ),
  serviceTransparency: ed25519Fixture(
    'service-transparency',
    'RFC 8032 section 7.1, TEST 1024',
    'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
  ),
} as const;

export const X25519_PUBLIC_KEY_A_HEX =
  '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
export const X25519_PUBLIC_KEY_B_HEX =
  'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';

export const REVOCATION_SECRET_A_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
export const REVOCATION_SECRET_B_HEX =
  'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

export const VECTOR_TIMES = {
  issuedAt: 1_786_400_000,
  registeredAt: 1_786_400_005,
  revokeIssuedAt: 1_786_400_020,
  continuityIssuedAt: 1_786_400_030,
} as const;
