/**
 * Test helpers: generate a real Ed25519 keypair, mint signed Claws,
 * expose the public JWKS the SDK will be told to trust.
 *
 * No mock crypto — the SDK is exercised against real EdDSA the same way
 * a real hub would sign tokens. We mock the HTTP transport (undici
 * MockAgent), not the math.
 */
import { generateKeyPair, exportJWK, SignJWT, type KeyLike, type JWK } from 'jose';

export interface TestKey {
  publicKey: KeyLike;
  privateKey: KeyLike;
  jwk: JWK;       // public JWK with kid set, ready to drop into the JWKS response
  kid: string;
}

/** Generate a fresh Ed25519 keypair + matching public JWK with a kid.
 * Call once per test that needs a hub signer; cheap enough not to share. */
export async function makeHubKey(kid = 'test-kid-1'): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = 'EdDSA';
  jwk.use = 'sig';
  return { publicKey, privateKey, jwk, kid };
}

export interface ClawPayload {
  /** Default: 'agt_test'. */
  sub?: string;
  /** Default: 'tnt_test'. */
  tenant?: string;
  /** Default: 'clw_test'. */
  jti?: string;
  /** Default: 3600 seconds in the future. */
  expSecondsFromNow?: number;
  leash?: Record<string, unknown>;
  cnf?: { agent_pub?: string };
  /** For testing INVALID-with-no-kid case. */
  omitKid?: boolean;
}

/** Mint a signed Claw with the test key. Matches the hub's claim shape:
 * iss/sub/tenant/jti/iat/exp/cnf/leash. */
export async function mintClaw(
  key: TestKey,
  opts: ClawPayload = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.expSecondsFromNow ?? 3600);
  const builder = new SignJWT({
    tenant: opts.tenant ?? 'tnt_test',
    cnf: opts.cnf ?? { agent_pub: '-----BEGIN PUBLIC KEY-----\nFAKEPEM\n-----END PUBLIC KEY-----' },
    leash: opts.leash ?? {
      spend_ceiling: 100,
      allowed_surfaces: ['stripe.com'],
      active_start_hour: 0,
      active_end_hour: 24,
    },
  })
    .setProtectedHeader(
      opts.omitKid ? { alg: 'EdDSA' } : { alg: 'EdDSA', kid: key.kid },
    )
    .setIssuer('claw-hub')
    .setSubject(opts.sub ?? 'agt_test')
    .setJti(opts.jti ?? 'clw_test')
    .setIssuedAt(now)
    .setExpirationTime(exp);
  return builder.sign(key.privateKey);
}

/** Build the JWKS document a hub would expose at /.well-known/jwks.json. */
export function jwksFor(...keys: TestKey[]): { keys: JWK[] } {
  return { keys: keys.map((k) => k.jwk) };
}
