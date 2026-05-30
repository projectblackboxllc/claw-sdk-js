/**
 * End-to-end verify tests using real EdDSA crypto + mocked HTTP.
 *
 * For each test we:
 *   1. Generate an Ed25519 keypair (the "hub" signing key).
 *   2. Mint a Claw signed with the private half.
 *   3. Stand up an undici MockAgent that responds to:
 *        GET /.well-known/jwks.json    → the public JWK
 *        POST /v1/verify               → a programmable response
 *   4. Construct the SDK with fetch wired to the MockAgent's dispatcher.
 *   5. Verify the Claw and assert on the result.
 *
 * No mock crypto. The SDK is exercised against the same JWS bytes a
 * production hub would emit. The HTTP boundary is the only thing mocked.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  MockAgent,
  setGlobalDispatcher,
  getGlobalDispatcher,
  type Dispatcher,
  type Interceptable,
} from 'undici';

import { Claw, ClawError, type VerifyStatus } from '../src/client.js';
import { setDefaultClient, verify } from '../src/verify.js';
import { makeHubKey, mintClaw, jwksFor, type TestKey } from './helpers.js';

const HUB = 'http://hub.test';

let mock: MockAgent;
let pool: Interceptable;
let key: TestKey;
let claw: Claw;
let originalDispatcher: Dispatcher;

beforeEach(async () => {
  // Swap undici's global dispatcher so EVERY fetch call (the SDK's own
  // POST /v1/verify AND jose's internal RemoteJWKSet GET) routes
  // through the mock. setGlobalDispatcher is the standard way to mock
  // undici-based fetch in Node 18+.
  originalDispatcher = getGlobalDispatcher();
  mock = new MockAgent();
  mock.disableNetConnect();
  setGlobalDispatcher(mock);
  pool = mock.get(HUB);

  key = await makeHubKey();
  claw = new Claw({ hubUrl: HUB });
});

afterEach(async () => {
  await mock.close();
  setGlobalDispatcher(originalDispatcher);
  setDefaultClient(null);
});

function expectJwksFetch(): void {
  pool
    .intercept({ path: '/.well-known/jwks.json', method: 'GET' })
    .reply(200, jwksFor(key), { headers: { 'content-type': 'application/json' } })
    .persist(); // jose's RemoteJWKSet may re-fetch; allow repeats
}

function expectVerifyHit(body: Record<string, unknown>): void {
  pool
    .intercept({ path: '/v1/verify', method: 'POST' })
    .reply(200, body, { headers: { 'content-type': 'application/json' } });
}

// ── happy path ──────────────────────────────────────────────────────

describe('verify — active Claw', () => {
  it('returns valid=true and structural fields populated', async () => {
    expectJwksFetch();
    expectVerifyHit({
      valid: true,
      status: 'active',
      agent_id: 'agt_test',
      tenant_id: 'tnt_test',
      jti: 'clw_test',
      issued_at: 1700000000,
      expires_at: 9999999999,
    });
    const token = await mintClaw(key);

    const result = await claw.verify(token);
    expect(result.valid).toBe(true);
    expect(result.status).toBe<VerifyStatus>('active');
    expect(result.agentId).toBe('agt_test');
    expect(result.tenantId).toBe('tnt_test');
    expect(result.jti).toBe('clw_test');
    expect(result.leash?.['spend_ceiling']).toBe(100);
    expect(result.leash?.['allowed_surfaces']).toContain('stripe.com');
  });

  it('module-level verify() uses the configured default client', async () => {
    expectJwksFetch();
    expectVerifyHit({ valid: true, status: 'active' });
    setDefaultClient(claw);

    const token = await mintClaw(key);
    const result = await verify(token);
    expect(result.valid).toBe(true);
  });
});

// ── lifecycle: revoked ─────────────────────────────────────────────

describe('verify — revoked Claw', () => {
  it('returns valid=false, status=revoked, structural fields still present', async () => {
    expectJwksFetch();
    expectVerifyHit({
      valid: false,
      status: 'revoked',
      reason: 'token revoked',
      agent_id: 'agt_test',
      tenant_id: 'tnt_test',
    });
    const token = await mintClaw(key);

    const result = await claw.verify(token);
    expect(result.valid).toBe(false);
    expect(result.status).toBe<VerifyStatus>('revoked');
    expect(result.reason).toBe('token revoked');
    // Structural fields survive — signature was good
    expect(result.agentId).toBe('agt_test');
  });
});

// ── lifecycle: expired ─────────────────────────────────────────────

describe('verify — expired Claw', () => {
  it('catches expiry at the JWS layer, never even calls /v1/verify', async () => {
    expectJwksFetch();
    // Intentionally DO NOT register /v1/verify — expired tokens are
    // rejected by jose before we get there. If the SDK called /verify
    // anyway, MockAgent would throw (disableNetConnect).
    const token = await mintClaw(key, { expSecondsFromNow: -10 });

    const result = await claw.verify(token);
    expect(result.valid).toBe(false);
    expect(result.status).toBe<VerifyStatus>('expired');
  });
});

// ── lifecycle: malformed ───────────────────────────────────────────

describe('verify — malformed token', () => {
  it('returns valid=false, status=invalid for garbage input', async () => {
    expectJwksFetch();
    const result = await claw.verify('not.even.close');
    expect(result.valid).toBe(false);
    expect(result.status).toBe<VerifyStatus>('invalid');
  });

  it('returns valid=false, status=invalid when the kid is missing', async () => {
    expectJwksFetch();
    const token = await mintClaw(key, { omitKid: true });
    const result = await claw.verify(token);
    expect(result.valid).toBe(false);
    expect(result.status).toBe<VerifyStatus>('invalid');
  });

  it('returns valid=false, status=invalid when no key matches the kid', async () => {
    expectJwksFetch();
    // Mint a token signed by a key whose kid the hub never advertises.
    const otherKey = await makeHubKey('rotated-out');
    const token = await mintClaw(otherKey);
    const result = await claw.verify(token);
    expect(result.valid).toBe(false);
    expect(result.status).toBe<VerifyStatus>('invalid');
  });
});

// ── offline mode ───────────────────────────────────────────────────

describe('verify — offline mode', () => {
  it('checks signature + expiry only, skips revocation', async () => {
    expectJwksFetch();
    // No /v1/verify expectation — offline must not hit it.
    const token = await mintClaw(key);
    const result = await claw.verify(token, 'offline');
    expect(result.valid).toBe(true);
    expect(result.status).toBe<VerifyStatus>('active');
    expect(result.reason).toMatch(/offline/);
  });
});

// ── infra errors ───────────────────────────────────────────────────

describe('verify — infrastructure failures', () => {
  it('throws ClawError when the hub returns 500 on /v1/verify', async () => {
    expectJwksFetch();
    pool
      .intercept({ path: '/v1/verify', method: 'POST' })
      .reply(500, 'oops', { headers: { 'content-type': 'text/plain' } });
    const token = await mintClaw(key);

    await expect(claw.verify(token)).rejects.toBeInstanceOf(ClawError);
  });
});

// ── async API symmetry ─────────────────────────────────────────────

describe('verify — async surface', () => {
  it('verify is already async — no separate verifyAsync needed', async () => {
    expectJwksFetch();
    expectVerifyHit({ valid: true, status: 'active', agent_id: 'agt_test' });
    setDefaultClient(claw);
    const token = await mintClaw(key);
    const { verifyAsync } = await import('../src/verify.js');
    const result = await verifyAsync(token);
    expect(result.valid).toBe(true);
    expect(result.agentId).toBe('agt_test');
  });
});
