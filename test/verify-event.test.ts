/**
 * verifyEvent — checking a push notice from the hub.
 *
 * Real Ed25519 signatures in the hub's exact notice format (RFC 8417
 * Security Event Token, typ=secevent+jwt). Only the JWKS fetch is mocked,
 * through the SDK's own `fetch` option.
 */
import { describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';

import { Claw, EVENT_URI_BASE } from '../src/client.js';
import { makeHubKey, mintClaw, jwksFor, type TestKey } from './helpers.js';

const HUB = 'http://hub.test';

function clawWith(...keys: TestKey[]): { claw: Claw; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify(jwksFor(...keys)), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;
  return { claw: new Claw({ hubUrl: HUB, fetch: fetchImpl }), calls };
}

interface NoticeOpts {
  event?: string;
  data?: Record<string, unknown>;
  events?: Record<string, unknown>;
  aud?: string;
  iat?: number;
  typ?: string;
  kid?: string;
  iss?: string;
}

async function notice(key: TestKey, o: NoticeOpts = {}): Promise<string> {
  const now = o.iat ?? Math.floor(Date.now() / 1000);
  const events = o.events ?? {
    [EVENT_URI_BASE + (o.event ?? 'claw.revoked')]: o.data ?? { claw_jti: 'clw_1', cause: 'owner' },
  };
  return new SignJWT({ events, toe: now })
    .setProtectedHeader({ alg: 'EdDSA', kid: o.kid ?? key.kid, typ: o.typ ?? 'secevent+jwt' })
    .setIssuer(o.iss ?? 'claw-hub')
    .setIssuedAt(now)
    .setJti('evt_' + 'a'.repeat(32))
    .setAudience(o.aud ?? 'tnt_vendor')
    .sign(key.privateKey);
}

describe('verifyEvent', () => {
  it('accepts a valid notice', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const r = await claw.verifyEvent(await notice(key), { audience: 'tnt_vendor' });
    expect(r.valid).toBe(true);
    expect(r.eventType).toBe('claw.revoked');
    expect(r.eventId).toBe('evt_' + 'a'.repeat(32));
    expect(r.data).toEqual({ claw_jti: 'clw_1', cause: 'owner' });
    expect(r.audience).toBe('tnt_vendor');
  });

  it('accepts a Uint8Array body with trailing whitespace', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const body = new TextEncoder().encode(
      (await notice(key, { event: 'hold.created', data: { hold_id: 'hld_1' } })) + '\n',
    );
    const r = await claw.verifyEvent(body);
    expect(r.valid).toBe(true);
    expect(r.eventType).toBe('hold.created');
  });

  it('refuses a Claw presented as a notice', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const r = await claw.verifyEvent(await mintClaw(key));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/wrong typ/);
  });

  it('refuses a notice signed by another key', async () => {
    const key = await makeHubKey();
    const attacker = await makeHubKey(); // same kid, different key
    const { claw } = clawWith(key);
    const r = await claw.verifyEvent(await notice(attacker));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/invalid notice/);
  });

  it('refuses a tampered payload', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const [h, , s] = (await notice(key)).split('.');
    const forged = Buffer.from(JSON.stringify({
      iss: 'claw-hub', iat: Math.floor(Date.now() / 1000), jti: 'evt_x', aud: 'tnt_vendor',
      events: { [EVENT_URI_BASE + 'claw.revoked']: { claw_jti: 'clw_someone_else' } },
    })).toString('base64url');
    expect((await claw.verifyEvent(`${h}.${forged}.${s}`)).valid).toBe(false);
  });

  it('enforces the audience only when asked', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const n = await notice(key, { aud: 'tnt_other' });
    const r = await claw.verifyEvent(n, { audience: 'tnt_vendor' });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/someone else/);
    expect((await claw.verifyEvent(n)).valid).toBe(true);
  });

  it('refuses the wrong issuer', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    expect((await claw.verifyEvent(await notice(key, { iss: 'someone-else' }))).valid).toBe(false);
  });

  it('refuses an unknown kid after one refresh', async () => {
    const key = await makeHubKey('rotated-away');
    const { claw, calls } = clawWith(key);
    const r = await claw.verifyEvent(await notice(key, { kid: 'hub-1' }));
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/no key with kid/);
    expect(calls.length).toBe(2);
  });

  it('refuses non-ClawID and multi-event payloads', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    expect((await claw.verifyEvent(await notice(key, {
      events: { 'https://evil.example/events/x': {} },
    }))).reason).toMatch(/not a ClawID event/);
    expect((await claw.verifyEvent(await notice(key, {
      events: { [EVENT_URI_BASE + 'a']: {}, [EVENT_URI_BASE + 'b']: {} },
    }))).reason).toMatch(/exactly one/);
  });

  it('applies age limits', async () => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const old = await notice(key, { iat: Math.floor(Date.now() / 1000) - 3600 });
    expect((await claw.verifyEvent(old)).valid).toBe(true);
    expect((await claw.verifyEvent(old, { maxAgeSeconds: 600 })).reason).toMatch(/too old/);
    const future = await notice(key, { iat: Math.floor(Date.now() / 1000) + 3600 });
    expect((await claw.verifyEvent(future)).valid).toBe(false);
  });

  it.each(['', 'not-a-jwt', 'a.b'])('never throws on garbage (%s)', async (junk) => {
    const key = await makeHubKey();
    const { claw } = clawWith(key);
    const r = await claw.verifyEvent(junk);
    expect(r.valid).toBe(false);
    expect(r.reason).toBeTruthy();
  });
});
