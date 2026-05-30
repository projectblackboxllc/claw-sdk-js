/**
 * ClawID — the client class and result types.
 *
 * `Claw` is the configurable client object. Use it when you need to point
 * the SDK at a specific hub (self-hosted, dev, staging) or tune the JWKS
 * cache TTL. For the common case — verifying against the production
 * ClawID hub — the module-level `verify(token)` is shorter.
 *
 * Two verification modes:
 *
 *   • online (default) — validates the JWS signature offline using cached
 *     JWKS + makes a POST /v1/verify round-trip to the hub to confirm
 *     the Claw hasn't been revoked. One network call per verify, ~50ms
 *     typical. This is the right default — it gives you live revocation.
 *
 *   • offline — JWS signature + expiry only, no revocation check. Zero
 *     network calls after the JWKS cache is warm. Use when latency
 *     matters more than catching a revoke within ~30s. Suitable for very
 *     high-throughput verifiers who poll /v1/verify out of band on a
 *     schedule.
 *
 * The SDK NEVER sends a Claw it received anywhere except the configured
 * hub. The hub's signing key is in cloud KMS; this is a verify-only client.
 */

import { importJWK, jwtVerify, errors as joseErrors, type JWK, type KeyLike } from 'jose';

export const DEFAULT_HUB_URL = 'https://api.holdtheleash.id';
export const DEFAULT_JWKS_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const DEFAULT_TIMEOUT_MS = 5_000;

/** Why a verify returned the result it did. */
export type VerifyStatus =
  | 'active'   // Claw is valid and live (online mode also confirmed not revoked)
  | 'revoked'  // owner hit the kill switch
  | 'expired'  // the Claw's `exp` claim is in the past
  | 'invalid'  // signature didn't verify, malformed, unknown issuer, etc.
  | 'unknown'; // hub returned a status this SDK version doesn't recognize

/** Verify mode. `online` (default) does signature + expiry + revocation
 * check. `offline` does signature + expiry only — no network call after
 * the JWKS cache is warm. */
export type VerifyMode = 'online' | 'offline';

/** The owner-defined policy a Claw carries. Fields stay in wire-form
 * snake_case because the owner authored them and may have stored them
 * elsewhere — we don't munge user-supplied configuration. */
export interface Leash {
  spend_ceiling?: number;
  allowed_surfaces?: string[];
  active_start_hour?: number;
  active_end_hour?: number;
  escalate_over?: number | null;
  auto_revoke_off_leash?: boolean;
  [key: string]: unknown; // forward-compat for new leash params
}

/** Structured result of a verify() call.
 *
 * Always populated: `valid`, `status`. The other fields are populated
 * when the JWS itself decoded successfully — even on REVOKED / EXPIRED,
 * the structural data is trustworthy because the signature was good.
 *
 * `if (result.valid)` is the documented usage. The boolean is set iff
 * the Claw is currently usable (signature good AND not expired AND, in
 * online mode, not revoked). */
export interface VerifyResult {
  valid: boolean;
  status: VerifyStatus;
  reason?: string;
  jti?: string;
  agentId?: string;
  tenantId?: string;
  leash?: Leash;
  agentPubkeyPem?: string;
  issuedAt?: number;
  expiresAt?: number;
  /** Raw decoded JWS payload — included so callers can read custom
   * claims in future Claw versions without an SDK upgrade. */
  payload?: Record<string, unknown>;
}

/** Options for constructing a Claw client. */
export interface ClawOptions {
  /** Hub base URL. Defaults to https://api.holdtheleash.id. */
  hubUrl?: string;
  /** JWKS cache TTL in milliseconds. Defaults to 5 minutes. */
  jwksTtlMs?: number;
  /** Per-request timeout in milliseconds. Defaults to 5 seconds. */
  timeoutMs?: number;
  /** Optional custom fetch implementation (testing, polyfills, etc.). */
  fetch?: typeof fetch;
}

/** Raised only on infrastructure failures (the hub is unreachable, JWKS
 * is malformed). Verification failures — bad signature, expired,
 * revoked — do NOT throw; they return a VerifyResult with `valid=false`
 * and a `status` describing what happened. */
export class ClawError extends Error {
  override readonly name = 'ClawError';
  // ES2022 Error already has a `cause` property — passing it through
  // super() preserves stack traces and lets callers introspect the
  // underlying error.
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
  }
}

/** The verify-only client.
 *
 * Configure once at process startup; reuse for every verify. Thread-safe
 * inside Node's single-threaded event loop; the JWKS cache is held by
 * the jose RemoteJWKSet which is itself reentrant.
 *
 *     const claw = new Claw({ hubUrl: 'https://api.holdtheleash.id' });
 *     const result = await claw.verify(token);
 *     if (result.valid) { handle(result.agentId, result.tenantId); }
 */
export class Claw {
  readonly hubUrl: string;
  readonly jwksTtlMs: number;
  readonly timeoutMs: number;
  readonly #fetch: typeof fetch;
  // We manage the JWKS cache ourselves rather than using jose's
  // createRemoteJWKSet so the SDK's custom fetch option (and undici's
  // global dispatcher in tests) is honored consistently for every HTTP
  // call. The cache shape mirrors the Python SDK's _JwksEntry.
  #jwksCache: { keys: JWK[]; fetchedAt: number } | null = null;
  // Pending fetch promise — coalesce concurrent first-time verifies so
  // they share one network round-trip instead of stampeding the hub.
  #jwksInFlight: Promise<JWK[]> | null = null;

  constructor(opts: ClawOptions = {}) {
    this.hubUrl = (opts.hubUrl ?? DEFAULT_HUB_URL).replace(/\/$/, '');
    this.jwksTtlMs = opts.jwksTtlMs ?? DEFAULT_JWKS_TTL_MS;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#fetch = opts.fetch ?? fetch;
  }

  /** Verify a Claw. Returns a VerifyResult; never throws on verify
   * failures. Throws `ClawError` only on infrastructure problems (hub
   * unreachable when mode='online' and JWKS not cached, etc.).
   *
   * @param token  The Claw — a compact-form EdDSA JWS issued by the hub.
   * @param mode   `'online'` (default) checks signature + expiry +
   *               revocation. `'offline'` checks signature + expiry
   *               only; no network call after JWKS is cached.
   */
  async verify(token: string, mode: VerifyMode = 'online'): Promise<VerifyResult> {
    // 1. JWS signature + expiry — same path in both modes.
    const decoded = await this.#verifyJws(token);
    if (!decoded.ok) return decoded.result;

    // 2. Live revocation check — only in online mode.
    if (mode === 'online') {
      return this.#checkRevocation(token, decoded.payload);
    }
    return this.#successResult(decoded.payload, 'active',
      'signature + expiry valid (offline mode)');
  }

  /** Force a fresh JWKS fetch on the next verify. Useful when you know
   * a key rotation just happened and don't want to wait for the TTL to
   * expire. */
  jwksCacheClear(): void {
    this.#jwksCache = null;
    this.#jwksInFlight = null;
  }

  /** Test / introspection accessor — returns the cached JWKS state so
   * tests can assert cache hit/miss by object identity. Not part of the
   * stable public API; subject to change. */
  _jwksCacheState(): { keys: JWK[]; fetchedAt: number } | null {
    return this.#jwksCache;
  }

  // ── internals ──────────────────────────────────────────────────────

  async #getJwks(): Promise<JWK[]> {
    const now = Date.now();
    if (this.#jwksCache && now - this.#jwksCache.fetchedAt < this.jwksTtlMs) {
      return this.#jwksCache.keys;
    }
    // Coalesce stampedes: if a fetch is already in flight, everyone awaits
    // the same promise.
    if (this.#jwksInFlight) return this.#jwksInFlight;
    this.#jwksInFlight = this.#fetchJwks();
    try {
      const keys = await this.#jwksInFlight;
      this.#jwksCache = { keys, fetchedAt: Date.now() };
      return keys;
    } finally {
      this.#jwksInFlight = null;
    }
  }

  async #fetchJwks(): Promise<JWK[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.#fetch(`${this.hubUrl}/.well-known/jwks.json`, {
        signal: controller.signal,
      });
      if (!res.ok) {
        // If we have a stale cache, prefer it over throwing — stale is
        // better than dead. Matches the Python SDK's posture.
        if (this.#jwksCache) return this.#jwksCache.keys;
        throw new ClawError(`JWKS fetch returned ${res.status}`);
      }
      const body = (await res.json()) as { keys?: JWK[] };
      if (!Array.isArray(body.keys)) {
        throw new ClawError('JWKS response missing "keys" array');
      }
      return body.keys;
    } catch (e) {
      if (e instanceof ClawError) throw e;
      if (this.#jwksCache) return this.#jwksCache.keys;
      throw new ClawError(
        `could not fetch JWKS from ${this.hubUrl}: ${(e as Error).message}`,
        e,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  async #verifyJws(token: string): Promise<DecodedOrError> {
    // 1. Decode header to find the kid — we need to know which key to
    //    use before we can verify.
    let kid: string | undefined;
    try {
      const headerB64 = token.split('.')[0];
      if (!headerB64) throw new Error('not a JWS');
      const headerJson = Buffer.from(headerB64, 'base64url').toString('utf-8');
      const header = JSON.parse(headerJson) as { kid?: string; alg?: string };
      kid = header.kid;
    } catch {
      return {
        ok: false,
        result: {
          valid: false,
          status: 'invalid',
          reason: 'malformed token: could not decode header',
        },
      };
    }
    if (!kid) {
      return {
        ok: false,
        result: {
          valid: false,
          status: 'invalid',
          reason: "token missing 'kid' header — no way to select a key",
        },
      };
    }

    // 2. Look up the matching JWK. One retry with a forced refresh
    //    handles a hub key rotation that landed after our cache TTL
    //    started.
    let keys: JWK[];
    try {
      keys = await this.#getJwks();
    } catch (e) {
      throw e instanceof ClawError ? e : new ClawError(
        `JWKS fetch failed: ${(e as Error).message}`, e,
      );
    }
    let jwk = keys.find((k) => k.kid === kid);
    if (!jwk) {
      this.jwksCacheClear();
      try {
        keys = await this.#getJwks();
      } catch (e) {
        throw e instanceof ClawError ? e : new ClawError(
          `JWKS refresh failed: ${(e as Error).message}`, e,
        );
      }
      jwk = keys.find((k) => k.kid === kid);
    }
    if (!jwk) {
      return {
        ok: false,
        result: {
          valid: false,
          status: 'invalid',
          reason: `no key with kid=${JSON.stringify(kid)} in hub JWKS`,
        },
      };
    }

    // 3. Import the public key and verify the signature + claims.
    let publicKey: KeyLike | Uint8Array;
    try {
      publicKey = await importJWK(jwk, 'EdDSA');
    } catch (e) {
      return {
        ok: false,
        result: {
          valid: false,
          status: 'invalid',
          reason: `could not load hub public key: ${(e as Error).message}`,
        },
      };
    }

    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(token, publicKey, {
        issuer: 'claw-hub',
        algorithms: ['EdDSA'],
        requiredClaims: ['exp', 'iss', 'sub', 'jti'],
      });
      payload = result.payload as Record<string, unknown>;
    } catch (e) {
      if (e instanceof joseErrors.JWTExpired) {
        return {
          ok: false,
          result: { valid: false, status: 'expired', reason: 'token expired' },
        };
      }
      if (e instanceof joseErrors.JOSEError) {
        // Any jose-class error at this point is a token problem (bad
        // signature, claim validation, etc.). Infra problems would have
        // surfaced in the JWKS fetch above and been thrown as ClawError.
        return {
          ok: false,
          result: {
            valid: false,
            status: 'invalid',
            reason: `invalid token: ${(e as Error).message}`,
          },
        };
      }
      throw new ClawError(
        `signature verify failed: ${(e as Error).message}`,
        e,
      );
    }
    return { ok: true, payload };
  }

  async #checkRevocation(
    token: string,
    payload: Record<string, unknown>,
  ): Promise<VerifyResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let body: Record<string, unknown>;
    try {
      const res = await this.#fetch(`${this.hubUrl}/v1/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new ClawError(`revocation check returned ${res.status}`);
      }
      body = (await res.json()) as Record<string, unknown>;
    } catch (e) {
      if (e instanceof ClawError) throw e;
      throw new ClawError(`revocation check failed: ${(e as Error).message}`, e);
    } finally {
      clearTimeout(timer);
    }
    return resultFromHubBody(body, payload);
  }

  #successResult(
    payload: Record<string, unknown>,
    status: VerifyStatus,
    reason?: string,
  ): VerifyResult {
    return {
      valid: status === 'active',
      status,
      reason,
      jti: payload['jti'] as string | undefined,
      agentId: payload['sub'] as string | undefined,
      tenantId: payload['tenant'] as string | undefined,
      leash: payload['leash'] as Leash | undefined,
      agentPubkeyPem: (payload['cnf'] as { agent_pub?: string } | undefined)
        ?.agent_pub,
      issuedAt: payload['iat'] as number | undefined,
      expiresAt: payload['exp'] as number | undefined,
      payload,
    };
  }
}

// ── helpers (module-private) ──────────────────────────────────────────

type DecodedOrError =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; result: VerifyResult };

function coerceStatus(s: unknown): VerifyStatus {
  if (typeof s !== 'string') return 'unknown';
  const known: VerifyStatus[] = ['active', 'revoked', 'expired', 'invalid'];
  return (known as string[]).includes(s.toLowerCase())
    ? (s.toLowerCase() as VerifyStatus)
    : 'unknown';
}

function resultFromHubBody(
  body: Record<string, unknown>,
  payload: Record<string, unknown>,
): VerifyResult {
  const cnf = payload['cnf'] as { agent_pub?: string } | undefined;
  return {
    valid: Boolean(body['valid']),
    status: coerceStatus(body['status']),
    reason: body['reason'] as string | undefined,
    jti: (body['jti'] ?? payload['jti']) as string | undefined,
    agentId: (body['agent_id'] ?? payload['sub']) as string | undefined,
    tenantId: (body['tenant_id'] ?? payload['tenant']) as string | undefined,
    leash: (body['leash'] ?? payload['leash']) as Leash | undefined,
    agentPubkeyPem: (body['agent_pubkey_pem'] ?? cnf?.agent_pub) as
      | string
      | undefined,
    issuedAt: (body['issued_at'] ?? payload['iat']) as number | undefined,
    expiresAt: (body['expires_at'] ?? payload['exp']) as number | undefined,
    payload,
  };
}
