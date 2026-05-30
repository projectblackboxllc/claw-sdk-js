/**
 * Module-level conveniences — `verify(token)` and `verifyAsync(token)`.
 *
 * These wrap a process-wide default `Claw` client pointed at the
 * production hub. Use them for the common case; instantiate `new Claw(...)`
 * explicitly when you need a self-hosted hub URL, a tuned JWKS TTL, or
 * a custom fetch implementation.
 */

import { Claw, type VerifyMode, type VerifyResult } from './client.js';

let defaultClient: Claw | null = null;

/** Lazy singleton. Reads CLAW_HUB_URL from the environment if set;
 * otherwise points at the production hub at api.holdtheleash.id. */
function getDefaultClient(): Claw {
  if (defaultClient === null) {
    const hubUrl =
      (typeof process !== 'undefined' && process.env?.['CLAW_HUB_URL']) ||
      undefined;
    defaultClient = new Claw(hubUrl ? { hubUrl } : {});
  }
  return defaultClient;
}

/** Replace the default client. Used by tests and by callers who want
 * `verify(token)` to point somewhere else without constructing a Claw
 * explicitly. */
export function setDefaultClient(claw: Claw | null): void {
  defaultClient = claw;
}

/** Verify a Claw against the default hub.
 *
 *     import { verify } from '@clawid/sdk';
 *     const result = await verify(token);
 *     if (result.valid) console.log(result.agentId);
 *
 * See `Claw.verify` for argument and return-value details. */
export function verify(
  token: string,
  mode: VerifyMode = 'online',
): Promise<VerifyResult> {
  return getDefaultClient().verify(token, mode);
}

/** Alias for `verify(token)`. Kept for API symmetry with the Python SDK
 * (where `verify_async` is the explicit async variant). In JS verify is
 * already async — both names work. */
export const verifyAsync = verify;
