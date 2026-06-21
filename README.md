<p align="center">
  <img src="https://holdtheleash.id/crab-claw-mark.png" width="120" alt="ClawID" />
</p>

<h1 align="center">clawid-sdk</h1>

<p align="center"><strong>Agent KYC. Verify autonomous AI agent credentials in three lines.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/clawid-sdk"><img src="https://img.shields.io/npm/v/clawid-sdk.svg" alt="npm" /></a>
  <a href="https://github.com/projectblackboxllc/claw-sdk-js/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <img src="https://img.shields.io/badge/node-%E2%89%A518-blue.svg" alt="Node 18+" />
  <img src="https://img.shields.io/badge/types-included-blue.svg" alt="TypeScript types included" />
</p>

---

```ts
import { verify } from 'clawid-sdk';

const result = await verify(token);
if (result.valid) {
  console.log(result.agentId, 'owned by', result.tenantId);
}
```

That's it. Three lines. **Free forever for verifiers.** No key, no contract.

## What is this?

ClawID is the trust layer for autonomous AI agents and the services they touch. Every agent
carries a **Claw** — a cryptographically signed credential that binds the agent to its
owner, declares the owner's policy (the **leash**), and produces a tamper-evident receipt
of every action. This SDK is what services use to verify a Claw on the way in.

When an AI agent calls your API, you want to know:

- **Who's behind it?** → `result.tenantId`, `result.agentId`
- **What did the owner permit?** → `result.leash`
- **Can the owner kill it?** → yes; `result.status` reflects current revocation state
- **Is there a record of the attempt?** → yes; every check-in lands in a hash-chained audit log on both sides

One round-trip, four answers. Free forever for verifiers.

## Install

```bash
npm install clawid-sdk
# or
pnpm add clawid-sdk
# or
yarn add clawid-sdk
```

Node 18+ (native `fetch`). One runtime dependency: [`jose`](https://github.com/panva/jose).
Ships dual ESM + CJS with TypeScript types included.

## Use

### The common case

```ts
import { verify } from 'clawid-sdk';

const result = await verify(token);

if (!result.valid) {
  return reject(result.status, result.reason);
}

// Now you know who this is.
console.log(`Agent ${result.agentId} owned by ${result.tenantId}`);
console.log(`Leash:`, result.leash);
```

### When you want to configure things

```ts
import { Claw } from 'clawid-sdk';

const claw = new Claw({
  hubUrl: 'https://api.holdtheleash.id',  // defaults to this
  jwksTtlMs: 5 * 60 * 1000,                // cache the hub's pubkey for 5 minutes
  timeoutMs: 5_000,                         // per-request timeout
});

const result = await claw.verify(token);
```

### Offline mode (signature + expiry only, no live revocation check)

```ts
const result = await verify(token, 'offline');
```

Use when latency matters more than catching a revoke within ~30s. The signature check
still uses the cached JWKS, so it's accurate; you just won't see a revoke immediately.
Suited for very high-throughput verifiers who poll `/v1/verify` on a schedule out of band.

### Web-framework integration

The SDK is framework-agnostic by design. An **Express** middleware looks like:

```ts
import express from 'express';
import { verify, type VerifyResult } from 'clawid-sdk';

declare global {
  namespace Express {
    interface Request { claw?: VerifyResult }
  }
}

const app = express();

app.use(async (req, res, next) => {
  const auth = req.header('Authorization') ?? '';
  const token = auth.replace(/^Bearer\s+/, '').trim();
  if (!token) return res.status(401).json({ error: 'missing Claw' });
  const result = await verify(token);
  if (!result.valid) {
    return res.status(401).json({ error: `${result.status}: ${result.reason}` });
  }
  req.claw = result;
  next();
});

app.post('/charge', (req, res) => {
  const amount = Number(req.body.amount);
  if (amount > (req.claw!.leash?.spend_ceiling ?? 0)) {
    return res.status(403).json({ error: 'amount exceeds agent\'s leash' });
  }
  res.json({ agentId: req.claw!.agentId, charged: amount });
});
```

For **Hono**:

```ts
import { Hono } from 'hono';
import { verify } from 'clawid-sdk';

const app = new Hono();

app.use('*', async (c, next) => {
  const token = (c.req.header('Authorization') ?? '').replace(/^Bearer\s+/, '');
  const result = await verify(token);
  if (!result.valid) return c.json({ error: result.reason }, 401);
  c.set('claw', result);
  await next();
});
```

## What the result tells you

`VerifyResult` is a fully-typed interface. The boolean `result.valid` is what you check.

```ts
interface VerifyResult {
  valid: boolean;                  // true iff the Claw is currently usable
  status: VerifyStatus;            // 'active' | 'revoked' | 'expired' | 'invalid' | 'unknown'
  reason?: string;                 // human-readable reason
  jti?: string;                    // JWT id of this Claw (stable receipt key)
  agentId?: string;                // who the agent is
  tenantId?: string;               // who owns the agent
  leash?: Leash;                   // the owner's policy
  agentPubkeyPem?: string;         // for proof-of-possession on signed actions
  issuedAt?: number;
  expiresAt?: number;
  payload?: Record<string, unknown>;  // raw decoded JWS, for custom claims
}
```

`VerifyStatus`:

| Status | Means |
|---|---|
| `'active'` | Claw is valid and live; owner has not revoked it. |
| `'revoked'` | Owner hit the kill switch. Deny the request. |
| `'expired'` | The `exp` claim is in the past. Agent needs a fresh Claw. |
| `'invalid'` | Signature didn't verify, malformed, unknown issuer, etc. |
| `'unknown'` | Hub returned a status this SDK version doesn't recognize. Treat as `'invalid'`. |

## What's the leash?

```ts
result.leash
// {
//   spend_ceiling: 50.0,
//   allowed_surfaces: ['stripe.com', 'openai.com'],
//   active_start_hour: 9,
//   active_end_hour: 17,
//   escalate_over: 25.0,
//   auto_revoke_off_leash: true,
// }
```

You can use the leash to short-circuit policy decisions on your side — for example,
refuse the request if `amount > leash.spend_ceiling` before doing any expensive work.

Leash field names stay in snake_case to match the wire format the owner authored. The
SDK-level fields (`agentId`, `tenantId`, `agentPubkeyPem`) use TypeScript camelCase
convention; the leash is the user's data and we don't munge it.

## How the verify path works

```
                          verify(token)
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
       Offline (JWS)                       Online (revocation)
       │                                   │
       1. Fetch JWKS from                  1. POST /v1/verify
          /.well-known/jwks.json              with the token
          (cached for jwksTtlMs)           2. Hub responds with
       2. Verify EdDSA signature              live revocation status
          (jose)                              + structural detail
       3. Check exp / iss / required
          claims

       If signature is bad → 'invalid'
       If exp in past      → 'expired'
       Otherwise:                          status: 'active' | 'revoked'
       online mode → run the right path
       offline mode → return 'active'
```

The hub's signing key is in cloud KMS. We never see your verify traffic if you stay in
offline mode after the first JWKS fetch.

## Errors

`ClawError` is thrown only for infrastructure problems (the hub is unreachable, JWKS is
malformed). Verification failures — bad signature, expired, revoked — never throw; they
return a `VerifyResult` with `valid=false` and a `status` that describes what happened.

```ts
import { verify, ClawError } from 'clawid-sdk';

try {
  const result = await verify(token);
  if (!result.valid) {
    return rejectWith401(result.status, result.reason);
  }
  // ... use result
} catch (e) {
  if (e instanceof ClawError) {
    // Hub is down or JWKS is unreachable. Decide based on your trust
    // posture — typically: fail closed.
    return rejectWith503(e.message);
  }
  throw e;
}
```

## Vendor onboarding

Verification is permissionless. You don't need a key, an account, or a contract to call
`verify(token)`. **It's free forever.** That's the whole network effect.

If you want to appear in the [Verified Vendors directory](https://holdtheleash.id) — and
get the matching audit-chain visibility on your side of every check-in to your domain —
apply at [holdtheleash.id/vendors](https://holdtheleash.id) (KYB-gated: entity + domain
ownership + live service + signed TOS). Listing is free; promotional placement is a
separate paid surface.

## TypeScript

Types are included in the package; no separate `@types/` install needed.

```ts
import type {
  VerifyResult,
  VerifyStatus,
  VerifyMode,
  Leash,
  ClawOptions,
} from 'clawid-sdk';
```

## Versioning

`clawid-sdk` follows [SemVer](https://semver.org/). The `VerifyResult` shape is stable
within a major; new optional fields are minor; field removals or behavior changes are
major. `payload` always carries the full decoded JWS for forward-compatibility with new
claims.

## License

[Apache License 2.0](LICENSE). Copyright © 2026 Project Black Box LLC.

## Links

- **Product**: [holdtheleash.id](https://holdtheleash.id)
- **Dashboard**: [app.holdtheleash.id](https://app.holdtheleash.id)
- **Issues**: [github.com/projectblackboxllc/claw-sdk-js/issues](https://github.com/projectblackboxllc/claw-sdk-js/issues)
- **Python SDK**: [github.com/projectblackboxllc/claw-sdk-python](https://github.com/projectblackboxllc/claw-sdk-python)
- **Spec**: [github.com/projectblackboxllc/claw-spec](https://github.com/projectblackboxllc/claw-spec) *(coming next)*
