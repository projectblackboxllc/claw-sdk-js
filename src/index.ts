/**
 * ClawID — Agent KYC.
 *
 * The TypeScript / JavaScript SDK for verifying Claws (the credential
 * autonomous AI agents carry to prove who they are, what their leash
 * permits, and whether the owner has revoked them).
 *
 *     import { verify } from '@clawid/sdk';
 *     const result = await verify(token);
 *     if (result.valid) console.log(result.agentId, 'owned by', result.tenantId);
 *
 * Three lines. Free forever for verifiers. No key, no contract.
 *
 * See https://holdtheleash.id for the product,
 * https://github.com/projectblackboxllc/claw-sdk-js for the source,
 * and the README for the full API surface.
 */
export { Claw, ClawError } from './client.js';
export type {
  VerifyResult,
  VerifyStatus,
  VerifyMode,
  Leash,
  ClawOptions,
} from './client.js';
export { verify, verifyAsync } from './verify.js';

export const VERSION = '0.1.0';
