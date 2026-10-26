/**
 * ClawID — Agent KYC.
 *
 * The TypeScript / JavaScript SDK for verifying Claws (the credential
 * autonomous AI agents carry to prove who they are, what their leash
 * permits, and whether the owner has revoked them).
 *
 *     import { verify } from 'clawid-sdk';
 *     const result = await verify(token);
 *     if (result.valid) console.log(result.agentId, 'owned by', result.tenantId);
 *
 * Three lines. Free forever for verifiers. No key, no contract.
 *
 * Push notices (revocations, approval requests) arrive as signed Security
 * Event Tokens; check one with `verifyEvent(body)`.
 *
 * See https://holdtheleash.id for the product,
 * https://github.com/projectblackboxllc/claw-sdk-js for the source,
 * and the README for the full API surface.
 */
export { Claw, ClawError, EVENT_URI_BASE } from './client.js';
export type {
  VerifyResult,
  VerifyStatus,
  VerifyMode,
  Leash,
  ClawOptions,
  EventResult,
  EventType,
  VerifyEventOptions,
} from './client.js';
export { verify, verifyAsync, verifyEvent } from './verify.js';

export const VERSION = '0.4.0';
