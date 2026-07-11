// Type definitions for @dynamicfeed/verify — DF-VERIFY/1 reference verifier.
// https://dynamicfeed.ai/standard

export declare const DEFAULT_BASE: string;
export declare const COMPILED_MIN_REGISTRY_REVISION: number;

export interface VerifyResult {
  /** true iff signature mathematics, key binding, and lifecycle policy all pass. */
  ok: boolean;
  /** Ed25519 validity over the matched canonical signed scope, independent of lifecycle. */
  cryptoValid?: boolean;
  keyBindingValid?: boolean;
  /** Whether the key is accepted by the supplied/fetched lifecycle registry. */
  signerAccepted?: boolean;
  lifecycleStatus?: "active" | "retired" | "compromised" | "unknown";
  lifecycle?: { status: string; accepted: boolean; reason: string; compromisedAfter?: string };
  trustBasis?: "current-domain" | "caller-configured-network-origin" | "out-of-band" | "key-bytes-only";
  policyAsOfAccepted?: boolean;
  mode?: "live" | "historical_snapshot";
  historicalSnapshot?: boolean;
  registryRevision?: number | null;
  effectiveRegistryFloor?: number;
  registrySource?: "current-domain-https" | "caller-configured-network-origin" | "out-of-band" | "key-bytes-only";
  /** Explicitly assert that caller-supplied/custom-origin registry material was authenticated. */
  registrySourceAuthenticated?: boolean;
  rollbackProtected?: boolean;
  /** true when an anchor was signed, false for legacy post-signature attachment, null without one. */
  anchorAuthenticated?: boolean | null;
  /** present when ok=false: why verification failed. */
  error?: string;
  keyId?: string;
  alg?: string;
  /** the canonicalization named in the signature block (e.g. "json-sorted-compact"). */
  canon?: string;
  /** true if signed with a demo/ephemeral key (will not verify after issuer restart). */
  ephemeral?: boolean;
  /** the verdict status (awareness/v1 profile), if present. */
  verdict?: string | null;
  snapshot?: string;
}

export interface VerifyOptions {
  /** base URL to fetch the no-store lifecycle registry from (default https://dynamicfeed.ai). */
  base?: string;
  /** Legacy flat key map: reports cryptoValid but cannot make ok=true without lifecycle policy. */
  jwks?: Record<string, string>;
  /** Supply an out-of-band pinned df-signing-key-registry/v1 document for offline policy. */
  lifecycleRegistry?: object;
  verificationMode?: "live" | "historical_snapshot";
  minimumRegistryRevision?: number;
  highestAuthenticatedRegistryRevision?: number;
  registrySourceAuthenticated?: boolean;
}

export declare function validateLifecycleRegistry(registry: object, opts?: VerifyOptions): Promise<object>;

/** The exact bytes that were signed: the response minus its `signature`, json-sorted-compact. */
export declare function canonical(input: string | object): string;

/** Verify a DF-VERIFY/1 signed response. Pass the RAW response text for byte-fidelity. */
export declare function verify(input: string | object, opts?: VerifyOptions): Promise<VerifyResult>;

/** Fetch a fresh signed awareness verdict and verify it. */
export declare function verifyLive(
  base?: string,
  body?: object
): Promise<{ text: string; result: VerifyResult }>;
