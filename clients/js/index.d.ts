// Type definitions for @dynamicfeed/verify — DF-VERIFY/1 reference verifier.
// https://dynamicfeed.ai/standard

export declare const DEFAULT_BASE: string;

export interface VerifyResult {
  /** true iff the Ed25519 signature is authentic over the canonical payload. */
  ok: boolean;
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
  /** base URL to fetch the public key set from (default https://dynamicfeed.ai). */
  base?: string;
  /** supply a JWKS map (key_id → base64url public key) to verify fully offline. */
  jwks?: Record<string, string>;
}

/** The exact bytes that were signed: the response minus its `signature`, json-sorted-compact. */
export declare function canonical(input: string | object): string;

/** Verify a DF-VERIFY/1 signed response. Pass the RAW response text for byte-fidelity. */
export declare function verify(input: string | object, opts?: VerifyOptions): Promise<VerifyResult>;

/** Fetch a fresh signed awareness verdict and verify it. */
export declare function verifyLive(
  base?: string,
  body?: object
): Promise<{ text: string; result: VerifyResult }>;
