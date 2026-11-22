export interface TextSpanPatch {
  readonly start: number;
  readonly deleteCount: number;
  readonly insert: string;
}

export const DEFAULT_MAX_TEXT_DELTA_CHAIN_DEPTH = 32;
export const MIN_TEXT_DELTA_BYTES = 64;

function isHighSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xd800 && codeUnit <= 0xdbff;
}

function isLowSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xdc00 && codeUnit <= 0xdfff;
}

// O(N) common-prefix + common-suffix single-span patch in UTF-16 code units.
// Aligns boundaries so UTF-16 surrogate pairs are never split into lone surrogates.
export function computeSingleSpanPatch(before: string, after: string): TextSpanPatch {
  const beforeLen = before.length;
  const afterLen = after.length;
  const minLen = Math.min(beforeLen, afterLen);

  let prefix = 0;
  while (prefix < minLen && before.charCodeAt(prefix) === after.charCodeAt(prefix)) {
    prefix++;
  }
  if (prefix > 0 && isHighSurrogate(before.charCodeAt(prefix - 1))) {
    prefix--;
  }

  const maxSuffix = minLen - prefix;
  let suffix = 0;
  while (
    suffix < maxSuffix &&
    before.charCodeAt(beforeLen - 1 - suffix) === after.charCodeAt(afterLen - 1 - suffix)
  ) {
    suffix++;
  }
  if (suffix > 0 && isLowSurrogate(before.charCodeAt(beforeLen - suffix))) {
    suffix--;
  }

  return {
    start: prefix,
    deleteCount: beforeLen - prefix - suffix,
    insert: after.slice(prefix, afterLen - suffix),
  };
}

// Applies a single-span UTF-16 patch with strict bounds and surrogate-pair checks.
export function applySingleSpanPatch(before: string, patch: TextSpanPatch): string | null {
  if (
    !patch ||
    typeof patch !== 'object' ||
    typeof patch.start !== 'number' ||
    typeof patch.deleteCount !== 'number' ||
    typeof patch.insert !== 'string' ||
    !Number.isSafeInteger(patch.start) ||
    !Number.isSafeInteger(patch.deleteCount) ||
    patch.start < 0 ||
    patch.deleteCount < 0 ||
    patch.start > before.length ||
    patch.deleteCount > before.length - patch.start ||
    !patch.insert.isWellFormed()
  ) {
    return null;
  }

  const end = patch.start + patch.deleteCount;
  if (
    patch.start > 0 &&
    patch.start < before.length &&
    isHighSurrogate(before.charCodeAt(patch.start - 1)) &&
    isLowSurrogate(before.charCodeAt(patch.start))
  ) {
    return null;
  }
  if (
    end > 0 &&
    end < before.length &&
    isHighSurrogate(before.charCodeAt(end - 1)) &&
    isLowSurrogate(before.charCodeAt(end))
  ) {
    return null;
  }

  const materialized = before.slice(0, patch.start) + patch.insert + before.slice(end);
  return materialized.isWellFormed() ? materialized : null;
}

// Decides whether storing a text delta frame is worthwhile over a full keyframe.
export function shouldStoreTextPatch(
  fullText: string,
  patch: TextSpanPatch,
  chainDepth: number,
  maxChainDepth = DEFAULT_MAX_TEXT_DELTA_CHAIN_DEPTH,
): boolean {
  if (
    !Number.isSafeInteger(chainDepth) ||
    chainDepth < 0 ||
    !Number.isSafeInteger(maxChainDepth) ||
    maxChainDepth <= 0 ||
    chainDepth >= maxChainDepth
  ) {
    return false;
  }
  const fullBytes = Buffer.byteLength(fullText, 'utf8');
  if (fullBytes < MIN_TEXT_DELTA_BYTES) {
    return false;
  }
  const patchBytes = Buffer.byteLength(JSON.stringify(patch), 'utf8');
  // Strict < 60% ratio using exact integer arithmetic (patchBytes / fullBytes < 3 / 5).
  return patchBytes * 5 < fullBytes * 3;
}
