/**
 * Stable identifiers for findings.
 *
 * A finding id must survive a reordering of the findings and a re-run of the
 * scan: it is derived from the rule id and from the *fingerprint* of the
 * matched material, never from the material itself and never from the
 * position of the finding in the report.
 */

import { createHash } from 'node:crypto';

/**
 * Separator between the rule id and the fingerprint inside the digest.
 * A NUL byte cannot appear in a rule id, so the pair cannot be forged by
 * moving characters between the two fields.
 */
const SEP = String.fromCharCode(0);

/**
 * SHA-256 of a string, lowercase hex.
 *
 * @param {string} input
 * @returns {string} 64 lowercase hex characters.
 */
export function sha256Hex(input) {
  const hash = createHash('sha256');
  hash.update(typeof input === 'string' ? input : String(input ?? ''), 'utf8');
  return hash.digest('hex');
}

/**
 * Identifier of a finding: `"f-" + 12 hex characters`.
 *
 * The rule id and the fingerprint are joined with a NUL separator so that
 * `("ab", "c")` and `("a", "bc")` cannot collide.
 *
 * @param {string} ruleId
 * @param {string} fingerprint
 * @returns {string} e.g. `f-9c1d2e3f4a5b`
 */
export function findingId(ruleId, fingerprint) {
  const rule = typeof ruleId === 'string' ? ruleId : String(ruleId ?? '');
  const print = typeof fingerprint === 'string' ? fingerprint : String(fingerprint ?? '');
  return `f-${sha256Hex(`${rule}${SEP}${print}`).slice(0, 12)}`;
}

/**
 * Short, stable digest of any text: the first 12 hex characters of its
 * SHA-256. Used by the artefacts that need a compact, content derived id
 * (scan ids, serial numbers, snapshot digests).
 *
 * @param {string} input
 * @returns {string} 12 lowercase hex characters.
 */
export function shortHex(input) {
  return sha256Hex(input).slice(0, 12);
}
