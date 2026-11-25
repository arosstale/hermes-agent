/**
 * Redaction by construction.
 *
 * This module is the only place in the kit where a value that looks like a
 * credential is allowed to exist. Every function exported here is built so
 * that the raw value can never leave:
 *
 *   - `fingerprintSecret` returns a digest, the length and (at most) the
 *     first four characters of the value;
 *   - `redactSnippet` returns the *kind* of the finding, an ellipsis and the
 *     length of the value - never a character of the value;
 *   - `redactText` replaces every occurrence of a value with a length-only
 *     placeholder.
 *
 * The invariant enforced by the tests is stronger than "we try not to leak":
 * the returned strings must not contain the value itself, nor any substring
 * of the value of five characters or more.
 */

import { sha256Hex } from './fingerprint.js';

/** Placeholder used when a value is replaced inside free text. */
const PLACEHOLDER = (length) => `<redacted len=${length}>`;

/**
 * Keeps only printable ASCII characters. A value that contains a control
 * character (a newline, a NUL, a tab) would otherwise break the one-line
 * artefacts the kit writes.
 *
 * @param {string} text
 * @returns {string}
 */
function printable(text) {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    out += code >= 0x20 && code <= 0x7e ? ch : '*';
  }
  return out;
}

/**
 * Fingerprint of a secret-bearing value.
 *
 * The result has the shape
 * `sha256:<12 lowercase hex>:len:<number of characters>:pfx:<first four characters>`.
 *
 * The digest is computed over the exact value, so two different values never
 * share a fingerprint and the same value always produces the same one - which
 * is what makes findings de-duplicable without storing the value.
 *
 * @param {string} value the raw value. It never leaves this function.
 * @returns {string} e.g. `sha256:1a2b3c4d5e6f:len:40:pfx:ghp_`
 */
export function fingerprintSecret(value) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  const digest = sha256Hex(text).slice(0, 12);
  const length = text.length;
  let prefix;
  if (length === 0) {
    prefix = '';
  } else if (length <= 4) {
    // A short value would be leaked in full by a prefix: mask it instead.
    prefix = '*'.repeat(length);
  } else {
    prefix = printable(text.slice(0, 4));
  }
  return `sha256:${digest}:len:${length}:pfx:${prefix}`;
}

/**
 * Redacted snippet of a matched value.
 *
 * The snippet names the *kind* of the finding (the rule that matched) and the
 * length of the value. It never contains a character of the value.
 *
 * @param {string} value the raw value. It never leaves this function.
 * @param {string} kind a short, non sensitive label (e.g. `github-pat`).
 * @returns {string} e.g. `github-pat…<redacted len=40>`
 */
export function redactSnippet(value, kind) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  const label = printable(typeof kind === 'string' ? kind : String(kind ?? '')).slice(0, 64);
  return `${label}…${PLACEHOLDER(text.length)}`;
}

/**
 * Replaces every occurrence of every given value inside a text.
 *
 * Longer values are replaced first, so that a value that contains another
 * value cannot leave a fragment of itself behind. After the replacement a
 * final pass guarantees that no value survived - not even as a fragment
 * produced by the placeholder itself.
 *
 * @param {string} text the text to redact.
 * @param {string[]} secrets the values to remove. They never appear in the result.
 * @returns {string} the redacted text.
 */
export function redactText(text, secrets) {
  const source = typeof text === 'string' ? text : String(text ?? '');
  const list = Array.isArray(secrets) ? secrets : [];
  const values = [];
  for (const item of list) {
    if (typeof item !== 'string' || item.length === 0) continue;
    if (!values.includes(item)) values.push(item);
  }
  values.sort((a, b) => b.length - a.length);

  let out = source;
  for (const value of values) {
    out = out.split(value).join(PLACEHOLDER(value.length));
  }
  // Safety net: the placeholder must not reintroduce a value.
  for (const value of values) {
    if (out.includes(value)) out = out.split(value).join('***');
  }
  return out;
}
