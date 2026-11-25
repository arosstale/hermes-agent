/**
 * Severity helpers.
 *
 * The kit knows five severities, from the least to the most severe:
 *
 *   info < low < medium < high < critical
 *
 * The comparison is total: every severity can be compared with every other
 * one. An unknown severity is treated as `critical` (the strictest choice,
 * so a malformed finding can never slip under a threshold) and an unknown
 * threshold is treated as `info` (the strictest choice as well: everything
 * is then at or above it).
 *
 * Signatures
 *   SEVERITY_ORDER: string[]              the severities, least to most severe
 *   severityRank(severity: string): number the rank of a severity (0..4);
 *                                      an unknown severity ranks as critical
 *   isSeverity(value: unknown): boolean   true for a known severity
 *   compareSeverity(a: string, b: string): number
 *                                      -1 when a < b, 0 when a === b, 1 when a > b
 *   atOrAbove(severity: string, threshold: string): boolean
 *                                      true when severity >= threshold
 *   strictestSeverity(a?: string, b?: string): string
 *                                      the strictest of the two (the one
 *                                      that fails on the most findings); an
 *                                      absent value is ignored, an invalid
 *                                      one counts as `info`
 */

import { SEVERITY_NAMES } from '../config/defaults.js';

/** The severities, from the least to the most severe. */
export const SEVERITY_ORDER = Object.freeze(SEVERITY_NAMES.slice());

/**
 * Tells whether a value is a known severity.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSeverity(value) {
  return typeof value === 'string' && SEVERITY_ORDER.includes(value.toLowerCase());
}

/**
 * The rank of a severity inside {@link SEVERITY_ORDER}.
 *
 * An unknown severity ranks as `critical`: a finding nobody classified must
 * not be able to hide below a threshold.
 *
 * @param {string} severity
 * @returns {number} 0 for `info` ... 4 for `critical`.
 */
export function severityRank(severity) {
  const text = typeof severity === 'string' ? severity.trim().toLowerCase() : '';
  const index = SEVERITY_ORDER.indexOf(text);
  if (index !== -1) return index;
  return SEVERITY_ORDER.length - 1;
}

/**
 * Compares two severities.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} -1 when a is less severe than b, 0 when they are equal,
 *   1 when a is more severe than b.
 */
export function compareSeverity(a, b) {
  const left = severityRank(a);
  const right = severityRank(b);
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * Tells whether a severity is at or above a threshold.
 *
 * An unknown threshold is treated as `info`, so an unknown threshold never
 * silently lets a finding through.
 *
 * @param {string} severity
 * @param {string} threshold
 * @returns {boolean}
 */
export function atOrAbove(severity, threshold) {
  const text = typeof threshold === 'string' ? threshold.trim().toLowerCase() : '';
  const limit = SEVERITY_ORDER.includes(text) ? SEVERITY_ORDER.indexOf(text) : 0;
  return severityRank(severity) >= limit;
}

/**
 * The strictest of two severities.
 *
 * The strictest severity is the one that fails on the most findings: the
 * *lower* one of the two (a `low` threshold is stricter than a `critical`
 * one, because a `low` threshold fails on every medium finding too).
 *
 * @param {string} [a]
 * @param {string} [b]
 * @returns {string} one of {@link SEVERITY_ORDER}.
 */
export function strictestSeverity(a, b) {
  const left = normalizeThreshold(a);
  const right = normalizeThreshold(b);
  if (left === null) return right === null ? 'info' : right;
  if (right === null) return left;
  return compareSeverity(left, right) <= 0 ? left : right;
}

/**
 * Normalises a threshold.
 *
 * @param {unknown} value
 * @returns {string|null} null when the value is absent, the severity itself
 *   when it is known and `info` (the strictest threshold) when it is not.
 */
function normalizeThreshold(value) {
  if (value === undefined || value === null) return null;
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (text === '') return null;
  if (SEVERITY_ORDER.includes(text)) return text;
  return 'info';
}
