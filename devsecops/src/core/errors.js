/**
 * Error registry of the kit.
 *
 * Every module of the kit fails closed: a problem that is a *configuration*
 * problem is reported as a {@link KitError} carrying a stable `E_*` code, so
 * the CLI can turn it into exit code 2 without having to guess the cause.
 *
 * Rules of the road:
 *   - a KitError message must never contain a credential value; only the
 *     redacted fingerprint of a value may ever be mentioned;
 *   - runtime scan problems are findings, never errors.
 */

/**
 * Registry of the error codes used across the kit.
 * @type {Readonly<Record<string, string>>}
 */
export const ERROR_CODES = Object.freeze({
  /** Bad command line / unknown flag. */
  E_ARGS: 'E_ARGS',
  /** Generic configuration problem. */
  E_CONFIG: 'E_CONFIG',
  /** Evidence document problem. */
  E_EVIDENCE: 'E_EVIDENCE',
  /** Policy gate violation (raised only by the CLI layer). */
  E_GATE: 'E_GATE',
  /** Unexpected internal failure. */
  E_INTERNAL: 'E_INTERNAL',
  /** Filesystem access problem. */
  E_IO: 'E_IO',
  /** The security policy is invalid or unreadable. */
  E_POLICY: 'E_POLICY',
  /** A rule pack is invalid or unreadable. */
  E_RULES: 'E_RULES',
  /** A YAML document could not be parsed. */
  E_YAML: 'E_YAML',
});

/** Short alias, handy at call sites: `E.E_POLICY`. */
export const E = ERROR_CODES;

/**
 * The only error type the kit throws.
 */
export class KitError extends Error {
  /**
   * @param {string} code one of {@link ERROR_CODES} (an unknown code is kept
   *   verbatim so that a caller can still report it, but it is flagged).
   * @param {string} [message] human readable, never contains a secret value.
   * @param {object} [details] structured context (paths, rule ids, problems).
   */
  constructor(code, message, details) {
    const text = message !== undefined && message !== null && String(message).length > 0
      ? String(message)
      : `kit error${code ? ` ${code}` : ''}`;
    super(text);
    this.name = 'KitError';
    this.code = typeof code === 'string' && code.length > 0 ? code : ERROR_CODES.E_INTERNAL;
    this.knownCode = Object.prototype.hasOwnProperty.call(ERROR_CODES, this.code);
    this.details = details && typeof details === 'object' ? { ...details } : {};
    this.status = 2;
  }

  /** Serialisable form (used by the JSON report writers). */
  toJSON() {
    return { name: this.name, code: this.code, message: this.message, details: this.details };
  }
}

/**
 * Convenience predicate: `isKitError(value)`.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isKitError(value) {
  return value instanceof KitError;
}
