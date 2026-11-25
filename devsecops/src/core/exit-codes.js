/**
 * Exit codes of the kit (plan section E).
 *
 *   0 - PASS     the gate passed / no finding at or above the threshold
 *   1 - FINDINGS a policy violation or a finding at/above `--fail-on`
 *   2 - ERROR    a tool or configuration error (bad YAML, bad policy, unknown
 *                 command or flag, unreadable config, internal error)
 *
 * The mapping is frozen: every layer of the kit returns one of these three
 * numbers and nothing else.
 */
export const EXIT = Object.freeze({
  PASS: 0,
  FINDINGS: 1,
  ERROR: 2,
});

/** Ordered list of the exit codes, useful for documentation and tests. */
export const EXIT_VALUES = Object.freeze([EXIT.PASS, EXIT.FINDINGS, EXIT.ERROR]);
