/**
 * Policy gate.
 *
 * The gate is the part of the kit that turns findings into a verdict. It is
 * deliberately boring and deliberately honest:
 *
 *   1. a denied path that is present is a violation;
 *      the deny list is judged against the findings, against the paths the
 *      scan really looked at (`paths`) and against the **tree** the scan
 *      root holds (`treePaths`): a denied path that no rule matches is a
 *      denied path all the same, and a path that the policy both denies
 *      and excludes is still a denied path. The deny list is a statement
 *      about the tree, not about the files the scanner happened to open;
 *   2. a severity whose count is above the policy threshold is a violation
 *      (a threshold of -1 means "unlimited");
 *   3. a finding at or above the effective fail-on threshold is a violation;
 *   4. a required evidence artefact that is missing is a violation;
 *   5. an enabled stage that produced no output is a violation;
 *   6. an enabled stage that inspected no file at all, although files were in
 *      scope, is a violation: the coverage of the scan vanished.
 *
 * Fail closed
 *   A missing or unusable policy, and a missing evidence list, never mean
 *   "pass": they produce violations and the gate fails. The gate can only be
 *   *tightened* from the outside: the effective fail-on threshold is the
 *   strictest of the policy default and the requested one, so a command line
 *   flag can never make the gate looser than the policy asks for.
 *
 * Signatures
 *   evaluateGate(input: {
 *     findings?: Finding[],     // the findings to judge
 *     policy?: object,          // the security policy
 *     evidence?: string[],      // the evidence artefacts that exist
 *     failOn?: string,          // the requested fail-on severity
 *     stages?: StageMeta[],     // optional stage metadata
 *     paths?: string[],         // optional scanned paths (deny check)
 *     treePaths?: string[],     // optional paths of the scan root (deny check)
 *     treeFiles?: number,       // optional number of files of the scan root
 *   }): {
 *     status: "pass" | "fail",
 *     passed: boolean,
 *     exitCode: 0 | 1,
 *     violations: { kind: string, detail: string, severity?: string }[],
 *     reasons: string[],
 *     counts: Record<string, number>,
 *     checks: { id: string, status: "pass" | "fail" | "skipped", detail: string }[],
 *     notes: string[],
 *     effectiveFailOn: string,
 *     denyPatterns: string[],
 *     deniedPaths: string[],
 *   }
 *
 * A Finding is the model of plan section F; a StageMeta is
 * `{ name, status, findingCount?, artifacts?, notes? }`.
 *
 * Also exported: `effectiveFailOn(policy, requested): string` (the threshold
 * the gate would apply), `compareSeverity(a, b): number` (re-exported) and
 * the constant `VIOLATION_KINDS` (the kinds of violation the gate reports).
 */

import { matchAny } from '../core/glob.js';
import { SEVERITY_ORDER, atOrAbove, compareSeverity, strictestSeverity } from './severity.js';
import { coverageViolation } from './coverage.js';

/** The kinds of violation the gate can report. */
export const VIOLATION_KINDS = Object.freeze([
  'policy-missing',
  'policy-invalid',
  'denied-path',
  'threshold',
  'fail-on',
  'missing-evidence',
  'stage-missing',
  'stage-no-output',
  'stage-coverage',
]);

/**
 * Tells whether a value is a plain object.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The severity of a finding, normalised.
 *
 * An unknown severity counts as `critical`: a finding nobody classified
 * must not be able to slip under a threshold.
 *
 * @param {object} finding
 * @returns {string}
 */
function severityOf(finding) {
  const severity = finding && typeof finding.severity === 'string' ? finding.severity.trim().toLowerCase() : '';
  return SEVERITY_ORDER.includes(severity) ? severity : 'critical';
}

/**
 * The path of a finding.
 *
 * @param {object} finding
 * @returns {string}
 */
function pathOf(finding) {
  const location = finding && isPlainObject(finding.location) ? finding.location : {};
  return typeof location.path === 'string' ? location.path : '';
}

/**
 * Counts the findings per severity.
 *
 * @param {object[]} findings
 * @returns {Record<string, number>}
 */
function countBySeverity(findings) {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0, total: findings.length };
  for (const finding of findings) {
    const severity = severityOf(finding);
    counts[severity] += 1;
  }
  return counts;
}

/**
 * Evaluates the policy gate.
 *
 * @param {object} input see the file header.
 * @returns {object} the verdict.
 */
export function evaluateGate(input) {
  const source = isPlainObject(input) ? input : {};
  const findings = Array.isArray(source.findings) ? source.findings : [];
  const evidence = Array.isArray(source.evidence) ? source.evidence : [];
  const requestedFailOn = typeof source.failOn === 'string' ? source.failOn : undefined;
  const stages = Array.isArray(source.stages) ? source.stages : null;
  const scannedPaths = Array.isArray(source.paths) ? source.paths : [];
  // The paths that exist in the scan root: the deny list is judged against
  // them, so that a path the policy both denies and excludes is still seen.
  const treePaths = Array.isArray(source.treePaths) ? source.treePaths : [];
  const treeFiles = Number.isInteger(source.treeFiles) ? source.treeFiles : 0;

  const violations = [];
  const checks = [];
  const notes = [];

  // ---------------------------------------------------------------- policy
  const policy = isPlainObject(source.policy) ? source.policy : null;
  if (policy === null) {
    violations.push({
      kind: 'policy-missing',
      detail: 'no security policy was provided: the gate fails closed',
    });
    checks.push({ id: 'policy', status: 'fail', detail: 'the policy is missing' });
  } else {
    checks.push({
      id: 'policy',
      status: 'pass',
      detail: `policy source: ${typeof policy.source === 'string' && policy.source !== '' ? policy.source : 'inline'}`,
    });
  }
  const effectivePolicy = policy === null ? {} : policy;

  const thresholds = isPlainObject(effectivePolicy.thresholds) ? effectivePolicy.thresholds : null;
  if (policy !== null && effectivePolicy.thresholds !== undefined && thresholds === null) {
    violations.push({
      kind: 'policy-invalid',
      detail: 'the policy thresholds are not a mapping: the gate fails closed',
    });
    checks[checks.length - 1] = { id: 'policy', status: 'fail', detail: 'the thresholds are not a mapping' };
  }

  const paths = isPlainObject(effectivePolicy.paths) ? effectivePolicy.paths : {};
  const requiredEvidence = Array.isArray(effectivePolicy.required_evidence) ? effectivePolicy.required_evidence : [];
  const policyStages = isPlainObject(effectivePolicy.stages) ? effectivePolicy.stages : {};
  const policyFailOn = isPlainObject(effectivePolicy.defaults) && typeof effectivePolicy.defaults.fail_on === 'string'
    ? effectivePolicy.defaults.fail_on
    : undefined;

  // ----------------------------------------------------------- denied paths
  const deny = Array.isArray(paths.deny) ? paths.deny.filter((item) => typeof item === 'string') : [];
  const candidates = [];
  for (const finding of findings) {
    const path = pathOf(finding);
    if (path !== '') candidates.push(path);
  }
  for (const path of scannedPaths) {
    if (typeof path === 'string' && path !== '') candidates.push(path);
  }
  for (const path of treePaths) {
    if (typeof path === 'string' && path !== '') candidates.push(path);
  }
  const denied = [...new Set(candidates.filter((path) => deny.length > 0 && matchAny(deny, path)))].sort();
  for (const path of denied) {
    violations.push({
      kind: 'denied-path',
      detail: `the path "${path}" is denied by the policy`,
    });
  }
  checks.push({
    id: 'denied-path',
    status: denied.length > 0 ? 'fail' : 'pass',
    detail: denied.length > 0 ? `${denied.length} denied path(s) present` : 'no denied path is present',
  });
  // The deny list and the paths it caught are part of the verdict: the
  // operator has to see what the policy deliberately kept out.
  const denyPatterns = [...deny].sort();

  // ------------------------------------------------------------- thresholds
  const counts = countBySeverity(findings);
  if (thresholds !== null) {
    for (const severity of SEVERITY_ORDER) {
      const limit = thresholds[severity];
      if (typeof limit !== 'number' || !Number.isFinite(limit)) continue;
      if (limit < 0) continue;
      if (counts[severity] > limit) {
        violations.push({
          kind: 'threshold',
          detail: `${counts[severity]} ${severity} finding(s) exceed the policy limit of ${limit}`,
          severity,
        });
      }
    }
    checks.push({
      id: 'threshold',
      status: 'pass',
      detail: 'the severity thresholds were applied',
    });
  } else {
    checks.push({ id: 'threshold', status: 'skipped', detail: 'the policy carries no thresholds' });
  }

  // ---------------------------------------------------------------- fail-on
  // The effective threshold is the strictest of the policy default and the
  // requested one: a command line flag can tighten the gate, never loosen it.
  const effectiveFailOn = strictestSeverity(policyFailOn, requestedFailOn);
  const bySeverity = {};
  for (const finding of findings) {
    const severity = severityOf(finding);
    if (!atOrAbove(severity, effectiveFailOn)) continue;
    bySeverity[severity] = (bySeverity[severity] || 0) + 1;
  }
  for (const severity of SEVERITY_ORDER) {
    const count = bySeverity[severity] || 0;
    if (count === 0) continue;
    violations.push({
      kind: 'fail-on',
      detail: `${count} finding(s) at or above the fail-on threshold "${effectiveFailOn}"`,
      severity,
    });
  }
  checks.push({
    id: 'fail-on',
    status: Object.keys(bySeverity).length > 0 ? 'fail' : 'pass',
    detail: `effective fail-on threshold: ${effectiveFailOn}`,
  });

  // --------------------------------------------------------------- evidence
  const present = new Set();
  for (const item of evidence) {
    if (typeof item !== 'string' || item.trim() === '') continue;
    const text = item.trim();
    present.add(text);
    const slash = text.lastIndexOf('/');
    if (slash !== -1) present.add(text.slice(slash + 1));
  }
  for (const name of requiredEvidence) {
    if (typeof name !== 'string' || name.trim() === '') continue;
    if (present.has(name.trim())) continue;
    violations.push({
      kind: 'missing-evidence',
      detail: `the required evidence "${name.trim()}" is missing`,
    });
  }
  checks.push({
    id: 'evidence',
    status: requiredEvidence.every((name) => typeof name === 'string' && present.has(name.trim()))
      ? 'pass'
      : 'fail',
    detail: `${present.size} evidence artefact(s) known, ${requiredEvidence.length} required`,
  });

  // ------------------------------------------------------------ stage output
  if (stages === null) {
    checks.push({ id: 'stage-output', status: 'skipped', detail: 'no stage metadata was provided' });
    notes.push('the stage output check was skipped: no stage metadata was provided');
  } else {
    for (const name of Object.keys(policyStages).sort()) {
      const config = policyStages[name];
      if (isPlainObject(config) && config.enabled === false) continue;
      const stage = stages.find((entry) => isPlainObject(entry) && entry.name === name);
      if (stage === undefined) {
        violations.push({
          kind: 'stage-missing',
          detail: `the stage "${name}" is enabled but produced no output`,
        });
        continue;
      }
      const status = typeof stage.status === 'string' ? stage.status : '';
      if (status !== 'completed') {
        // The reason of a stage that did not run is part of the violation:
        // "the stage did not complete" is not actionable, "the dependency
        // manifest is excluded by the policy" is.
        const reason = typeof stage.reason === 'string' ? stage.reason.trim() : '';
        violations.push({
          kind: 'stage-no-output',
          detail: `the stage "${name}" did not complete (status: ${status === '' ? 'unknown' : status}${reason === '' ? '' : `, reason: ${reason}`})`,
        });
        continue;
      }
      if (Array.isArray(stage.artifacts) && stage.artifacts.length === 0) {
        violations.push({
          kind: 'stage-no-output',
          detail: `the stage "${name}" completed without producing any artefact`,
        });
      }
      const coverage = coverageViolation(stage, treeFiles);
      if (coverage !== null) {
        violations.push(coverage);
      }
    }
    checks.push({
      id: 'stage-output',
      status: violations.some((violation) => violation.kind === 'stage-missing'
        || violation.kind === 'stage-no-output'
        || violation.kind === 'stage-coverage')
        ? 'fail'
        : 'pass',
      detail: `${stages.length} stage(s) reported`,
    });
  }

  const passed = violations.length === 0;
  return {
    status: passed ? 'pass' : 'fail',
    passed,
    exitCode: passed ? 0 : 1,
    violations,
    reasons: violations.map((violation) => `${violation.kind}: ${violation.detail}`),
    counts,
    checks,
    notes,
    effectiveFailOn,
    denyPatterns,
    deniedPaths: denied,
  };
}

/**
 * The severity that the gate would use for a set of findings, without
 * evaluating it. Handy for the CLI, which prints the threshold it applied.
 *
 * @param {object} policy
 * @param {string} [requested]
 * @returns {string}
 */
export function effectiveFailOn(policy, requested) {
  const policyFailOn = isPlainObject(policy) && isPlainObject(policy.defaults) && typeof policy.defaults.fail_on === 'string'
    ? policy.defaults.fail_on
    : undefined;
  return strictestSeverity(policyFailOn, requested);
}

/**
 * Compares two severities; re-exported so that a caller of the gate does not
 * need a second import.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export { compareSeverity };
