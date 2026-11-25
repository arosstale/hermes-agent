/**
 * Policy loading, merging and validation.
 *
 * The security policy is the contract between the scanners and the gate. A
 * policy that cannot be understood is never partially applied: an unknown
 * key, a wrong type or an unreadable file aborts the run with a
 * {@link KitError} (`E_POLICY`), which the CLI turns into exit code 2.
 *
 * The merge order is: built-in defaults, then the policy file, then the
 * explicit overrides given on the command line. Objects are merged key by
 * key, lists are replaced (never concatenated): a policy that adds a path to
 * `paths.exclude` means exactly that.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseYamlFile } from '../yaml/parse-yaml.js';
import { KitError } from '../core/errors.js';
import { DEFAULT_POLICY, clonePolicy, SEVERITY_NAMES, STAGE_NAMES } from './defaults.js';

/**
 * @param {unknown} value
 * @returns {boolean} true for a plain object (not an array, not null).
 */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * @param {unknown} value
 * @returns {boolean} true for an array of non empty strings.
 */
function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.trim() !== '');
}

/**
 * Deep merges `patch` into `base` and returns a new object.
 *
 * Plain objects are merged key by key, everything else (lists included) is
 * replaced by the value of `patch`.
 *
 * @param {object} base
 * @param {object} patch
 * @returns {object}
 */
function deepMerge(base, patch) {
  const out = clonePolicy(base);
  if (!isPlainObject(patch)) return out;
  for (const key of Object.keys(patch)) {
    const next = patch[key];
    if (isPlainObject(next) && isPlainObject(out[key])) {
      out[key] = deepMerge(out[key], next);
    } else {
      out[key] = clonePolicy(next);
    }
  }
  return out;
}

/**
 * Validates a policy object.
 *
 * @param {object} policy
 * @returns {string[]} the problems found; an empty list means the policy is valid.
 */
export function validatePolicy(policy) {
  const problems = [];
  if (!isPlainObject(policy)) return ['policy: must be a mapping'];

  const known = ['version', 'fail_closed', 'source', 'defaults', 'stages', 'thresholds', 'required_evidence', 'paths', 'allowlist', 'limits'];
  for (const key of Object.keys(policy)) {
    if (!known.includes(key)) problems.push(`unknown key "${key}"`);
  }

  if (!Number.isInteger(policy.version) || policy.version < 1) {
    problems.push('version: must be an integer greater than zero');
  }
  if (typeof policy.fail_closed !== 'boolean') {
    problems.push('fail_closed: must be a boolean');
  }
  if (policy.source !== undefined && typeof policy.source !== 'string') {
    problems.push('source: must be a string');
  }

  if (!isPlainObject(policy.defaults)) {
    problems.push('defaults: must be a mapping');
  } else {
    for (const key of Object.keys(policy.defaults)) {
      if (key !== 'fail_on') problems.push(`defaults: unknown key "${key}"`);
    }
    if (!SEVERITY_NAMES.includes(policy.defaults.fail_on)) {
      problems.push(`defaults.fail_on: must be one of ${SEVERITY_NAMES.join(', ')}`);
    }
  }

  if (!isPlainObject(policy.stages)) {
    problems.push('stages: must be a mapping');
  } else {
    for (const name of Object.keys(policy.stages)) {
      if (!STAGE_NAMES.includes(name)) {
        problems.push(`stages: unknown stage "${name}"`);
        continue;
      }
      const stage = policy.stages[name];
      if (!isPlainObject(stage)) {
        problems.push(`stages.${name}: must be a mapping`);
        continue;
      }
      for (const key of Object.keys(stage)) {
        if (key !== 'enabled' && key !== 'severity') problems.push(`stages.${name}: unknown key "${key}"`);
      }
      if (typeof stage.enabled !== 'boolean') problems.push(`stages.${name}.enabled: must be a boolean`);
      if (stage.severity !== undefined && !SEVERITY_NAMES.includes(stage.severity)) {
        problems.push(`stages.${name}.severity: must be one of ${SEVERITY_NAMES.join(', ')}`);
      }
    }
  }

  if (!isPlainObject(policy.thresholds)) {
    problems.push('thresholds: must be a mapping');
  } else {
    for (const key of Object.keys(policy.thresholds)) {
      if (!SEVERITY_NAMES.includes(key)) {
        problems.push(`thresholds: unknown severity "${key}"`);
        continue;
      }
      const value = policy.thresholds[key];
      if (!Number.isInteger(value) || value < -1) {
        problems.push(`thresholds.${key}: must be an integer greater than or equal to -1 (-1 means unlimited)`);
      }
    }
  }

  if (!isStringArray(policy.required_evidence)) {
    problems.push('required_evidence: must be a list of non empty strings');
  }

  if (!isPlainObject(policy.limits)) {
    problems.push('limits: must be a mapping');
  } else {
    for (const key of Object.keys(policy.limits)) {
      if (key !== 'max_file_bytes') problems.push(`limits: unknown key "${key}"`);
    }
    const cap = policy.limits.max_file_bytes;
    if (cap !== undefined && (!Number.isInteger(cap) || cap <= 0)) {
      problems.push('limits.max_file_bytes: must be an integer greater than zero (the default is 2000000)');
    }
  }

  if (!isPlainObject(policy.paths)) {
    problems.push('paths: must be a mapping');
  } else {
    for (const key of Object.keys(policy.paths)) {
      if (!['include', 'exclude', 'deny'].includes(key)) problems.push(`paths: unknown key "${key}"`);
    }
    for (const key of ['include', 'exclude', 'deny']) {
      if (policy.paths[key] !== undefined && !isStringArray(policy.paths[key])) {
        problems.push(`paths.${key}: must be a list of non empty strings`);
      }
    }
  }

  if (!isPlainObject(policy.allowlist)) {
    problems.push('allowlist: must be a mapping');
  } else {
    for (const name of Object.keys(policy.allowlist)) {
      if (!STAGE_NAMES.includes(name)) {
        problems.push(`allowlist: unknown stage "${name}"`);
        continue;
      }
      const entries = policy.allowlist[name];
      if (!Array.isArray(entries)) {
        problems.push(`allowlist.${name}: must be a list`);
        continue;
      }
      entries.forEach((entry, index) => {
        if (!isPlainObject(entry)) {
          problems.push(`allowlist.${name}[${index}]: must be a mapping`);
          return;
        }
        for (const key of Object.keys(entry)) {
          if (key !== 'path' && key !== 'reason') problems.push(`allowlist.${name}[${index}]: unknown key "${key}"`);
        }
        if (typeof entry.path !== 'string' || entry.path.trim() === '') {
          problems.push(`allowlist.${name}[${index}].path: must be a non empty string`);
        }
        if (entry.reason !== undefined && typeof entry.reason !== 'string') {
          problems.push(`allowlist.${name}[${index}].reason: must be a string`);
        }
      });
    }
  }

  return problems;
}

/**
 * Loads the security policy.
 *
 * @param {string} file path of the policy file. An empty string selects the
 *   built-in fail-closed defaults.
 * @param {object} [opts]
 * @param {object} [opts.overrides] values that win over the file.
 * @returns {object} the resolved policy.
 * @throws {KitError} with code `E_POLICY` when the file cannot be read, is
 *   not a mapping, or does not describe a valid policy.
 */
export function loadPolicy(file, opts = {}) {
  const overrides = opts && isPlainObject(opts.overrides) ? opts.overrides : {};
  const useBuiltIn = file === undefined || file === null || file === '';
  let policy;
  let source;

  if (useBuiltIn) {
    policy = clonePolicy(DEFAULT_POLICY);
    source = 'builtin-default';
  } else {
    let doc;
    try {
      doc = parseYamlFile(file);
    } catch (err) {
      throw new KitError('E_POLICY', `cannot read the policy file ${file}: ${err && err.message ? err.message : String(err)}`, {
        file,
        cause: err && err.message ? err.message : String(err),
      });
    }
    if (!isPlainObject(doc)) {
      throw new KitError('E_POLICY', `the policy file ${file} must contain a mapping`, { file });
    }
    policy = deepMerge(DEFAULT_POLICY, doc);
    source = file;
  }

  policy = deepMerge(policy, overrides);
  policy.source = source;

  const problems = validatePolicy(policy);
  if (problems.length > 0) {
    throw new KitError('E_POLICY', `invalid policy${useBuiltIn ? '' : ` ${file}`}`, {
      file: useBuiltIn ? null : file,
      source,
      problems,
    });
  }
  return policy;
}

/**
 * Resolves which policy file has to be used.
 *
 * @param {string|undefined} explicit the file given on the command line.
 * @param {string} root the scan root.
 * @returns {string} the explicit file when given, otherwise
 *   `<root>/policy/security-policy.yml` when it exists, otherwise an empty
 *   string - the signal to use the built-in fail-closed defaults.
 */
export function resolvePolicyFile(explicit, root) {
  if (typeof explicit === 'string' && explicit.trim() !== '') return explicit;
  const base = typeof root === 'string' && root !== '' ? root : process.cwd();
  const candidate = join(base, 'policy', 'security-policy.yml');
  if (existsSync(candidate)) return candidate;
  return '';
}
