/**
 * Rule pack loader and validator.
 *
 * A rule pack is configuration: it decides what the scanners look for and
 * how severe a match is. A pack that is malformed, ambiguous or incomplete
 * must never be silently downgraded to "no rules" - that would turn a broken
 * configuration into a green build. The loader therefore fails closed:
 * anything it cannot fully validate is reported as a {@link KitError} with
 * the stable code `E_RULES`.
 */

import { parseYamlFile } from '../yaml/parse-yaml.js';
import { KitError } from './errors.js';

/** Severities a rule may declare. */
export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

/** Kinds a secret rule may declare. */
export const SECRET_RULE_KINDS = Object.freeze(['provider', 'entropy', 'env_file', 'tracked_env']);

/** Rule packs the kit knows about. */
export const PACK_KINDS = Object.freeze(['secrets', 'sast']);

/** Lowercase slug: `js.eval-call`, `github-pat`, `secret.tracked-env-file`. */
const ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

/** A backreference (`\1`, `\k<name>`) is not allowed in a rule pattern. */
const BACKREFERENCE_PATTERN = /(^|[^\\])\\(?:[1-9]\d*|k<[A-Za-z_][A-Za-z0-9_]*>)/;

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
 * Checks that a pattern compiles and carries no backreference.
 *
 * @param {string} pattern
 * @param {string} where human readable location, used in the problem text.
 * @returns {string[]} the problems found (empty when the pattern is fine).
 */
function checkPattern(pattern, where) {
  const problems = [];
  if (typeof pattern !== 'string' || pattern === '') {
    problems.push(`${where}: "pattern" must be a non empty string`);
    return problems;
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern, 'g');
  } catch (err) {
    problems.push(`${where}: "pattern" is not a valid regular expression (${err && err.message ? err.message : String(err)})`);
    return problems;
  }
  if (BACKREFERENCE_PATTERN.test(pattern)) {
    problems.push(`${where}: "pattern" must not contain a backreference`);
  }
  return problems;
}

/**
 * Validates the optional `entropy` section of a secret rule pack.
 *
 * @param {unknown} entropy
 * @returns {string[]}
 */
function checkEntropy(entropy) {
  const problems = [];
  if (entropy === undefined || entropy === null) return problems;
  if (!isPlainObject(entropy)) return ['entropy: must be a mapping'];
  if (entropy.enabled !== undefined && typeof entropy.enabled !== 'boolean') {
    problems.push('entropy.enabled: must be a boolean');
  }
  if (entropy.min_length !== undefined && !(Number.isInteger(entropy.min_length) && entropy.min_length > 0)) {
    problems.push('entropy.min_length: must be a positive integer');
  }
  if (entropy.min_entropy !== undefined && !(typeof entropy.min_entropy === 'number' && entropy.min_entropy > 0)) {
    problems.push('entropy.min_entropy: must be a positive number');
  }
  if (entropy.separator_pattern !== undefined && typeof entropy.separator_pattern !== 'string') {
    problems.push('entropy.separator_pattern: must be a string');
  }
  if (entropy.require_quoted_value !== undefined && typeof entropy.require_quoted_value !== 'boolean') {
    problems.push('entropy.require_quoted_value: must be a boolean');
  }
  if (entropy.keywords !== undefined && !isStringArray(entropy.keywords)) {
    problems.push('entropy.keywords: must be a list of non empty strings');
  }
  if (entropy.ignore_values !== undefined && !isStringArray(entropy.ignore_values)) {
    problems.push('entropy.ignore_values: must be a list of non empty strings');
  }
  return problems;
}

/**
 * Validates the optional `env_files` section of a secret rule pack.
 *
 * @param {unknown} envFiles
 * @returns {string[]}
 */
function checkEnvFiles(envFiles) {
  const problems = [];
  if (envFiles === undefined || envFiles === null) return problems;
  if (!isPlainObject(envFiles)) return ['env_files: must be a mapping'];
  if (envFiles.patterns !== undefined && !isStringArray(envFiles.patterns)) {
    problems.push('env_files.patterns: must be a list of non empty strings');
  }
  if (envFiles.ignore !== undefined && !isStringArray(envFiles.ignore)) {
    problems.push('env_files.ignore: must be a list of non empty strings');
  }
  return problems;
}

/**
 * Validates the optional `git` section of a secret rule pack.
 *
 * @param {unknown} git
 * @returns {string[]}
 */
function checkGit(git) {
  const problems = [];
  if (git === undefined || git === null) return problems;
  if (!isPlainObject(git)) return ['git: must be a mapping'];
  if (git.detect_tracked_env !== undefined && typeof git.detect_tracked_env !== 'boolean') {
    problems.push('git.detect_tracked_env: must be a boolean');
  }
  return problems;
}

/**
 * Validates a rule pack.
 *
 * Every rule must have a lowercase slug id (unique inside the pack), a
 * severity, a message and a remediation. SAST rules must additionally
 * declare the languages they apply to and a valid pattern; secret rules must
 * additionally declare their kind.
 *
 * A pack with **no rule at all** is rejected outright: it is not a pack, it
 * is a rubber stamp, and a scanner that runs with it reports "0 findings"
 * about everything. The same goes for a secrets pack that does not carry the
 * whole family of detectors (a provider rule, the entropy heuristic, the
 * environment file rule and the tracked environment file rule): a partial
 * pack is never silently downgraded to "no rule".
 *
 * @param {object} pack
 * @returns {string[]} the problems found; an empty list means the pack is valid.
 * @throws {KitError} with code `E_RULES` when the pack carries no detection
 *   rule at all.
 */
export function validateRulePack(pack) {
  const problems = [];
  if (!isPlainObject(pack)) return ['rule pack: must be a mapping'];

  if (!Number.isInteger(pack.version) || pack.version < 1) {
    problems.push('version: must be an integer greater than zero');
  }
  if (!PACK_KINDS.includes(pack.kind)) {
    problems.push(`kind: must be one of ${PACK_KINDS.join(', ')}`);
  }
  if (!Array.isArray(pack.rules)) {
    problems.push('rules: must be a list');
    return problems;
  }
  if (pack.rules.length === 0) {
    throw new KitError('E_RULES', 'the rule pack carries no detection rule', {
      kind: pack.kind,
      problems: ['rules: the pack carries no detection rule'],
    });
  }

  const seen = new Set();
  pack.rules.forEach((rule, index) => {
    const where = `rules[${index}]`;
    if (!isPlainObject(rule)) {
      problems.push(`${where}: must be a mapping`);
      return;
    }
    const id = rule.id;
    if (typeof id !== 'string' || id.trim() === '') {
      problems.push(`${where}: "id" must be a non empty string`);
    } else if (!ID_PATTERN.test(id)) {
      problems.push(`${where}: "id" must be a lowercase slug (got "${id}")`);
    } else if (seen.has(id)) {
      problems.push(`${where}: duplicate rule id "${id}"`);
    } else {
      seen.add(id);
    }

    if (!SEVERITIES.includes(rule.severity)) {
      problems.push(`${where}: "severity" must be one of ${SEVERITIES.join(', ')}`);
    }
    if (typeof rule.message !== 'string' || rule.message.trim() === '') {
      problems.push(`${where}: "message" must be a non empty string`);
    }
    if (typeof rule.remediation !== 'string' || rule.remediation.trim() === '') {
      problems.push(`${where}: "remediation" must be a non empty string`);
    }

    if (pack.kind === 'sast') {
      if (!isStringArray(rule.languages)) {
        problems.push(`${where}: "languages" must be a non empty list of strings`);
      }
      problems.push(...checkPattern(rule.pattern, where));
      if (rule.exclude_patterns !== undefined) {
        if (!isStringArray(rule.exclude_patterns)) {
          problems.push(`${where}: "exclude_patterns" must be a list of non empty strings`);
        } else {
          rule.exclude_patterns.forEach((pattern, position) => {
            problems.push(...checkPattern(pattern, `${where}.exclude_patterns[${position}]`));
          });
        }
      }
    }

    if (pack.kind === 'secrets') {
      if (!SECRET_RULE_KINDS.includes(rule.kind)) {
        problems.push(`${where}: "kind" must be one of ${SECRET_RULE_KINDS.join(', ')}`);
      } else if (rule.kind === 'provider') {
        problems.push(...checkPattern(rule.pattern, where));
      }
    }
  });

  if (pack.kind === 'secrets') {
    problems.push(...checkEntropy(pack.entropy));
    problems.push(...checkEnvFiles(pack.env_files));
    problems.push(...checkGit(pack.git));
    // The secrets pack must carry the whole family of detectors: a provider
    // rule, the keyword + entropy heuristic, the environment file rule and
    // the tracked environment file rule. A pack that misses one of them is
    // rejected, never downgraded to "no rule".
    const carried = new Set(pack.rules.filter((rule) => isPlainObject(rule)).map((rule) => rule.kind));
    const missing = SECRET_RULE_KINDS.filter((kind) => !carried.has(kind));
    if (missing.length > 0) {
      problems.push(`rules: the secrets pack carries no "${missing.join('" rule and no "')}" rule`);
    }
  }
  if (pack.kind === 'sast' && pack.languages !== undefined && !isStringArray(pack.languages)) {
    problems.push('languages: must be a list of non empty strings');
  }

  return problems;
}

/**
 * Guesses the kind of a rule pack from its file name and its content.
 *
 * @param {string} file
 * @param {object} doc the parsed document.
 * @returns {string|null} `secrets`, `sast` or null when it cannot be told.
 */
function detectKind(file, doc) {
  const name = String(file || '').toLowerCase();
  if (name.includes('sast')) return 'sast';
  if (name.includes('secret')) return 'secrets';
  if (Array.isArray(doc.rules)) return 'sast';
  if (Array.isArray(doc.providers)) return 'secrets';
  return null;
}

/**
 * Loads and validates a rule pack.
 *
 * @param {string} file path of the YAML rule pack.
 * @returns {object} the rule pack: `{ version, kind, rules, ... }`.
 * @throws {KitError} with code `E_RULES` when the file cannot be read, parsed
 *   or does not describe a valid rule pack.
 */
export function loadRulePack(file) {
  let doc;
  try {
    doc = parseYamlFile(file);
  } catch (err) {
    throw new KitError('E_RULES', `cannot read rule pack ${file}: ${err && err.message ? err.message : String(err)}`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!isPlainObject(doc)) {
    throw new KitError('E_RULES', `rule pack ${file} must contain a mapping`, { file });
  }

  const kind = detectKind(file, doc);
  if (!kind) {
    throw new KitError('E_RULES', `cannot tell the kind of the rule pack ${file} (expected a "rules" or "providers" list)`, {
      file,
    });
  }

  const rawRules = kind === 'sast'
    ? doc.rules
    : (Array.isArray(doc.rules) ? doc.rules : doc.providers);
  if (!Array.isArray(rawRules)) {
    throw new KitError('E_RULES', `rule pack ${file} must contain a list of rules`, { file, kind });
  }

  const pack = {
    version: Number.isInteger(doc.version) && doc.version > 0 ? doc.version : 1,
    kind,
    rules: rawRules,
    source: file,
  };
  if (kind === 'sast') {
    if (doc.languages !== undefined) pack.languages = doc.languages;
  } else {
    if (doc.entropy !== undefined) pack.entropy = doc.entropy;
    if (doc.env_files !== undefined) pack.env_files = doc.env_files;
    if (doc.git !== undefined) pack.git = doc.git;
  }

  let problems;
  try {
    problems = validateRulePack(pack);
  } catch (err) {
    // `validateRulePack` rejects a pack that carries no rule at all: the
    // loader reports it with the name of the file, like every other problem.
    throw new KitError('E_RULES', `invalid rule pack ${file}: ${err && err.message ? err.message : String(err)}`, {
      file,
      kind,
      cause: err && err.message ? err.message : String(err),
      problems: err && err.details && Array.isArray(err.details.problems) ? err.details.problems : [],
    });
  }
  if (problems.length > 0) {
    throw new KitError('E_RULES', `invalid rule pack ${file}`, { file, kind, problems });
  }
  return pack;
}
