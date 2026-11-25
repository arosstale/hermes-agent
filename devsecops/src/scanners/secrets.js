/**
 * Secret scanner.
 *
 * The scanner looks for credentials that leaked into a repository. It has
 * three independent heuristics:
 *
 *   1. **provider prefix** - a regular expression per provider family
 *      (`ghp_`, `github_pat_`, `sk-`, `AKIA`, `xox[baprs]-`, a private key
 *      header, a JWT, ...). The patterns live in `rules/secrets.yml`.
 *   2. **keyword + entropy** - a credential keyword (`token`, `secret`,
 *      `api_key`, ...) followed by a separator, a quoted value, a minimum
 *      length and a minimum Shannon entropy.
 *   3. **environment files** - a file whose name looks like `.env`, plus the
 *      environment files that git tracks (those are a finding on their own,
 *      whatever they contain).
 *
 * Redaction by construction
 *   A matched value never leaves this module. The only things that are kept
 *   are the fingerprint (`sha256:<12 hex>:len:<n>:pfx:<4 chars>`) and the
 *   redacted snippet (`<kind>…<redacted len=n>`), both produced by
 *   `src/core/redact.js`. The raw value is dropped as soon as it has been
 *   fingerprinted.
 *
 * Signatures
 *   scanSecrets(root: string, opts?: {
 *     policy?: object,        // the security policy (paths, allowlist)
 *     rules?: object,         // the secret rule pack (rulePack is an alias)
 *     rulePack?: object,
 *     isGitRepo?: boolean,    // false skips the tracked environment check
 *     gitBin?: string,        // the git binary to use ("git" by default)
 *     timeoutMs?: number,
 *     onlyFiles?: string[],   // the only files to look at (the staged set)
 *     fs?: object,            // the file system seam (the real one by default)
 *   }): {
 *     status: "completed" | "skipped",
 *     findings: Finding[],
 *     notes: string[],
 *     stats: { files: number, inScope: number, inspected: number, scanned: number,
 *              dropped: number, findings: number, bySeverity: object, byRule: object },
 *   }
 *
 *   detectTrackedEnvFiles(root: string, opts?: { gitBin?: string, isGitRepo?: boolean, timeoutMs?: number }):
 *     { status: "completed" | "skipped", files: string[], reason?: string }
 *
 *   shannonEntropy(value: string, charset?: string): number
 *
 * Fail closed
 *   The scanner never reports "0 findings" for a tree it did not look at: an
 *   unreadable scan root raises an `E_IO` {@link KitError}, and a rule pack
 *   that carries no rule raises an `E_RULES` {@link KitError}. Both abort the
 *   run with the exit code 2 of a configuration error.
 *
 * A Finding is the model of plan section F:
 *   { id, ruleId, stage, severity, confidence, message,
 *     location: { path, startLine, endLine, column },
 *     fingerprint, redacted, snippet, remediation, tags, metadata }
 *
 * The findings are sorted by (path, line, ruleId, fingerprint), so two runs
 * over the same tree produce byte identical output.
 */

import { execFileSync } from 'node:child_process';
import { basename, join, resolve } from 'node:path';
import { KitError } from '../core/errors.js';
import { droppedNote, readTextSafe, walkTree } from '../core/fs-walk.js';
import { findingId, sha256Hex } from '../core/fingerprint.js';
import { matchAny, matchGlob } from '../core/glob.js';
import { fingerprintSecret, redactSnippet } from '../core/redact.js';
import { maxFileBytesOf } from '../config/defaults.js';

/** The stage name used in the findings. */
export const STAGE = 'secrets';

/** Severities, from the least to the most severe. */
export const SEVERITY_ORDER = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

/** The characters the entropy heuristic takes into account. */
export const ENTROPY_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_';

/** Parameters used when the rule pack does not carry an entropy section. */
const DEFAULT_ENTROPY = Object.freeze({
  min_length: 24,
  min_entropy: 4.0,
  separator_pattern: '[:=]',
  require_quoted_value: true,
  keywords: Object.freeze([
    'apikey', 'api_key', 'api-key', 'secret', 'token', 'password', 'passwd',
    'pwd', 'credential', 'private_key', 'access_key', 'auth_token',
  ]),
  ignore_values: Object.freeze([
    '<REDACTED>', 'REDACTED', 'changeme', 'change-me', 'example',
    'placeholder', 'xxxxx', 'your_token_here', 'process.env',
  ]),
});

/** Rule used when the pack carries no entropy rule of its own. */
const DEFAULT_ENTROPY_RULE = Object.freeze({
  id: 'generic-entropy',
  severity: 'high',
  message: 'High entropy value assigned to a credential keyword',
  remediation: 'Move the value into a secret store and rotate the credential.',
});

/** Rule used when the pack carries no environment file rule of its own. */
const DEFAULT_ENV_RULE = Object.freeze({
  id: 'env-file',
  severity: 'medium',
  message: 'Environment file present in the tree',
  remediation: 'Keep environment files out of the repository and ignore them in git.',
});

/** Rule used when the pack carries no tracked environment file rule. */
const DEFAULT_TRACKED_RULE = Object.freeze({
  id: 'tracked-env-file',
  severity: 'high',
  message: 'Environment file is tracked by git',
  remediation: 'Remove the file from the index, rotate the credentials it holds and ignore it.',
});

/** The kinds of rule a secret pack must carry. */
export const REQUIRED_SECRET_RULE_KINDS = Object.freeze(['provider', 'entropy', 'env_file', 'tracked_env']);

/**
 * Escapes the characters that have a meaning inside a regular expression.
 *
 * @param {string} text
 * @returns {string}
 */
function escapeRegExp(text) {
  return String(text ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Shannon entropy of a value, computed over the characters of `charset`.
 *
 * Characters outside the charset are ignored: a value that is mostly
 * punctuation is not a credential.
 *
 * @param {string} value
 * @param {string} [charset]
 * @returns {number} the entropy in bits per character (0 for an empty value).
 */
export function shannonEntropy(value, charset = ENTROPY_CHARSET) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  const counts = new Map();
  let total = 0;
  for (const ch of text) {
    if (!charset.includes(ch)) continue;
    counts.set(ch, (counts.get(ch) || 0) + 1);
    total += 1;
  }
  if (total === 0) return 0;
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / total;
    entropy -= probability * Math.log2(probability);
  }
  return Math.round(entropy * 1000) / 1000;
}

/**
 * Fingerprint of a finding that carries no secret value.
 *
 * The shape is the one of the secret fingerprints (`sha256:<12 hex>:len:<n>:
 * pfx:<4 chars>`) but the digest is computed over the location: the path and
 * the line. The prefix is the first four characters of the path, never of a
 * value.
 *
 * @param {string} path
 * @param {number} line
 * @returns {string}
 */
export function locationFingerprint(path, line) {
  const key = `${String(path ?? '')}\u0000${Number(line) || 0}`;
  const digest = sha256Hex(key).slice(0, 12);
  const prefix = String(path ?? '').slice(0, 4).replace(/[^\x20-\x7e]/g, '*');
  return `sha256:${digest}:len:${Number(line) || 0}:pfx:${prefix}`;
}

/**
 * Compiles a rule pattern.
 *
 * @param {string} pattern
 * @param {string} ruleId
 * @returns {RegExp}
 * @throws {KitError} with code `E_RULES` when the pattern does not compile.
 */
function compilePattern(pattern, ruleId) {
  try {
    return new RegExp(pattern, 'g');
  } catch (err) {
    throw new KitError('E_RULES', `rule "${ruleId}" has an invalid pattern`, {
      ruleId,
      cause: err && err.message ? err.message : String(err),
    });
  }
}

/**
 * Builds the regular expression of the keyword + entropy heuristic.
 *
 * @param {object} config
 * @returns {RegExp|null} null when the heuristic is disabled.
 */
function buildEntropyRegExp(config) {
  if (!config.enabled) return null;
  const keywords = config.keywords.map(escapeRegExp).join('|');
  if (keywords === '') return null;
  const separator = config.separator_pattern || '[:=]';
  const minLength = config.min_length;
  const value = config.require_quoted_value
    ? `(['"])([^'"\\n]{${minLength},})\\2`
    : `([A-Za-z0-9+/=_-]{${minLength},})`;
  return new RegExp(`(${keywords})\\s*(?:${separator})\\s*${value}`, 'g');
}

/**
 * Normalises the entropy configuration of a rule pack.
 *
 * @param {object|null} pack
 * @param {boolean} hasEntropyRule
 * @returns {object}
 */
function buildEntropyConfig(pack, hasEntropyRule) {
  const section = pack && pack.entropy && typeof pack.entropy === 'object' ? pack.entropy : null;
  const base = {
    enabled: section ? section.enabled !== false : hasEntropyRule,
    min_length: DEFAULT_ENTROPY.min_length,
    min_entropy: DEFAULT_ENTROPY.min_entropy,
    separator_pattern: DEFAULT_ENTROPY.separator_pattern,
    require_quoted_value: DEFAULT_ENTROPY.require_quoted_value,
    keywords: DEFAULT_ENTROPY.keywords.slice(),
    ignore_values: DEFAULT_ENTROPY.ignore_values.slice(),
  };
  if (!section) return base;
  if (Number.isInteger(section.min_length) && section.min_length > 0) base.min_length = section.min_length;
  if (typeof section.min_entropy === 'number' && section.min_entropy > 0) base.min_entropy = section.min_entropy;
  if (typeof section.separator_pattern === 'string' && section.separator_pattern !== '') {
    base.separator_pattern = section.separator_pattern;
  }
  if (typeof section.require_quoted_value === 'boolean') base.require_quoted_value = section.require_quoted_value;
  if (Array.isArray(section.keywords) && section.keywords.length > 0) {
    base.keywords = section.keywords.filter((item) => typeof item === 'string' && item !== '');
  }
  if (Array.isArray(section.ignore_values)) {
    base.ignore_values = section.ignore_values.filter((item) => typeof item === 'string' && item !== '');
  }
  return base;
}

/**
 * Tells whether a file name is an environment file.
 *
 * @param {string} name the base name of the file.
 * @param {string[]} [patterns] glob patterns, e.g. `.env`, `.env.*`, `*.env`.
 * @param {string[]} [ignore] file names that are *not* environment files.
 * @returns {boolean}
 */
export function isEnvFileName(name, patterns, ignore) {
  const list = Array.isArray(patterns) && patterns.length > 0
    ? patterns
    : ['.env', '.env.*', '*.env'];
  const ignored = Array.isArray(ignore) ? ignore : [];
  const base = String(name ?? '');
  if (base === '') return false;
  for (const pattern of ignored) {
    if (typeof pattern === 'string' && matchGlob(pattern, base)) return false;
  }
  for (const pattern of list) {
    if (typeof pattern === 'string' && matchGlob(pattern, base)) return true;
  }
  return false;
}

/**
 * Lists the files git tracks in a directory.
 *
 * @param {string} root
 * @param {object} [opts]
 * @param {string} [opts.gitBin]
 * @param {boolean} [opts.isGitRepo] false skips the check.
 * @param {number} [opts.timeoutMs]
 * @returns {{ status: "completed" | "skipped", files: string[], reason?: string }}
 */
export function detectTrackedEnvFiles(root, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  if (options.isGitRepo === false) {
    return { status: 'skipped', files: [], reason: 'the scan root is not a git repository' };
  }
  const gitBin = typeof options.gitBin === 'string' && options.gitBin !== '' ? options.gitBin : 'git';
  const rootPath = resolve(String(root ?? '.'));
  const timeoutMs = typeof options.timeoutMs === 'number' && options.timeoutMs > 0 ? options.timeoutMs : 15000;
  let output;
  try {
    output = execFileSync(gitBin, ['-C', rootPath, 'ls-files', '--cached', '-z'], {
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    return {
      status: 'skipped',
      files: [],
      reason: 'git is not available or the scan root is not a git repository',
    };
  }
  const files = String(output)
    .split('\u0000')
    .filter((entry) => entry !== '')
    .map((entry) => entry.split('\\').join('/'))
    .sort();
  return { status: 'completed', files };
}

/**
 * Offset of the beginning of every line of a text.
 *
 * @param {string} text
 * @returns {number[]}
 */
function lineStarts(text) {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') starts.push(index + 1);
  }
  return starts;
}

/**
 * Line and column of an offset inside a text.
 *
 * @param {number[]} starts
 * @param {number} offset
 * @returns {{ line: number, column: number }}
 */
function locate(starts, offset) {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (starts[middle] <= offset) low = middle;
    else high = middle - 1;
  }
  return { line: low + 1, column: offset - starts[low] + 1 };
}

/**
 * Builds a finding of the model of plan section F.
 *
 * @param {object} input
 * @returns {object}
 */
function makeFinding(input) {
  return {
    id: findingId(input.ruleId, input.fingerprint),
    ruleId: input.ruleId,
    stage: STAGE,
    severity: input.severity,
    confidence: input.confidence,
    message: input.message,
    location: {
      path: input.path,
      startLine: input.line,
      endLine: input.line,
      column: input.column,
    },
    fingerprint: input.fingerprint,
    redacted: true,
    snippet: input.snippet,
    remediation: input.remediation,
    tags: input.tags,
    metadata: input.metadata,
  };
}

/**
 * Names the rule id of a pack rule: the findings use the `secret.` prefix.
 *
 * @param {object} rule
 * @returns {string}
 */
function ruleIdOf(rule) {
  const id = typeof rule.id === 'string' && rule.id !== '' ? rule.id : 'unknown';
  return id.startsWith('secret.') ? id : `secret.${id}`;
}

/**
 * Sorts the findings deterministically.
 *
 * @param {object[]} findings
 * @returns {object[]} the same array, sorted.
 */
function sortFindings(findings) {
  return findings.sort((a, b) => {
    if (a.location.path !== b.location.path) return a.location.path < b.location.path ? -1 : 1;
    if (a.location.startLine !== b.location.startLine) return a.location.startLine - b.location.startLine;
    if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
    if (a.fingerprint !== b.fingerprint) return a.fingerprint < b.fingerprint ? -1 : 1;
    return 0;
  });
}

/**
 * Scans a tree for leaked credentials.
 *
 * @param {string} root the scan root.
 * @param {object} [opts] see the file header.
 * @returns {{ status: string, findings: object[], notes: string[], stats: object }}
 */
export function scanSecrets(root, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const policy = options.policy && typeof options.policy === 'object' ? options.policy : {};
  const pack = options.rules || options.rulePack || null;
  const rootPath = resolve(String(root ?? '.'));
  const notes = [];
  const findings = [];

  const paths = policy.paths && typeof policy.paths === 'object' ? policy.paths : {};
  const include = Array.isArray(paths.include) ? paths.include : [];
  // `.git/**` is always out of scope: the object store is binary, packed and
  // full of material that is not part of the working tree.
  const exclude = [...(Array.isArray(paths.exclude) ? paths.exclude : []), '.git/**'];
  const allowlist = policy.allowlist && typeof policy.allowlist === 'object' && Array.isArray(policy.allowlist.secrets)
    ? policy.allowlist.secrets.filter((entry) => entry && typeof entry.path === 'string')
    : [];
  const allowlistPaths = allowlist.map((entry) => entry.path);

  const walked = walkTree(rootPath, { include, exclude, maxFileBytes: maxFileBytesOf(policy), fs: options.fs });

  // The restriction of the scan: when the caller asks for a subset of the
  // tree (the staged set of `--git-staged`), only the files of that subset
  // are looked at. The restriction is applied *after* the walk, so the
  // policy still decides what a file is worth.
  const only = Array.isArray(options.onlyFiles)
    ? new Set(options.onlyFiles.map((entry) => String(entry).split('\\').join('/')).filter((entry) => entry !== ''))
    : null;
  const files = only === null ? walked.files : walked.files.filter((relPath) => only.has(relPath));
  // The files the walk dropped are files of the scope as well: they are
  // counted, and the coverage line says that they were not opened.
  const dropped = only === null
    ? walked.dropped
    : walked.dropped.filter((entry) => only.has(entry.path));
  if (only !== null) {
    notes.push(`the scan was restricted to the ${files.length} file(s) of the requested set.`);
  }
  if (dropped.length > 0) {
    notes.push(droppedNote(dropped));
  }

  const rawRules = pack && Array.isArray(pack.rules)
    ? pack.rules
    : (pack && Array.isArray(pack.providers) ? pack.providers : []);
  const rules = rawRules.filter((rule) => rule && typeof rule === 'object');

  // A pack that carries no rule is a broken configuration, not a clean
  // tree: the scanner says so loudly instead of reporting "0 findings".
  if (rules.length === 0) {
    throw new KitError('E_RULES', 'the secret rule pack carries no detection rule: the scanner refuses to run without one', {
      source: pack && typeof pack.source === 'string' ? pack.source : null,
    });
  }
  const carriedKinds = new Set(rules.map((rule) => rule.kind));
  const missingKinds = REQUIRED_SECRET_RULE_KINDS.filter((kind) => !carriedKinds.has(kind));
  if (missingKinds.length > 0) {
    throw new KitError('E_RULES', `the secret rule pack carries no "${missingKinds.join('" rule and no "')}" rule: the scanner refuses to run with a partial pack`, {
      source: pack && typeof pack.source === 'string' ? pack.source : null,
      missing: missingKinds,
    });
  }

  const providerRules = rules
    .filter((rule) => rule.kind === 'provider' && typeof rule.pattern === 'string' && rule.pattern !== '')
    .map((rule) => ({ rule, regexp: compilePattern(rule.pattern, rule.id || 'unknown') }));

  const entropyRule = rules.find((rule) => rule.kind === 'entropy') || DEFAULT_ENTROPY_RULE;
  const envRule = rules.find((rule) => rule.kind === 'env_file') || DEFAULT_ENV_RULE;
  const trackedRule = rules.find((rule) => rule.kind === 'tracked_env') || DEFAULT_TRACKED_RULE;

  const entropyConfig = buildEntropyConfig(pack, rules.some((rule) => rule.kind === 'entropy'));
  const entropyRegExp = buildEntropyRegExp(entropyConfig);
  const ignoreValues = entropyConfig.ignore_values.map((value) => String(value).toLowerCase());

  const envFiles = pack && pack.env_files && typeof pack.env_files === 'object' ? pack.env_files : {};
  const envPatterns = Array.isArray(envFiles.patterns) ? envFiles.patterns : undefined;
  const envIgnore = Array.isArray(envFiles.ignore) ? envFiles.ignore : undefined;
  const detectTracked = !(pack && pack.git && pack.git.detect_tracked_env === false);

  let scanned = 0;
  let inspected = 0;
  // The files the scanner could not open: they are part of the scope, and
  // the coverage floor counts them.
  let unreadable = 0;
  for (const relPath of files) {
    const base = basename(relPath);

    if (isEnvFileName(base, envPatterns, envIgnore)) {
      findings.push(makeFinding({
        ruleId: ruleIdOf(envRule),
        severity: envRule.severity || 'medium',
        confidence: 'medium',
        message: envRule.message || DEFAULT_ENV_RULE.message,
        path: relPath,
        line: 1,
        column: 1,
        fingerprint: locationFingerprint(relPath, 1),
        snippet: redactSnippet('', envRule.id || DEFAULT_ENV_RULE.id),
        remediation: envRule.remediation || DEFAULT_ENV_RULE.remediation,
        tags: ['security', 'CWE-16'],
        metadata: { kind: 'env_file' },
      }));
    }

    const { text, binary, error } = readTextSafe(join(rootPath, relPath), maxFileBytesOf(policy), options.fs);
    if (error) {
      notes.push(`${relPath}: ${error}`);
      unreadable += 1;
      continue;
    }
    inspected += 1;
    if (binary || text === '') continue;
    scanned += 1;

    const starts = lineStarts(text);

    for (const { rule, regexp } of providerRules) {
      regexp.lastIndex = 0;
      let match = regexp.exec(text);
      while (match !== null) {
        const value = match[0];
        if (value === '') {
          regexp.lastIndex += 1;
          match = regexp.exec(text);
          continue;
        }
        const position = locate(starts, match.index);
        const fingerprint = fingerprintSecret(value);
        findings.push(makeFinding({
          ruleId: ruleIdOf(rule),
          severity: rule.severity || 'high',
          confidence: 'high',
          message: rule.message || DEFAULT_ENTROPY_RULE.message,
          path: relPath,
          line: position.line,
          column: position.column,
          fingerprint,
          snippet: redactSnippet(value, rule.id || 'provider'),
          remediation: rule.remediation || DEFAULT_ENTROPY_RULE.remediation,
          tags: ['security', 'CWE-798'],
          metadata: { provider: rule.id || 'unknown' },
        }));
        match = regexp.exec(text);
      }
    }

    if (entropyRegExp) {
      entropyRegExp.lastIndex = 0;
      let match = entropyRegExp.exec(text);
      while (match !== null) {
        const value = match[match.length - 1];
        if (value === '') {
          entropyRegExp.lastIndex += 1;
          match = entropyRegExp.exec(text);
          continue;
        }
        if (value.length < entropyConfig.min_length) {
          match = entropyRegExp.exec(text);
          continue;
        }
        if (ignoreValues.includes(value.toLowerCase())) {
          match = entropyRegExp.exec(text);
          continue;
        }
        const entropy = shannonEntropy(value);
        if (entropy < entropyConfig.min_entropy) {
          match = entropyRegExp.exec(text);
          continue;
        }
        const position = locate(starts, match.index);
        const fingerprint = fingerprintSecret(value);
        findings.push(makeFinding({
          ruleId: ruleIdOf(entropyRule),
          severity: entropyRule.severity || 'high',
          confidence: 'medium',
          message: entropyRule.message || DEFAULT_ENTROPY_RULE.message,
          path: relPath,
          line: position.line,
          column: position.column,
          fingerprint,
          snippet: redactSnippet(value, entropyRule.id || DEFAULT_ENTROPY_RULE.id),
          remediation: entropyRule.remediation || DEFAULT_ENTROPY_RULE.remediation,
          tags: ['security', 'CWE-798'],
          metadata: { keyword: match[1], entropy },
        }));
        match = entropyRegExp.exec(text);
      }
    }
  }

  if (detectTracked) {
    const tracked = detectTrackedEnvFiles(rootPath, {
      gitBin: options.gitBin,
      isGitRepo: options.isGitRepo,
      timeoutMs: options.timeoutMs,
    });
    if (tracked.status === 'completed') {
      for (const relPath of tracked.files) {
        // The tracked check honours the restriction too: a tracked file that
        // is not part of the requested set is not a finding of this run.
        if (only !== null && !only.has(relPath)) continue;
        if (!isEnvFileName(basename(relPath), envPatterns, envIgnore)) continue;
        findings.push(makeFinding({
          ruleId: ruleIdOf(trackedRule),
          severity: trackedRule.severity || 'high',
          confidence: 'high',
          message: trackedRule.message || DEFAULT_TRACKED_RULE.message,
          path: relPath,
          line: 1,
          column: 1,
          fingerprint: locationFingerprint(relPath, 1),
          snippet: redactSnippet('', trackedRule.id || DEFAULT_TRACKED_RULE.id),
          remediation: trackedRule.remediation || DEFAULT_TRACKED_RULE.remediation,
          tags: ['security', 'CWE-538'],
          metadata: { kind: 'tracked_env' },
        }));
      }
    } else {
      notes.push(`tracked environment files were not checked: ${tracked.reason}`);
    }
  }

  const kept = [];
  let suppressed = 0;
  for (const finding of findings) {
    if (allowlistPaths.length > 0 && matchAny(allowlistPaths, finding.location.path)) {
      suppressed += 1;
      continue;
    }
    kept.push(finding);
  }
  if (suppressed > 0) {
    notes.push(`${suppressed} finding(s) were suppressed by the policy allow list.`);
  }

  sortFindings(kept);
  return {
    status: 'completed',
    findings: kept,
    notes,
    stats: buildStats(kept, files.length, scanned, inspected, dropped.length, unreadable),
  };
}

/**
 * Builds the statistics block of a scan.
 *
 * @param {object[]} findings
 * @param {number} files the number of files in scope.
 * @param {number} scanned the number of text files that were read.
 * @param {number} [inspected] the number of files that were opened.
 * @param {number} [dropped] the number of files the walk dropped.
 * @param {number} [unreadable] the number of files that could not be read.
 * @returns {object}
 */
function buildStats(findings, files, scanned, inspected = scanned, dropped = 0, unreadable = 0) {
  const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byRule = {};
  for (const finding of findings) {
    const severity = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : 'info';
    bySeverity[severity] += 1;
    byRule[finding.ruleId] = (byRule[finding.ruleId] || 0) + 1;
  }
  return {
    files,
    // The scope counts the files the walk dropped: they are files of the
    // repository that the scanner could not open.
    inScope: files + dropped,
    inspected,
    unreadable,
    scanned,
    dropped,
    findings: findings.length,
    bySeverity,
    byRule,
  };
}
