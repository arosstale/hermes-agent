/**
 * SAST engine.
 *
 * A small, predictable, line oriented regular expression engine. Every rule
 * of `rules/sast.yml` declares the languages it applies to, a pattern, a
 * severity, the weakness it maps to (CWE), a message and a remediation.
 *
 * The engine is deliberately boring:
 *
 *   - a rule applies to a file when the language detected from the file name
 *     is one of the languages of the rule;
 *   - the pattern is matched line by line (never across lines), so a match
 *     always has a precise line and column;
 *   - `exclude_patterns` suppress a whole line (a safe variant of a pattern
 *     does not produce a finding);
 *   - at most 200 findings are reported per rule and per scan; the overflow
 *     is reported as a note instead of being silently dropped.
 *
 * The engine never reports the source line: a finding carries the location,
 * the rule and the fix, never the matched text (which could contain a
 * credential).
 *
 * Signatures
 *   scanSast(root: string, opts?: {
 *     policy?: object,        // the security policy (paths)
 *     rules?: object,         // the SAST rule pack (rulePack is an alias)
 *     rulePack?: object,
 *     languages?: string[],   // restrict the scan to these languages
 *     ruleIds?: string[],     // restrict the scan to these rule ids
 *     maxFileBytes?: number,
 *     fs?: object,            // the file system seam (the real one by default)
 *   }): {
 *     status: "completed" | "skipped",
 *     findings: Finding[],
 *     notes: string[],
 *     stats: { files: number, inScope: number, inspected: number, scanned: number,
 *              dropped: number, findings: number, bySeverity: object, byRule: object },
 *   }
 *
 *   detectLanguage(relPath: string): string | null
 *
 * Fail closed
 *   An unreadable scan root raises an `E_IO` {@link KitError} and a rule pack
 *   that carries no rule raises an `E_RULES` {@link KitError}: the engine
 *   never reports "0 findings" for a tree it did not look at.
 *
 * A Finding is the model of plan section F:
 *   { id, ruleId, stage, severity, confidence, message,
 *     location: { path, startLine, endLine, column },
 *     fingerprint, redacted, remediation, tags, metadata }
 *
 * The findings are sorted by (path, line, ruleId, fingerprint), so two runs
 * over the same tree produce byte identical output.
 */

import { extname, join, resolve } from 'node:path';
import { KitError } from '../core/errors.js';
import { droppedNote, readTextSafe, walkTree } from '../core/fs-walk.js';
import { findingId, sha256Hex } from '../core/fingerprint.js';
import { maxFileBytesOf } from '../config/defaults.js';

/** The stage name used in the findings. */
export const STAGE = 'sast';

/** Severities, from the least to the most severe. */
export const SEVERITY_ORDER = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

/** Maximum number of findings reported per rule and per scan. */
export const MAX_FINDINGS_PER_RULE = 200;

/** The languages the engine knows about, by file extension. */
export const LANGUAGE_BY_EXTENSION = Object.freeze({
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.py': 'python',
  '.pyi': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.sh': 'bash',
  '.bash': 'bash',
});

/**
 * Detects the language of a file from its name.
 *
 * @param {string} relPath a POSIX relative path.
 * @returns {string|null} the language, or null when the file is not scanned.
 */
export function detectLanguage(relPath) {
  const extension = extname(String(relPath ?? '')).toLowerCase();
  if (!extension) return null;
  return LANGUAGE_BY_EXTENSION[extension] || null;
}

/**
 * Fingerprint of a finding that carries no secret value.
 *
 * The digest is computed over the location (path and line), so the same
 * finding keeps the same identifier across runs and reorderings.
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
    return new RegExp(pattern);
  } catch (err) {
    throw new KitError('E_RULES', `rule "${ruleId}" has an invalid pattern`, {
      ruleId,
      cause: err && err.message ? err.message : String(err),
    });
  }
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
    remediation: input.remediation,
    tags: input.tags,
    metadata: input.metadata,
  };
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
 * Scans a tree for the weaknesses described by the rule pack.
 *
 * @param {string} root the scan root.
 * @param {object} [opts] see the file header.
 * @returns {{ status: string, findings: object[], notes: string[], stats: object }}
 */
export function scanSast(root, opts = {}) {
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

  const languageFilter = Array.isArray(options.languages)
    ? options.languages.filter((item) => typeof item === 'string' && item !== '')
    : [];
  const ruleFilter = Array.isArray(options.ruleIds)
    ? options.ruleIds.filter((item) => typeof item === 'string' && item !== '')
    : [];

  const walked = walkTree(rootPath, { include, exclude, maxFileBytes: maxFileBytesOf(policy), fs: options.fs });
  const files = walked.files;
  if (walked.dropped.length > 0) {
    notes.push(droppedNote(walked.dropped));
  }

  const rawRules = pack && Array.isArray(pack.rules)
    ? pack.rules
    : (pack && Array.isArray(pack.providers) ? pack.providers : []);
  const allRules = rawRules.filter((rule) => rule && typeof rule === 'object' && typeof rule.id === 'string');
  const rules = allRules.filter((rule) => ruleFilter.length === 0 || ruleFilter.includes(rule.id));

  // A pack that carries no rule is a broken configuration, not a clean tree.
  if (allRules.length === 0) {
    throw new KitError('E_RULES', 'the SAST rule pack carries no detection rule: the engine refuses to run without one', {
      source: pack && typeof pack.source === 'string' ? pack.source : null,
    });
  }
  if (rules.length === 0) {
    throw new KitError('E_RULES', `no rule of the SAST pack matches the requested rule id(s): ${ruleFilter.join(', ')}`, {
      source: pack && typeof pack.source === 'string' ? pack.source : null,
      ruleIds: ruleFilter,
    });
  }

  const compiled = rules
    .map((rule) => ({
      rule,
      languages: Array.isArray(rule.languages) ? rule.languages : [],
      pattern: typeof rule.pattern === 'string' ? compilePattern(rule.pattern, rule.id) : null,
      excludes: Array.isArray(rule.exclude_patterns)
        ? rule.exclude_patterns.map((pattern) => compilePattern(pattern, rule.id))
        : [],
    }))
    .filter((entry) => entry.pattern !== null);

  const perRuleCount = new Map();
  let scanned = 0;
  let inspected = 0;
  // The files the engine could not open: they are part of the scope, and
  // the coverage floor counts them.
  let unreadable = 0;

  // The rules that apply to a language, computed once.
  const rulesByLanguage = new Map();
  for (const entry of compiled) {
    for (const language of entry.languages) {
      if (!rulesByLanguage.has(language)) rulesByLanguage.set(language, []);
      rulesByLanguage.get(language).push(entry);
    }
  }

  // The files the engine could look at: the ones whose language it knows and
  // for which the pack carries a rule. The files the walk dropped are part
  // of the scope as well: a file the engine could not open is not a file it
  // did not have to look at.
  const eligible = new Set();
  for (const relPath of [...files, ...walked.dropped.map((entry) => entry.path)]) {
    const language = detectLanguage(relPath);
    if (!language) continue;
    if (languageFilter.length > 0 && !languageFilter.includes(language)) continue;
    if (!rulesByLanguage.has(language)) continue;
    eligible.add(relPath);
  }

  for (const relPath of files) {
    const language = detectLanguage(relPath);
    if (!language) continue;
    if (languageFilter.length > 0 && !languageFilter.includes(language)) continue;

    const applicable = rulesByLanguage.get(language) || [];
    if (applicable.length === 0) continue;

    const { text, binary, error } = readTextSafe(join(rootPath, relPath), maxFileBytesOf(policy), options.fs);
    if (error) {
      notes.push(`${relPath}: ${error}`);
      unreadable += 1;
      continue;
    }
    inspected += 1;
    if (binary || text === '') continue;
    scanned += 1;

    const lines = text.split(/\r\n|\r|\n/);

    for (const entry of applicable) {
      const { rule } = entry;

      for (let index = 0; index < lines.length; index += 1) {
        const count = perRuleCount.get(rule.id) || 0;
        if (count >= MAX_FINDINGS_PER_RULE) break;
        const line = lines[index];
        if (line === '') continue;
        if (entry.excludes.some((exclude) => exclude.test(line))) continue;
        const match = entry.pattern.exec(line);
        if (!match) continue;

        const severity = SEVERITY_ORDER.includes(rule.severity) ? rule.severity : 'medium';
        const cwe = typeof rule.cwe === 'string' && rule.cwe !== '' ? rule.cwe : 'CWE-0';
        findings.push(makeFinding({
          ruleId: rule.id,
          severity,
          confidence: severity === 'critical' || severity === 'high' ? 'high' : 'medium',
          message: typeof rule.message === 'string' ? rule.message : `Rule ${rule.id} matched`,
          path: relPath,
          line: index + 1,
          column: match.index + 1,
          fingerprint: locationFingerprint(relPath, index + 1),
          remediation: typeof rule.remediation === 'string' ? rule.remediation : 'Review the flagged line.',
          tags: ['security', cwe],
          metadata: { language, cwe },
        }));

        perRuleCount.set(rule.id, count + 1);
        if (count + 1 === MAX_FINDINGS_PER_RULE) {
          notes.push(`rule "${rule.id}" reached the limit of ${MAX_FINDINGS_PER_RULE} findings; the extra matches were dropped.`);
        }
        // One finding per rule, file and line: the next line is checked too.
      }
    }
  }

  sortFindings(findings);
  return {
    status: 'completed',
    findings,
    notes,
    stats: buildStats(findings, files.length, scanned, inspected, eligible.size, walked.dropped.length, unreadable),
  };
}

/**
 * Builds the statistics block of a scan.
 *
 * @param {object[]} findings
 * @param {number} files the number of files in scope.
 * @param {number} scanned the number of text files that were read.
 * @param {number} [inspected] the number of files that were opened.
 * @param {number} [inScope] the number of files the engine could look at.
 * @param {number} [dropped] the number of files the walk dropped.
 * @param {number} [unreadable] the number of files that could not be read.
 * @returns {object}
 */
function buildStats(findings, files, scanned, inspected = scanned, inScope = files, dropped = 0, unreadable = 0) {
  const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byRule = {};
  for (const finding of findings) {
    const severity = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : 'info';
    bySeverity[severity] += 1;
    byRule[finding.ruleId] = (byRule[finding.ruleId] || 0) + 1;
  }
  return {
    files,
    inScope,
    inspected,
    unreadable,
    scanned,
    dropped,
    findings: findings.length,
    bySeverity,
    byRule,
  };
}
