/**
 * Dependency audit (offline first, optional online lookup).
 *
 * The scanner reads the manifests of a project, compares the declared
 * versions with a local advisory database and reports the dependencies that
 * fall inside a vulnerable range.
 *
 * Offline by default
 *   The default path never touches the network: the advisory database is the
 *   local file `policy/advisories.json` (or the list handed over by the
 *   caller). The online lookup against the OSV API exists only when it is
 *   explicitly asked for (`--online`), it has a hard timeout and every
 *   failure - network, timeout, HTTP error, malformed answer - is swallowed
 *   into a `skipped` status with a reason. The scan then continues with the
 *   offline result: a missing network never breaks a build.
 *
 * Signatures
 *   parsePackageJson(text: string): { deps: Dependency[], name: string, version: string }
 *   parsePackageLock(text: string): Dependency[]
 *   parseRequirementsTxt(text: string): Dependency[]
 *   parseGoMod(text: string): Dependency[]
 *   loadAdvisories(file: string): { version: number, updated: string, advisories: Advisory[] }
 *   compareVersions(a: string, b: string): number
 *   satisfiesRange(version: string, range: string): boolean
 *   rangesIntersect(a: string, b: string): boolean
 *   matchAdvisory(dep: Dependency, advisory: Advisory): boolean
 *   collectDependencies(root: string, opts?: object): {
 *     deps: Dependency[], manifests: string[], excluded: string[],
 *     broken: { name: string, problem: string, detail?: string }[],
 *     notes: string[], root: { name: string, version: string } }
 *   brokenManifestReason(broken: { name: string, problem: string }[]): string
 *   auditDependenciesOffline(root: string, opts?: object): {
 *     status: "completed" | "skipped", findings: Finding[], notes: string[],
 *     components: number, reason?: string }
 *   auditDependencies(root: string, opts?: object): Promise<{
 *     status: "completed" | "skipped", findings: Finding[], notes: string[],
 *     components: number, reason?: string,
 *     online?: { status: "completed" | "skipped", advisories: object[], reason?: string } }>
 *   queryOsvBatch(pkgs: { name: string, version: string, ecosystem: string }[],
 *                 opts?: { timeoutMs?: number, endpoint?: string, fetchImpl?: Function }):
 *     Promise<{ status: "completed" | "skipped", advisories: object[], reason?: string }>
 *
 * Also exported: `versionParts(value): number[]`, `isConcreteVersion(value):
 * boolean`, `dependencyFingerprint(advisoryId, name, version): string`, and the
 * constants `STAGE`, `RULE_ID`, `MANIFEST_FILES`, `OSV_ENDPOINT` and
 * `DEFAULT_TIMEOUT_MS`.
 *
 * A Dependency is `{ ecosystem: "npm" | "pypi" | "golang", name, version,
 * manifest, dev }`; an Advisory is `{ id, ecosystem, package, vulnerableRange,
 * severity, cwe, title, url }`; a Finding is the model of plan section F.
 *
 * A manifest that is there but cannot be used
 *   "There is nothing to audit" and "I could not read what there is to
 *   audit" are two different answers, and the second one must never be
 *   reported as the first one. A manifest that cannot be read, that is not
 *   a text file or that cannot be parsed is therefore reported as
 *   **broken**: the stage says so, and the gate turns it into a violation
 *   instead of a green "nothing to audit".
 *
 * The manifest of a dependency is the repository relative POSIX path of the
 * file the dependency was read from (`package-lock.json`, `requirements.txt`,
 * `go.mod`, ...).
 */

import { existsSync, readFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { join, resolve } from 'node:path';
import { KitError } from '../core/errors.js';
import { findingId, sha256Hex } from '../core/fingerprint.js';
import { readTextSafe } from '../core/fs-walk.js';
import { matchAny } from '../core/glob.js';
import { SEVERITY_ORDER } from '../policy/severity.js';

/** The stage name used in the findings. */
export const STAGE = 'deps';

/** The rule id of the findings of this stage. */
export const RULE_ID = 'deps.vulnerable-dependency';

/** The manifest files the scanner understands. */
export const MANIFEST_FILES = Object.freeze(['package.json', 'package-lock.json', 'requirements.txt', 'go.mod']);

/** The default endpoint of the online advisory service. */
export const OSV_ENDPOINT = 'https://api.osv.dev/v1/querybatch';

/** The default hard timeout of the online lookup, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 5000;

/** The ecosystem names used by the online advisory service. */
const OSV_ECOSYSTEM = Object.freeze({
  npm: 'npm',
  pypi: 'PyPI',
  golang: 'Go',
});

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
 * The numeric parts of a version.
 *
 * A leading `v` is dropped, the prerelease part is ignored and a missing
 * part counts as zero: `1.2` and `1.2.0` are the same version.
 *
 * @param {string} value
 * @returns {number[]}
 */
export function versionParts(value) {
  const text = String(value ?? '').trim().replace(/^v/i, '');
  const parts = [];
  for (const segment of text.split('.')) {
    const match = /^(\d+)/.exec(segment);
    if (!match) break;
    parts.push(Number(match[1]));
  }
  return parts;
}

/**
 * Compares two numeric version part lists.
 *
 * @param {number[]} a
 * @param {number[]} b
 * @returns {number} -1, 0 or 1.
 */
function compareParts(a, b) {
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index] === undefined ? 0 : a[index];
    const right = b[index] === undefined ? 0 : b[index];
    if (left < right) return -1;
    if (left > right) return 1;
  }
  return 0;
}

/**
 * Compares two versions.
 *
 * The comparison is numeric and dotted: the prerelease part is ignored, so
 * `1.2.3-beta` and `1.2.3` are equal and `1.10.0` is greater than `1.9.0`.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} -1 when a is lower than b, 0 when they are equal, 1 when
 *   a is greater than b.
 */
export function compareVersions(a, b) {
  return compareParts(versionParts(a), versionParts(b));
}

/**
 * Tells whether a version string is a concrete version (and not a range).
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isConcreteVersion(value) {
  return /^v?\d/.test(String(value ?? '').trim());
}

/**
 * The upper bound of a caret range.
 *
 * @param {number[]} parts
 * @returns {number[]}
 */
function caretUpperBound(parts) {
  const major = parts[0] === undefined ? 0 : parts[0];
  const minor = parts[1] === undefined ? 0 : parts[1];
  const patch = parts[2] === undefined ? 0 : parts[2];
  if (major > 0) return [major + 1];
  if (minor > 0) return [0, minor + 1];
  return [0, 0, patch + 1];
}

/**
 * The upper bound of a tilde range.
 *
 * @param {number[]} parts
 * @param {number} precision the number of numeric parts of the range.
 * @param {boolean} pessimistic true for the `~>` (pessimistic) operator.
 * @returns {number[]}
 */
function tildeUpperBound(parts, precision, pessimistic) {
  const major = parts[0] === undefined ? 0 : parts[0];
  const minor = parts[1] === undefined ? 0 : parts[1];
  if (precision <= 1) return [major + 1];
  if (pessimistic && precision === 2) return [major + 1];
  return [major, minor + 1];
}

/**
 * The number of numeric parts of a version string.
 *
 * @param {string} value
 * @returns {number}
 */
function precisionOf(value) {
  const text = String(value ?? '').trim().replace(/^v/i, '');
  let count = 0;
  for (const segment of text.split('.')) {
    if (!/^\d+/.test(segment)) break;
    count += 1;
  }
  return count;
}

/**
 * Checks a single comparator of a range against a version.
 *
 * @param {number[]} parts the parts of the version.
 * @param {string} token the comparator, e.g. `>=1.2.3`.
 * @returns {boolean}
 */
function satisfiesToken(parts, token) {
  const match = /^(\^|~>|~|>=|<=|==|!=|>|<|=)?\s*(.+)$/.exec(String(token ?? '').trim());
  if (!match) return false;
  const operator = match[1] === undefined ? '=' : match[1];
  const raw = match[2].trim();
  if (raw === '' || raw === '*' || raw.toLowerCase() === 'x') return true;
  const other = versionParts(raw);
  const comparison = compareParts(parts, other);
  switch (operator) {
    case '>':
      return comparison > 0;
    case '>=':
      return comparison >= 0;
    case '<':
      return comparison < 0;
    case '<=':
      return comparison <= 0;
    case '=':
    case '==':
      return comparison === 0;
    case '!=':
      return comparison !== 0;
    case '^':
      return comparison >= 0 && compareParts(parts, caretUpperBound(other)) < 0;
    case '~':
    case '~>':
      return comparison >= 0
        && compareParts(parts, tildeUpperBound(other, precisionOf(raw), operator === '~>')) < 0;
    default:
      return false;
  }
}

/**
 * Tells whether a version satisfies a range.
 *
 * The supported syntax is the one of the advisory database: `<`, `<=`, `>`,
 * `>=`, `=`, a space separated list of comparators (all of them must hold)
 * and `||` between alternatives (one of them must hold). The caret and the
 * tilde operators of the npm ranges are supported as well.
 *
 * @param {string} version the concrete version to test.
 * @param {string} range the range, e.g. `>=1.0.0 <2.0.0`.
 * @returns {boolean}
 */
export function satisfiesRange(version, range) {
  const parts = versionParts(version);
  const spec = String(range ?? '').trim();
  if (spec === '') return false;
  if (spec === '*' || spec.toLowerCase() === 'x') return true;
  return spec.split('||').some((alternative) => {
    const tokens = alternative.trim().split(/\s+/).filter((token) => token !== '');
    if (tokens.length === 0) return true;
    return tokens.every((token) => satisfiesToken(parts, token));
  });
}

/**
 * The bounds of a range.
 *
 * @param {string} range
 * @returns {{ min: number[]|null, max: number[]|null }}
 */
function rangeBounds(range) {
  const spec = String(range ?? '').trim();
  if (spec === '' || spec === '*' || spec.toLowerCase() === 'x') return { min: null, max: null };
  let min = null;
  let max = null;
  for (const alternative of spec.split('||')) {
    const tokens = alternative.trim().split(/\s+/).filter((token) => token !== '');
    let localMin = null;
    let localMax = null;
    for (const token of tokens) {
      const match = /^(\^|~>|~|>=|<=|==|!=|>|<|=)?\s*(.+)$/.exec(token.trim());
      if (!match) continue;
      const operator = match[1] === undefined ? '=' : match[1];
      const raw = match[2].trim();
      if (raw === '' || raw === '*' || raw.toLowerCase() === 'x') continue;
      const other = versionParts(raw);
      if (operator === '>=' || operator === '>') {
        if (localMin === null || compareParts(other, localMin) > 0) localMin = other;
      } else if (operator === '<=' || operator === '<') {
        if (localMax === null || compareParts(other, localMax) < 0) localMax = other;
      } else if (operator === '=' || operator === '==') {
        if (localMin === null || compareParts(other, localMin) > 0) localMin = other;
        if (localMax === null || compareParts(other, localMax) < 0) localMax = other;
      } else if (operator === '^') {
        if (localMin === null || compareParts(other, localMin) > 0) localMin = other;
        const upper = caretUpperBound(other);
        if (localMax === null || compareParts(upper, localMax) < 0) localMax = upper;
      } else if (operator === '~' || operator === '~>') {
        if (localMin === null || compareParts(other, localMin) > 0) localMin = other;
        const upper = tildeUpperBound(other, precisionOf(raw), operator === '~>');
        if (localMax === null || compareParts(upper, localMax) < 0) localMax = upper;
      }
    }
    if (localMin !== null && (min === null || compareParts(localMin, min) < 0)) min = localMin;
    if (localMax !== null && (max === null || compareParts(localMax, max) > 0)) max = localMax;
  }
  return { min, max };
}

/**
 * Tells whether two ranges overlap.
 *
 * The test is conservative: when the bounds touch, the ranges are reported
 * as overlapping. A range that overlaps a vulnerable range is reported, with
 * a message that says the declared range *intersects* the vulnerable one.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function rangesIntersect(a, b) {
  const left = rangeBounds(a);
  const right = rangeBounds(b);
  if (left.min !== null && right.max !== null && compareParts(left.min, right.max) > 0) return false;
  if (left.max !== null && right.min !== null && compareParts(left.max, right.min) < 0) return false;
  return true;
}

/**
 * Tells whether a dependency falls inside the vulnerable range of an
 * advisory.
 *
 * @param {object} dep
 * @param {object} advisory
 * @returns {boolean}
 */
export function matchAdvisory(dep, advisory) {
  if (!isPlainObject(dep) || !isPlainObject(advisory)) return false;
  const ecosystem = String(advisory.ecosystem ?? '').trim().toLowerCase();
  if (ecosystem !== dep.ecosystem) return false;
  const advisoryPackage = String(advisory.package ?? '').trim();
  if (advisoryPackage === '') return false;
  const left = dep.ecosystem === 'pypi' ? advisoryPackage.toLowerCase() : advisoryPackage;
  const right = dep.ecosystem === 'pypi' ? String(dep.name).toLowerCase() : String(dep.name);
  if (left !== right) return false;
  const range = String(advisory.vulnerableRange ?? '').trim();
  if (range === '') return false;
  const version = String(dep.version ?? '').trim();
  if (version === '') return false;
  if (isConcreteVersion(version)) return satisfiesRange(version, range);
  return rangesIntersect(version, range);
}

/**
 * Parses a `package.json` document.
 *
 * @param {string} text the content of the manifest.
 * @returns {{ deps: object[], name: string, version: string }}
 * @throws {KitError} with code `E_CONFIG` when the document is not valid JSON.
 */
export function parsePackageJson(text) {
  let doc;
  try {
    doc = JSON.parse(String(text ?? ''));
  } catch (err) {
    throw new KitError('E_CONFIG', 'the package.json manifest is not valid JSON', {
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!isPlainObject(doc)) {
    throw new KitError('E_CONFIG', 'the package.json manifest must contain an object');
  }
  const deps = [];
  const read = (section, dev) => {
    if (!isPlainObject(section)) return;
    for (const name of Object.keys(section).sort()) {
      const spec = section[name];
      deps.push({
        ecosystem: 'npm',
        name,
        version: typeof spec === 'string' ? spec.trim() : '',
        manifest: 'package.json',
        dev,
      });
    }
  };
  read(doc.dependencies, false);
  read(doc.devDependencies, true);
  return {
    deps,
    name: typeof doc.name === 'string' ? doc.name : '',
    version: typeof doc.version === 'string' ? doc.version : '',
  };
}

/**
 * Parses a `package-lock.json` document (lockfile version 1, 2 and 3).
 *
 * @param {string} text the content of the lock file.
 * @returns {object[]} the dependencies.
 * @throws {KitError} with code `E_CONFIG` when the document is not valid JSON.
 */
export function parsePackageLock(text) {
  let doc;
  try {
    doc = JSON.parse(String(text ?? ''));
  } catch (err) {
    throw new KitError('E_CONFIG', 'the package-lock.json manifest is not valid JSON', {
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!isPlainObject(doc)) {
    throw new KitError('E_CONFIG', 'the package-lock.json manifest must contain an object');
  }
  const deps = [];
  const packages = isPlainObject(doc.packages) ? doc.packages : null;
  if (packages !== null) {
    const keys = Object.keys(packages).sort();
    for (const key of keys) {
      if (key === '') continue;
      const marker = 'node_modules/';
      const index = key.lastIndexOf(marker);
      if (index === -1) continue;
      const name = key.slice(index + marker.length);
      if (name === '') continue;
      const entry = packages[key];
      if (!isPlainObject(entry)) continue;
      const version = typeof entry.version === 'string' ? entry.version.trim() : '';
      if (version === '') continue;
      deps.push({
        ecosystem: 'npm',
        name,
        version,
        manifest: 'package-lock.json',
        dev: entry.dev === true,
      });
    }
    return deps;
  }
  const walk = (section) => {
    if (!isPlainObject(section)) return;
    for (const name of Object.keys(section).sort()) {
      const entry = section[name];
      if (!isPlainObject(entry)) continue;
      const version = typeof entry.version === 'string' ? entry.version.trim() : '';
      if (version !== '') {
        deps.push({
          ecosystem: 'npm',
          name,
          version,
          manifest: 'package-lock.json',
          dev: entry.dev === true,
        });
      }
      walk(entry.dependencies);
    }
  };
  walk(doc.dependencies);
  return deps;
}

/**
 * Parses a `requirements.txt` document.
 *
 * The version of a dependency is the pinned version when the requirement is
 * pinned (`==`) and the raw specifier otherwise (`>=2.30.0`), so that the
 * offline matcher can compare a declared range with a vulnerable range.
 *
 * @param {string} text the content of the requirements file.
 * @returns {object[]} the dependencies.
 */
export function parseRequirementsTxt(text) {
  const deps = [];
  const lines = String(text ?? '').split(/\r?\n/);
  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    if (line.startsWith('-')) continue;
    const comment = line.indexOf(' #');
    if (comment !== -1) line = line.slice(0, comment).trim();
    const marker = line.indexOf(';');
    if (marker !== -1) line = line.slice(0, marker).trim();
    const extras = line.indexOf('[');
    if (extras !== -1) {
      const close = line.indexOf(']', extras);
      line = close === -1 ? line.slice(0, extras) : line.slice(0, extras) + line.slice(close + 1);
    }
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|>=|<=|~=|!=|>|<|=)?\s*(.*)$/.exec(line);
    if (!match) continue;
    const name = match[1];
    const operator = match[2] === undefined ? '' : match[2];
    const value = match[3].trim();
    if (value === '') continue;
    const version = operator === '==' ? value : `${operator}${value}`;
    deps.push({
      ecosystem: 'pypi',
      name,
      version,
      manifest: 'requirements.txt',
      dev: false,
    });
  }
  return deps;
}

/**
 * Parses a `go.mod` document.
 *
 * @param {string} text the content of the module file.
 * @returns {object[]} the dependencies.
 */
export function parseGoMod(text) {
  const deps = [];
  const lines = String(text ?? '').split(/\r?\n/);
  let inBlock = false;
  for (const rawLine of lines) {
    let line = rawLine.trim();
    if (line === '' || line.startsWith('//')) continue;
    if (inBlock) {
      if (line === ')') {
        inBlock = false;
        continue;
      }
    } else if (line.startsWith('require (')) {
      inBlock = true;
      continue;
    } else if (line.startsWith('require ')) {
      line = line.slice('require '.length).trim();
    } else {
      continue;
    }
    const comment = line.indexOf('//');
    if (comment !== -1) line = line.slice(0, comment).trim();
    const parts = line.split(/\s+/).filter((part) => part !== '');
    if (parts.length < 2) continue;
    const name = parts[0];
    const version = parts[1];
    if (!version.startsWith('v')) continue;
    deps.push({
      ecosystem: 'golang',
      name,
      version,
      manifest: 'go.mod',
      dev: false,
    });
  }
  return deps;
}

/**
 * Loads the local advisory database.
 *
 * @param {string} file the path of the JSON file.
 * @returns {{ version: number, updated: string, advisories: object[] }}
 * @throws {KitError} with code `E_CONFIG` when the file cannot be read or is
 *   not valid JSON.
 */
export function loadAdvisories(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new KitError('E_CONFIG', `the advisory database ${file} cannot be read`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new KitError('E_CONFIG', `the advisory database ${file} is not valid JSON`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!isPlainObject(doc)) {
    throw new KitError('E_CONFIG', `the advisory database ${file} must contain an object`, { file });
  }
  const advisories = Array.isArray(doc.advisories) ? doc.advisories : [];
  return {
    version: typeof doc.version === 'number' ? doc.version : 1,
    updated: typeof doc.updated === 'string' ? doc.updated : '',
    advisories,
  };
}

/**
 * Reads a manifest of the root.
 *
 * The three cases are told apart, because they are not the same case:
 *
 *   - `absent`: the tree does not hold that manifest;
 *   - `excluded`: the tree holds it and the policy keeps it out of the
 *     scope. A manifest that the policy hid is **not** an absent manifest:
 *     "there is nothing to audit" and "the policy hid what there is to
 *     audit" lead to two different verdicts;
 *   - `unreadable` / `binary`: the manifest is there but cannot be read.
 *
 * @param {string} root the absolute scan root.
 * @param {string} name the POSIX relative name of the manifest.
 * @param {string[]} exclude the excluded paths.
 * @param {string[]} notes the notes of the scan.
 * @returns {{ status: string, text: string }} the status and the content.
 */
function readManifest(root, name, exclude, notes) {
  const file = join(root, ...name.split('/'));
  if (!existsSync(file)) return { status: 'absent', text: '' };
  if (exclude.length > 0 && matchAny(exclude, name)) {
    notes.push(`${name} is excluded by the policy: the dependency manifest is out of scope.`);
    return { status: 'excluded', text: '' };
  }
  const { text, error, binary } = readTextSafe(file);
  if (error) {
    notes.push(`${name}: ${error}`);
    return { status: 'unreadable', text: '' };
  }
  if (binary) {
    notes.push(`${name}: the file is not a text file and was skipped.`);
    return { status: 'binary', text: '' };
  }
  return { status: 'ok', text };
}

/**
 * The reason of a stage whose manifest is there but cannot be used.
 *
 * The reason never says that the stage is not applicable: the manifest
 * **is** there, the kit simply could not read it. The wording is the one
 * the gate and the summary show to the reader.
 *
 * @param {{ name: string, problem: string }[]} broken the broken manifests.
 * @returns {string} the reason; an empty string when nothing is broken.
 */
export function brokenManifestReason(broken) {
  const list = Array.isArray(broken) ? broken.filter((entry) => entry && typeof entry.name === 'string') : [];
  if (list.length === 0) return '';
  const names = (problem) => list
    .filter((entry) => entry.problem === problem)
    .map((entry) => entry.name)
    .sort();
  const parts = [];
  const unreadable = names('unreadable');
  if (unreadable.length > 0) {
    parts.push(`the dependency manifest could not be read: ${unreadable.join(', ')}`);
  }
  const binary = names('binary');
  if (binary.length > 0) {
    parts.push(`the dependency manifest is not a text file: ${binary.join(', ')}`);
  }
  const invalid = names('invalid');
  if (invalid.length > 0) {
    parts.push(`the dependency manifest could not be parsed: ${invalid.join(', ')}`);
  }
  return parts.join('; ');
}

/**
 * Collects the dependencies declared by the manifests of a root.
 *
 * The lock file wins over the manifest when both are present: the lock file
 * carries the versions that are actually installed.
 *
 * @param {string} root the scan root.
 * @param {object} [opts]
 * @param {object} [opts.policy] the security policy (paths).
 * @returns {{ deps: object[], manifests: string[], excluded: string[], broken: object[], notes: string[], root: object }}
 */
export function collectDependencies(root, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const policy = isPlainObject(options.policy) ? options.policy : {};
  const paths = isPlainObject(policy.paths) ? policy.paths : {};
  const exclude = Array.isArray(paths.exclude) ? paths.exclude : [];
  const rootPath = resolve(String(root ?? '.'));
  const notes = [];
  const deps = [];
  const manifests = [];
  const excluded = [];
  // The manifests that are there but cannot be used: they are not absent
  // manifests, and the stage has to say so.
  const broken = [];
  const project = { name: '', version: '' };

  let packageDeps = [];
  let hasManifest = false;
  const packageManifest = readManifest(rootPath, 'package.json', exclude, notes);
  if (packageManifest.status === 'excluded') excluded.push('package.json');
  if (packageManifest.status === 'unreadable' || packageManifest.status === 'binary') {
    broken.push({ name: 'package.json', problem: packageManifest.status });
  }
  if (packageManifest.status === 'ok') {
    hasManifest = true;
    try {
      const parsed = parsePackageJson(packageManifest.text);
      project.name = parsed.name;
      project.version = parsed.version;
      packageDeps = parsed.deps;
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      notes.push(`package.json: ${detail}`);
      broken.push({ name: 'package.json', problem: 'invalid', detail });
    }
  }

  let lockDeps = null;
  const lockManifest = readManifest(rootPath, 'package-lock.json', exclude, notes);
  if (lockManifest.status === 'excluded') excluded.push('package-lock.json');
  if (lockManifest.status === 'unreadable' || lockManifest.status === 'binary') {
    broken.push({ name: 'package-lock.json', problem: lockManifest.status });
  }
  if (lockManifest.status === 'ok') {
    try {
      lockDeps = parsePackageLock(lockManifest.text);
      manifests.push('package-lock.json');
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      notes.push(`package-lock.json: ${detail}`);
      broken.push({ name: 'package-lock.json', problem: 'invalid', detail });
    }
  }

  if (lockDeps !== null) {
    // The lock file wins: it carries the versions that are installed.
    deps.push(...lockDeps);
  } else if (hasManifest) {
    manifests.push('package.json');
    deps.push(...packageDeps);
  }

  const requirementsManifest = readManifest(rootPath, 'requirements.txt', exclude, notes);
  if (requirementsManifest.status === 'excluded') excluded.push('requirements.txt');
  if (requirementsManifest.status === 'unreadable' || requirementsManifest.status === 'binary') {
    broken.push({ name: 'requirements.txt', problem: requirementsManifest.status });
  }
  if (requirementsManifest.status === 'ok') {
    manifests.push('requirements.txt');
    deps.push(...parseRequirementsTxt(requirementsManifest.text));
  }

  const goModManifest = readManifest(rootPath, 'go.mod', exclude, notes);
  if (goModManifest.status === 'excluded') excluded.push('go.mod');
  if (goModManifest.status === 'unreadable' || goModManifest.status === 'binary') {
    broken.push({ name: 'go.mod', problem: goModManifest.status });
  }
  if (goModManifest.status === 'ok') {
    manifests.push('go.mod');
    deps.push(...parseGoMod(goModManifest.text));
  }

  return { deps, manifests, excluded, broken, notes, root: project };
}

/**
 * The fingerprint of a dependency finding.
 *
 * @param {string} advisoryId the identifier of the advisory.
 * @param {string} name the name of the package.
 * @param {string} version the version of the package.
 * @returns {string}
 */
export function dependencyFingerprint(advisoryId, name, version) {
  const key = `${String(advisoryId ?? '')}\u0000${String(name ?? '')}\u0000${String(version ?? '')}`;
  const digest = sha256Hex(key).slice(0, 12);
  const prefix = String(name ?? '').slice(0, 4).replace(/[^\x20-\x7e]/g, '*');
  return `sha256:${digest}:len:${String(version ?? '').length}:pfx:${prefix}`;
}

/**
 * Builds a finding of the model of plan section F.
 *
 * @param {object} input
 * @returns {object}
 */
function makeFinding(input) {
  return {
    id: findingId(RULE_ID, input.fingerprint),
    ruleId: RULE_ID,
    stage: STAGE,
    severity: input.severity,
    confidence: 'high',
    message: input.message,
    location: {
      path: input.path,
      startLine: 1,
      endLine: 1,
      column: 1,
    },
    fingerprint: input.fingerprint,
    redacted: false,
    snippet: input.snippet,
    remediation: input.remediation,
    tags: input.tags,
    metadata: input.metadata,
  };
}

/**
 * Normalises a severity.
 *
 * @param {string} value
 * @param {string} fallback
 * @returns {string}
 */
function normalizeSeverity(value, fallback) {
  const text = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (SEVERITY_ORDER.includes(text)) return text;
  return fallback;
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
 * Runs the offline audit of the dependencies of a root.
 *
 * @param {string} root the scan root.
 * @param {object} [opts]
 * @param {object} [opts.policy] the security policy (paths).
 * @param {object[]} [opts.advisories] the advisory database.
 * @returns {{ status: string, findings: object[], notes: string[], components: number, reason?: string }}
 */
export function auditDependenciesOffline(root, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const advisories = Array.isArray(options.advisories) ? options.advisories : [];
  const collected = collectDependencies(root, { policy: options.policy });
  const notes = collected.notes.slice();
  const findings = [];

  // A manifest that is there but cannot be read, that is not a text file or
  // that cannot be parsed is **not** an absent manifest: the tree holds it,
  // and the dependency audit of the tree is therefore impossible. The stage
  // says exactly that, and the gate turns it into a violation instead of a
  // green "nothing to audit".
  if (collected.broken.length > 0) {
    return {
      status: 'skipped',
      findings,
      notes,
      components: collected.deps.length,
      reason: brokenManifestReason(collected.broken),
    };
  }

  // A manifest that the policy keeps out of the scope is not an absent
  // manifest: the tree holds it, and the dependency audit of the tree is
  // therefore incomplete. The stage says exactly that, and the gate turns
  // it into a violation instead of a green "nothing to audit".
  if (collected.excluded.length > 0) {
    return {
      status: 'skipped',
      findings,
      notes,
      components: collected.deps.length,
      reason: `the dependency manifest is excluded by the policy: ${collected.excluded.join(', ')}`,
    };
  }

  if (collected.manifests.length === 0) {
    return {
      status: 'skipped',
      findings,
      notes,
      components: 0,
      // The stage is not applicable: the tree holds no dependency manifest
      // to audit. The reason says so explicitly, and it is the one reason
      // that does not fail the gate (the aggregate `scan` and the
      // standalone `deps` treat the very same tree the very same way).
      reason: 'not applicable: no dependency manifest in the tree',
    };
  }

  for (const dep of collected.deps) {
    for (const advisory of advisories) {
      if (!matchAdvisory(dep, advisory)) continue;
      const advisoryId = String(advisory.id ?? 'unknown');
      const severity = normalizeSeverity(advisory.severity, 'high');
      const cwe = typeof advisory.cwe === 'string' && advisory.cwe !== '' ? advisory.cwe : 'CWE-0';
      const title = typeof advisory.title === 'string' && advisory.title !== '' ? advisory.title : 'Vulnerable dependency';
      const range = String(advisory.vulnerableRange ?? '');
      const concrete = isConcreteVersion(dep.version);
      const message = concrete
        ? `${title} (${advisoryId})`
        : `${title} (${advisoryId}): the declared range intersects ${range}`;
      findings.push(makeFinding({
        severity,
        message,
        path: dep.manifest,
        fingerprint: dependencyFingerprint(advisoryId, dep.name, dep.version),
        snippet: `${dep.name}@${dep.version}`,
        remediation: `Upgrade ${dep.name} to a version that is outside ${range}.`,
        tags: ['security', cwe],
        metadata: {
          ecosystem: dep.ecosystem,
          package: dep.name,
          version: dep.version,
          advisoryId,
          vulnerableRange: range,
          dev: dep.dev === true,
          source: 'offline',
        },
      }));
    }
  }

  sortFindings(findings);
  return {
    status: 'completed',
    findings,
    notes,
    components: collected.deps.length,
  };
}

/**
 * The default transport of the online lookup: a POST over HTTPS with a hard
 * timeout.
 *
 * @param {string} endpoint the URL of the service.
 * @param {string} body the JSON body.
 * @param {number} timeoutMs the hard timeout.
 * @returns {Promise<{ statusCode: number, body: string }>}
 */
function osvPost(endpoint, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      reject(new Error('the advisory endpoint is not a valid URL'));
      return;
    }
    const payload = Buffer.from(body, 'utf8');
    const req = httpsRequest({
      hostname: url.hostname,
      port: url.port === '' ? undefined : Number(url.port),
      path: `${url.pathname}${url.search}`,
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'content-length': payload.length,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`the request timed out after ${timeoutMs} ms`));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

/**
 * The severity of an advisory of the online service.
 *
 * @param {object} vuln
 * @returns {string}
 */
function osvSeverity(vuln) {
  const details = isPlainObject(vuln) && isPlainObject(vuln.database_specific) ? vuln.database_specific : null;
  if (details !== null && typeof details.severity === 'string') {
    const text = details.severity.trim().toLowerCase();
    if (SEVERITY_ORDER.includes(text)) return text;
    if (text === 'moderate') return 'medium';
  }
  return 'medium';
}

/**
 * Queries the online advisory service.
 *
 * Every failure - an unreachable host, a timeout, a non 2xx answer, an
 * answer that is not JSON - is swallowed into a `skipped` status with a
 * reason. The function never throws and never rejects.
 *
 * @param {object[]} pkgs the packages to query.
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] the hard timeout (default 5000).
 * @param {string} [opts.endpoint] the URL of the service.
 * @param {Function} [opts.fetchImpl] an injectable transport, used by the
 *   tests to simulate an unreachable network.
 * @returns {Promise<{ status: string, advisories: object[], reason?: string }>}
 */
export async function queryOsvBatch(pkgs, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const timeoutMs = typeof options.timeoutMs === 'number' && options.timeoutMs > 0
    ? options.timeoutMs
    : DEFAULT_TIMEOUT_MS;
  const endpoint = typeof options.endpoint === 'string' && options.endpoint !== ''
    ? options.endpoint
    : OSV_ENDPOINT;
  const transport = typeof options.fetchImpl === 'function' ? options.fetchImpl : osvPost;
  const list = Array.isArray(pkgs)
    ? pkgs.filter((entry) => isPlainObject(entry)
      && typeof entry.name === 'string' && entry.name !== ''
      && typeof entry.version === 'string' && entry.version !== '')
    : [];

  if (list.length === 0) {
    return { status: 'completed', advisories: [] };
  }

  const body = JSON.stringify({
    queries: list.map((entry) => ({
      package: {
        name: entry.name,
        ecosystem: OSV_ECOSYSTEM[entry.ecosystem] || String(entry.ecosystem ?? ''),
      },
      version: entry.version,
    })),
  });

  let response;
  try {
    response = await transport(endpoint, body, timeoutMs);
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { status: 'skipped', advisories: [], reason: `the advisory service is not reachable: ${message}` };
  }

  if (!isPlainObject(response) || typeof response.statusCode !== 'number') {
    return { status: 'skipped', advisories: [], reason: 'the advisory service returned an unusable answer' };
  }
  if (response.statusCode < 200 || response.statusCode >= 300) {
    return {
      status: 'skipped',
      advisories: [],
      reason: `the advisory service answered with HTTP ${response.statusCode}`,
    };
  }

  let doc;
  try {
    doc = JSON.parse(String(response.body ?? ''));
  } catch (err) {
    return {
      status: 'skipped',
      advisories: [],
      reason: `the advisory service returned an answer that is not JSON: ${err && err.message ? err.message : String(err)}`,
    };
  }

  const results = isPlainObject(doc) && Array.isArray(doc.results) ? doc.results : [];
  const advisories = [];
  results.forEach((result, index) => {
    const vulns = isPlainObject(result) && Array.isArray(result.vulns) ? result.vulns : [];
    const pkg = list[index] === undefined ? null : list[index];
    for (const vuln of vulns) {
      if (!isPlainObject(vuln)) continue;
      const summary = typeof vuln.summary === 'string' && vuln.summary !== ''
        ? vuln.summary
        : (typeof vuln.details === 'string' ? vuln.details : '');
      advisories.push({
        id: typeof vuln.id === 'string' && vuln.id !== '' ? vuln.id : 'OSV-unknown',
        package: pkg === null ? '' : pkg.name,
        severity: osvSeverity(vuln),
        summary: summary.slice(0, 200),
      });
    }
  });

  return { status: 'completed', advisories };
}

/**
 * Runs the dependency audit, with the optional online lookup.
 *
 * @param {string} root the scan root.
 * @param {object} [opts]
 * @param {object} [opts.policy] the security policy (paths).
 * @param {object[]} [opts.advisories] the offline advisory database.
 * @param {boolean} [opts.online] ask for the online lookup (default false).
 * @param {number} [opts.timeoutMs] the hard timeout of the online lookup.
 * @param {Function} [opts.queryOsv] an injectable online lookup, used by the
 *   tests; it is never called when `online` is false.
 * @param {Function} [opts.fetchImpl] an injectable transport for the default
 *   online lookup.
 * @returns {Promise<object>} the result of the audit.
 */
export async function auditDependencies(root, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const offline = auditDependenciesOffline(root, options);
  const notes = offline.notes.slice();
  const findings = offline.findings.slice();

  if (options.online !== true) {
    return { ...offline, notes, findings };
  }

  const collected = collectDependencies(root, { policy: options.policy });
  const packages = collected.deps
    .filter((dep) => isConcreteVersion(dep.version))
    .map((dep) => ({ name: dep.name, version: dep.version, ecosystem: dep.ecosystem }));

  if (packages.length === 0) {
    const reason = 'the online lookup was skipped: no dependency with a concrete version was found';
    notes.push(reason);
    return { ...offline, notes, findings, online: { status: 'skipped', advisories: [], reason } };
  }

  const query = typeof options.queryOsv === 'function' ? options.queryOsv : queryOsvBatch;
  let result;
  try {
    result = await query(packages, {
      timeoutMs: options.timeoutMs,
      endpoint: options.endpoint,
      fetchImpl: options.fetchImpl,
    });
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    result = { status: 'skipped', advisories: [], reason: `the advisory lookup failed: ${message}` };
  }

  if (!isPlainObject(result) || result.status !== 'completed') {
    const reason = isPlainObject(result) && typeof result.reason === 'string' && result.reason !== ''
      ? result.reason
      : 'the advisory lookup did not complete';
    notes.push(`the online advisory lookup was skipped: ${reason}`);
    return {
      ...offline,
      notes,
      findings,
      online: { status: 'skipped', advisories: [], reason },
    };
  }

  const advisories = Array.isArray(result.advisories) ? result.advisories : [];
  const byPackage = new Map();
  for (const dep of collected.deps) {
    byPackage.set(`${dep.ecosystem}:${dep.name}`, dep);
  }
  const seen = new Set(findings.map((finding) => `${finding.metadata.advisoryId}:${finding.metadata.package}`));
  for (const advisory of advisories) {
    if (!isPlainObject(advisory)) continue;
    const name = String(advisory.package ?? '');
    const dep = byPackage.get(`npm:${name}`) || byPackage.get(`pypi:${name}`) || byPackage.get(`golang:${name}`);
    if (dep === undefined) continue;
    const advisoryId = String(advisory.id ?? 'OSV-unknown');
    const key = `${advisoryId}:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const severity = normalizeSeverity(advisory.severity, 'medium');
    const summary = String(advisory.summary ?? '').trim();
    findings.push(makeFinding({
      severity,
      message: summary === '' ? `Advisory ${advisoryId}` : `${summary} (${advisoryId})`,
      path: dep.manifest,
      fingerprint: dependencyFingerprint(advisoryId, dep.name, dep.version),
      snippet: `${dep.name}@${dep.version}`,
      remediation: `Upgrade ${dep.name} to a version that is not affected by ${advisoryId}.`,
      tags: ['security', 'CWE-0'],
      metadata: {
        ecosystem: dep.ecosystem,
        package: dep.name,
        version: dep.version,
        advisoryId,
        dev: dep.dev === true,
        source: 'online',
      },
    }));
  }

  sortFindings(findings);
  return {
    status: offline.status,
    findings,
    notes,
    components: offline.components,
    online: { status: 'completed', advisories },
  };
}
