/**
 * CycloneDX software bill of materials.
 *
 * The builder produces a small, deterministic CycloneDX 1.5 document:
 *
 *   - the components come from `package.json`, `package-lock.json`,
 *     `requirements.txt` and `go.mod`; the lock file wins over the manifest
 *     when both are present, because the lock file carries the versions that
 *     are actually installed;
 *   - the components are sorted by (ecosystem, name, version), so two runs
 *     over the same tree produce byte identical documents;
 *   - the serial number is derived from the digest of the components, so it
 *     is stable as well;
 *   - there is **no timestamp** in the document, unless the caller injects
 *     one explicitly (`opts.now`). A bill of materials that changes on every
 *     run cannot be diffed.
 *
 * Signatures
 *   buildSbom(root: string, opts?: {
 *     enrich?: boolean,      // ask npm for the licenses of the tree
 *     now?: string | number | Date,  // the only way to get a timestamp
 *     policy?: object,       // the security policy (paths)
 *     npmLs?: Function,      // an injectable `npm ls` runner
 *     tool?: { name?: string, version?: string },
 *   }): {
 *     status: "completed" | "skipped",
 *     bom: object,
 *     components: number,
 *     notes: string[],
 *     digest: string,
 *     reason?: string,
 *   }
 *
 *   componentDigest(components: { name: string, version: string, ecosystem: string }[]): string
 *   purlFor(ecosystem: string, name: string, version: string): string
 *   serialNumberFor(digest: string): string
 *   licensesFromNpmLs(text: string): Record<string, string[]>
 *   toolVersion(): string
 *   kitRoot(): string
 *
 * Also exported: `TOOL_NAME` (the name of the producer), `SPEC_VERSION`
 * (the CycloneDX specification version produced here).
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { collectDependencies, isConcreteVersion, brokenManifestReason } from './deps.js';
import { sha256Hex } from '../core/fingerprint.js';

/** The name of the producer of the bill of materials. */
export const TOOL_NAME = 'devsecops-kit';

/** The CycloneDX specification version produced by the builder. */
export const SPEC_VERSION = '1.5';

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
 * The version of the kit, read from its own manifest.
 *
 * @returns {string}
 */
export function toolVersion() {
  try {
    const manifest = fileURLToPath(new URL('../../package.json', import.meta.url));
    const doc = JSON.parse(readFileSync(manifest, 'utf8'));
    return typeof doc.version === 'string' && doc.version !== '' ? doc.version : '1.0.0';
  } catch {
    return '1.0.0';
  }
}

/**
 * The package URL of a component.
 *
 * @param {string} ecosystem `npm`, `pypi` or `golang`.
 * @param {string} name the name of the package.
 * @param {string} version the version of the package.
 * @returns {string} e.g. `pkg:npm/lodash@4.17.20`.
 */
export function purlFor(ecosystem, name, version) {
  const type = ecosystem === 'pypi' ? 'pypi' : (ecosystem === 'golang' ? 'golang' : 'npm');
  const encoded = String(name ?? '')
    .split('/')
    .map((segment) => segment.replace(/@/g, '%40'))
    .join('/');
  return `pkg:${type}/${encoded}@${String(version ?? '')}`;
}

/**
 * The digest of a list of components.
 *
 * The digest covers the (ecosystem, name, version) triples only, sorted, so
 * that an enrichment (a license, a resolved url) never changes it.
 *
 * @param {object[]} components
 * @returns {string} the lowercase hexadecimal SHA-256 of the components.
 */
export function componentDigest(components) {
  const list = Array.isArray(components) ? components : [];
  const lines = list
    .filter((entry) => isPlainObject(entry))
    .map((entry) => `${String(entry.ecosystem ?? '')}:${String(entry.name ?? '')}@${String(entry.version ?? '')}`)
    .sort();
  return sha256Hex(lines.join('\n'));
}

/**
 * The serial number of the document, derived from the digest.
 *
 * @param {string} digest the digest of the components.
 * @returns {string} e.g. `urn:uuid:0123456789ab-cdef-0123-4567-0123456789ab`.
 */
export function serialNumberFor(digest) {
  const hex = String(digest ?? '').replace(/[^0-9a-f]/g, '');
  const padded = (hex + '0'.repeat(36)).slice(0, 36);
  const parts = [padded.slice(0, 12), padded.slice(12, 16), padded.slice(16, 20), padded.slice(20, 24), padded.slice(24, 36)];
  return `urn:uuid:${parts.join('-')}`;
}

/**
 * The default runner of the enrichment: `npm ls --json --long`.
 *
 * The runner never installs anything and never reaches the network; when npm
 * is missing or fails, the caller turns the failure into a note.
 *
 * @param {string} root the scan root.
 * @returns {string} the JSON output of npm.
 */
function defaultNpmLs(root) {
  return execFileSync('npm', ['ls', '--json', '--long'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 20000,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024 * 1024,
  });
}

/**
 * Reads the licenses of the tree from the output of `npm ls --json --long`.
 *
 * @param {string} text the JSON output of npm.
 * @returns {Record<string, string[]>} the licenses per package name.
 */
export function licensesFromNpmLs(text) {
  const licenses = {};
  let doc;
  try {
    doc = JSON.parse(String(text ?? ''));
  } catch {
    return licenses;
  }
  const walk = (node) => {
    if (!isPlainObject(node)) return;
    const dependencies = isPlainObject(node.dependencies) ? node.dependencies : {};
    for (const name of Object.keys(dependencies).sort()) {
      const entry = dependencies[name];
      if (!isPlainObject(entry)) continue;
      const names = [];
      if (typeof entry.license === 'string' && entry.license !== '') names.push(entry.license);
      if (isPlainObject(entry.license) && typeof entry.license.type === 'string') names.push(entry.license.type);
      if (names.length > 0 && licenses[name] === undefined) licenses[name] = names.sort();
      walk(entry);
    }
  };
  walk(doc);
  return licenses;
}

/**
 * Builds the bill of materials of a tree.
 *
 * @param {string} root the scan root.
 * @param {object} [opts] see the file header.
 * @returns {{ status: string, bom: object, components: number, notes: string[], digest: string, reason?: string }}
 */
export function buildSbom(root, opts = {}) {
  const options = isPlainObject(opts) ? opts : {};
  const notes = [];
  const collected = collectDependencies(root, { policy: options.policy });

  for (const note of collected.notes) notes.push(note);

  // A manifest that is there but cannot be read, that is not a text file or
  // that cannot be parsed is not an absent manifest: the bill of materials
  // would describe a tree whose dependency graph is unknown, and the gate
  // has to say so instead of shipping an empty document.
  if (collected.broken.length > 0) {
    return {
      status: 'skipped',
      bom: {},
      components: 0,
      notes,
      digest: componentDigest([]),
      reason: brokenManifestReason(collected.broken),
    };
  }

  // A manifest that the policy keeps out of the scope is not an absent
  // manifest: the bill of materials would describe a tree whose dependency
  // graph is only partly known, and the gate has to say so.
  if (collected.excluded.length > 0) {
    return {
      status: 'skipped',
      bom: {},
      components: 0,
      notes,
      digest: componentDigest([]),
      reason: `the dependency manifest is excluded by the policy: ${collected.excluded.join(', ')}`,
    };
  }

  if (collected.manifests.length === 0) {
    return {
      status: 'skipped',
      bom: {},
      components: 0,
      notes,
      digest: componentDigest([]),
      // The stage is not applicable: the tree holds no dependency manifest
      // to describe. The reason says so explicitly, and it is the one reason
      // that does not fail the gate (the aggregate `scan` and the
      // standalone `sbom` treat the very same tree the very same way).
      reason: 'not applicable: no dependency manifest in the tree',
    };
  }

  const entries = [];
  let ranged = 0;
  for (const dep of collected.deps) {
    if (!isConcreteVersion(dep.version)) ranged += 1;
    entries.push({
      ecosystem: dep.ecosystem,
      name: dep.name,
      version: dep.version,
      dev: dep.dev === true,
    });
  }
  if (ranged > 0) {
    notes.push(`${ranged} dependency/dependencies declare a range instead of a version: the range is kept as it is.`);
  }

  const unique = new Map();
  for (const entry of entries) {
    const key = `${entry.ecosystem}:${entry.name}@${entry.version}`;
    if (!unique.has(key)) unique.set(key, entry);
  }
  const sorted = [...unique.values()].sort((a, b) => {
    if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    if (a.version !== b.version) return a.version < b.version ? -1 : 1;
    return 0;
  });

  const licenses = {};
  if (options.enrich === true) {
    const runner = typeof options.npmLs === 'function' ? options.npmLs : defaultNpmLs;
    try {
      const output = runner(String(root ?? '.'));
      Object.assign(licenses, licensesFromNpmLs(output));
    } catch (err) {
      notes.push(`the enrichment was skipped: ${err && err.message ? err.message : String(err)}`);
    }
  }

  const components = sorted.map((entry) => {
    const component = {
      type: 'library',
      name: entry.name,
      version: entry.version,
      purl: purlFor(entry.ecosystem, entry.name, entry.version),
      scope: entry.dev ? 'dev' : 'required',
    };
    const names = licenses[entry.name];
    if (Array.isArray(names) && names.length > 0) {
      component.licenses = names.map((name) => ({ license: { name } }));
    }
    return component;
  });

  const digest = componentDigest(sorted);
  const tool = isPlainObject(options.tool) ? options.tool : {};
  const metadata = {
    tools: [{
      vendor: TOOL_NAME,
      name: typeof tool.name === 'string' && tool.name !== '' ? tool.name : TOOL_NAME,
      version: typeof tool.version === 'string' && tool.version !== '' ? tool.version : toolVersion(),
    }],
  };

  // A timestamp is only written when the caller injects one explicitly: the
  // bill of materials must stay byte identical across runs.
  if (options.now !== undefined && options.now !== null && options.now !== '') {
    const date = options.now instanceof Date ? options.now : new Date(options.now);
    if (!Number.isNaN(date.getTime())) metadata.timestamp = date.toISOString();
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: SPEC_VERSION,
    serialNumber: serialNumberFor(digest),
    version: 1,
    metadata,
    components,
  };

  return {
    status: 'completed',
    bom,
    components: components.length,
    notes,
    digest,
  };
}

/**
 * The path of the manifest of the kit, used by the tests.
 *
 * @returns {string}
 */
export function kitRoot() {
  return fileURLToPath(new URL('../..', import.meta.url));
}
