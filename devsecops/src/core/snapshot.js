/**
 * The snapshot of a scanned tree.
 *
 * A scan receipt that does not bind the tree it describes proves nothing: a
 * digest of an empty list is the same digest for every repository on earth.
 * The snapshot of the kit is therefore **content derived**:
 *
 *   - every file the scan looked at is hashed with SHA-256, over the bytes
 *     that are really on disk;
 *   - the snapshot digest is the SHA-256 of the sorted `(path, digest)`
 *     pairs, so two different trees have two different digests and the same
 *     tree always has the same one;
 *   - the scan id is derived from the snapshot digest, so the id identifies
 *     the content and not the clock.
 *
 * The digest never carries the content of a file, only its hash: a manifest
 * can be written without leaking anything.
 *
 * The digest is never stale by construction
 *   The evidence log describes the tree it was generated from, and the log
 *   is part of that tree: a digest that included the log could never be a
 *   fixed point. The snapshot therefore **excludes the evidence log and the
 *   artefacts the kit generates**, and the label that says so is part of the
 *   emitted document and of the receipt. The exclusion set is canonical:
 *   the artefacts are excluded by name, wherever they live, so that the
 *   receipt of a scan and the evidence log of the same tree quote the same
 *   digest even when the scan wrote its artefacts into a custom directory.
 *
 * Signatures
 *   buildSnapshot(root: string, relPaths: string[], opts?: { exclude?: string[] }): {
 *     files: { path: string, sha256: string }[],
 *     paths: string[],
 *     digest: string,
 *     excluded: string[],
 *   }
 *   sha256File(file: string): string
 *   sha256Bytes(bytes: Buffer|Uint8Array): string
 *   snapshotDigestOf(files: { path: string, sha256: string }[]): string
 *
 * Fail closed
 *   A file that cannot be read is an `E_IO` error: a snapshot that silently
 *   skips a file would describe a tree that was never scanned.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { KitError } from './errors.js';
import { sha256Hex } from './fingerprint.js';
import { matchAny } from './glob.js';
import { ARTEFACTS } from '../report/writer.js';

/** The prefix of the snapshot digest (plan section F). */
export const SNAPSHOT_PREFIX = 'devsecops-snapshot/v1:sha256:';

/**
 * The label of the snapshot digest.
 *
 * The digest describes the tree *without* the evidence log and without the
 * artefacts of the kit: a reader must never believe that it describes the
 * tree the log itself is part of.
 */
export const SNAPSHOT_DIGEST_LABEL = 'digest of the tree at scan time, excluding the evidence log and the generated artefacts';

/**
 * The paths that are never part of the snapshot.
 *
 * The evidence log is the proof of a run: it is written *after* the tree was
 * hashed, and hashing it would make the digest stale by construction.
 */
export const SNAPSHOT_EXCLUDED = Object.freeze(['EVIDENCE.md']);

/**
 * The default directory of the artefacts of a scan.
 */
export const DEFAULT_ARTEFACT_DIR = 'reports';

/**
 * The exclusion set of a run: the paths that are never part of the digest.
 *
 * The evidence log is the proof of a run and the artefacts are its output:
 * neither of them can be part of the digest of the tree the run describes,
 * or the digest would be stale by construction (the log is written after
 * the tree was hashed, and the artefacts carry the digest of the run that
 * wrote them).
 *
 * The set is **canonical**: it does not depend on the directory the
 * artefacts were written to. The receipt of a scan and the evidence log of
 * the same tree quote the same digest, and they can only do that when they
 * exclude the same paths - with a custom output directory as well. The
 * artefacts are therefore excluded **by name, wherever they live**: a scan
 * that writes its artefacts into `artifacts/` produces the same digest as
 * a scan that writes them into `reports/`.
 *
 * @returns {string[]} the excluded paths, relative to the root.
 */
export function snapshotExclusions() {
  const excluded = [...SNAPSHOT_EXCLUDED];
  // The default directory of the artefacts.
  excluded.push(`${DEFAULT_ARTEFACT_DIR}/**`);
  // The artefacts of the kit, wherever they live.
  for (const artefact of ARTEFACTS) excluded.push(`**/${artefact.file}`);
  return excluded;
}

/**
 * The label of the hashed payload: it keeps the digest of an empty tree
 * different from the digest of an empty string.
 */
const PAYLOAD_LABEL = 'devsecops-snapshot/v1';

/**
 * The SHA-256 of a buffer, lowercase hex.
 *
 * @param {Buffer|Uint8Array} bytes
 * @returns {string} 64 lowercase hex characters.
 */
export function sha256Bytes(bytes) {
  const hash = createHash('sha256');
  hash.update(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes ?? []));
  return hash.digest('hex');
}

/**
 * The SHA-256 of the bytes of a file, lowercase hex.
 *
 * @param {string} file the absolute path of the file.
 * @returns {string} 64 lowercase hex characters.
 * @throws {KitError} with code `E_IO` when the file cannot be read.
 */
export function sha256File(file) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (err) {
    throw new KitError('E_IO', `cannot read the file ${file}: ${err && err.message ? err.message : String(err)}`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  return sha256Bytes(bytes);
}

/**
 * The digest of a set of hashed files.
 *
 * The pairs are sorted by path, so the digest does not depend on the order
 * in which the files were walked.
 *
 * @param {{ path: string, sha256: string }[]} files
 * @returns {string} `devsecops-snapshot/v1:sha256:<64 hex>`.
 */
export function snapshotDigestOf(files) {
  const list = (Array.isArray(files) ? files : [])
    .filter((entry) => entry && typeof entry.path === 'string' && entry.path !== '')
    .map((entry) => ({ path: entry.path, sha256: String(entry.sha256 === undefined ? '' : entry.sha256) }))
    .sort((a, b) => (a.path < b.path ? -1 : (a.path > b.path ? 1 : 0)));
  const payload = [PAYLOAD_LABEL, ...list.map((entry) => `${entry.path} ${entry.sha256}`)].join('\n');
  return `${SNAPSHOT_PREFIX}${sha256Hex(payload)}`;
}

/**
 * Builds the snapshot of a set of files of a tree.
 *
 * @param {string} root the absolute path of the scan root.
 * @param {string[]} relPaths the POSIX relative paths of the files that were
 *   scanned.
 * @param {object} [opts]
 * @param {string[]} [opts.exclude] the paths (or globs) that are not part of
 *   the snapshot: the evidence log and the artefacts of the kit.
 * @returns {{ files: { path: string, sha256: string }[], paths: string[], digest: string, excluded: string[] }}
 * @throws {KitError} with code `E_IO` when a file cannot be read.
 */
export function buildSnapshot(root, relPaths, opts = {}) {
  const base = typeof root === 'string' && root !== '' ? root : '.';
  const exclude = Array.isArray(opts.exclude)
    ? opts.exclude.filter((entry) => typeof entry === 'string' && entry !== '')
    : [];
  const paths = [...new Set(
    (Array.isArray(relPaths) ? relPaths : [])
      .filter((entry) => typeof entry === 'string' && entry !== '')
      .filter((entry) => (exclude.length === 0 ? true : !matchAny(exclude, entry))),
  )].sort();

  const files = [];
  for (const path of paths) {
    const absolute = join(base, ...path.split('/'));
    files.push({ path, sha256: sha256File(absolute) });
  }

  return {
    files,
    paths: files.map((entry) => entry.path),
    digest: snapshotDigestOf(files),
    excluded: exclude.slice(),
  };
}
