/**
 * Deterministic file walk.
 *
 * The scanners of the kit must produce the same report for the same tree on
 * every machine and on every run, so the walk is:
 *
 *   - **deterministic**: the returned paths are sorted, POSIX relative to the
 *     scan root and free of any platform specific separator;
 *   - **bounded**: files bigger than `maxFileBytes` are skipped, so a stray
 *     multi-gigabyte artefact cannot turn a scan into an out-of-memory event;
 *   - **conservative**: symbolic links are skipped unless they are explicitly
 *     followed, so a link cannot smuggle a file from outside the tree into
 *     the scan;
 *   - **fail closed**: a scan root that cannot be read, and a directory that
 *     cannot be listed, raise an `E_IO` {@link KitError}. A tree that was
 *     never opened must never look like a tree without a finding.
 *
 * The walk reports the directories too
 *   A directory is part of the tree, even when it holds no file at all: an
 *   empty directory is still a path of the tree, and the deny list of the
 *   policy is judged against the tree. The walk therefore returns the
 *   directories it visited (`dirs`), next to the files it found.
 *
 * The walk never hides what it dropped
 *   A file that the walk does not return is a file the scanner did not look
 *   at. The walk therefore *reports* the files it drops and the reason of
 *   the drop (`size-cap`, `binary`): a tree whose files are all above the
 *   size cap is not an empty tree, it is a tree the scanner could not open.
 *   The report is what lets the coverage assertion tell the two apart.
 *
 * Signatures
 *   walkFiles(root: string, opts?: {
 *     include?: string[], exclude?: string[], maxFileBytes?: number,
 *     followSymlinks?: boolean, skipBinary?: boolean, fs?: object,
 *   }): string[]
 *   walkTree(root: string, opts?: { ...same... }): {
 *     files: string[],
 *     dirs: string[],
 *     dropped: { path: string, reason: string, bytes?: number, limit?: number }[],
 *     maxFileBytes: number,
 *   }
 *   isBinary(buf: Buffer): boolean
 *   readTextSafe(file: string, maxFileBytes?: number, fs?: object): {
 *     text: string, truncated: boolean, binary: boolean, error?: string,
 *   }
 *
 * The `fs` seam
 *   The walk reads the file system through a tiny seam: an object with the
 *   `readdirSync`, `statSync` and `readFileSync` functions of `node:fs`. The
 *   default is the real file system. The seam exists so that the behaviour
 *   of an unreadable directory or of an unreadable file can be exercised on
 *   every platform, including the ones that do not enforce the permission
 *   bits: a test injects a reader that fails instead of waiting for a
 *   permission that the operating system never enforces.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { KitError } from './errors.js';
import { matchAny } from './glob.js';

/** Default size cap of a single file (2 MB). */
export const DEFAULT_MAX_FILE_BYTES = 2_000_000;

/** Number of leading bytes inspected by the binary heuristic. */
export const BINARY_SNIFF_BYTES = 8000;

/** Paths that are never worth scanning, unless the caller says otherwise. */
const DEFAULT_EXCLUDE = ['.git/**'];

/** The reasons the walk can drop a file. */
export const DROP_REASONS = Object.freeze({
  SIZE: 'size-cap',
  BINARY: 'binary',
});

/**
 * The real file system: the default of the seam.
 *
 * @type {Readonly<{ readdirSync: Function, statSync: Function, readFileSync: Function }>}
 */
const REAL_FS = Object.freeze({ readdirSync, statSync, readFileSync });

/**
 * The functions of the seam, with the real file system as the default.
 *
 * @param {object} [seam] the injected seam (may be null).
 * @returns {{ readdirSync: Function, statSync: Function, readFileSync: Function }}
 */
function fsOf(seam) {
  if (seam === null || seam === undefined || typeof seam !== 'object') return REAL_FS;
  return {
    readdirSync: typeof seam.readdirSync === 'function' ? seam.readdirSync : REAL_FS.readdirSync,
    statSync: typeof seam.statSync === 'function' ? seam.statSync : REAL_FS.statSync,
    readFileSync: typeof seam.readFileSync === 'function' ? seam.readFileSync : REAL_FS.readFileSync,
  };
}

/**
 * Converts a platform path into a POSIX relative path.
 *
 * @param {string} root absolute scan root.
 * @param {string} absolute absolute path of the entry.
 * @returns {string} e.g. `src/core/glob.js`
 */
function toRelativePosix(root, absolute) {
  return relative(root, absolute).split(sep).join('/');
}

/**
 * Binary heuristic: a NUL byte in the first {@link BINARY_SNIFF_BYTES} bytes
 * means the file is not text.
 *
 * @param {Buffer} buf
 * @returns {boolean}
 */
export function isBinary(buf) {
  if (!buf || buf.length === 0) return false;
  const limit = Math.min(buf.length, BINARY_SNIFF_BYTES);
  for (let i = 0; i < limit; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/**
 * Reads a file as text, without ever loading more than the size cap.
 *
 * Binary files are reported as such and their content is not returned: a
 * scanner must never try to match patterns inside a compiled artefact.
 *
 * @param {string} file
 * @param {number} [maxFileBytes]
 * @param {object} [fs] the file system seam (the real one by default).
 * @returns {{ text: string, truncated: boolean, binary: boolean, error?: string }}
 */
export function readTextSafe(file, maxFileBytes = DEFAULT_MAX_FILE_BYTES, fs = undefined) {
  const limit = typeof maxFileBytes === 'number' && maxFileBytes > 0 ? maxFileBytes : DEFAULT_MAX_FILE_BYTES;
  const io = fsOf(fs);
  let size = 0;
  try {
    size = io.statSync(file).size;
  } catch (err) {
    return { text: '', truncated: false, binary: false, error: err && err.message ? err.message : String(err) };
  }
  let buffer;
  try {
    buffer = io.readFileSync(file);
  } catch (err) {
    return { text: '', truncated: false, binary: false, error: err && err.message ? err.message : String(err) };
  }
  const truncated = size > limit;
  const sliced = truncated ? buffer.subarray(0, limit) : buffer;
  const binary = isBinary(sliced);
  return {
    text: binary ? '' : sliced.toString('utf8'),
    truncated,
    binary,
  };
}

/**
 * Walks a tree and returns the files that a scanner should look at, and the
 * files the walk dropped.
 *
 * @param {string} root absolute path of the scan root.
 * @param {object} [opts]
 * @param {string[]} [opts.include] only paths matching one of these globs are
 *   returned (an empty list means "everything").
 * @param {string[]} [opts.exclude] paths matching one of these globs are
 *   skipped. Defaults to `['.git/**']`.
 * @param {number} [opts.maxFileBytes] files bigger than this are skipped.
 * @param {boolean} [opts.followSymlinks] follow symbolic links (default false).
 * @param {boolean} [opts.skipBinary] skip binary files (default false).
 * @param {object} [opts.fs] the file system seam (the real one by default).
 * @returns {{ files: string[], dirs: string[], dropped: object[], maxFileBytes: number }}
 */
export function walkTree(root, opts = {}) {
  const rootPath = resolve(root);
  const include = Array.isArray(opts.include) ? opts.include : [];
  const exclude = Array.isArray(opts.exclude) ? opts.exclude : DEFAULT_EXCLUDE;
  const maxFileBytes = typeof opts.maxFileBytes === 'number' && opts.maxFileBytes > 0
    ? opts.maxFileBytes
    : DEFAULT_MAX_FILE_BYTES;
  const followSymlinks = opts.followSymlinks === true;
  const skipBinary = opts.skipBinary === true;
  const io = fsOf(opts.fs);

  let rootStat;
  try {
    rootStat = io.statSync(rootPath);
  } catch (err) {
    throw new KitError('E_IO', `scan root is not readable: ${root}`, {
      root,
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!rootStat.isDirectory()) {
    throw new KitError('E_IO', `the scan root is not a directory: ${root}`, { root });
  }

  const found = [];
  const dirs = [];
  const dropped = [];
  const visited = new Set();

  const walk = (absoluteDir) => {
    let entries;
    try {
      entries = io.readdirSync(absoluteDir, { withFileTypes: true });
    } catch (err) {
      // A directory that cannot be listed is an I/O failure, not an empty
      // directory: the scan must fail closed instead of looking at nothing.
      throw new KitError('E_IO', `cannot read the directory ${absoluteDir}: ${err && err.message ? err.message : String(err)}`, {
        path: absoluteDir,
        cause: err && err.message ? err.message : String(err),
      });
    }
    for (const entry of entries) {
      const absolute = join(absoluteDir, entry.name);
      const relPath = toRelativePosix(rootPath, absolute);
      let isDirectory = entry.isDirectory();
      let isFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        if (!followSymlinks) continue;
        let target;
        try {
          target = io.statSync(absolute);
        } catch {
          continue;
        }
        const key = `${target.dev}:${target.ino}`;
        if (visited.has(key)) continue;
        visited.add(key);
        isDirectory = target.isDirectory();
        isFile = target.isFile();
      }
      if (isDirectory) {
        if (matchAny(exclude, `${relPath}/`) || matchAny(exclude, relPath)) continue;
        // The directory is part of the tree: an empty directory is a path
        // of the tree all the same, and the deny list is judged against the
        // tree.
        dirs.push(relPath);
        walk(absolute);
        continue;
      }
      if (!isFile) continue;
      if (matchAny(exclude, relPath)) continue;
      if (include.length > 0 && !matchAny(include, relPath)) continue;
      let size = 0;
      try {
        size = io.statSync(absolute).size;
      } catch (err) {
        throw new KitError('E_IO', `cannot read the file ${absolute}: ${err && err.message ? err.message : String(err)}`, {
          path: absolute,
          cause: err && err.message ? err.message : String(err),
        });
      }
      // A file above the size cap is not scanned: it is *dropped*, and the
      // drop is reported. A tree of big files is not an empty tree.
      if (size > maxFileBytes) {
        dropped.push({ path: relPath, reason: DROP_REASONS.SIZE, bytes: size, limit: maxFileBytes });
        continue;
      }
      if (skipBinary) {
        let head;
        try {
          const fd = io.readFileSync(absolute);
          head = fd.subarray(0, BINARY_SNIFF_BYTES);
        } catch {
          dropped.push({ path: relPath, reason: DROP_REASONS.BINARY });
          continue;
        }
        if (isBinary(head)) {
          dropped.push({ path: relPath, reason: DROP_REASONS.BINARY });
          continue;
        }
      }
      found.push(relPath);
    }
  };

  walk(rootPath);
  found.sort();
  dirs.sort();
  dropped.sort((a, b) => (a.path < b.path ? -1 : (a.path > b.path ? 1 : 0)));
  return { files: found, dirs, dropped, maxFileBytes };
}

/**
 * The sentence that tells what the walk dropped.
 *
 * The note names the count and the reason of the drop: a reader must never
 * wonder why a file was not scanned.
 *
 * @param {{ path: string, reason: string }[]} dropped
 * @returns {string} the note (an empty string when nothing was dropped).
 */
export function droppedNote(dropped) {
  const list = Array.isArray(dropped) ? dropped.filter((entry) => entry && typeof entry.path === 'string') : [];
  if (list.length === 0) return '';
  const byReason = new Map();
  for (const entry of list) {
    const reason = typeof entry.reason === 'string' && entry.reason !== '' ? entry.reason : 'unknown';
    byReason.set(reason, (byReason.get(reason) || 0) + 1);
  }
  const parts = [...byReason.keys()].sort().map((reason) => {
    const count = byReason.get(reason);
    if (reason === DROP_REASONS.SIZE) return `${count} above the size cap`;
    if (reason === DROP_REASONS.BINARY) return `${count} binary file(s)`;
    return `${count} (${reason})`;
  });
  const shown = list.slice(0, 5).map((entry) => entry.path);
  const more = list.length > shown.length ? `, and ${list.length - shown.length} more` : '';
  return `the walk dropped ${list.length} file(s): ${parts.join(', ')}: ${shown.join(', ')}${more}`;
}

/**
 * Walks a tree and returns the files that a scanner should look at.
 *
 * @param {string} root absolute path of the scan root.
 * @param {object} [opts] see {@link walkTree}.
 * @returns {string[]} sorted POSIX relative paths.
 */
export function walkFiles(root, opts = {}) {
  return walkTree(root, opts).files;
}
