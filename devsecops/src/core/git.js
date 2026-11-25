/**
 * Git helpers.
 *
 * The kit asks git exactly two things, and it asks them *explicitly*:
 *
 *   1. **which files are staged** - the set the `--git-staged` flag of the
 *      `secrets` command restricts the scan to. The set is the one git
 *      reports for the index against `HEAD`
 *      (`git diff --cached --name-only`), so a file that is staged as new is
 *      part of it;
 *   2. **which revision is checked out** - the receipt of a scan names it.
 *
 * Fail closed
 *   Neither question has a "maybe" answer. When git is not available, or
 *   when the scan root is not a git repository, the staged set cannot be
 *   computed: the caller gets an `E_IO` {@link KitError} (exit code 2)
 *   instead of a silent scan of everything. The revision, on the other hand,
 *   cannot abort a scan that already succeeded: it is recorded as
 *   {@link UNKNOWN_REVISION} and the reason is recorded with it, so that the
 *   receipt never carries a silent hole.
 *
 * Signatures
 *   stagedFiles(root: string, opts?: { gitBin?: string, timeoutMs?: number }):
 *     string[]                      the staged paths, POSIX relative, sorted.
 *   gitRevision(root: string, opts?: { gitBin?: string, timeoutMs?: number }):
 *     { revision: string, reason: string }
 *   isGitRepository(root: string, opts?): boolean
 *
 * The paths are relative to the scan root (`--relative`), so the scan root
 * may be the repository itself or one of its directories.
 */

import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

import { KitError } from './errors.js';

/** The revision recorded when git cannot tell it. */
export const UNKNOWN_REVISION = 'unknown';

/** The default timeout of a git call (milliseconds). */
export const GIT_TIMEOUT_MS = 15000;

/**
 * The first line of the error of a failed git call.
 *
 * The message never carries a stack trace and never carries a credential: it
 * is the first line of what git wrote on stderr.
 *
 * @param {unknown} err
 * @returns {string}
 */
function reasonOf(err) {
  const stderr = err && typeof err.stderr === 'string' ? err.stderr : '';
  const text = stderr.trim() !== ''
    ? stderr
    : (err && typeof err.message === 'string' ? err.message : String(err ?? ''));
  const line = text.split(/\r\n|\r|\n/).map((entry) => entry.trim()).filter((entry) => entry !== '')[0] || 'git failed';
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

/**
 * Runs git in a directory and returns its standard output.
 *
 * @param {string} root the directory git runs in.
 * @param {string[]} args the arguments of the git command.
 * @param {object} [opts]
 * @param {string} [opts.gitBin] the git binary ("git" by default).
 * @param {number} [opts.timeoutMs] the hard timeout of the call.
 * @returns {string} the standard output.
 */
function runGit(root, args, opts = {}) {
  const gitBin = typeof opts.gitBin === 'string' && opts.gitBin !== '' ? opts.gitBin : 'git';
  const timeoutMs = typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0 ? opts.timeoutMs : GIT_TIMEOUT_MS;
  const output = execFileSync(gitBin, ['-C', resolve(String(root ?? '.')), ...args], {
    encoding: 'utf8',
    timeout: timeoutMs,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024 * 1024,
  });
  return String(output);
}

/**
 * The files that git reports as staged.
 *
 * The set is the one of `git diff --cached --name-only`: the index against
 * `HEAD`. A file that is staged as new is part of it, a file that is staged
 * as deleted is part of it too (it simply cannot be read any more), and a
 * file that is only modified in the working tree is not.
 *
 * @param {string} root the scan root.
 * @param {object} [opts]
 * @param {string} [opts.gitBin] the git binary ("git" by default).
 * @param {number} [opts.timeoutMs] the hard timeout of the call.
 * @returns {string[]} the staged paths, POSIX relative to the root, sorted.
 * @throws {KitError} with the code `E_IO` when git is not available or when
 *   the root is not inside a git repository.
 */
export function stagedFiles(root, opts = {}) {
  const rootPath = resolve(String(root ?? '.'));

  // The root must belong to a git repository: outside of one the staged set
  // does not exist, and the flag has to fail loudly instead of scanning the
  // whole tree.
  let inside = false;
  try {
    inside = runGit(rootPath, ['rev-parse', '--is-inside-work-tree'], opts).trim() === 'true';
  } catch (err) {
    const missing = err && (err.code === 'ENOENT' || err.code === 'EACCES');
    const reason = missing ? 'git is not available' : reasonOf(err);
    throw new KitError('E_IO', `the staged files of ${rootPath} cannot be read: ${reason}`, {
      root: rootPath,
      cause: reason,
    });
  }
  if (!inside) {
    throw new KitError('E_IO', `the scan root ${rootPath} is not a git repository: the staged files cannot be read`, {
      root: rootPath,
    });
  }

  let output;
  try {
    output = runGit(rootPath, ['diff', '--cached', '--name-only', '--relative', '-z'], opts);
  } catch (err) {
    const missing = err && (err.code === 'ENOENT' || err.code === 'EACCES');
    const reason = missing ? 'git is not available' : reasonOf(err);
    throw new KitError('E_IO', `the staged files of ${rootPath} cannot be read: ${reason}`, {
      root: rootPath,
      cause: reason,
    });
  }
  const files = output
    .split('\u0000')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
    .map((entry) => entry.split('\\').join('/'))
    .sort();
  return files;
}

/**
 * The revision that is checked out in a directory.
 *
 * The revision is read explicitly, and the reason of a failure is recorded
 * with it: a receipt that carries an empty revision proves nothing, and a
 * receipt that carries a revision without saying how it was obtained hides a
 * hole.
 *
 * @param {string} root the scan root.
 * @param {object} [opts]
 * @param {string} [opts.gitBin] the git binary ("git" by default).
 * @param {number} [opts.timeoutMs] the hard timeout of the call.
 * @returns {{ revision: string, reason: string }} the revision (`unknown`
 *   when git cannot tell it) and the reason of a failure (empty when the
 *   revision was read).
 */
export function gitRevision(root, opts = {}) {
  try {
    const output = runGit(root, ['rev-parse', '--verify', 'HEAD'], opts);
    const revision = output.trim();
    if (revision === '') {
      return { revision: UNKNOWN_REVISION, reason: 'git returned an empty revision' };
    }
    return { revision, reason: '' };
  } catch (err) {
    const missing = err && (err.code === 'ENOENT' || err.code === 'EACCES');
    const reason = missing
      ? 'git is not available'
      : reasonOf(err);
    return { revision: UNKNOWN_REVISION, reason };
  }
}

/**
 * Tells whether a directory belongs to a git repository.
 *
 * @param {string} root the directory.
 * @param {object} [opts] the options of the git call.
 * @returns {boolean}
 */
export function isGitRepository(root, opts = {}) {
  try {
    const output = runGit(root, ['rev-parse', '--is-inside-work-tree'], opts);
    return output.trim() === 'true';
  } catch {
    return false;
  }
}
