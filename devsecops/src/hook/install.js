/**
 * The installer of the pre-commit hook.
 *
 * The kit ships a POSIX shell hook in `.githooks/pre-commit`. The installer
 * copies it into the hooks directory of the repository and makes it
 * executable. It is deliberately conservative:
 *
 *   - a repository without a `.git` directory is not a repository: nothing is
 *     installed and the reason says so;
 *   - a hook that the kit did not write is **never** overwritten, unless the
 *     caller asks for it explicitly (`force`);
 *   - installing the hook twice is a no-op: the installer recognises its
 *     own hook by the marker of its first line.
 *
 * Signatures
 *   installHook(opts?: {
 *     root?: string,      // the repository (default: the working directory)
 *     source?: string,    // the hook to install (default: <root>/.githooks/pre-commit)
 *     target?: string,    // the file to write (default: <root>/.git/hooks/pre-commit)
 *     force?: boolean,    // overwrite a hook the kit did not write
 *     hooksPath?: boolean // point core.hooksPath at the .githooks directory
 *   }): {
 *     installed: boolean,
 *     target: string,
 *     reason: string,
 *     hooksPath?: string,
 *   }
 *
 * Also exported: the constants `HOOK_MARKER`, `HOOK_RELATIVE_PATH` and
 * `HOOK_MODE`.
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

/** The marker that identifies a hook written by the kit. */
export const HOOK_MARKER = 'devsecops-kit pre-commit hook';

/** The path of the hook inside the repository. */
export const HOOK_RELATIVE_PATH = join('.githooks', 'pre-commit');

/** The mode of the installed hook. */
export const HOOK_MODE = 0o755;

/**
 * Installs the pre-commit hook of the kit.
 *
 * @param {object} [opts] see the file header.
 * @returns {{ installed: boolean, target: string, reason: string, hooksPath?: string }}
 */
export function installHook(opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const root = resolve(typeof options.root === 'string' && options.root !== '' ? options.root : '.');
  const gitDir = join(root, '.git');

  const source = typeof options.source === 'string' && options.source !== ''
    ? resolve(options.source)
    : join(root, HOOK_RELATIVE_PATH);
  const target = typeof options.target === 'string' && options.target !== ''
    ? resolve(options.target)
    : join(gitDir, 'hooks', 'pre-commit');

  if (!existsSync(gitDir)) {
    return { installed: false, target, reason: 'not a git repository' };
  }
  if (!existsSync(source)) {
    return { installed: false, target, reason: `the hook source ${source} does not exist` };
  }

  let content;
  try {
    content = readFileSync(source);
  } catch (err) {
    return {
      installed: false,
      target,
      reason: `the hook source ${source} cannot be read: ${err && err.message ? err.message : String(err)}`,
    };
  }

  if (existsSync(target) && options.force !== true) {
    let existing = '';
    try {
      existing = readFileSync(target, 'utf8');
    } catch {
      existing = '';
    }
    if (!existing.includes(HOOK_MARKER)) {
      return {
        installed: false,
        target,
        reason: 'a hook that the kit did not write is already installed (use --force to overwrite it)',
      };
    }
  }

  try {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
    chmodSync(target, HOOK_MODE);
  } catch (err) {
    return {
      installed: false,
      target,
      reason: `the hook cannot be written: ${err && err.message ? err.message : String(err)}`,
    };
  }

  const result = { installed: true, target, reason: 'the pre-commit hook was installed' };

  if (options.hooksPath === true) {
    const hooksDir = join(root, '.githooks');
    try {
      execFileSync('git', ['-C', root, 'config', 'core.hooksPath', '.githooks'], {
        encoding: 'utf8',
        timeout: 10000,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      result.hooksPath = hooksDir;
      result.reason = 'the pre-commit hook was installed and core.hooksPath points at .githooks';
    } catch (err) {
      result.reason = `the pre-commit hook was installed, but core.hooksPath could not be set: ${err && err.message ? err.message : String(err)}`;
    }
  }

  return result;
}
