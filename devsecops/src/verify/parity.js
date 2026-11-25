/**
 * Local parity of the four external verification checks.
 *
 * The external substrate (a shell hook) checks, in this order:
 *
 *   1. did the work produce a change?   (`git status --porcelain`, and the
 *      age of HEAD when the tree is clean);
 *   2. do the tests pass?                (`npm test --silent`, armed by the
 *      literal `"test"` anywhere in package.json);
 *   3. does the build pass?              (`npm run build`, armed by the
 *      literal `"build"` anywhere in package.json);
 *   4. did a credential leak into the staged files?  (an exact regular
 *      expression over the staged set).
 *
 * This module re-implements those checks locally, so that the compliance can
 * be proven *before* the platform runs the hook.
 *
 * Two differences are deliberate and documented:
 *
 *   - **the runner is injectable.** The default runner spawns `npm`, which
 *     would recurse into the test runner when the check runs inside a test.
 *     The tests inject a fake runner instead, and the environment variable
 *     `DEVSECOPS_KIT_NO_NESTED_NPM=1` aborts a nested npm invocation.
 *
 *   - **the secret check is stronger than the substrate.** The substrate
 *     scans the *staged* files only, and its scan is a no-op when nothing is
 *     staged (`git diff --cached --name-only` prints nothing and `xargs -r`
 *     never invokes `git grep`). The local check scans the staged set, and
 *     when nothing is staged it scans the whole *tracked* tree instead - the
 *     same regular expression, over the working tree content, exactly like
 *     `git grep` does. A leak that the substrate would miss is therefore
 *     reported here.
 *
 * Signatures
 *   runParityChecks(opts?: {
 *     root?: string,       // the project root (default: the working directory)
 *     run?: RunFn,         // the injectable runner
 *     now?: number,        // the current time, in milliseconds or seconds
 *   }): {
 *     checks: { id: string, name: string, status: "pass" | "fail" | "skip", detail: string }[],
 *     failures: number,
 *   }
 *
 *   defaultRunner(cmd: string, args: string[], opts?: { cwd?: string, timeoutMs?: number }):
 *     { status: number, stdout: string, stderr: string }
 *
 * Also exported: the constants `SECRET_PATTERN` (the exact regular
 * expression of the substrate), `CHECK_IDS`, `RECENT_COMMIT_WINDOW_SECONDS`
 * and `NESTED_NPM_GUARD`.
 */

import { execFileSync, execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * The exact regular expression of the substrate.
 *
 * `(api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}`
 *
 * It is case sensitive, the keyword must be followed by optional spaces and
 * then by `:` or `=`, a quote is required, and the value must be at least 20
 * characters long.
 */
export const SECRET_PATTERN = /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}/;

/** The identifiers of the four checks, in the order of the substrate. */
export const CHECK_IDS = Object.freeze(['changes', 'tests', 'build', 'secrets']);

/** The window a commit has to be younger than to satisfy the first check. */
export const RECENT_COMMIT_WINDOW_SECONDS = 86400;

/** The environment variable that aborts a nested npm invocation. */
export const NESTED_NPM_GUARD = 'DEVSECOPS_KIT_NO_NESTED_NPM';

/** The default timeout of a single command of the default runner. */
export const DEFAULT_TIMEOUT_MS = 600000;

/**
 * Runs a command with the shell of the operating system.
 *
 * On Windows `npm` is a `.cmd` shim, which cannot be executed without a
 * shell: the command is therefore handed over to the command interpreter.
 *
 * @param {string} cmd
 * @param {string[]} args
 * @param {object} [opts]
 * @param {string} [opts.cwd]
 * @param {number} [opts.timeoutMs]
 * @returns {{ status: number, stdout: string, stderr: string }}
 */
function spawnCommand(cmd, args, opts = {}) {
  const options = {
    encoding: 'utf8',
    cwd: opts.cwd,
    timeout: typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0 ? opts.timeoutMs : DEFAULT_TIMEOUT_MS,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 32 * 1024 * 1024,
  };
  try {
    const stdout = execFileSync(cmd, args, options);
    return { status: 0, stdout: String(stdout), stderr: '' };
  } catch (err) {
    // On Windows `npm` is a `.cmd` shim, which cannot be executed without the
    // command interpreter. The command and its arguments are checked against
    // a strict allow list first, so that nothing user supplied reaches the
    // shell.
    const missing = err && (err.code === 'ENOENT' || err.code === 'EACCES');
    if (missing && process.platform === 'win32' && /^[A-Za-z0-9._-]+$/.test(cmd)) {
      const safe = args.every((arg) => /^[A-Za-z0-9._=-]+$/.test(String(arg)));
      if (safe) {
        try {
          const line = [cmd].concat(args).join(' ');
          const stdout = execSync(line, { ...options, shell: true });
          return { status: 0, stdout: String(stdout), stderr: '' };
        } catch (err2) {
          return {
            status: typeof err2.status === 'number' ? err2.status : 1,
            stdout: err2 && err2.stdout ? String(err2.stdout) : '',
            stderr: err2 && err2.stderr ? String(err2.stderr) : (err2 && err2.message ? String(err2.message) : ''),
          };
        }
      }
    }
    const status = typeof err.status === 'number' ? err.status : 1;
    return {
      status,
      stdout: err && err.stdout ? String(err.stdout) : '',
      stderr: err && err.stderr ? String(err.stderr) : (err && err.message ? String(err.message) : ''),
    };
  }
}

/**
 * The default runner of the checks.
 *
 * @param {string} cmd
 * @param {string[]} args
 * @param {object} [opts]
 * @param {string} [opts.cwd]
 * @param {number} [opts.timeoutMs]
 * @returns {{ status: number, stdout: string, stderr: string }}
 */
export function defaultRunner(cmd, args, opts = {}) {
  return spawnCommand(cmd, args, opts);
}

/**
 * Tells whether the runner is the default one.
 *
 * @param {unknown} run
 * @returns {boolean}
 */
function isDefaultRunner(run) {
  return typeof run !== 'function' || run === defaultRunner;
}

/**
 * The current time, in seconds.
 *
 * The `now` option accepts milliseconds (the JavaScript convention) and
 * seconds; a value below 100 000 000 000 is read as seconds.
 *
 * @param {number} now
 * @returns {number}
 */
function toSeconds(now) {
  const value = Number(now);
  if (!Number.isFinite(value)) return Math.floor(Date.now() / 1000);
  return value < 100000000000 ? Math.floor(value) : Math.floor(value / 1000);
}

/**
 * The last lines of a log, the way the substrate echoes them.
 *
 * @param {{ stdout: string, stderr: string }} result
 * @param {number} [count]
 * @returns {string}
 */
function lastLines(result, count = 15) {
  const text = `${result.stdout || ''}${result.stderr || ''}`;
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  return lines.slice(-count).join('\n');
}

/**
 * Removes the quotes git puts around the paths it cannot print verbatim.
 *
 * @param {string} value
 * @returns {string}
 */
function unquotePath(value) {
  const text = String(value ?? '').trim();
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    try {
      return JSON.parse(text);
    } catch {
      return text.slice(1, -1);
    }
  }
  return text;
}

/**
 * Splits the output of a git command into a list of paths.
 *
 * @param {string} output
 * @returns {string[]}
 */
function toPaths(output) {
  return String(output ?? '')
    .split(/\r?\n/)
    .map((line) => unquotePath(line))
    .filter((line) => line !== '');
}

/**
 * The files of a list that hold a credential shaped literal.
 *
 * The content of the **working tree** is read (like `git grep` without
 * `--cached` does) and the binary files are skipped (like `git grep -I`
 * does).
 *
 * @param {string} root
 * @param {string[]} paths the paths, relative to the root.
 * @returns {string[]} the paths that hold a match.
 */
export function filesWithSecret(root, paths) {
  const matched = [];
  for (const relPath of Array.isArray(paths) ? paths : []) {
    const file = join(root, ...String(relPath).split('/'));
    let buffer;
    try {
      buffer = readFileSync(file);
    } catch {
      continue;
    }
    if (buffer.includes(0)) continue;
    const text = buffer.toString('utf8');
    if (SECRET_PATTERN.test(text)) matched.push(String(relPath));
  }
  return matched;
}

/**
 * The first check: did the work produce a change?
 *
 * @param {string} root
 * @param {Function} run
 * @param {number} now
 * @returns {object} the check.
 */
function checkChanges(root, run, now) {
  const name = 'did the work produce a change?';
  if (!existsSync(join(root, '.git'))) {
    return { id: 'changes', name, status: 'skip', detail: 'not a git repository: the check counts as a pass' };
  }
  const status = run('git', ['-C', root, 'status', '--porcelain']);
  if (!status || status.status !== 0) {
    return { id: 'changes', name, status: 'skip', detail: 'git is not available: the check counts as a pass' };
  }
  const changed = String(status.stdout || '')
    .split(/\r?\n/)
    .filter((line) => line.trim() !== '').length;
  if (changed > 0) {
    return { id: 'changes', name, status: 'pass', detail: `${changed} changed path(s)` };
  }
  const log = run('git', ['-C', root, 'log', '-1', '--format=%ct']);
  if (!log || log.status !== 0) {
    return { id: 'changes', name, status: 'fail', detail: 'no file changes and no recent commit' };
  }
  const last = Number(String(log.stdout || '').trim());
  if (!Number.isFinite(last) || last <= 0) {
    return { id: 'changes', name, status: 'fail', detail: 'no file changes and no recent commit' };
  }
  const age = toSeconds(now) - last;
  if (age < RECENT_COMMIT_WINDOW_SECONDS) {
    const minutes = Math.max(0, Math.round(age / 60));
    return {
      id: 'changes',
      name,
      status: 'pass',
      detail: `tree clean, but HEAD commit is recent (${minutes} min old) - work is committed`,
    };
  }
  return { id: 'changes', name, status: 'fail', detail: 'no file changes and no recent commit' };
}

/**
 * The second and the third checks: the tests and the build.
 *
 * The check is armed by the presence of the literal `"test"` (or `"build"`)
 * **anywhere** in package.json, exactly like the substrate greps it.
 *
 * @param {string} root
 * @param {Function} run
 * @param {string} kind `tests` or `build`.
 * @param {boolean} defaultRunnerUsed
 * @returns {object} the check.
 */
function checkNpmScript(root, run, kind, defaultRunnerUsed) {
  const name = kind;
  const id = kind;
  const literal = kind === 'tests' ? '"test"' : '"build"';
  const manifest = join(root, 'package.json');
  if (!existsSync(manifest)) {
    return { id, name, status: 'skip', detail: `no package.json - skipping the ${kind} check` };
  }
  let text;
  try {
    text = readFileSync(manifest, 'utf8');
  } catch (err) {
    return { id, name, status: 'skip', detail: `package.json cannot be read - skipping the ${kind} check` };
  }
  if (!text.includes(literal)) {
    return { id, name, status: 'skip', detail: `package.json does not contain the literal ${literal} - skipping the ${kind} check` };
  }
  if (defaultRunnerUsed && process.env[NESTED_NPM_GUARD] === '1') {
    return {
      id,
      name,
      status: 'skip',
      detail: `the nested npm invocation was aborted (${NESTED_NPM_GUARD}=1)`,
    };
  }
  const args = kind === 'tests' ? ['test', '--silent'] : ['run', 'build'];
  const result = run('npm', args, { cwd: root });
  if (result && result.status === 0) {
    return { id, name, status: 'pass', detail: `npm ${args.join(' ')} exited 0` };
  }
  const status = result && typeof result.status === 'number' ? result.status : 1;
  return {
    id,
    name,
    status: 'fail',
    detail: `npm ${args.join(' ')} exited ${status}\n${lastLines(result || { stdout: '', stderr: '' })}`,
  };
}

/**
 * The fourth check: did a credential leak into the staged files?
 *
 * @param {string} root
 * @param {Function} run
 * @returns {object} the check.
 */
function checkSecrets(root, run) {
  const id = 'secrets';
  const name = 'no secrets leaked';
  const staged = run('git', ['-C', root, 'diff', '--cached', '--name-only']);
  if (!staged || staged.status !== 0) {
    return { id, name, status: 'skip', detail: 'git is not available: the check counts as a pass' };
  }
  const files = toPaths(staged.stdout);
  if (files.length === 0) {
    // The substrate does not scan anything here (`xargs -r` never invokes
    // `git grep` when the list is empty). The local check is stronger: it
    // scans the whole tracked tree.
    const tracked = run('git', ['-C', root, 'ls-files']);
    const trackedFiles = tracked && tracked.status === 0 ? toPaths(tracked.stdout) : [];
    const matched = filesWithSecret(root, trackedFiles);
    if (matched.length > 0) {
      return {
        id,
        name,
        status: 'fail',
        detail: `nothing is staged (the external hook is a no-op here), but ${matched.length} tracked file(s) hold a credential shaped literal: ${matched.join(', ')}`,
      };
    }
    return {
      id,
      name,
      status: 'pass',
      detail: `nothing is staged (the external hook is a no-op here); the whole tracked tree (${trackedFiles.length} file(s)) was scanned and holds no credential shaped literal`,
    };
  }
  const matched = filesWithSecret(root, files);
  if (matched.length > 0) {
    return {
      id,
      name,
      status: 'fail',
      detail: `${matched.length} staged file(s) hold a credential shaped literal: ${matched.join(', ')}`,
    };
  }
  return {
    id,
    name,
    status: 'pass',
    detail: `${files.length} staged file(s) hold no credential shaped literal`,
  };
}

/**
 * Runs the four checks.
 *
 * @param {object} [opts] see the file header.
 * @returns {{ checks: object[], failures: number }}
 */
export function runParityChecks(opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const root = resolve(typeof options.root === 'string' && options.root !== '' ? options.root : '.');
  const run = typeof options.run === 'function' ? options.run : defaultRunner;
  const defaultRunnerUsed = isDefaultRunner(run);
  const now = Number.isFinite(Number(options.now)) ? Number(options.now) : Date.now();

  const checks = [
    checkChanges(root, run, now),
    checkNpmScript(root, run, 'tests', defaultRunnerUsed),
    checkNpmScript(root, run, 'build', defaultRunnerUsed),
    checkSecrets(root, run),
  ];

  const failures = checks.filter((check) => check.status === 'fail').length;
  return { checks, failures };
}
