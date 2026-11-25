/**
 * Tool preflight ("doctor").
 *
 * The kit is deliberately self contained: it never *requires* an external
 * scanner. The optional adapters (gitleaks, semgrep, trivy, osv-scanner,
 * syft, grype, hadolint, docker, gh, ...) are guarded: when a binary is
 * missing the corresponding stage degrades to `skipped` instead of failing.
 *
 * `doctor` is what tells a human (or a CI job) which of those binaries are
 * available on this machine. It must never throw: a missing binary, a broken
 * PATH entry or a probe that exits non-zero are all *results*, not errors.
 *
 * Signatures
 *   whichSync(bin: string): string | null
 *       The absolute path of `bin` on PATH, or null when it is not there.
 *
 *   doctor(opts?: { root?: string, tools?: Array<{name: string, args?: string[]}>, timeoutMs?: number }):
 *       { tools: ToolStatus[], root: string, found: number, missing: number, notes: string[] }
 *
 *   ToolStatus = { name: string, status: "found" | "missing", path: string | null,
 *                  version: string | null, note: string }
 *
 * The result is deterministic: the tools are probed in the fixed order of
 * {@link PROBED_TOOLS}.
 */

import { execFileSync, execSync } from 'node:child_process';
import { accessSync, constants, statSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';

/** Default timeout of a single version probe (milliseconds). */
export const PROBE_TIMEOUT_MS = 5000;

/**
 * The tools the kit probes, in a fixed order.
 *
 * The first group is what the kit itself relies on (git, node, npm, python,
 * bash, rg); the second group are the optional guarded adapters.
 */
export const PROBED_TOOLS = Object.freeze([
  Object.freeze({ name: 'git', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'node', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'npm', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'python', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'bash', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'rg', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'gitleaks', args: Object.freeze(['version']) }),
  Object.freeze({ name: 'semgrep', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'trivy', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'osv-scanner', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'syft', args: Object.freeze(['version']) }),
  Object.freeze({ name: 'grype', args: Object.freeze(['version']) }),
  Object.freeze({ name: 'hadolint', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'detect-secrets', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'shellcheck', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'docker', args: Object.freeze(['--version']) }),
  Object.freeze({ name: 'gh', args: Object.freeze(['--version']) }),
]);

/**
 * @param {unknown} value
 * @returns {string} a single line message, never containing a credential.
 */
function messageOf(value) {
  if (value && typeof value.message === 'string' && value.message !== '') return value.message;
  return String(value ?? '');
}

/**
 * @param {string} file
 * @returns {boolean} true when the path is a regular file that can be run.
 */
function isRunnableFile(file) {
  try {
    const stats = statSync(file);
    if (!stats.isFile()) return false;
    if (process.platform === 'win32') return true;
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Finds an executable on PATH.
 *
 * The lookup is done in pure JavaScript (no shell, no `where.exe`): the PATH
 * of the current process is scanned segment by segment and, on Windows, the
 * extensions of `PATHEXT` are tried as well.
 *
 * @param {string} bin the binary name, e.g. `git`.
 * @returns {string|null} the absolute path, or null when it is not on PATH.
 */
export function whichSync(bin) {
  if (typeof bin !== 'string') return null;
  const name = bin.trim();
  if (name === '') return null;

  if (name.includes('/') || name.includes('\\')) {
    const absolute = resolve(name);
    return isRunnableFile(absolute) ? absolute : null;
  }

  const searchPath = typeof process.env.PATH === 'string' ? process.env.PATH : '';
  const directories = searchPath.split(delimiter).filter((entry) => entry !== '');
  const extensions = process.platform === 'win32'
    ? String(process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter((entry) => entry !== '')
    : [''];

  const seen = new Set();
  for (const directory of directories) {
    for (const extension of extensions) {
      const candidate = join(directory, name + extension);
      if (seen.has(candidate)) continue;
      seen.add(candidate);
      if (isRunnableFile(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Keeps the first non empty line of a probe output.
 *
 * @param {unknown} output
 * @returns {string|null} the version line, or null when there is none.
 */
function firstLine(output) {
  if (typeof output !== 'string') return null;
  for (const raw of output.split(/\r\n|\r|\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    return line.length > 200 ? `${line.slice(0, 197)}...` : line;
  }
  return null;
}

/**
 * Runs the version probe of a tool.
 *
 * @param {string} bin
 * @param {string} executable the resolved path.
 * @param {string[]} args
 * @param {number} timeoutMs
 * @returns {{ version: string|null, error: string|null }}
 */
function probeVersion(bin, executable, args, timeoutMs) {
  const options = {
    encoding: 'utf8',
    timeout: timeoutMs,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  try {
    const stdout = execFileSync(bin, args, options);
    return { version: firstLine(stdout), error: null };
  } catch (err) {
    // A tool that prints its version on stderr and exits non-zero still tells
    // us something useful.
    const partial = firstLine(err && err.stdout) || firstLine(err && err.stderr);
    if (partial) return { version: partial, error: null };
    // On Windows a `.cmd`/`.bat` shim cannot be executed directly: it needs
    // the command interpreter. The binary name and the arguments are checked
    // against a strict allow list first, so nothing user supplied ever reaches
    // the shell.
    const shim = process.platform === 'win32' && /\.(cmd|bat)$/i.test(String(executable || ''));
    const safe = /^[A-Za-z0-9._-]+$/.test(bin) && args.every((arg) => /^[A-Za-z0-9._=-]+$/.test(String(arg)));
    if (shim && safe) {
      try {
        // The shell of the operating system knows how to run a `.cmd` shim;
        // the command and its arguments are checked against a strict allow
        // list first, so that nothing user supplied ever reaches the shell.
        const line = [bin].concat(args).join(' ');
        const stdout = execSync(line, { ...options, shell: true });
        return { version: firstLine(stdout), error: null };
      } catch (err2) {
        return { version: null, error: messageOf(err2) };
      }
    }
    return { version: null, error: messageOf(err) };
  }
}

/**
 * Probes a single tool.
 *
 * @param {{name: string, args?: string[]}} tool
 * @param {number} timeoutMs
 * @returns {object} a ToolStatus.
 */
function probeTool(tool, timeoutMs) {
  const name = String(tool && tool.name ? tool.name : '');
  const args = Array.isArray(tool && tool.args) ? tool.args : ['--version'];
  try {
    const executable = whichSync(name);
    if (!executable) {
      return {
        name,
        status: 'missing',
        path: null,
        version: null,
        note: 'not found on PATH (the kit works without it; the matching stage is skipped)',
      };
    }
    const probe = probeVersion(name, executable, args, timeoutMs);
    if (probe.version) {
      return { name, status: 'found', path: executable, version: probe.version, note: '' };
    }
    return {
      name,
      status: 'found',
      path: executable,
      version: null,
      note: `version probe failed: ${probe.error || 'no output'}`,
    };
  } catch (err) {
    return {
      name,
      status: 'missing',
      path: null,
      version: null,
      note: `probe failed: ${messageOf(err)}`,
    };
  }
}

/**
 * The cached probe result.
 *
 * The tools of a machine do not change while a process runs: the preflight
 * is probed once and the result is reused, so that a pipeline that runs the
 * preflight several times does not spawn the same probes again and again.
 */
let cachedTools = null;

/**
 * Forgets the cached probe result.
 *
 * @returns {void}
 */
export function clearDoctorCache() {
  cachedTools = null;
}

/**
 * Builds the result of the preflight out of the probed tools.
 *
 * @param {object[]} tools the probed tools.
 * @param {string} root the scan root (informational).
 * @returns {{ tools: object[], root: string, found: number, missing: number, notes: string[] }}
 */
function buildResult(tools, root) {
  const found = tools.filter((tool) => tool.status === 'found').length;
  const missing = tools.length - found;
  const notes = [];
  if (missing > 0) {
    notes.push(`${missing} optional tool(s) are not installed: the matching stages degrade to "skipped".`);
  }
  return { tools, root, found, missing, notes };
}

/**
 * Runs the preflight.
 *
 * @param {object} [opts]
 * @param {string} [opts.root] the scan root (informational).
 * @param {Array<{name: string, args?: string[]}>} [opts.tools] overrides the
 *   probed tool list.
 * @param {number} [opts.timeoutMs] timeout of a single probe.
 * @param {boolean} [opts.cache] false probes the tools again (default: the
 *   probe result is reused).
 * @returns {{ tools: object[], root: string, found: number, missing: number, notes: string[] }}
 */
export function doctor(opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const root = typeof options.root === 'string' && options.root !== ''
    ? resolve(options.root)
    : process.cwd();
  const timeoutMs = typeof options.timeoutMs === 'number' && options.timeoutMs > 0
    ? options.timeoutMs
    : PROBE_TIMEOUT_MS;
  const list = Array.isArray(options.tools) && options.tools.length > 0
    ? options.tools
    : PROBED_TOOLS;

  if (options.cache !== false && cachedTools !== null && list === PROBED_TOOLS) {
    return buildResult(cachedTools, root);
  }

  const tools = [];
  for (const tool of list) {
    tools.push(probeTool(tool, timeoutMs));
  }
  if (list === PROBED_TOOLS) cachedTools = tools;

  return buildResult(tools, root);
}

/**
 * Renders the tool table as plain text (used by the CLI).
 *
 * @param {object[]} tools
 * @returns {string} the table.
 */
export function formatToolsTable(tools) {
  const list = Array.isArray(tools) ? tools : [];
  const rows = list.map((tool) => `| ${tool.name} | ${tool.status.toUpperCase()} | ${tool.version || tool.note || '-'} |`);
  return ['| tool | status | version |', '| --- | --- | --- |', ...rows].join('\n');
}
