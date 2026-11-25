/**
 * The help of the kit.
 *
 * This module is the single source of truth of the command surface: the
 * README and `docs/cli.md` are expected to repeat what is written here, and
 * the flags are rendered straight from the specifications of
 * `src/cli/args.js`, so a flag can never be documented but not accepted (or
 * accepted but not documented).
 *
 * Signatures
 *   globalHelp(): string          the help of the tool (the command list).
 *   commandHelp(command: string): string
 *                                the help of one command; the global help
 *                                when the command is unknown.
 *   helpFor(command: string): string
 *                                the help to print for a command (the same
 *                                as `commandHelp`).
 *   flagLines(command: string): string[]
 *                                the rendered option lines of a command.
 *   commandSummaries(): { command: string, summary: string }[]
 *
 * Also exported: the constants `TOOL_NAME`, `TOOL_VERSION`, `DESCRIPTIONS`
 * and `NOTES`.
 */

import { COMMANDS, GLOBAL_FLAGS, flagsFor, isCommand } from './args.js';

/** The name of the tool. */
export const TOOL_NAME = 'devsecops-kit';

/** The version of the tool. */
export const TOOL_VERSION = '1.0.0';

/**
 * The one line description of every command.
 *
 * @type {Readonly<Record<string, string>>}
 */
export const DESCRIPTIONS = Object.freeze({
  doctor: 'report which optional tools are available on this machine',
  secrets: 'scan a tree for leaked credentials (the values are never printed)',
  sast: 'scan a tree for the weaknesses of the SAST rule pack',
  deps: 'audit the dependencies against the offline advisory database',
  sbom: 'build a deterministic CycloneDX bill of materials',
  policy: 'judge a findings document with the security policy',
  scan: 'run the whole pipeline and write the report artefacts',
  verify: 'run the local parity of the four external verification checks',
  evidence: 'write the evidence log of the acceptance criteria',
  'validate-evidence': 'check that the evidence log is complete',
  'install-hook': 'install the pre-commit hook of the kit',
});

/**
 * The notes of the commands.
 *
 * A one line summary of a flag cannot describe an edge case: the notes below
 * spell out what the flags really do, so that the help never states
 * something the code does not do.
 *
 * @type {Readonly<Record<string, ReadonlyArray<string>>>}
 */
export const NOTES = Object.freeze({
  secrets: Object.freeze([
    'The flag --git-staged restricts the scan to the files that git reports as',
    'staged (the index against HEAD, the new files included). The content that',
    'is read is the content of the working tree at those paths.',
    'When nothing is staged the stage is skipped, with the reason "nothing is',
    'staged": it scans 0 file, the coverage reads "inspected 0 of 0" and the',
    'gate fails (exit code 1). An empty index is never a successful',
    'inspection, and never a silent pass.',
    'Outside a git repository, or without git, the flag fails with the exit',
    'code 2: it never scans the whole tree silently.',
  ]),
  evidence: Object.freeze([
    'The flag --emit writes the evidence document. Without --run the document',
    'carries no output at all, so the emitter refuses to overwrite an',
    'existing document: an accidental invocation never destroys the proof',
    'that is committed. Use --run to produce the evidence, or --force to',
    'replace the document knowingly.',
  ]),
});

/**
 * The exit codes, rendered the same way for every command.
 *
 * @param {string} [extra] an extra line for the command.
 * @returns {string[]} the lines.
 */
function exitCodeLines(extra) {
  const lines = [
    'Exit codes:',
    '  0  the gate passed / no finding at or above the threshold',
    '  1  findings at or above the threshold, or a policy violation',
    '  2  a tool or configuration error (bad flag, bad policy, unreadable file)',
  ];
  if (typeof extra === 'string' && extra !== '') lines.push(`  (${extra})`);
  return lines;
}

/**
 * Renders the option lines of a command.
 *
 * @param {string} command
 * @returns {string[]} the lines, one per flag, sorted by flag name.
 */
export function flagLines(command) {
  const spec = flagsFor(command);
  const names = Object.keys(spec).sort();
  const width = names.reduce((max, name) => Math.max(max, name.length), 0);
  return names.map((name) => {
    const definition = spec[name];
    const value = typeof definition.value === 'string' ? ` ${definition.value}` : '';
    const label = `--${name}${value}`;
    return `  ${label.padEnd(width + 12)} ${definition.summary}`;
  });
}

/**
 * The help of the tool: the list of the commands and of the global flags.
 *
 * @returns {string}
 */
export function globalHelp() {
  const lines = [];
  lines.push(`${TOOL_NAME} ${TOOL_VERSION} - offline secret scanning, SAST, dependency audit, SBOM and policy gating`);
  lines.push('');
  lines.push('Usage:');
  lines.push('  devsecops <command> [options]');
  lines.push('  devsecops <command> --help');
  lines.push('');
  lines.push('Commands:');
  const width = COMMANDS.reduce((max, name) => Math.max(max, name.length), 0);
  for (const name of COMMANDS) {
    lines.push(`  ${name.padEnd(width)}  ${DESCRIPTIONS[name]}`);
  }
  lines.push('');
  lines.push('Global options:');
  const names = Object.keys(GLOBAL_FLAGS).sort();
  const globalWidth = names.reduce((max, name) => Math.max(max, name.length), 0);
  for (const name of names) {
    const definition = GLOBAL_FLAGS[name];
    const value = typeof definition.value === 'string' ? ` ${definition.value}` : '';
    lines.push(`  --${name}${value}`.padEnd(globalWidth + 16) + ` ${definition.summary}`);
  }
  lines.push('');
  lines.push(...exitCodeLines());
  lines.push('');
  lines.push('Examples:');
  lines.push('  devsecops scan --path . --format json');
  lines.push('  devsecops verify');
  lines.push('  devsecops validate-evidence --file EVIDENCE.md');
  return `${lines.join('\n')}\n`;
}

/**
 * The help of one command.
 *
 * @param {string} command
 * @returns {string} the help; the global help when the command is unknown.
 */
export function commandHelp(command) {
  if (!isCommand(command)) return globalHelp();

  const lines = [];
  lines.push(`${TOOL_NAME} ${command} - ${DESCRIPTIONS[command]}`);
  lines.push('');
  lines.push('Usage:');
  lines.push(`  devsecops ${command} [options]`);
  lines.push('');
  lines.push('Options:');
  for (const line of flagLines(command)) lines.push(line);
  lines.push('');
  const notes = Array.isArray(NOTES[command]) ? NOTES[command] : [];
  if (notes.length > 0) {
    lines.push('Notes:');
    for (const note of notes) lines.push(`  ${note}`);
    lines.push('');
  }
  lines.push(...exitCodeLines());
  return `${lines.join('\n')}\n`;
}

/**
 * The help to print for a command.
 *
 * @param {string} command
 * @returns {string}
 */
export function helpFor(command) {
  return commandHelp(command);
}

/**
 * The one line summaries of the commands, for the documentation tests.
 *
 * @returns {{ command: string, summary: string }[]}
 */
export function commandSummaries() {
  return COMMANDS.map((command) => ({ command, summary: DESCRIPTIONS[command] }));
}
