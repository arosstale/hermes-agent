/**
 * Command line parser of the kit.
 *
 * The parser is deliberately strict: a flag that the command does not know
 * is an *error* (exit code 2), never a silently ignored typo. A tool that
 * quietly ignores `--fail-on` is a tool that quietly ignores its own
 * security policy.
 *
 * The contract
 *   - the first token that is not a flag is the command;
 *   - every flag belongs either to the global set or to the set of the
 *     command; anything else is an error;
 *   - a flag that expects a value consumes the next token, or the part
 *     after the `=` of `--flag=value`;
 *   - `--` ends the flags: everything after it is a positional argument;
 *   - `--help` is accepted by every command and never fails.
 *
 * Signatures
 *   parseArgs(argv: string[]): {
 *     command: string,
 *     flags: Record<string, string | boolean | string[]>,
 *     positionals: string[],
 *     errors: string[],
 *   }
 *   flagsFor(command: string): Record<string, object>
 *   knownFlags(command: string): string[]
 *   isCommand(name: string): boolean
 *
 * The constants `COMMANDS`, `FORMATS`, `GLOBAL_FLAGS` and `COMMAND_FLAGS`
 * describe the surface of the tool; `src/cli/help.js` renders the same
 * information as text, so the documentation and the parser can never drift
 * apart.
 */

import { SEVERITY_ORDER } from '../policy/severity.js';

/** The commands of the kit, in the order the help lists them. */
export const COMMANDS = Object.freeze([
  'doctor',
  'secrets',
  'sast',
  'deps',
  'sbom',
  'policy',
  'scan',
  'verify',
  'evidence',
  'validate-evidence',
  'install-hook',
]);

/** The output formats the kit understands. */
export const FORMATS = Object.freeze(['json', 'sarif', 'markdown']);

/**
 * The flags every command understands.
 *
 * @type {Readonly<Record<string, object>>}
 */
export const GLOBAL_FLAGS = Object.freeze({
  help: Object.freeze({ type: 'boolean', summary: 'print the help of the command and exit with 0' }),
  version: Object.freeze({ type: 'boolean', summary: 'print the version of the kit and exit with 0' }),
  path: Object.freeze({ type: 'string', value: '<dir>', summary: 'the directory to work on (default: the current directory)' }),
  format: Object.freeze({ type: 'string', value: '<json|sarif|markdown>', choices: FORMATS, summary: 'the format of the output' }),
  offline: Object.freeze({ type: 'boolean', summary: 'never use the network (this is the default)' }),
  config: Object.freeze({ type: 'string', value: '<file>', summary: 'the security policy to apply (default: policy/security-policy.yml)' }),
  'fail-on': Object.freeze({ type: 'string', value: '<severity>', choices: SEVERITY_ORDER, summary: 'the severity at which the gate fails' }),
  out: Object.freeze({ type: 'string', value: '<path>', summary: 'the output directory (the output file, for "evidence")' }),
  now: Object.freeze({ type: 'string', value: '<iso>', summary: 'the ISO timestamp written into the scan manifest' }),
  verbose: Object.freeze({ type: 'boolean', summary: 'print the details of the run' }),
});

/**
 * The flags of the commands, on top of the global ones.
 *
 * @type {Readonly<Record<string, Readonly<Record<string, object>>>>}
 */
export const COMMAND_FLAGS = Object.freeze({
  doctor: Object.freeze({}),
  secrets: Object.freeze({
    'git-staged': Object.freeze({ type: 'boolean', summary: 'scan only the files that git reports as staged' }),
  }),
  sast: Object.freeze({
    lang: Object.freeze({ type: 'string', value: '<a,b>', summary: 'restrict the scan to these languages' }),
    rule: Object.freeze({ type: 'string', value: '<id>', summary: 'restrict the scan to this rule id' }),
  }),
  deps: Object.freeze({
    online: Object.freeze({ type: 'boolean', summary: 'ask the online advisory service (opt-in, the default is offline)' }),
    timeout: Object.freeze({ type: 'string', value: '<ms>', summary: 'the hard timeout of the online lookup' }),
  }),
  sbom: Object.freeze({
    enrich: Object.freeze({ type: 'boolean', summary: 'add the licenses resolved by npm' }),
  }),
  policy: Object.freeze({
    findings: Object.freeze({ type: 'string', value: '<file>', summary: 'the findings document to judge (default: reports/findings.json)' }),
  }),
  scan: Object.freeze({
    stage: Object.freeze({ type: 'string', value: '<name>', multiple: true, summary: 'run only this stage (repeatable)' }),
    'out-dir': Object.freeze({ type: 'string', value: '<dir>', summary: 'an alias of --out' }),
    'no-write': Object.freeze({ type: 'boolean', summary: 'do not write the report artefacts' }),
  }),
  verify: Object.freeze({
    root: Object.freeze({ type: 'string', value: '<dir>', summary: 'the project root to verify (default: the current directory)' }),
  }),
  evidence: Object.freeze({
    emit: Object.freeze({ type: 'boolean', summary: 'write the evidence document' }),
    criteria: Object.freeze({ type: 'string', value: '<file>', summary: 'the acceptance criteria (default: evidence/acceptance.yml)' }),
    run: Object.freeze({ type: 'boolean', summary: 'execute every command of the criteria and capture its output' }),
    force: Object.freeze({ type: 'boolean', summary: 'overwrite an existing evidence document even without the evidence it produced' }),
  }),
  'validate-evidence': Object.freeze({
    file: Object.freeze({ type: 'string', value: '<path>', summary: 'the evidence document to validate (default: EVIDENCE.md)' }),
    criteria: Object.freeze({ type: 'string', value: '<file>', summary: 'the acceptance criteria to check against (default: evidence/acceptance.yml)' }),
  }),
  'install-hook': Object.freeze({
    target: Object.freeze({ type: 'string', value: '<path>', summary: 'the file to write (default: .git/hooks/pre-commit)' }),
    source: Object.freeze({ type: 'string', value: '<path>', summary: 'the hook to install (default: the hook of the kit)' }),
    force: Object.freeze({ type: 'boolean', summary: 'overwrite a hook that the kit did not write' }),
    'hooks-path': Object.freeze({ type: 'boolean', summary: 'point core.hooksPath at the .githooks directory' }),
  }),
});

/**
 * Tells whether a name is one of the commands of the kit.
 *
 * @param {unknown} name
 * @returns {boolean}
 */
export function isCommand(name) {
  return typeof name === 'string' && COMMANDS.includes(name);
}

/**
 * The flags a command understands: the global ones plus its own.
 *
 * @param {string} command
 * @returns {Record<string, object>} the flag specifications.
 */
export function flagsFor(command) {
  const own = isCommand(command) ? COMMAND_FLAGS[command] : {};
  return { ...GLOBAL_FLAGS, ...own };
}

/**
 * The names of the flags a command understands.
 *
 * @param {string} command
 * @returns {string[]} the flag names, sorted.
 */
export function knownFlags(command) {
  return Object.keys(flagsFor(command)).sort();
}

/**
 * Splits a token of the form `--flag=value`.
 *
 * @param {string} token
 * @returns {{ name: string, value: string|null }}
 */
function splitToken(token) {
  const body = token.slice(2);
  const index = body.indexOf('=');
  if (index === -1) return { name: body, value: null };
  return { name: body.slice(0, index), value: body.slice(index + 1) };
}

/**
 * Splits the command line into flags and positionals.
 *
 * The flags are kept in the order they were given, and every flag that has
 * no inline value keeps its position, so that the second pass can look at
 * the token that follows it.
 *
 * @param {string[]} tokens
 * @returns {{ entries: object[], positionals: string[], errors: string[] }}
 */
function tokenize(tokens) {
  const entries = [];
  const positionals = [];
  const errors = [];
  let terminated = false;

  for (const token of tokens) {
    if (terminated) {
      positionals.push(token);
      continue;
    }
    if (token === '--') {
      terminated = true;
      continue;
    }
    if (token === '-h') {
      entries.push({ kind: 'flag', name: 'help', value: null });
      continue;
    }
    if (token.startsWith('--')) {
      const { name, value } = splitToken(token);
      if (name === '') {
        errors.push(`unknown flag "${token}"`);
        continue;
      }
      entries.push({ kind: 'flag', name, value });
      continue;
    }
    if (token.startsWith('-') && token !== '-') {
      errors.push(`unknown flag "${token}"`);
      continue;
    }
    entries.push({ kind: 'positional', value: token });
  }

  return { entries, positionals, errors };
}

/**
 * Parses the command line of the kit.
 *
 * @param {string[]} argv the arguments, without the node executable and the
 *   script name.
 * @returns {{ command: string, flags: object, positionals: string[], errors: string[] }}
 */
export function parseArgs(argv) {
  const tokens = Array.isArray(argv) ? argv.map((token) => String(token)) : [];
  const { entries, positionals, errors } = tokenize(tokens);

  // The command is the first positional token; the other ones are arguments
  // that no command accepts (unless a flag consumes them as its value).
  let command = '';
  const rest = [];
  for (const entry of entries) {
    if (entry.kind === 'positional' && command === '') {
      command = entry.value;
      continue;
    }
    rest.push(entry);
  }

  const flags = {};
  const spec = flagsFor(command);

  for (let index = 0; index < rest.length; index += 1) {
    const entry = rest[index];
    if (entry.kind !== 'flag') continue;
    const definition = spec[entry.name];
    if (definition === undefined) {
      errors.push(`unknown flag "--${entry.name}"${command === '' ? '' : ` for the command "${command}"`}`);
      continue;
    }

    if (definition.type === 'boolean') {
      if (entry.value === null) {
        flags[entry.name] = true;
        continue;
      }
      flags[entry.name] = String(entry.value).toLowerCase() !== 'false';
      continue;
    }

    // A flag that expects a value: either it was given inline, or it
    // consumes the next token.
    let text = entry.value;
    if (text === null) {
      const next = rest[index + 1];
      if (next !== undefined && next.kind === 'positional') {
        text = String(next.value);
        next.consumed = true;
        index += 1;
      }
    }
    if (text === null) {
      errors.push(`the flag "--${entry.name}" needs a value`);
      continue;
    }
    if (Array.isArray(definition.choices) && !definition.choices.includes(text)) {
      errors.push(`the flag "--${entry.name}" only accepts ${definition.choices.join(', ')} (got "${text}")`);
      continue;
    }
    if (definition.multiple === true) {
      const list = Array.isArray(flags[entry.name]) ? flags[entry.name].slice() : [];
      list.push(text);
      flags[entry.name] = list;
      continue;
    }
    flags[entry.name] = text;
  }

  const isHelp = flags.help === true;
  const isVersion = flags.version === true;

  if (command === '') {
    if (!isHelp && !isVersion) {
      errors.push('no command given: run "devsecops --help" to see the commands');
    }
  } else if (!isCommand(command)) {
    errors.push(`unknown command "${command}": run "devsecops --help" to see the commands`);
  }

  const argumentsFound = [];
  for (const entry of rest) {
    if (entry.kind !== 'positional' || entry.consumed === true) continue;
    argumentsFound.push(String(entry.value));
  }
  for (const value of positionals) argumentsFound.push(value);
  if (argumentsFound.length > 0) {
    errors.push(`unexpected argument "${argumentsFound[0]}"`);
  }

  return { command, flags, positionals, errors };
}
