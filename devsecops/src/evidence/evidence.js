/**
 * The evidence gate.
 *
 * A piece of work is only complete when it carries its proof. The gate
 * checks that every acceptance criterion of the evidence document carries:
 *
 *   - a heading (`### Criterio: <title>` or `### Criterion: <title>`);
 *   - the command that was run (a line starting with `$ `, or a `comando:`
 *     line);
 *   - a fenced block with at least one non empty line: the output of the
 *     command;
 *   - a verdict line (`esito: PASS`, or `esito: FAIL`).
 *
 * The document is only valid when every criterion carries all three and no
 * criterion failed.
 *
 * The shape of the document is not enough: a document that proves nothing
 * (one trivial criterion, a hand written block, a placeholder) must not
 * satisfy the gate. When the acceptance criteria are known
 * (`opts.criteria`), the document is checked against them as well:
 *
 *   - every criterion of the acceptance criteria must be present;
 *   - the command of the block must be the command of the criterion;
 *   - the output must be a real output, not a placeholder;
 *   - the verdict must be `esito: PASS`;
 *   - a criterion that the acceptance criteria do not know is an error.
 *
 * Two rules against the forged proofs
 *   A document can be forged in two ways that the shape does not catch:
 *
 *   - a **duplicated criterion**: the same criterion id appears twice, and
 *     the first block wins while the second one is ignored. A document that
 *     carries the same criterion id twice is refused;
 *   - a **copied output**: the output of one criterion is pasted into the
 *     block of another one, whose command is different. Two criteria whose
 *     command lines differ and whose outputs are byte identical are refused,
 *     unless the acceptance criteria declare the sharing explicitly
 *     (`allow_shared_output`).
 *
 * Signatures
 *   parseCriteriaFile(file: string): Criterion[]
 *       reads `evidence/acceptance.yml` (or any file of the same shape).
 *   renderEvidence(criteria: Criterion[], results?: Map<string, {
 *       command: string, output: string, exitCode: number }>, opts?: {
 *       snapshot?: { digest?: string, label?: string, excluded?: string[] },
 *     }): string
 *       renders the evidence document.
 *   validateEvidence(text: string, opts?: { source?: string,
 *       criteria?: Criterion[] }): {
 *       ok: boolean,
 *       criteria: { title: string, id: string, hasCommand: boolean,
 *                    hasOutput: boolean, verdict: "PASS" | "FAIL" | "MISSING" }[],
 *       errors: string[],
 *   }
 *
 * A Criterion is `{ id: string, title: string, command: string,
 * allowSharedOutput?: boolean | string[] }`.
 *
 * The digest of the tree
 *   The document quotes the digest of the tree it describes, and it quotes
 *   it **with its label**: the digest never covers the evidence log nor the
 *   artefacts of the kit, and a reader who does not know that would compare
 *   it with the digest of a tree that carries the log. A document that
 *   quotes a digest without its label is refused by the validator.
 *
 * Also exported: the constants `CRITERION_HEADING`, `VERDICT_LINE`,
 * `PLACEHOLDER_OUTPUTS` and `MIN_SHARED_OUTPUT_LENGTH`.
 */

import { existsSync } from 'node:fs';
import { KitError } from '../core/errors.js';
import { parseYamlFile } from '../yaml/parse-yaml.js';

/** The heading of a criterion. */
export const CRITERION_HEADING = /^#{2,4}\s+(?:criterio|criterion)\s*:\s*(.+)$/i;

/** The verdict line of a criterion. */
export const VERDICT_LINE = /^\s*(?:esito|verdict)\s*:\s*(pass|fail|missing)\b\s*$/i;

/**
 * The identifier of a criterion, at the beginning of its heading.
 *
 * The identifiers of the acceptance criteria look like `A1`, `A12` or `X1`:
 * a few letters followed by digits.
 */
const CRITERION_ID = /^([A-Za-z]{1,4}\d+)\s*(?:[-–—:|]\s*)?(.*)$/;

/**
 * The outputs that are a placeholder instead of a proof.
 *
 * @type {ReadonlyArray<string>}
 */
export const PLACEHOLDER_OUTPUTS = Object.freeze([
  '(no output)',
  'no output',
  '(none)',
  'none',
  'n/a',
  'na',
  'todo',
  'tbd',
  'pending',
  'placeholder',
  '...',
]);

/**
 * The shortest output that can be compared with another one.
 *
 * A trivial output ("(no output)", a single character) says nothing about
 * the command that produced it: comparing it with another trivial output
 * would only produce noise.
 */
export const MIN_SHARED_OUTPUT_LENGTH = 40;

/**
 * The environment variable the emitter sets while it runs the criteria.
 *
 * The evidence log under construction cannot be the proof of the run that
 * writes it: the test that checks the committed log stands down while the
 * emitter works, and the log is checked again as soon as it is committed.
 */
export const EMITTING_ENV = 'DEVSECOPS_KIT_EMITTING_EVIDENCE';

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
 * Reads the acceptance criteria of a file.
 *
 * The file is a YAML document with a `criteria` list:
 *
 * ```yaml
 * version: 1
 * criteria:
 *   - id: A1
 *     title: "Zero third-party runtime dependencies"
 *     command: "node bin/devsecops.js doctor"
 * ```
 *
 * @param {string} file
 * @returns {object[]} the criteria: `{ id, title, command }`.
 * @throws {KitError} with code `E_EVIDENCE` when the file cannot be read or
 *   does not describe valid criteria.
 */
export function parseCriteriaFile(file) {
  if (typeof file !== 'string' || file === '') {
    throw new KitError('E_EVIDENCE', 'the acceptance criteria file is missing');
  }
  if (!existsSync(file)) {
    throw new KitError('E_EVIDENCE', `the acceptance criteria file ${file} does not exist`, { file });
  }
  let document;
  try {
    document = parseYamlFile(file);
  } catch (err) {
    throw new KitError('E_EVIDENCE', `the acceptance criteria file ${file} cannot be parsed: ${err && err.message ? err.message : String(err)}`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  if (!isPlainObject(document)) {
    throw new KitError('E_EVIDENCE', `the acceptance criteria file ${file} must contain a mapping`, { file });
  }
  const list = Array.isArray(document.criteria) ? document.criteria : [];
  if (list.length === 0) {
    throw new KitError('E_EVIDENCE', `the acceptance criteria file ${file} carries no criterion`, { file });
  }
  return list.map((entry, index) => {
    if (!isPlainObject(entry)) {
      throw new KitError('E_EVIDENCE', `the criterion ${index} of ${file} is not a mapping`, { file, index });
    }
    const id = typeof entry.id === 'string' ? entry.id.trim() : '';
    const title = typeof entry.title === 'string' ? entry.title.trim() : '';
    const command = typeof entry.command === 'string' ? entry.command.trim() : '';
    if (id === '' || title === '' || command === '') {
      throw new KitError('E_EVIDENCE', `the criterion ${index} of ${file} must carry an id, a title and a command`, { file, index });
    }
    return { id, title, command, allowSharedOutput: parseSharedOutput(entry.allow_shared_output, file, index) };
  });
}

/**
 * Reads the declaration that allows two criteria to share their output.
 *
 * The declaration is explicit: `true` (the output may be shared with any
 * other criterion) or the list of the criterion ids it may be shared with.
 *
 * @param {unknown} value the raw value of the key.
 * @param {string} file the criteria file (for the error message).
 * @param {number} index the index of the criterion (for the error message).
 * @returns {boolean|string[]} the declaration.
 * @throws {KitError} with the code `E_EVIDENCE` when the value is invalid.
 */
function parseSharedOutput(value, file, index) {
  if (value === undefined || value === null) return [];
  if (value === true) return true;
  if (Array.isArray(value)) {
    const list = value.filter((entry) => typeof entry === 'string' && entry.trim() !== '');
    if (list.length !== value.length) {
      throw new KitError('E_EVIDENCE', `the criterion ${index} of ${file} must list the criterion ids it shares its output with`, { file, index });
    }
    return list.map((entry) => entry.trim());
  }
  throw new KitError('E_EVIDENCE', `the criterion ${index} of ${file} must declare "allow_shared_output" as a boolean or a list of criterion ids`, { file, index });
}

/**
 * The result of a criterion.
 *
 * @param {Criterion} criterion
 * @param {Map<string, object>|object|null} results
 * @returns {{ command: string, output: string, exitCode: number }|null}
 */
function resultOf(criterion, results) {
  if (results === null || results === undefined) return null;
  if (typeof results.get === 'function') {
    const found = results.get(criterion.id);
    return found === undefined ? null : found;
  }
  if (isPlainObject(results)) {
    const found = results[criterion.id];
    return found === undefined ? null : found;
  }
  return null;
}

/**
 * Renders the evidence document of a list of criteria.
 *
 * The document is the skeleton of the proof: a heading, the command, the
 * output of the command and the verdict. When a result is known, the output
 * and the verdict are filled in; otherwise the verdict is `MISSING`, because
 * a criterion that was not run cannot be a pass.
 *
 * The header carries the digest of the tree the document describes, the
 * label that says what the digest does not cover, and the paths that are
 * excluded from it: a digest without its label misleads.
 *
 * @param {object[]} criteria the criteria.
 * @param {Map<string, { command: string, output: string, exitCode: number }>|object} [results]
 *   the outcome of every criterion, indexed by criterion id.
 * @param {object} [opts] the options of the document.
 * @param {object} [opts.snapshot] the snapshot of the tree.
 * @param {string} [opts.snapshot.digest] the digest of the tree.
 * @param {string} [opts.snapshot.label] the label of the digest.
 * @param {string[]} [opts.snapshot.excluded] the paths excluded from it.
 * @returns {string} the Markdown document.
 */
export function renderEvidence(criteria, results = null, opts = {}) {
  const list = Array.isArray(criteria) ? criteria : [];
  const options = opts && typeof opts === 'object' ? opts : {};
  const snapshot = options.snapshot && typeof options.snapshot === 'object' ? options.snapshot : {};
  const digest = typeof snapshot.digest === 'string' ? snapshot.digest : '';
  const label = typeof snapshot.label === 'string' ? snapshot.label : '';
  const excluded = Array.isArray(snapshot.excluded)
    ? snapshot.excluded.filter((entry) => typeof entry === 'string' && entry !== '')
    : [];
  const lines = [];
  lines.push('# Evidence log');
  lines.push('');
  lines.push('Generated by devsecops-kit. Every criterion carries the command that was run,');
  lines.push('its output and the verdict of the run.');
  lines.push('');
  if (digest !== '') {
    lines.push(`- Snapshot digest: \`${digest}\``);
    if (label !== '') lines.push(`- Snapshot digest label: ${label}`);
    if (excluded.length > 0) {
      lines.push(`- Excluded from the digest: ${excluded.map((entry) => `\`${entry}\``).join(', ')}`);
    }
    lines.push('');
  }

  for (const criterion of list) {
    const id = String(criterion && criterion.id ? criterion.id : '');
    const title = String(criterion && criterion.title ? criterion.title : '');
    const command = String(criterion && criterion.command ? criterion.command : '');
    const result = resultOf({ id }, results);
    const commandLine = result && typeof result.command === 'string' && result.command !== ''
      ? result.command
      : command;
    let output = result && typeof result.output === 'string' ? result.output : '';
    if (output.trim() === '') output = '(no output)';
    let verdict = 'MISSING';
    if (result && typeof result.exitCode === 'number') {
      verdict = result.exitCode === 0 ? 'PASS' : 'FAIL';
    }

    lines.push(`### Criterio: ${id ? `${id} - ` : ''}${title}`);
    lines.push('');
    lines.push(`$ ${commandLine}`);
    lines.push('');
    lines.push('```');
    for (const line of output.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n')) {
      lines.push(line);
    }
    lines.push('```');
    lines.push('');
    lines.push(`esito: ${verdict}`);
    lines.push('');
  }

  return `${lines.join('\n')}`;
}

/**
 * Splits a document into its criterion blocks.
 *
 * @param {string} text
 * @returns {{ title: string, id: string, body: string[] }[]}
 */
function splitCriteria(text) {
  const lines = String(text ?? '').split(/\r\n|\r|\n/);
  const blocks = [];
  let current = null;
  for (const line of lines) {
    const heading = CRITERION_HEADING.exec(line);
    if (heading !== null) {
      if (current !== null) blocks.push(current);
      current = { title: heading[1].trim(), id: criterionIdOf(heading[1].trim()), body: [] };
      continue;
    }
    if (current !== null) {
      if (/^\s*#{1,6}\s/.test(line)) {
        blocks.push(current);
        current = null;
        continue;
      }
      current.body.push(line);
    }
  }
  if (current !== null) blocks.push(current);
  return blocks;
}

/**
 * The identifier of a criterion, read from its heading.
 *
 * @param {string} title the text of the heading.
 * @returns {string} the identifier, or an empty string when the heading does
 *   not carry one.
 */
export function criterionIdOf(title) {
  const match = CRITERION_ID.exec(String(title ?? '').trim());
  return match === null ? '' : match[1];
}

/**
 * The command of a block, read from its body.
 *
 * @param {string[]} body
 * @returns {string} the command, or an empty string when there is none.
 */
function commandOf(body) {
  for (const line of body) {
    const dollar = /^\s*\$\s+(.*)$/.exec(line);
    if (dollar !== null) return dollar[1].trim();
    const named = /^\s*comando\s*:\s*(.*)$/i.exec(line);
    if (named !== null) return named[1].trim();
  }
  return '';
}

/**
 * Tells whether a block carries a command line.
 *
 * @param {string[]} body
 * @returns {boolean}
 */
function hasCommandLine(body) {
  return commandOf(body) !== '';
}

/**
 * The output of a block: the content of its fenced block.
 *
 * @param {string[]} body
 * @returns {string} the output, or an empty string when there is none.
 */
function outputOf(body) {
  const lines = [];
  let inside = false;
  for (const line of body) {
    if (/^\s*(?:```|~~~)/.test(line)) {
      inside = !inside;
      continue;
    }
    if (inside) lines.push(line);
  }
  return lines.join('\n');
}

/**
 * Tells whether a block carries a fenced block with an output.
 *
 * @param {string[]} body
 * @returns {boolean}
 */
function hasOutputBlock(body) {
  let inside = false;
  let content = 0;
  for (const line of body) {
    if (/^\s*(?:```|~~~)/.test(line)) {
      if (inside) {
        inside = false;
        if (content > 0) return true;
        continue;
      }
      inside = true;
      content = 0;
      continue;
    }
    if (inside && line.trim() !== '') content += 1;
  }
  return false;
}

/**
 * Tells whether an output is a placeholder instead of a real output.
 *
 * @param {string} output
 * @returns {boolean}
 */
export function isPlaceholderOutput(output) {
  const text = String(output ?? '').trim().toLowerCase();
  if (text === '') return true;
  return PLACEHOLDER_OUTPUTS.includes(text);
}

/**
 * Tells whether two command lines are the same command.
 *
 * @param {string} left
 * @param {string} right
 * @returns {boolean}
 */
function sameCommand(left, right) {
  const a = String(left ?? '').trim();
  const b = String(right ?? '').trim();
  if (a === b) return true;
  return a.replace(/\s+/g, ' ') === b.replace(/\s+/g, ' ');
}

/**
 * The verdict of a block.
 *
 * @param {string[]} body
 * @returns {"PASS" | "FAIL" | "MISSING"}
 */
function verdictOf(body) {
  let verdict = 'MISSING';
  for (const line of body) {
    const match = VERDICT_LINE.exec(line);
    if (match === null) continue;
    verdict = match[1].toUpperCase();
  }
  return verdict;
}

/**
 * Tells whether an output is too trivial to be compared with another one.
 *
 * @param {string} output
 * @returns {boolean}
 */
export function isTrivialOutput(output) {
  const text = String(output ?? '').trim();
  if (text === '') return true;
  if (isPlaceholderOutput(text)) return true;
  return text.length < MIN_SHARED_OUTPUT_LENGTH;
}

/**
 * Tells whether two criteria are allowed to carry the same output.
 *
 * The allowance is explicit and comes from the acceptance criteria: a
 * criterion may declare `allow_shared_output: true` (the output may be
 * shared with any other criterion) or list the criterion ids it may be
 * shared with.
 *
 * @param {object} left the criterion of the left block.
 * @param {object} right the criterion of the right block.
 * @param {Map<string, object>} known the acceptance criteria, by id.
 * @returns {boolean}
 */
function sharedOutputAllowed(left, right, known) {
  const declares = (criterion, otherId) => {
    if (!criterion || typeof criterion !== 'object') return false;
    const value = criterion.allowSharedOutput;
    if (value === true) return true;
    if (Array.isArray(value)) return value.includes(otherId);
    return false;
  };
  const leftCriterion = known.get(left.id);
  const rightCriterion = known.get(right.id);
  if (declares(leftCriterion, right.id)) return true;
  if (declares(rightCriterion, left.id)) return true;
  return false;
}

/**
 * Validates an evidence document.
 *
 * When the acceptance criteria are known (`opts.criteria`), the document is
 * checked against them: every criterion must be present, with the command of
 * the criterion, a real output and a `PASS` verdict. A document that proves
 * something else is not a proof of this build.
 *
 * @param {string} text the document.
 * @param {object} [opts]
 * @param {string} [opts.source] the name of the document, used in the errors.
 * @param {object[]} [opts.criteria] the acceptance criteria to check against.
 * @returns {{ ok: boolean, criteria: object[], errors: string[] }}
 */
export function validateEvidence(text, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const source = typeof options.source === 'string' && options.source !== '' ? options.source : 'the evidence document';
  const document = String(text ?? '');
  const errors = [];
  const criteria = [];

  const blocks = splitCriteria(document);
  for (const block of blocks) {
    const hasCommand = hasCommandLine(block.body);
    const hasOutput = hasOutputBlock(block.body);
    const verdict = verdictOf(block.body);
    criteria.push({
      title: block.title,
      id: block.id,
      hasCommand,
      hasOutput,
      verdict,
      command: commandOf(block.body),
      output: outputOf(block.body),
    });

    if (!hasCommand) errors.push(`the criterion "${block.title}" carries no command line`);
    if (!hasOutput) errors.push(`the criterion "${block.title}" carries no output block`);
    if (verdict === 'MISSING') errors.push(`the criterion "${block.title}" carries no verdict (expected "esito: PASS")`);
    if (verdict === 'FAIL') errors.push(`the criterion "${block.title}" failed`);
  }

  // A duplicated criterion: the same id twice. The first block would win
  // and the second one would be ignored, so a document that carries the
  // same criterion twice is a document that proves something else than it
  // says.
  const seenIds = new Map();
  for (const block of criteria) {
    if (block.id === '') continue;
    if (seenIds.has(block.id)) {
      errors.push(`the criterion "${block.id}" is declared twice: a document must not carry the same criterion id twice`);
      continue;
    }
    seenIds.set(block.id, block);
  }

  if (criteria.length === 0) {
    errors.push(`${source} carries no criterion (expected a "### Criterio: <title>" heading)`);
  }

  // A failure anywhere in the document fails the document, even when it
  // sits outside a criterion block.
  const foreignFailures = document.split(/\r\n|\r|\n/).filter((line) => /^\s*(?:esito|verdict)\s*:\s*fail\b/i.test(line));
  if (foreignFailures.length > 0 && !criteria.some((criterion) => criterion.verdict === 'FAIL')) {
    errors.push(`${source} carries a failure verdict outside a criterion`);
  }

  // A digest without its label misleads: the label says what the digest does
  // *not* cover (the evidence log and the artefacts of the kit). A document
  // that quotes a digest must quote its label too.
  const documentLines = document.split(/\r\n|\r|\n/);
  const quotesDigest = documentLines.some((line) => /snapshot\s*digest|snapshotDigest/i.test(line) && /devsecops-snapshot\//i.test(line));
  const quotesLabel = documentLines.some((line) => /snapshot\s*digest\s*label|snapshotDigestLabel/i.test(line));
  if (quotesDigest && !quotesLabel) {
    errors.push(`${source} quotes a snapshot digest without its label: a digest must say what it does not cover`);
  }

  // The acceptance criteria: the shape of the document is not enough, it has
  // to prove *these* criteria.
  const expected = Array.isArray(options.criteria) ? options.criteria : null;
  if (expected !== null) {
    const known = new Map();
    for (const criterion of expected) {
      if (!criterion || typeof criterion !== 'object') continue;
      const id = typeof criterion.id === 'string' ? criterion.id.trim() : '';
      if (id === '') continue;
      known.set(id, criterion);
    }
    const blocksById = new Map();
    for (const block of criteria) {
      if (block.id === '') continue;
      if (!blocksById.has(block.id)) blocksById.set(block.id, block);
    }

    for (const [id, criterion] of known) {
      const block = blocksById.get(id);
      if (block === undefined) {
        errors.push(`${source} does not evidence the criterion "${id}" (${criterion.title})`);
        continue;
      }
      if (!block.hasCommand) continue; // already reported
      const wanted = typeof criterion.command === 'string' ? criterion.command.trim() : '';
      if (!sameCommand(block.command, wanted)) {
        errors.push(`the criterion "${id}" runs "${block.command}" but the acceptance criteria require "${wanted}"`);
      }
      if (block.hasOutput && isPlaceholderOutput(block.output)) {
        errors.push(`the criterion "${id}" carries a placeholder instead of the real output of the command`);
      }
      if (block.verdict !== 'PASS') {
        errors.push(`the criterion "${id}" is not a pass (verdict: ${block.verdict})`);
      }
    }

    for (const block of criteria) {
      if (block.id === '') continue;
      if (known.has(block.id)) continue;
      errors.push(`${source} evidences the unknown criterion "${block.id}"`);
    }

    // A copied output: two criteria whose command lines differ and whose
    // outputs are byte identical. The output of one criterion cannot be
    // the proof of another one, unless the acceptance criteria declare the
    // sharing explicitly.
    const byOutput = new Map();
    for (const block of criteria) {
      if (block.id === '') continue;
      if (!block.hasOutput) continue;
      if (isTrivialOutput(block.output)) continue;
      const key = block.output;
      if (!byOutput.has(key)) byOutput.set(key, []);
      byOutput.get(key).push(block);
    }
    for (const group of byOutput.values()) {
      for (let left = 0; left < group.length; left += 1) {
        for (let right = left + 1; right < group.length; right += 1) {
          const first = group[left];
          const second = group[right];
          if (first.id === second.id) continue;
          if (sameCommand(first.command, second.command)) continue;
          if (sharedOutputAllowed(first, second, known)) continue;
          errors.push(`the criteria "${first.id}" and "${second.id}" carry the same output: the output of a criterion cannot be the proof of another one`);
        }
      }
    }
  }

  const ok = criteria.length > 0
    && errors.length === 0
    && criteria.every((criterion) => criterion.hasCommand && criterion.hasOutput && criterion.verdict === 'PASS');

  return { ok, criteria, errors };
}
