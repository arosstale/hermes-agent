/**
 * The command line of the kit.
 *
 * `main()` is the only entry point of the command line: it parses the
 * arguments, dispatches to the command and returns the exit code. The
 * launcher (`bin/devsecops.js`) only has to put that number into
 * `process.exitCode`.
 *
 * The exit code contract (plan section E)
 *   0  the gate passed, no finding at or above the threshold;
 *   1  findings at or above the threshold, or a policy violation;
 *   2  a tool or configuration error: an unknown command, an unknown flag,
 *      an unreadable or invalid policy, an invalid rule pack.
 *
 * An expected error is *never* a stack trace: the CLI prints
 * `error: <code> <message>` on stderr and returns 2.
 *
 * Signatures
 *   main(argv?: string[], io?: {
 *     stdout?: (text: string) => void,
 *     stderr?: (text: string) => void,
 *     cwd?: string,
 *   }): Promise<number>
 *   runCommand(command: string, flags: object, io: object): Promise<number>
 *   buildContext(flags: object, cwd: string): object
 *
 * The context of a run bundles the scan root, the security policy, the rule
 * packs and the advisory database. The rule packs and the advisory database
 * always come from the kit itself: they are the *detectors*, not the target.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { EXIT } from './core/exit-codes.js';
import { KitError, isKitError } from './core/errors.js';
import { sha256Hex } from './core/fingerprint.js';
import { buildSnapshot, sha256File, snapshotExclusions, SNAPSHOT_DIGEST_LABEL } from './core/snapshot.js';
import { gitRevision, stagedFiles } from './core/git.js';
import { loadPolicy, resolvePolicyFile } from './config/load-policy.js';
import { loadRulePack } from './core/rule-loader.js';
import { evaluateGate } from './policy/gate.js';
import { assertPolicyScope, coverageLine, scopeOf } from './policy/coverage.js';
import { auditDependencies, loadAdvisories } from './scanners/deps.js';
import { doctor as runDoctor, formatToolsTable } from './scanners/doctor.js';
import { buildSbom, componentDigest, serialNumberFor } from './scanners/sbom.js';
import { scanSast } from './scanners/sast.js';
import { scanSecrets } from './scanners/secrets.js';
import { buildFindingsDocument } from './report/findings.js';
import { buildScanManifest } from './report/manifest.js';
import { toSarif } from './report/sarif.js';
import { toSummaryMarkdown } from './report/summary-md.js';
import { ARTEFACTS, writeJson, writeReports } from './report/writer.js';
import { COMMANDS, parseArgs } from './cli/args.js';
import { TOOL_NAME, TOOL_VERSION, commandHelp, globalHelp } from './cli/help.js';
import { parseCriteriaFile, renderEvidence, validateEvidence, EMITTING_ENV } from './evidence/evidence.js';
import { installHook } from './hook/install.js';
import { runParityChecks } from './verify/parity.js';

/** The root of the kit: the directory that carries `src/`, `rules/` and `policy/`. */
export const KIT_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** The default output directory of the report artefacts. */
export const DEFAULT_OUT_DIR = 'reports';

/** The default file of the evidence log. */
export const DEFAULT_EVIDENCE_FILE = 'EVIDENCE.md';

/**
 * The default output streams.
 *
 * @returns {{ stdout: (text: string) => void, stderr: (text: string) => void, cwd: string }}
 */
function defaultIo() {
  return {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    cwd: process.cwd(),
  };
}

/**
 * Prints an expected error and returns the exit code 2.
 *
 * The message never carries a stack trace: the user has to be able to read
 * it, and it must never carry a credential.
 *
 * @param {unknown} error
 * @param {object} io
 * @returns {number} always 2.
 */
function reportError(error, io) {
  const code = isKitError(error) ? error.code : 'E_INTERNAL';
  const message = error && error.message ? String(error.message) : String(error);
  io.stderr(`error: ${code} ${message}\n`);
  return EXIT.ERROR;
}

/**
 * A copy of the policy without the evidence requirement.
 *
 * The evidence requirement describes the artefacts of a *complete* scan: the
 * single stage commands do not produce them, and must not fail because of
 * artefacts they never wrote.
 *
 * @param {object} policy
 * @returns {object} the copy.
 */
function withoutEvidenceRequirement(policy) {
  const copy = { ...policy, required_evidence: [] };
  return copy;
}

/**
 * A copy of the policy that only judges one stage.
 *
 * The single stage commands (`secrets`, `sast`, `deps`, `sbom`) run one
 * stage: the other stages are not missing, they were never asked for. The
 * copy keeps the stage under judgement enabled, so that the gate can still
 * refuse a stage that produced nothing.
 *
 * @param {object} policy
 * @param {string} stageName
 * @returns {object} the copy.
 */
function policyForStage(policy, stageName) {
  const copy = { ...policy, required_evidence: [] };
  const stages = policy && typeof policy.stages === 'object' && policy.stages !== null ? policy.stages : {};
  const config = stages[stageName] && typeof stages[stageName] === 'object' ? stages[stageName] : { enabled: true };
  copy.stages = { [stageName]: { ...config } };
  return copy;
}

/**
 * The reasons that make a stage not applicable.
 *
 * @type {ReadonlyArray<RegExp>}
 */
const NOT_APPLICABLE_REASONS = Object.freeze([
  /no dependency manifest was found/i,
  /not applicable: no dependency manifest in the tree/i,
]);

/**
 * Tells whether a stage is legitimately not applicable.
 *
 * A stage that does not apply (no dependency manifest to audit, no bill of
 * materials to build) may be disabled: it had nothing to do. A stage that
 * *failed* is never not applicable: the gate must report it as a violation
 * instead of turning it off.
 *
 * @param {object} stage the metadata of the stage.
 * @returns {boolean} true when the stage may be disabled.
 */
export function isNotApplicable(stage) {
  if (!stage || typeof stage !== 'object') return false;
  if (stage.status === 'completed') return false;
  const reason = typeof stage.reason === 'string' ? stage.reason : '';
  if (reason === '') return false;
  return NOT_APPLICABLE_REASONS.some((pattern) => pattern.test(reason));
}

/**
 * Builds the context of a run: the scan root, the policy, the rule packs and
 * the advisory database.
 *
 * The rule packs and the advisory database always come from the kit itself:
 * they are the *detectors*, not the target.
 *
 * @param {object} flags the parsed flags.
 * @param {string} cwd the working directory.
 * @param {object} [fs] the file system seam (the real one by default).
 * @returns {object} the context.
 * @throws {KitError} `E_POLICY` or `E_RULES` when the configuration is broken.
 */
export function buildContext(flags, cwd, fs = undefined) {
  const base = typeof cwd === 'string' && cwd !== '' ? cwd : process.cwd();
  const pathFlag = typeof flags.path === 'string' && flags.path !== '' ? flags.path : '.';
  const root = resolve(base, pathFlag);

  const configFlag = typeof flags.config === 'string' && flags.config !== '' ? flags.config : undefined;
  const policyFile = resolvePolicyFile(configFlag === undefined ? undefined : resolve(base, configFlag), root);
  const policy = loadPolicy(policyFile);

  const secretsPack = loadRulePack(join(KIT_ROOT, 'rules', 'secrets.yml'));
  const sastPack = loadRulePack(join(KIT_ROOT, 'rules', 'sast.yml'));
  const advisories = loadAdvisories(join(KIT_ROOT, 'policy', 'advisories.json')).advisories;

  return { root, policy, policyFile, secretsPack, sastPack, advisories, cwd: base, fs };
}

/**
 * The acceptance criteria of a run.
 *
 * The criteria of the repository come first (`<cwd>/evidence/acceptance.yml`),
 * so that a consumer of the kit proves its own criteria; the criteria of the
 * kit itself are the fallback.
 *
 * @param {object} flags the parsed flags.
 * @param {object} ctx the context of the run.
 * @returns {string} the absolute path of the criteria file.
 */
function criteriaFileOf(flags, ctx) {
  if (typeof flags.criteria === 'string' && flags.criteria !== '') {
    return resolve(ctx.cwd, flags.criteria);
  }
  const local = join(ctx.cwd, 'evidence', 'acceptance.yml');
  if (existsSync(local)) return local;
  return join(KIT_ROOT, 'evidence', 'acceptance.yml');
}

/**
 * The severity the gate has to apply.
 *
 * @param {object} flags
 * @param {object} policy
 * @returns {string|undefined} the requested severity, if any.
 */
function requestedFailOn(flags, policy) {
  if (typeof flags['fail-on'] === 'string' && flags['fail-on'] !== '') return flags['fail-on'];
  if (policy && policy.defaults && typeof policy.defaults.fail_on === 'string') return policy.defaults.fail_on;
  return undefined;
}

/**
 * The severity of a finding, normalised.
 *
 * @param {object} finding
 * @returns {string}
 */
function severityOf(finding) {
  const severity = finding && typeof finding.severity === 'string' ? finding.severity.trim().toLowerCase() : '';
  return ['info', 'low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'critical';
}

/**
 * Renders the findings as a Markdown table.
 *
 * @param {object[]} findings
 * @returns {string} the table.
 */
function findingsTable(findings) {
  const lines = ['| severity | rule | location | message |', '| --- | --- | --- | --- |'];
  for (const finding of findings) {
    const location = finding && finding.location ? finding.location : {};
    const line = Number(location.startLine);
    const where = Number.isFinite(line) && line > 0 ? `${location.path}:${line}` : String(location.path || '');
    const message = String(finding && finding.message ? finding.message : '').replace(/\|/g, '\\|');
    lines.push(`| ${severityOf(finding)} | ${finding.ruleId} | ${where} | ${message} |`);
  }
  return lines.join('\n');
}

/**
 * The counts of the findings per severity.
 *
 * @param {object[]} findings
 * @returns {Record<string, number>}
 */
function countBySeverity(findings) {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) counts[severityOf(finding)] += 1;
  return counts;
}

/**
 * The output format of a command.
 *
 * The default is the one of plan section E: `markdown` for `doctor`, `json`
 * for every other command. The human rendering (the tables) is asked for
 * with `--format markdown`.
 *
 * @param {object} flags the parsed flags.
 * @param {string} [command] the command the format is resolved for.
 * @returns {string} `json`, `sarif` or `markdown`.
 */
export function formatOf(flags, command = '') {
  const value = typeof flags.format === 'string' ? flags.format : '';
  if (value === 'json' || value === 'sarif' || value === 'markdown') return value;
  return command === 'doctor' ? 'markdown' : 'json';
}

/**
 * Prints the notes of a run.
 *
 * In the machine formats the notes go to the standard error, so that the
 * standard output stays a document a tool can parse.
 *
 * @param {object} io
 * @param {string[]} notes
 * @returns {void}
 */
function printNotes(io, notes) {
  for (const note of Array.isArray(notes) ? notes : []) io.stderr(`note: ${note}\n`);
}

/**
 * Prints the violations of the gate.
 *
 * @param {object} io
 * @param {object[]} violations
 * @returns {void}
 */
function printViolations(io, violations) {
  for (const violation of Array.isArray(violations) ? violations : []) {
    io.stderr(`  - ${violation.kind}: ${violation.detail}\n`);
  }
}

/**
 * Prints a document as JSON.
 *
 * @param {object} io
 * @param {object} document
 * @returns {void}
 */
function printJson(io, document) {
  io.stdout(`${JSON.stringify(document, null, 2)}\n`);
}

/* ------------------------------------------------------------------ stages */

/**
 * The coverage of a stage: the numbers and the sentence that tells them.
 *
 * @param {object} stats the statistics of a scanner.
 * @returns {{ inspected: number, filesInScope: number, dropped: number, unreadable: number, line: string }}
 */
function stageCoverage(stats) {
  const source = stats && typeof stats === 'object' ? stats : {};
  const inspected = Number.isInteger(source.inspected) ? source.inspected : 0;
  const filesInScope = Number.isInteger(source.inScope) ? source.inScope : 0;
  const dropped = Number.isInteger(source.dropped) ? source.dropped : 0;
  const unreadable = Number.isInteger(source.unreadable) ? source.unreadable : 0;
  return {
    inspected,
    filesInScope,
    dropped,
    unreadable,
    line: coverageLine({ inspected, filesInScope, dropped }),
  };
}

/**
 * The metadata of a stage.
 *
 * The notes of the stage always carry the coverage line: a reader of the
 * summary or of the manifest knows what the stage covered, and how many
 * files the walk dropped.
 *
 * @param {string} name the name of the stage.
 * @param {object} result the result of the scanner.
 * @param {string[]} artifacts the artefacts of the stage.
 * @param {object} [opts]
 * @param {string} [opts.status] the status of the stage.
 * @param {string} [opts.reason] the reason of a stage that did not run.
 * @param {string[]} [opts.extraNotes] the notes of the stage.
 * @returns {object} the metadata of the stage.
 */
function stageMetaOf(name, result, artifacts, opts = {}) {
  const stats = result && typeof result.stats === 'object' ? result.stats : {};
  const coverage = stageCoverage(stats);
  const reason = typeof opts.reason === 'string' ? opts.reason : '';
  const notes = Array.isArray(result && result.notes) ? result.notes.slice() : [];
  for (const note of Array.isArray(opts.extraNotes) ? opts.extraNotes : []) notes.push(note);
  // The reason of a stage that did not run is part of its notes: the
  // summary and the manifest render the notes of a stage, and a reader must
  // find there *why* the stage did not run.
  if (reason !== '') notes.push(reason);
  notes.push(coverage.line);
  return {
    name,
    status: typeof opts.status === 'string' && opts.status !== '' ? opts.status : String(result && result.status ? result.status : 'unknown'),
    reason,
    findingCount: Array.isArray(result && result.findings) ? result.findings.length : 0,
    artifacts: Array.isArray(artifacts) ? artifacts : [],
    notes: notes.join('; '),
    inspected: coverage.inspected,
    filesInScope: coverage.filesInScope,
    dropped: coverage.dropped,
    unreadable: coverage.unreadable,
    coverage: coverage.line,
  };
}

/**
 * Runs the stages of a scan.
 *
 * @param {object} input
 * @returns {Promise<object>} the findings, the stages and the notes.
 */
async function runStages(input) {
  const { root, policy, secretsPack, sastPack, advisories, stages, flags, fs } = input;
  const findings = [];
  const stageMeta = [];
  const notes = [];
  let sbom = null;

  const wanted = new Set(stages);

  if (wanted.has('secrets')) {
    const result = scanSecrets(root, { policy, rules: secretsPack, fs });
    findings.push(...result.findings);
    for (const note of result.notes) notes.push(`secrets: ${note}`);
    stageMeta.push(stageMetaOf('secrets', result, ['findings.json']));
  }

  if (wanted.has('sast')) {
    const languages = typeof flags.lang === 'string' && flags.lang !== ''
      ? flags.lang.split(',').map((item) => item.trim()).filter((item) => item !== '')
      : undefined;
    const ruleIds = typeof flags.rule === 'string' && flags.rule !== '' ? [flags.rule] : undefined;
    const result = scanSast(root, { policy, rules: sastPack, languages, ruleIds, fs });
    findings.push(...result.findings);
    for (const note of result.notes) notes.push(`sast: ${note}`);
    stageMeta.push(stageMetaOf('sast', result, ['findings.json', 'sarif.json']));
  }

  if (wanted.has('deps')) {
    const timeoutMs = typeof flags.timeout === 'string' && flags.timeout !== ''
      ? Number(flags.timeout)
      : undefined;
    const online = flags.online === true;
    const result = await auditDependencies(root, {
      policy,
      advisories,
      online,
      timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : undefined,
    });
    findings.push(...result.findings);
    for (const note of result.notes) notes.push(`deps: ${note}`);
    const reason = typeof result.reason === 'string' ? result.reason : '';
    stageMeta.push({
      name: 'deps',
      status: result.status,
      findingCount: result.findings.length,
      artifacts: ['findings.json'],
      notes: reason === '' ? result.notes.join('; ') : [...result.notes, reason].join('; '),
      reason,
    });
  }

  if (wanted.has('sbom')) {
    const result = buildSbom(root, { policy, enrich: flags.enrich === true });
    sbom = result;
    for (const note of result.notes) notes.push(`sbom: ${note}`);
    const reason = typeof result.reason === 'string' ? result.reason : '';
    stageMeta.push({
      name: 'sbom',
      status: result.status,
      findingCount: 0,
      artifacts: ['sbom.json'],
      notes: reason === '' ? result.notes.join('; ') : [...result.notes, reason].join('; '),
      reason,
    });
  }

  return { findings, stageMeta, notes, sbom };
}

/**
 * The bill of materials of a scan, even when the stage was skipped.
 *
 * A skipped stage still has to produce a document: an empty bill of
 * materials is a valid answer, a missing file is not.
 *
 * @param {object|null} sbom the result of the sbom stage.
 * @returns {object} the CycloneDX document.
 */
function sbomDocument(sbom) {
  if (sbom && sbom.status === 'completed' && sbom.bom && typeof sbom.bom === 'object') return sbom.bom;
  const digest = componentDigest([]);
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: serialNumberFor(digest),
    version: 1,
    metadata: {
      tools: [{ vendor: TOOL_NAME, name: TOOL_NAME, version: TOOL_VERSION }],
    },
    components: [],
  };
}

/* ---------------------------------------------------------------- commands */

/**
 * The `doctor` command: the preflight of the optional tools.
 *
 * @param {object} flags
 * @param {object} io
 * @returns {number} the exit code.
 */
function commandDoctor(flags, io) {
  const root = resolve(io.cwd, typeof flags.path === 'string' && flags.path !== '' ? flags.path : '.');
  const result = runDoctor({ root });
  const format = formatOf(flags, 'doctor');
  if (format === 'json') {
    printJson(io, { tools: result.tools, found: result.found, missing: result.missing, notes: result.notes });
  } else {
    io.stdout(`devsecops doctor - ${root}\n\n`);
    io.stdout(`${formatToolsTable(result.tools)}\n\n`);
    io.stdout(`${result.found} tool(s) found, ${result.missing} missing. The kit works without the optional ones.\n`);
    for (const note of result.notes) io.stdout(`note: ${note}\n`);
  }
  return EXIT.PASS;
}

/**
 * The `secrets` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandSecrets(flags, io, ctx) {
  const scope = assertPolicyScope(ctx.root, ctx.policy, ctx.fs);

  // The `--git-staged` flag restricts the scan to the files that git reports
  // as staged. The set is asked to git explicitly: when git is not available,
  // or when the scan root is not a git repository, the flag fails loudly
  // (exit code 2) instead of scanning everything.
  const stagedOnly = flags['git-staged'] === true;
  const staged = stagedOnly ? stagedFiles(ctx.root) : null;
  const inScope = staged === null
    ? scope.inScope
    : scope.inScope.filter((relPath) => staged.includes(relPath));

  const result = scanSecrets(ctx.root, {
    policy: ctx.policy,
    rules: ctx.secretsPack,
    onlyFiles: staged,
    fs: ctx.fs,
  });

  // Nothing staged is not a successful inspection: the stage is skipped,
  // the reason is named, and the gate refuses to pass over a stage that
  // looked at nothing.
  const nothingStaged = stagedOnly && staged.length === 0;
  const stageNote = nothingStaged
    ? 'nothing is staged: the index of the repository is empty, the scan covered no file.'
    : '';
  const stage = stageMetaOf('secrets', result, ['findings.json'], {
    status: nothingStaged ? 'skipped' : '',
    reason: nothingStaged ? 'nothing is staged' : '',
    extraNotes: stageNote === '' ? [] : [stageNote],
  });
  // The state of the stage, in one line: a stage that did not run must never
  // be read as a stage that ran and found nothing.
  const stageState = `stage: ${stage.status}${stage.reason === '' ? '' : ` (reason: ${stage.reason})`}`;

  const gate = evaluateGate({
    findings: result.findings,
    policy: policyForStage(ctx.policy, 'secrets'),
    failOn: requestedFailOn(flags, ctx.policy),
    stages: [stage],
    // The paths the scan really looked at: the deny list is judged against
    // them and not only against the paths that produced a finding.
    paths: inScope,
    // The paths the tree holds: the deny list is a statement about the
    // tree, so a path that the policy also excludes is still a denied path.
    treePaths: scope.treePaths,
    treeFiles: scope.tree.length,
  });
  const format = formatOf(flags, 'secrets');
  if (format === 'json') {
    printJson(io, buildFindingsDocument(result.findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } }));
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stage.coverage, stageState]);
    printNotes(io, stageNote === '' ? [] : [stageNote]);
  } else if (format === 'sarif') {
    printJson(io, toSarif(result.findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } }));
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stage.coverage, stageState]);
    printNotes(io, stageNote === '' ? [] : [stageNote]);
  } else {
    io.stdout(`devsecops secrets - ${ctx.root}\n\n`);
    io.stdout(`${result.findings.length} finding(s), ${result.stats.scanned} file(s) scanned.\n\n`);
    io.stdout(`coverage: ${stage.coverage}\n\n`);
    io.stdout(`${stageState}\n\n`);
    io.stdout(`${findingsTable(result.findings)}\n\n`);
    io.stdout(`Gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n`);
    if (gate.violations.length > 0) {
      io.stdout('\nviolations:\n');
      for (const violation of gate.violations) io.stdout(`  - ${violation.kind}: ${violation.detail}\n`);
    }
    for (const note of result.notes) io.stdout(`note: ${note}\n`);
    if (stageNote !== '') io.stdout(`note: ${stageNote}\n`);
  }
  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `sast` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandSast(flags, io, ctx) {
  const scope = assertPolicyScope(ctx.root, ctx.policy, ctx.fs);
  const languages = typeof flags.lang === 'string' && flags.lang !== ''
    ? flags.lang.split(',').map((item) => item.trim()).filter((item) => item !== '')
    : undefined;
  const ruleIds = typeof flags.rule === 'string' && flags.rule !== '' ? [flags.rule] : undefined;
  const result = scanSast(ctx.root, { policy: ctx.policy, rules: ctx.sastPack, languages, ruleIds, fs: ctx.fs });
  const stage = stageMetaOf('sast', result, ['findings.json', 'sarif.json']);
  const gate = evaluateGate({
    findings: result.findings,
    policy: policyForStage(ctx.policy, 'sast'),
    failOn: requestedFailOn(flags, ctx.policy),
    stages: [stage],
    // The paths the scan really looked at: the deny list is judged against
    // them and not only against the paths that produced a finding.
    paths: scope.inScope,
    // The paths the tree holds: a denied path that the policy excludes is
    // still a denied path.
    treePaths: scope.treePaths,
    treeFiles: scope.tree.length,
  });
  const format = formatOf(flags, 'sast');
  if (format === 'json') {
    printJson(io, buildFindingsDocument(result.findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } }));
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stage.coverage]);
  } else if (format === 'sarif') {
    printJson(io, toSarif(result.findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } }));
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stage.coverage]);
  } else {
    io.stdout(`devsecops sast - ${ctx.root}\n\n`);
    io.stdout(`${result.findings.length} finding(s), ${result.stats.scanned} file(s) scanned.\n\n`);
    io.stdout(`coverage: ${stage.coverage}\n\n`);
    io.stdout(`${findingsTable(result.findings)}\n\n`);
    io.stdout(`Gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n`);
    if (gate.violations.length > 0) {
      io.stdout('\nviolations:\n');
      for (const violation of gate.violations) io.stdout(`  - ${violation.kind}: ${violation.detail}\n`);
    }
    for (const note of result.notes) io.stdout(`note: ${note}\n`);
  }
  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `deps` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {Promise<number>} the exit code.
 */
async function commandDeps(flags, io, ctx) {
  const scope = assertPolicyScope(ctx.root, ctx.policy, ctx.fs);
  const timeoutMs = typeof flags.timeout === 'string' && flags.timeout !== ''
    ? Number(flags.timeout)
    : undefined;
  const result = await auditDependencies(ctx.root, {
    policy: ctx.policy,
    advisories: ctx.advisories,
    online: flags.online === true,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : undefined,
  });
  const reason = typeof result.reason === 'string' ? result.reason : '';
  const stage = {
    name: 'deps',
    status: result.status,
    findingCount: result.findings.length,
    artifacts: ['findings.json'],
    notes: reason === '' ? result.notes.join('; ') : [...result.notes, reason].join('; '),
    reason,
  };
  // A stage that does not apply (no dependency manifest in the tree) is
  // reported as skipped and does not fail the gate: the aggregate `scan`
  // treats the very same tree the very same way, and one tree must have
  // one verdict. A stage that *failed* stays enabled: the gate reports it
  // as a violation instead of turning it off.
  const gatePolicy = policyForStage(ctx.policy, 'deps');
  if (isNotApplicable(stage)) {
    const config = gatePolicy.stages.deps;
    gatePolicy.stages.deps = { ...config, enabled: false };
  }
  const gate = evaluateGate({
    findings: result.findings,
    policy: gatePolicy,
    failOn: requestedFailOn(flags, ctx.policy),
    stages: [stage],
    // The paths the scan really looked at: the deny list is judged against
    // them and not only against the paths that produced a finding.
    paths: scope.inScope,
    // The paths the tree holds: a denied path that the policy excludes is
    // still a denied path.
    treePaths: scope.treePaths,
    treeFiles: scope.tree.length,
  });
  // The state of the stage, in one line: a stage that did not run must
  // never be read as a stage that ran and found nothing.
  const stageState = `stage: ${stage.status}${reason === '' ? '' : ` (reason: ${reason})`}`;
  const format = formatOf(flags, 'deps');
  if (format === 'json') {
    printJson(io, buildFindingsDocument(result.findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } }));
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stageState]);
  } else {
    io.stdout(`devsecops deps - ${ctx.root}\n\n`);
    io.stdout(`status: ${result.status}, ${result.components} component(s), ${result.findings.length} finding(s).\n`);
    io.stdout(`${stageState}\n`);
    io.stdout(`\n${findingsTable(result.findings)}\n\n`);
    io.stdout(`Gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n`);
    if (gate.violations.length > 0) {
      io.stdout('\nviolations:\n');
      for (const violation of gate.violations) io.stdout(`  - ${violation.kind}: ${violation.detail}\n`);
    }
    for (const note of result.notes) io.stdout(`note: ${note}\n`);
    if (reason !== '') io.stdout(`note: ${reason}\n`);
  }
  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `sbom` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandSbom(flags, io, ctx) {
  const scope = assertPolicyScope(ctx.root, ctx.policy, ctx.fs);
  const result = buildSbom(ctx.root, { policy: ctx.policy, enrich: flags.enrich === true });
  const document = sbomDocument(result);
  const reason = typeof result.reason === 'string' ? result.reason : '';
  const stage = {
    name: 'sbom',
    status: result.status,
    findingCount: 0,
    artifacts: ['sbom.json'],
    notes: reason === '' ? result.notes.join('; ') : [...result.notes, reason].join('; '),
    reason,
  };
  // The bill of materials is judged by the gate, exactly like the aggregate
  // `scan` judges it: a bill of materials that the policy made impossible,
  // or that the kit could not build because the manifest could not be read,
  // is a policy violation, not a successful run. The deny list of the
  // policy is judged against the tree the scan root holds, so a denied path
  // of the tree fails the command as well. Only a tree without any
  // manifest is a legitimate "there is nothing to describe": that is the one
  // reason that makes the stage not applicable.
  const gatePolicy = policyForStage(ctx.policy, 'sbom');
  if (isNotApplicable(stage)) {
    const config = gatePolicy.stages.sbom;
    gatePolicy.stages.sbom = { ...config, enabled: false };
  }
  const gate = evaluateGate({
    findings: [],
    policy: gatePolicy,
    failOn: requestedFailOn(flags, ctx.policy),
    stages: [stage],
    // The paths the scan really looked at: the deny list is judged against
    // them and not only against the paths that produced a finding.
    paths: scope.inScope,
    // The paths the tree holds: a denied path that the policy excludes is
    // still a denied path.
    treePaths: scope.treePaths,
    treeFiles: scope.tree.length,
  });
  const stageState = `stage: ${stage.status}${reason === '' ? '' : ` (reason: ${reason})`}`;
  const format = formatOf(flags, 'sbom');
  if (format === 'json' || format === 'sarif') {
    printJson(io, document);
    printViolations(io, gate.violations);
    printNotes(io, result.notes);
    printNotes(io, [stageState]);
  } else {
    io.stdout(`devsecops sbom - ${ctx.root}\n\n`);
    io.stdout(`status: ${result.status}, ${result.components} component(s).\n`);
    io.stdout(`${stageState}\n`);
    io.stdout(`serial number: ${document.serialNumber}\n`);
    io.stdout(`digest: ${result.digest}\n\n`);
    io.stdout(`Gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n`);
    if (gate.violations.length > 0) {
      io.stdout('\nviolations:\n');
      for (const violation of gate.violations) io.stdout(`  - ${violation.kind}: ${violation.detail}\n`);
    }
    for (const note of result.notes) io.stdout(`note: ${note}\n`);
    if (reason !== '') io.stdout(`reason: ${reason}\n`);
  }
  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `policy` command: the verdict of the gate on a findings document.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandPolicy(flags, io, ctx) {
  const file = typeof flags.findings === 'string' && flags.findings !== ''
    ? resolve(ctx.cwd, flags.findings)
    : resolve(ctx.cwd, DEFAULT_OUT_DIR, 'findings.json');
  if (!existsSync(file)) {
    throw new KitError('E_CONFIG', `the findings document ${file} does not exist`, { file });
  }
  let document;
  try {
    document = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new KitError('E_CONFIG', `the findings document ${file} is not valid JSON`, {
      file,
      cause: err && err.message ? err.message : String(err),
    });
  }
  const findings = Array.isArray(document.findings) ? document.findings : [];
  const gate = evaluateGate({
    findings,
    policy: withoutEvidenceRequirement(ctx.policy),
    failOn: requestedFailOn(flags, ctx.policy),
  });
  const format = formatOf(flags, 'policy');
  if (format === 'json') {
    printJson(io, {
      status: gate.status,
      exitCode: gate.exitCode,
      effectiveFailOn: gate.effectiveFailOn,
      counts: gate.counts,
      violations: gate.violations,
      checks: gate.checks,
    });
  } else {
    io.stdout(`devsecops policy - ${file}\n\n`);
    io.stdout(`Gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n\n`);
    io.stdout(`| kind | detail |\n| --- | --- |\n`);
    for (const violation of gate.violations) {
      io.stdout(`| ${violation.kind} | ${String(violation.detail).replace(/\|/g, '\\|')} |\n`);
    }
    if (gate.violations.length === 0) io.stdout('| - | no violation |\n');
    io.stdout('\n');
  }
  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `scan` command: the whole pipeline.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {Promise<number>} the exit code.
 */
async function commandScan(flags, io, ctx) {
  const selected = Array.isArray(flags.stage) && flags.stage.length > 0
    ? flags.stage
    : ['secrets', 'sast', 'deps', 'sbom'];
  for (const name of selected) {
    if (!['secrets', 'sast', 'deps', 'sbom'].includes(name)) {
      throw new KitError('E_ARGS', `unknown stage "${name}": the stages are secrets, sast, deps and sbom`, { stage: name });
    }
  }

  const scope = assertPolicyScope(ctx.root, ctx.policy, ctx.fs);

  const { findings, stageMeta, notes, sbom } = await runStages({
    root: ctx.root,
    policy: ctx.policy,
    secretsPack: ctx.secretsPack,
    sastPack: ctx.sastPack,
    advisories: ctx.advisories,
    stages: selected,
    flags,
    fs: ctx.fs,
  });

  // A stage that does not apply (no manifest to audit, no bill of materials
  // to build) is reported as skipped and does not fail the gate. A stage that
  // *failed* stays enabled: the gate must report it as a violation instead
  // of turning it off. A gate that passes over a stage that did not produce
  // its output is a gate that approves a tree it never looked at.
  const gatePolicy = { ...ctx.policy, stages: { ...ctx.policy.stages } };
  for (const stage of stageMeta) {
    if (stage.status === 'completed') continue;
    if (!isNotApplicable(stage)) continue;
    const config = gatePolicy.stages[stage.name];
    if (config && typeof config === 'object') gatePolicy.stages[stage.name] = { ...config, enabled: false };
  }
  // A stage that was not selected is disabled as well.
  for (const name of Object.keys(gatePolicy.stages)) {
    if (selected.includes(name)) continue;
    const config = gatePolicy.stages[name];
    if (config && typeof config === 'object') gatePolicy.stages[name] = { ...config, enabled: false };
  }

  // The artefacts of this run: with `--no-write` nothing is written, so the
  // run cannot promise an evidence artefact it never produced.
  const writesArtefacts = flags['no-write'] !== true;
  if (!writesArtefacts) gatePolicy.required_evidence = [];

  const outDir = resolve(
    io.cwd,
    typeof flags['out-dir'] === 'string' && flags['out-dir'] !== ''
      ? flags['out-dir']
      : (typeof flags.out === 'string' && flags.out !== '' ? flags.out : DEFAULT_OUT_DIR),
  );

  // The snapshot of the tree: the digest of the content that was really
  // scanned. The scan id is derived from it, so two different trees have two
  // different ids and the same tree always has the same one.
  //
  // The snapshot never covers the evidence log nor the artefacts of the kit:
  // the log is written *after* the tree was hashed, and a digest that
  // included it could never be a fixed point. The exclusion set is
  // canonical: the artefacts are excluded by name, wherever they live, so
  // the receipt of this scan and the evidence log of the same tree quote
  // the same digest even when `--out-dir` points somewhere else. The label
  // that says what the digest does not cover is part of the emitted
  // document and of the receipt.
  const snapshot = buildSnapshot(ctx.root, scope.inScope, {
    exclude: snapshotExclusions(),
  });
  const scanId = `scan_${sha256Hex(snapshot.digest).slice(0, 12)}`;

  const gate = evaluateGate({
    findings,
    policy: gatePolicy,
    evidence: writesArtefacts ? ARTEFACTS.map((artefact) => artefact.file) : [],
    failOn: requestedFailOn(flags, ctx.policy),
    stages: stageMeta,
    // The paths the scan really looked at: the deny list is judged against
    // them and not only against the paths that produced a finding.
    paths: scope.inScope,
    // The paths the tree holds: the deny list is a statement about the
    // tree, so a denied path that the policy also excludes is still a
    // denied path, and the receipt says the truth about it.
    treePaths: scope.treePaths,
    treeFiles: scope.tree.length,
  });

  const findingsDocument = buildFindingsDocument(findings, { scanId, tool: { name: TOOL_NAME, version: TOOL_VERSION } });
  const sarif = toSarif(findings, { tool: { name: TOOL_NAME, version: TOOL_VERSION } });
  const bom = sbomDocument(sbom);

  // The preflight of the tools: the summary of a scan carries the table of
  // the tools that were found and of the ones that are missing (plan section
  // F), so the reader knows what the scan was and was not able to look at.
  const preflight = runDoctor({ root: ctx.root });
  const summary = toSummaryMarkdown({
    findings,
    gate,
    stages: stageMeta,
    scan: { id: scanId, digest: snapshot.digest, digestLabel: SNAPSHOT_DIGEST_LABEL },
    denied: { patterns: gate.denyPatterns, paths: gate.deniedPaths },
    tools: preflight.tools,
  });

  // The manifest is the receipt: it carries the digests of the artefacts
  // that are really on disk, so it is built after them and written last.
  // The manifest cannot carry its own digest: it signs the other artefacts,
  // not itself.
  const now = typeof flags.now === 'string' && flags.now !== '' ? flags.now : '';

  // The revision of the tree: it is read explicitly, and the reason of a
  // failure is recorded with it. A receipt never carries an empty revision.
  const revision = gitRevision(ctx.root);

  let written = [];
  if (writesArtefacts) {
    written = writeReports(outDir, {
      findings: findingsDocument,
      sbom: bom,
      sarif,
      summary,
    });
    const artifacts = ARTEFACTS
      .filter((artefact) => artefact.key !== 'manifest' && written.includes(artefact.file))
      .map((artefact) => ({
        path: artefact.file,
        sha256: sha256File(join(outDir, artefact.file)),
        mediaType: artefact.mediaType,
      }));
    const manifest = buildScanManifest({
      scanId,
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      target: {
        kind: 'git_worktree',
        targetId: `sha256:${sha256Hex(ctx.root).slice(0, 12)}`,
        revision: revision.revision,
        revisionReason: revision.reason,
        snapshotDigest: snapshot.digest,
        snapshotDigestLabel: SNAPSHOT_DIGEST_LABEL,
        // The paths that are not part of the digest: the receipt says what
        // it does *not* cover, so that a reader can compare it with the
        // digest of the evidence log of the same tree.
        snapshotExcluded: snapshot.excluded,
      },
      scope: {
        includePaths: Array.isArray(ctx.policy.paths.include) ? ctx.policy.paths.include : [],
        excludePaths: Array.isArray(ctx.policy.paths.exclude) ? ctx.policy.paths.exclude : [],
        denyPaths: gate.denyPatterns,
        deniedPaths: gate.deniedPaths,
      },
      stages: stageMeta,
      artifacts,
      startedAt: now,
      completedAt: now,
    });
    writeJson(join(outDir, 'scan-manifest.json'), manifest);
    written = [...written, 'scan-manifest.json'];
    // The evidence of the run is real: every artefact the kit writes must
    // exist on disk once the run is over. (A policy that requires an
    // artefact the kit does not produce is a different matter: that is a
    // missing-evidence violation of the gate, not an error of the tool.)
    for (const artefact of ARTEFACTS) {
      const file = join(outDir, artefact.file);
      if (!existsSync(file)) {
        throw new KitError('E_IO', `the artefact ${artefact.file} was not written in ${outDir}`, { file });
      }
    }
  }

  const format = formatOf(flags, 'scan');
  if (format === 'json') {
    printJson(io, {
      scanId,
      snapshotDigest: snapshot.digest,
      snapshotDigestLabel: SNAPSHOT_DIGEST_LABEL,
      root: ctx.root,
      status: gate.status,
      exitCode: gate.exitCode,
      effectiveFailOn: gate.effectiveFailOn,
      counts: gate.counts,
      stages: stageMeta,
      violations: gate.violations,
      denyPatterns: gate.denyPatterns,
      deniedPaths: gate.deniedPaths,
      artefacts: written.map((name) => join(outDir, name)),
    });
    printNotes(io, notes);
  } else if (format === 'sarif') {
    printJson(io, sarif);
    printNotes(io, notes);
  } else {
    io.stdout(`devsecops scan - ${ctx.root}\n\n`);
    io.stdout('| stage | status | findings | coverage | notes |\n| --- | --- | --- | --- | --- |\n');
    for (const stage of stageMeta) {
      const coverage = typeof stage.coverage === 'string' ? stage.coverage : '-';
      const notes = typeof stage.notes === 'string' ? stage.notes : '';
      io.stdout(`| ${stage.name} | ${stage.status} | ${stage.findingCount} | ${coverage} | ${notes} |\n`);
    }
    const counts = countBySeverity(findings);
    io.stdout(`\nfindings: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})\n`);
    io.stdout(`gate: ${gate.status === 'pass' ? 'PASS' : 'FAIL'} (fail-on: ${gate.effectiveFailOn})\n`);
    if (gate.denyPatterns.length > 0) {
      const present = gate.deniedPaths.length > 0 ? `present: ${gate.deniedPaths.join(', ')}` : 'none present';
      io.stdout(`denied paths: ${gate.denyPatterns.join(', ')} (${present})\n`);
    }
    if (gate.violations.length > 0) {
      io.stdout('\nviolations:\n');
      for (const violation of gate.violations) io.stdout(`  - ${violation.kind}: ${violation.detail}\n`);
    }
    if (written.length > 0) {
      io.stdout(`\nartefacts: ${written.map((name) => join(outDir, name)).join(', ')}\n`);
    }
    for (const note of notes) io.stdout(`note: ${note}\n`);
  }

  return gate.status === 'pass' ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `verify` command: the local parity of the four external checks.
 *
 * @param {object} flags
 * @param {object} io
 * @returns {number} the exit code.
 */
function commandVerify(flags, io) {
  const root = resolve(
    io.cwd,
    typeof flags.root === 'string' && flags.root !== ''
      ? flags.root
      : (typeof flags.path === 'string' && flags.path !== '' ? flags.path : '.'),
  );
  const result = runParityChecks({ root });
  const format = formatOf(flags, 'verify');
  if (format === 'json') {
    printJson(io, result);
  } else {
    io.stdout(`devsecops verify - ${root}\n\n`);
    result.checks.forEach((check, index) => {
      const mark = check.status === 'pass' ? 'OK  ' : (check.status === 'skip' ? 'SKIP' : 'FAIL');
      io.stdout(`${mark} Check ${index + 1}: ${check.name} - ${check.detail}\n`);
    });
    io.stdout(`\n${result.failures} failure(s).\n`);
  }
  return result.failures === 0 ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `evidence` command: the evidence log of the acceptance criteria.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {Promise<number>} the exit code.
 */
async function commandEvidence(flags, io, ctx) {
  const criteriaFile = criteriaFileOf(flags, ctx);
  if (!existsSync(criteriaFile)) {
    throw new KitError('E_CONFIG', `the acceptance criteria ${criteriaFile} do not exist`, { file: criteriaFile });
  }
  const criteria = parseCriteriaFile(criteriaFile);
  if (criteria.length === 0) {
    throw new KitError('E_EVIDENCE', `the acceptance criteria ${criteriaFile} are empty`, { file: criteriaFile });
  }

  const outFile = resolve(
    ctx.cwd,
    typeof flags.out === 'string' && flags.out !== '' ? flags.out : DEFAULT_EVIDENCE_FILE,
  );

  // The emitter never destroys a proof it cannot replace. Without `--run`
  // the document carries no output at all: writing it would throw away the
  // committed log and leave a document that proves nothing. The refusal is
  // the default; `--run` (the evidence is produced) and `--force` (the
  // replacement is deliberate) are the two ways out.
  const produced = flags.run === true;
  const forced = flags.force === true;
  if (flags.emit === true && existsSync(outFile) && !produced && !forced) {
    throw new KitError('E_EVIDENCE', `the evidence document ${outFile} already exists: the emitter refuses to overwrite it with a document that carries no evidence (use --run to produce the evidence, or --force to replace it)`, { file: outFile });
  }

  let results = null;
  if (flags.run === true) {
    results = new Map();
    for (const criterion of criteria) {
      const outcome = await runCriterionCommand(criterion.command, ctx.cwd);
      results.set(criterion.id, outcome);
    }
  }

  // The digest of the tree the log describes. The evidence log and the
  // artefacts of the kit are excluded: the log is written *after* the tree
  // was hashed, and a digest that included it could never be a fixed point.
  // The exclusion set is the one of the scan receipt, so that the receipt
  // of a scan and the evidence log of the same tree quote the same digest.
  const scope = scopeOf(ctx.root, ctx.policy, ctx.fs);
  const snapshot = buildSnapshot(ctx.root, scope.inScope, {
    exclude: snapshotExclusions(),
  });

  const document = renderEvidence(criteria, results, {
    snapshot: {
      digest: snapshot.digest,
      label: SNAPSHOT_DIGEST_LABEL,
      excluded: snapshot.excluded,
    },
  });
  const format = formatOf(flags, 'evidence');

  if (flags.emit === true) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(outFile, document, 'utf8');
    const validation = validateEvidence(document, { source: outFile, criteria });
    if (format === 'json') {
      printJson(io, {
        file: outFile,
        criteria: criteria.length,
        ok: validation.ok,
        errors: validation.errors,
      });
    } else {
      io.stdout(`evidence: ${outFile}\n`);
    }
    if (!validation.ok) {
      for (const error of validation.errors) io.stderr(`error: E_EVIDENCE ${error}\n`);
      return EXIT.FINDINGS;
    }
    return EXIT.PASS;
  }

  if (format === 'json') {
    printJson(io, { file: outFile, criteria: criteria.length, document });
  } else {
    io.stdout(document);
  }
  return EXIT.PASS;
}

/**
 * The `validate-evidence` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandValidateEvidence(flags, io, ctx) {
  const file = resolve(
    ctx.cwd,
    typeof flags.file === 'string' && flags.file !== '' ? flags.file : DEFAULT_EVIDENCE_FILE,
  );
  if (!existsSync(file)) {
    throw new KitError('E_CONFIG', `the evidence document ${file} does not exist`, { file });
  }
  // The acceptance criteria are the contract: the document is checked
  // against them, not only against its own shape.
  const criteriaFile = criteriaFileOf(flags, ctx);
  if (!existsSync(criteriaFile)) {
    throw new KitError('E_CONFIG', `the acceptance criteria ${criteriaFile} do not exist`, { file: criteriaFile });
  }
  const criteria = parseCriteriaFile(criteriaFile);
  const text = readFileSync(file, 'utf8');
  const validation = validateEvidence(text, { source: file, criteria });
  const format = formatOf(flags, 'validate-evidence');
  if (format === 'json') {
    printJson(io, { ...validation, criteriaFile });
  } else {
    io.stdout(`devsecops validate-evidence - ${file}\n\n`);
    io.stdout(`acceptance criteria: ${criteriaFile}\n\n`);
    io.stdout('| criterion | command | output | verdict |\n| --- | --- | --- | --- |\n');
    for (const criterion of validation.criteria) {
      io.stdout(`| ${criterion.title} | ${criterion.hasCommand ? 'yes' : 'no'} | ${criterion.hasOutput ? 'yes' : 'no'} | ${criterion.verdict} |\n`);
    }
    io.stdout(`\n${validation.ok ? 'PASS' : 'FAIL'}: ${validation.errors.length} problem(s).\n`);
    for (const error of validation.errors) io.stdout(`  - ${error}\n`);
  }
  return validation.ok ? EXIT.PASS : EXIT.FINDINGS;
}

/**
 * The `install-hook` command.
 *
 * @param {object} flags
 * @param {object} io
 * @param {object} ctx
 * @returns {number} the exit code.
 */
function commandInstallHook(flags, io, ctx) {
  const target = typeof flags.target === 'string' && flags.target !== ''
    ? resolve(ctx.cwd, flags.target)
    : undefined;
  const source = typeof flags.source === 'string' && flags.source !== ''
    ? resolve(ctx.cwd, flags.source)
    : join(KIT_ROOT, '.githooks', 'pre-commit');
  const result = installHook({
    root: ctx.root,
    source,
    target,
    force: flags.force === true,
    hooksPath: flags['hooks-path'] === true,
  });
  const format = formatOf(flags, 'install-hook');
  if (format === 'json') {
    printJson(io, result);
    if (!result.installed) {
      io.stderr(`error: E_CONFIG the pre-commit hook was not installed: ${result.reason}\n`);
    }
  } else if (result.installed) {
    io.stdout(`the pre-commit hook was installed: ${result.target}\n`);
    io.stdout(`reason: ${result.reason}\n`);
  } else {
    io.stderr(`error: E_CONFIG the pre-commit hook was not installed: ${result.reason}\n`);
  }
  return result.installed ? EXIT.PASS : EXIT.ERROR;
}

/**
 * Runs the command of an acceptance criterion and captures its output.
 *
 * The command comes from the acceptance criteria of the repository: it is
 * run through the shell, exactly like a developer would run it.
 *
 * @param {string} command
 * @param {string} cwd
 * @returns {Promise<{ command: string, output: string, exitCode: number }>}
 */
async function runCriterionCommand(command, cwd) {
  const text = String(command ?? '').trim();
  if (text === '') return { command: text, output: '', exitCode: 1 };
  const result = spawnSync(text, {
    cwd,
    encoding: 'utf8',
    timeout: 300000,
    windowsHide: true,
    shell: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 32 * 1024 * 1024,
    // The log that is being written cannot be the proof of the run that
    // writes it: the test that checks the committed log stands down while
    // the emitter works.
    env: { ...process.env, [EMITTING_ENV]: '1' },
  });
  const stdout = result && result.stdout ? String(result.stdout) : '';
  const stderr = result && result.stderr ? String(result.stderr) : '';
  // Both streams are part of the proof: a note on the standard error (the
  // reason of a skipped online lookup, for instance) is evidence too.
  const code = result && typeof result.status === 'number' ? result.status : 1;
  return { command: text, output: `${stdout}${stderr}`, exitCode: code };
}

/**
 * Dispatches a command.
 *
 * @param {string} command
 * @param {object} flags
 * @param {object} io
 * @returns {Promise<number>} the exit code.
 */
export async function runCommand(command, flags, io) {
  const context = io.cwd ? buildContext(flags, io.cwd, io.fs) : null;
  switch (command) {
    case 'doctor':
      return commandDoctor(flags, io);
    case 'secrets':
      return commandSecrets(flags, io, context);
    case 'sast':
      return commandSast(flags, io, context);
    case 'deps':
      return commandDeps(flags, io, context);
    case 'sbom':
      return commandSbom(flags, io, context);
    case 'policy':
      return commandPolicy(flags, io, context);
    case 'scan':
      return commandScan(flags, io, context);
    case 'verify':
      return commandVerify(flags, io);
    case 'evidence':
      return commandEvidence(flags, io, context);
    case 'validate-evidence':
      return commandValidateEvidence(flags, io, context);
    case 'install-hook':
      return commandInstallHook(flags, io, context);
    default:
      throw new KitError('E_ARGS', `unknown command "${command}"`);
  }
}

/**
 * The entry point of the command line.
 *
 * @param {string[]} [argv] the arguments, without the node executable and
 *   the script name.
 * @param {object} [io] the output streams and the working directory.
 * @returns {Promise<number>} the exit code.
 */
export async function main(argv = process.argv.slice(2), io = defaultIo()) {
  const streams = {
    stdout: typeof io.stdout === 'function' ? io.stdout : (text) => process.stdout.write(text),
    stderr: typeof io.stderr === 'function' ? io.stderr : (text) => process.stderr.write(text),
    cwd: typeof io.cwd === 'string' && io.cwd !== '' ? io.cwd : process.cwd(),
    // The file system seam: the tests inject a reader that fails, so that
    // the behaviour of an unreadable tree can be exercised on every
    // platform. The real file system is the default.
    fs: io.fs && typeof io.fs === 'object' ? io.fs : undefined,
  };

  let parsed;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    return reportError(err, streams);
  }

  if (parsed.flags.version === true) {
    streams.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    return EXIT.PASS;
  }

  if (parsed.errors.length > 0) {
    for (const error of parsed.errors) streams.stderr(`error: E_ARGS ${error}\n`);
    streams.stderr(`\n${globalHelp()}`);
    return EXIT.ERROR;
  }

  if (parsed.flags.help === true) {
    streams.stdout(commandHelp(parsed.command));
    return EXIT.PASS;
  }

  try {
    return await runCommand(parsed.command, parsed.flags, streams);
  } catch (err) {
    return reportError(err, streams);
  }
}

/** The commands of the kit, re-exported for the documentation tests. */
export { COMMANDS };
