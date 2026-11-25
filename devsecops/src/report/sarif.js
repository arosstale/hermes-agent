/**
 * SARIF 2.1.0 export.
 *
 * The kit produces the subset of SARIF 2.1.0 that the code scanning
 * consumers understand:
 *
 *   - one run, whose driver is the kit;
 *   - one rule descriptor per distinct rule id, with the default level
 *     derived from the severity;
 *   - one result per finding, with the physical location of the finding
 *     (a repository relative POSIX path and the `%SRCROOT%` base), the
 *     partial fingerprint of the finding and the remediation.
 *
 * The export is deterministic: the rules and the results are sorted, and no
 * timestamp is written.
 *
 * Signatures
 *   severityToSarifLevel(severity: string): "error" | "warning" | "note"
 *   toSarif(findings: Finding[], opts?: {
 *     tool?: { name?: string, version?: string },
 *     rules?: object[],     // the rule packs, used to enrich the descriptors
 *   }): object            // the SARIF document
 *
 * A Finding is the model of plan section F.
 *
 * Also exported: `cweOf(finding): string` (the weakness of a finding) and
 * the constants `TOOL_NAME`, `TOOL_VERSION`, `SARIF_SCHEMA` and
 * `SARIF_VERSION`.
 */

import { sortFindings } from './findings.js';

/** The name of the producer of the document. */
export const TOOL_NAME = 'devsecops-kit';

/** The version of the producer of the document. */
export const TOOL_VERSION = '1.0.0';

/** The schema of the SARIF documents. */
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

/** The version of the SARIF specification. */
export const SARIF_VERSION = '2.1.0';

/**
 * Maps a severity of the kit onto a SARIF level.
 *
 * `critical` and `high` are errors, `medium` is a warning, `low` and `info`
 * are notes. An unknown severity is a note: it must not hide a problem, but
 * it must not fail a build either.
 *
 * @param {string} severity
 * @returns {"error" | "warning" | "note"}
 */
export function severityToSarifLevel(severity) {
  const text = typeof severity === 'string' ? severity.trim().toLowerCase() : '';
  if (text === 'critical' || text === 'high') return 'error';
  if (text === 'medium') return 'warning';
  return 'note';
}

/**
 * The CWE of a finding, when it has one.
 *
 * @param {object} finding
 * @returns {string} e.g. `CWE-798`, or `CWE-0` when the finding has none.
 */
export function cweOf(finding) {
  const tags = finding && Array.isArray(finding.tags) ? finding.tags : [];
  for (const tag of tags) {
    if (typeof tag === 'string' && /^CWE-\d+$/.test(tag)) return tag;
  }
  return 'CWE-0';
}

/**
 * The rules of the packs, indexed by rule id.
 *
 * @param {object[]} packs the rule packs.
 * @returns {Record<string, object>}
 */
function indexRules(packs) {
  const index = {};
  const lists = Array.isArray(packs) ? packs : [];
  for (const pack of lists) {
    if (!pack || typeof pack !== 'object') continue;
    const rules = Array.isArray(pack.rules) ? pack.rules : [];
    for (const rule of rules) {
      if (!rule || typeof rule !== 'object' || typeof rule.id !== 'string') continue;
      if (index[rule.id] === undefined) index[rule.id] = rule;
    }
  }
  return index;
}

/**
 * Exports the findings as a SARIF document.
 *
 * @param {object[]} findings the findings of the scan.
 * @param {object} [opts]
 * @param {object} [opts.tool] `{ name, version }` of the driver.
 * @param {object[]} [opts.rules] the rule packs, used to enrich the rule
 *   descriptors with the remediation and the CWE.
 * @returns {object} the SARIF document.
 */
export function toSarif(findings, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const tool = options.tool && typeof options.tool === 'object' ? options.tool : {};
  const ruleIndex = indexRules(options.rules);
  const sorted = sortFindings(findings);

  const byRule = new Map();
  for (const finding of sorted) {
    const ruleId = String(finding && finding.ruleId ? finding.ruleId : 'unknown');
    if (!byRule.has(ruleId)) {
      byRule.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: String(finding && finding.message ? finding.message : ruleId) },
        fullDescription: { text: '' },
        defaultConfiguration: { level: severityToSarifLevel(finding && finding.severity) },
        properties: { tags: ['security', cweOf(finding)], cwe: cweOf(finding) },
      });
    }
  }

  const rules = [...byRule.values()].sort((a, b) => (a.id < b.id ? -1 : (a.id > b.id ? 1 : 0)));
  for (const rule of rules) {
    const source = ruleIndex[rule.id];
    const message = rule.shortDescription.text;
    const remediation = source && typeof source.remediation === 'string' ? source.remediation : '';
    rule.fullDescription = { text: remediation === '' ? message : `${message} ${remediation}` };
    if (source && typeof source.cwe === 'string' && /^CWE-\d+$/.test(source.cwe)) {
      rule.properties.cwe = source.cwe;
      rule.properties.tags = ['security', source.cwe];
    }
  }

  const results = sorted.map((finding) => {
    const location = finding && typeof finding.location === 'object' && finding.location !== null
      ? finding.location
      : {};
    const startLine = Number(location.startLine);
    const column = Number(location.column);
    const region = {};
    if (Number.isFinite(startLine) && startLine > 0) region.startLine = startLine;
    if (Number.isFinite(column) && column > 0) region.startColumn = column;
    const physicalLocation = {
      artifactLocation: {
        uri: String(location.path || ''),
        uriBaseId: '%SRCROOT%',
      },
    };
    if (Object.keys(region).length > 0) physicalLocation.region = region;
    return {
      ruleId: String(finding && finding.ruleId ? finding.ruleId : 'unknown'),
      level: severityToSarifLevel(finding && finding.severity),
      message: { text: String(finding && finding.message ? finding.message : '') },
      locations: [{
        physicalLocation,
      }],
      partialFingerprints: {
        primary: String(finding && finding.fingerprint ? finding.fingerprint : ''),
      },
      properties: {
        severity: String(finding && finding.severity ? finding.severity : ''),
        stage: String(finding && finding.stage ? finding.stage : ''),
        remediation: String(finding && finding.remediation ? finding.remediation : ''),
        redacted: finding && finding.redacted === true,
      },
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: {
        driver: {
          name: typeof tool.name === 'string' && tool.name !== '' ? tool.name : TOOL_NAME,
          version: typeof tool.version === 'string' && tool.version !== '' ? tool.version : TOOL_VERSION,
          rules,
        },
      },
      invocations: [{ executionSuccessful: true }],
      results,
    }],
  };
}
