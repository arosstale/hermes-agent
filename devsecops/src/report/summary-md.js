/**
 * The Markdown summary of a scan.
 *
 * `reports/summary.md` is the human readable receipt of a scan: the stages,
 * the severity counts, the findings, the verdict of the gate, the table of
 * the tools of the preflight (the FOUND/MISSING table of the doctor) and the
 * list of the remediations.
 *
 * The summary carries **no timestamp** and no secret value: two runs over
 * the same tree produce the same file, byte for byte.
 *
 * Signatures
 *   toSummaryMarkdown(input: {
 *     findings?: Finding[],
 *     gate?: object,          // the result of the policy gate
 *     tools?: ToolStatus[],   // the result of the preflight
 *     stages?: StageMeta[],   // the stages of the scan
 *     scan?: { id?: string, target?: object },
 *     denied?: { patterns?: string[], paths?: string[] }, // the deny list
 *   }): string               // the Markdown document
 *
 * A Finding is the model of plan section F; a ToolStatus is
 * `{ name, status, path, version, note }`; a StageMeta is
 * `{ name, status, findingCount, notes }`.
 */

import { sortFindings } from './findings.js';
import { SEVERITY_ORDER } from '../policy/severity.js';
import { matchAny } from '../core/glob.js';

/**
 * Escapes the characters that would break a Markdown table.
 *
 * @param {unknown} value
 * @returns {string}
 */
function cell(value) {
  const text = value === undefined || value === null ? '' : String(value);
  return text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/**
 * The severity of a finding, normalised.
 *
 * @param {object} finding
 * @returns {string}
 */
function severityOf(finding) {
  const severity = finding && typeof finding.severity === 'string' ? finding.severity.trim().toLowerCase() : '';
  return SEVERITY_ORDER.includes(severity) ? severity : 'info';
}

/**
 * The location of a finding, as `path:line`.
 *
 * @param {object} finding
 * @returns {string}
 */
function locationOf(finding) {
  const location = finding && typeof finding.location === 'object' && finding.location !== null
    ? finding.location
    : {};
  const path = typeof location.path === 'string' ? location.path : '';
  const line = Number(location.startLine);
  return Number.isFinite(line) && line > 0 ? `${path}:${line}` : path;
}

/**
 * Builds the Markdown summary of a scan.
 *
 * @param {object} input see the file header.
 * @returns {string} the Markdown document, ending with a newline.
 */
export function toSummaryMarkdown(input = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const findings = sortFindings(Array.isArray(source.findings) ? source.findings : []);
  const gate = source.gate && typeof source.gate === 'object' ? source.gate : null;
  const tools = Array.isArray(source.tools) ? source.tools : [];
  const stages = Array.isArray(source.stages) ? source.stages : [];
  const scan = source.scan && typeof source.scan === 'object' ? source.scan : {};
  const denied = source.denied && typeof source.denied === 'object' ? source.denied : {};
  const denyPatterns = Array.isArray(denied.patterns)
    ? denied.patterns
    : (gate !== null && Array.isArray(gate.denyPatterns) ? gate.denyPatterns : []);
  const deniedPaths = Array.isArray(denied.paths)
    ? denied.paths
    : (gate !== null && Array.isArray(gate.deniedPaths) ? gate.deniedPaths : []);

  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byStage = new Map();
  for (const finding of findings) {
    counts[severityOf(finding)] += 1;
    const stage = String(finding && finding.stage ? finding.stage : 'unknown');
    byStage.set(stage, (byStage.get(stage) || 0) + 1);
  }

  const lines = [];
  lines.push('# DevSecOps scan summary');
  lines.push('');
  if (typeof scan.id === 'string' && scan.id !== '') {
    lines.push(`- Scan id: \`${cell(scan.id)}\``);
  }
  if (typeof scan.digest === 'string' && scan.digest !== '') {
    lines.push(`- Snapshot digest: \`${cell(scan.digest)}\``);
  }
  if (typeof scan.digestLabel === 'string' && scan.digestLabel !== '') {
    lines.push(`- Snapshot digest: ${cell(scan.digestLabel)}`);
  }
  lines.push(`- Findings: ${findings.length}`);
  if (gate !== null) {
    const verdict = gate.status === 'pass' ? 'PASS' : 'FAIL';
    lines.push(`- Gate: **${verdict}**`);
  }
  lines.push('');

  lines.push('## Stages');
  lines.push('');
  lines.push('| Stage | Status | Findings | Coverage | Notes |');
  lines.push('| --- | --- | --- | --- | --- |');
  if (stages.length === 0) {
    for (const stage of [...byStage.keys()].sort()) {
      lines.push(`| ${cell(stage)} | completed | ${byStage.get(stage)} | | |`);
    }
  } else {
    for (const stage of stages) {
      const name = String(stage && stage.name ? stage.name : 'unknown');
      const count = Number.isFinite(Number(stage && stage.findingCount))
        ? Number(stage.findingCount)
        : (byStage.get(name) || 0);
      const coverage = typeof (stage && stage.coverage) === 'string' ? stage.coverage : '';
      lines.push(`| ${cell(name)} | ${cell(stage && stage.status ? stage.status : 'unknown')} | ${count} | ${cell(coverage)} | ${cell(stage && stage.notes ? stage.notes : '')} |`);
    }
  }
  lines.push('');

  lines.push('## Severity counts');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const severity of SEVERITY_ORDER) {
    lines.push(`| ${severity} | ${counts[severity]} |`);
  }
  lines.push(`| **total** | **${findings.length}** |`);
  lines.push('');

  lines.push('## Findings');
  lines.push('');
  if (findings.length === 0) {
    lines.push('No finding was reported.');
    lines.push('');
  } else {
    lines.push('| Severity | Rule | Location | Message | Fingerprint |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const finding of findings) {
      lines.push(`| ${cell(severityOf(finding))} | ${cell(finding && finding.ruleId)} | ${cell(locationOf(finding))} | ${cell(finding && finding.message)} | ${cell(finding && finding.fingerprint)} |`);
    }
    lines.push('');
  }

  lines.push('## Gate');
  lines.push('');
  if (gate === null) {
    lines.push('The gate was not evaluated.');
    lines.push('');
  } else {
    const verdict = gate.status === 'pass' ? 'PASS' : 'FAIL';
    lines.push(`**${verdict}**${typeof gate.effectiveFailOn === 'string' ? ` - fail-on threshold: \`${cell(gate.effectiveFailOn)}\`` : ''}`);
    lines.push('');
    const violations = Array.isArray(gate.violations) ? gate.violations : [];
    if (violations.length === 0) {
      lines.push('No policy violation was reported.');
    } else {
      lines.push('| Kind | Detail |');
      lines.push('| --- | --- |');
      for (const violation of violations) {
        lines.push(`| ${cell(violation && violation.kind)} | ${cell(violation && violation.detail)} |`);
      }
    }
    lines.push('');
  }

  lines.push('## Denied paths');
  lines.push('');
  if (denyPatterns.length === 0) {
    lines.push('The policy denies no path.');
    lines.push('');
  } else {
    lines.push('The policy denies the paths below: they must never be part of the tree.');
    lines.push('');
    lines.push('| Denied pattern | Present in the tree |');
    lines.push('| --- | --- |');
    for (const pattern of denyPatterns) {
      const present = deniedPaths.some((path) => matchAny([pattern], path)) ? 'yes' : 'no';
      lines.push(`| \`${cell(pattern)}\` | ${present} |`);
    }
    lines.push('');
    if (deniedPaths.length > 0) {
      lines.push(`The denied path(s) present in the tree: ${deniedPaths.map((path) => `\`${cell(path)}\``).join(', ')}.`);
      lines.push('');
    }
  }

  lines.push('## Tool preflight');
  lines.push('');
  if (tools.length === 0) {
    lines.push('The preflight was not run.');
  } else {
    lines.push('| Tool | Status | Version | Note |');
    lines.push('| --- | --- | --- | --- |');
    for (const tool of tools) {
      lines.push(`| ${cell(tool && tool.name)} | ${cell(tool && tool.status ? String(tool.status).toUpperCase() : '')} | ${cell(tool && tool.version ? tool.version : '')} | ${cell(tool && tool.note ? tool.note : '')} |`);
    }
  }
  lines.push('');

  lines.push('## Remediation');
  lines.push('');
  if (findings.length === 0) {
    lines.push('Nothing to remediate.');
  } else {
    const seen = new Set();
    for (const finding of findings) {
      const ruleId = String(finding && finding.ruleId ? finding.ruleId : 'unknown');
      if (seen.has(ruleId)) continue;
      seen.add(ruleId);
      const remediation = finding && finding.remediation ? String(finding.remediation) : 'Review the flagged code.';
      lines.push(`- \`${cell(ruleId)}\` - ${cell(remediation)}`);
    }
  }
  lines.push('');

  return `${lines.join('\n')}`;
}
