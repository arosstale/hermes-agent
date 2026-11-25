/**
 * The findings document.
 *
 * `reports/findings.json` is the machine readable result of a scan. The
 * document is deterministic: the findings are sorted, the identifiers are
 * derived from the rule id and from the fingerprint of the finding (never
 * from its position in the report), and there is no timestamp anywhere.
 *
 * Signatures
 *   sortFindings(findings: Finding[]): Finding[]
 *       the findings, sorted by path, then start line, then rule id, then
 *       fingerprint; the input array is not modified.
 *   buildFindingsDocument(findings: Finding[], opts?: {
 *     scanId?: string, tool?: { name?: string, version?: string },
 *   }): {
 *     documentType: "devsecops.findings",
 *     schemaVersion: "1.0",
 *     scanId: string,
 *     tool: { name: string, version: string },
 *     findings: Finding[],
 *   }
 *
 * A Finding is the model of plan section F:
 *   { id, ruleId, stage, severity, confidence, message,
 *     location: { path, startLine, endLine, column },
 *     fingerprint, redacted, snippet, remediation, tags, metadata }
 *
 * Also exported: the constants `TOOL_NAME` and `TOOL_VERSION`.
 */

/** The name of the producer of the documents. */
export const TOOL_NAME = 'devsecops-kit';

/** The version of the producer of the documents. */
export const TOOL_VERSION = '1.0.0';

/**
 * The path of a finding.
 *
 * @param {object} finding
 * @returns {string}
 */
function pathOf(finding) {
  const location = finding && typeof finding.location === 'object' && finding.location !== null
    ? finding.location
    : {};
  return typeof location.path === 'string' ? location.path : '';
}

/**
 * The first line of a finding.
 *
 * @param {object} finding
 * @returns {number}
 */
function lineOf(finding) {
  const location = finding && typeof finding.location === 'object' && finding.location !== null
    ? finding.location
    : {};
  const line = Number(location.startLine);
  return Number.isFinite(line) ? line : 0;
}

/**
 * Sorts the findings deterministically.
 *
 * @param {object[]} findings
 * @returns {object[]} a new array, sorted by path, start line, rule id and
 *   fingerprint.
 */
export function sortFindings(findings) {
  const list = Array.isArray(findings) ? findings.slice() : [];
  return list.sort((a, b) => {
    const pathA = pathOf(a);
    const pathB = pathOf(b);
    if (pathA !== pathB) return pathA < pathB ? -1 : 1;
    const lineA = lineOf(a);
    const lineB = lineOf(b);
    if (lineA !== lineB) return lineA - lineB;
    const ruleA = String(a && a.ruleId ? a.ruleId : '');
    const ruleB = String(b && b.ruleId ? b.ruleId : '');
    if (ruleA !== ruleB) return ruleA < ruleB ? -1 : 1;
    const printA = String(a && a.fingerprint ? a.fingerprint : '');
    const printB = String(b && b.fingerprint ? b.fingerprint : '');
    if (printA !== printB) return printA < printB ? -1 : 1;
    return 0;
  });
}

/**
 * Builds the findings document.
 *
 * @param {object[]} findings the findings of the scan.
 * @param {object} [opts]
 * @param {string} [opts.scanId] the identifier of the scan.
 * @param {object} [opts.tool] `{ name, version }` of the producer.
 * @returns {object} the document.
 */
export function buildFindingsDocument(findings, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const tool = options.tool && typeof options.tool === 'object' ? options.tool : {};
  return {
    documentType: 'devsecops.findings',
    schemaVersion: '1.0',
    scanId: typeof options.scanId === 'string' ? options.scanId : '',
    tool: {
      name: typeof tool.name === 'string' && tool.name !== '' ? tool.name : TOOL_NAME,
      version: typeof tool.version === 'string' && tool.version !== '' ? tool.version : TOOL_VERSION,
    },
    findings: sortFindings(findings),
  };
}
