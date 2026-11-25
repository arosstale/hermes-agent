/**
 * The scan manifest.
 *
 * `reports/scan-manifest.json` is the receipt of a scan: it says what was
 * scanned, which stages ran, which artefacts were written and what their
 * digests are. It is the only artefact of the kit that may carry a
 * timestamp, and even then only when the caller injects one explicitly: a
 * receipt that invents its own clock is not reproducible.
 *
 * Signatures
 *   buildScanManifest(input: {
 *     scanId?: string,
 *     tool?: { name?: string, version?: string },
 *     target?: { kind?: string, targetId?: string, revision?: string, revisionReason?: string, snapshotDigest?: string, snapshotDigestLabel?: string, snapshotExcluded?: string[] },
 *     scope?: { includePaths?: string[], excludePaths?: string[], denyPaths?: string[], deniedPaths?: string[] },
 *     stages?: StageMeta[],
 *     artifacts?: ArtifactMeta[],
 *     status?: string,
 *     startedAt?: string,
 *     completedAt?: string,
 *   }): {
 *     documentType: "devsecops.scan-manifest",
 *     schemaVersion: "1.0",
 *     scan: {
 *       id, producer, status, startedAt?, completedAt?, target, scope,
 *       stages, findingsRef, artifacts,
 *     },
 *   }
 *
 * A StageMeta is `{ name, status, findingCount, notes }`; an ArtifactMeta is
 * `{ path, sha256, mediaType }`.
 *
 * The digests of the artefacts are the digests of the bytes that were really
 * written: a reader can recompute them and compare. The manifest cannot
 * carry its own digest (it would have to contain its own hash), so it signs
 * the other artefacts and not itself.
 *
 * Also exported: the constants `TOOL_NAME`, `TOOL_VERSION` and
 * `FINDINGS_REF`.
 */

/** The name of the producer of the document. */
export const TOOL_NAME = 'devsecops-kit';

/** The version of the producer of the document. */
export const TOOL_VERSION = '1.0.0';

/** The reference of the findings document inside the manifest. */
export const FINDINGS_REF = 'findings.json';

/**
 * The revision recorded when git cannot tell it.
 *
 * The value is documented: a receipt that carries an empty revision proves
 * nothing, and a receipt that carries a revision without a reason hides a
 * hole.
 */
export const UNKNOWN_REVISION = 'unknown';

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
 * Normalises a list of strings.
 *
 * @param {unknown} value
 * @returns {string[]}
 */
function stringList(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((entry) => typeof entry === 'string' && entry.trim() !== '')
    .map((entry) => entry.trim())
    .sort();
}

/**
 * Builds the scan manifest.
 *
 * @param {object} input see the file header.
 * @returns {object} the manifest.
 */
export function buildScanManifest(input) {
  const source = isPlainObject(input) ? input : {};
  const tool = isPlainObject(source.tool) ? source.tool : {};
  const target = isPlainObject(source.target) ? source.target : {};
  const scope = isPlainObject(source.scope) ? source.scope : {};

  const stages = (Array.isArray(source.stages) ? source.stages : [])
    .filter((stage) => isPlainObject(stage))
    .map((stage) => ({
      name: String(stage.name === undefined ? '' : stage.name),
      status: String(stage.status === undefined ? 'unknown' : stage.status),
      findingCount: Number.isFinite(Number(stage.findingCount)) ? Number(stage.findingCount) : 0,
      notes: String(stage.notes === undefined ? '' : stage.notes),
      reason: String(stage.reason === undefined ? '' : stage.reason),
      inspected: Number.isFinite(Number(stage.inspected)) ? Number(stage.inspected) : 0,
      filesInScope: Number.isFinite(Number(stage.filesInScope)) ? Number(stage.filesInScope) : 0,
      dropped: Number.isFinite(Number(stage.dropped)) ? Number(stage.dropped) : 0,
      unreadable: Number.isFinite(Number(stage.unreadable)) ? Number(stage.unreadable) : 0,
      coverage: String(stage.coverage === undefined ? '' : stage.coverage),
    }))
    .sort((a, b) => (a.name < b.name ? -1 : (a.name > b.name ? 1 : 0)));

  const artifacts = (Array.isArray(source.artifacts) ? source.artifacts : [])
    .filter((artifact) => isPlainObject(artifact))
    .map((artifact) => ({
      path: String(artifact.path === undefined ? '' : artifact.path),
      sha256: String(artifact.sha256 === undefined ? '' : artifact.sha256),
      mediaType: String(artifact.mediaType === undefined ? 'application/octet-stream' : artifact.mediaType),
    }))
    .sort((a, b) => (a.path < b.path ? -1 : (a.path > b.path ? 1 : 0)));

  const scan = {
    id: String(source.scanId === undefined ? '' : source.scanId),
    producer: {
      name: typeof tool.name === 'string' && tool.name !== '' ? tool.name : TOOL_NAME,
      version: typeof tool.version === 'string' && tool.version !== '' ? tool.version : TOOL_VERSION,
    },
    status: String(source.status === undefined ? 'completed' : source.status),
  };

  // The timestamps are only written when the caller injects them: the
  // manifest is the receipt, but it never invents a clock of its own.
  if (typeof source.startedAt === 'string' && source.startedAt !== '') scan.startedAt = source.startedAt;
  if (typeof source.completedAt === 'string' && source.completedAt !== '') scan.completedAt = source.completedAt;

  scan.target = {
    kind: String(target.kind === undefined ? 'git_worktree' : target.kind),
    targetId: String(target.targetId === undefined ? '' : target.targetId),
    // The revision is never empty: when git cannot tell it, the receipt
    // carries the documented value `unknown` and the reason of the failure,
    // so that a hole in the receipt is visible instead of silent.
    revision: typeof target.revision === 'string' && target.revision.trim() !== ''
      ? target.revision.trim()
      : UNKNOWN_REVISION,
    revisionReason: typeof target.revisionReason === 'string' ? target.revisionReason : '',
    snapshotDigest: String(target.snapshotDigest === undefined ? '' : target.snapshotDigest),
    // The label of the digest: it says what the digest does *not* cover
    // (the evidence log and the artefacts of the kit), so that a reader
    // never compares it with the digest of a tree that carries the log.
    snapshotDigestLabel: String(target.snapshotDigestLabel === undefined ? '' : target.snapshotDigestLabel),
    // The paths that are not part of the digest: the exclusion set is the
    // one of the evidence log of the same tree, so that the two can be
    // compared.
    snapshotExcluded: stringList(target.snapshotExcluded),
  };
  scan.scope = {
    includePaths: stringList(scope.includePaths),
    excludePaths: stringList(scope.excludePaths),
    denyPaths: stringList(scope.denyPaths),
    deniedPaths: stringList(scope.deniedPaths),
  };
  scan.stages = stages;
  scan.findingsRef = FINDINGS_REF;
  scan.artifacts = artifacts;

  return {
    documentType: 'devsecops.scan-manifest',
    schemaVersion: '1.0',
    scan,
  };
}
