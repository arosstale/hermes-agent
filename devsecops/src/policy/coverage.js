/**
 * Coverage of a scan.
 *
 * A gate that answers "PASS" about a tree it did not open is worse than no
 * gate at all: it turns a typo, a wrong volume or an over-broad exclusion
 * into an approval. This module computes what a scan is *allowed* to look
 * at, and refuses the configurations whose answer is "nothing":
 *
 *   - the policy excludes every file of the scan root: the scan would look at
 *     nothing, and the policy is wrong (an `E_POLICY` error, exit code 2);
 *   - the policy leaves no file in scope (an `include` that matches nothing,
 *     for instance): same verdict, same exit code.
 *
 * An empty scan root is **not** an error: a tree without a file is empty by
 * construction, and there is nothing to look at. A tree whose files are all
 * above the size cap is *not* empty: the files are counted, the walk
 * reports that it dropped them, and the coverage assertion compares the
 * inspected count with the count of the files of the tree.
 *
 * The coverage line
 *   Every stage reports what it covered with the same sentence:
 *   `inspected <inspected> of <in scope> (<dropped> dropped)`. The number of
 *   dropped files is part of the line: a reader who sees "inspected 0 of 1
 *   (1 dropped)" knows that the tree was not empty.
 *
 * Signatures
 *   scopeOf(root: string, policy: object, fs?: object): {
 *     tree: string[],      // every file of the working tree
 *     dirs: string[],      // every directory of the working tree
 *     treePaths: string[], // the files and the directories of the tree
 *     inScope: string[],   // the files the policy leaves in scope
 *     dropped: object[],   // the files the walk dropped, and why
 *     include: string[],
 *     exclude: string[],
 *     maxFileBytes: number,
 *   }
 *   assertPolicyScope(root: string, policy: object, fs?: object): object
 *       the scope, or a `KitError` with the code `E_POLICY`.
 *   coverageViolation(stage: object, treeFiles: number): object|null
 *       the gate violation of a stage that inspected nothing, of a stage
 *       whose coverage is too low, or null.
 *   coverageLine(stats: object): string
 *       the sentence that tells what a stage covered.
 *
 * A StageMeta is `{ name, status, findingCount?, artifacts?, notes?,
 * inspected?, filesInScope?, dropped?, unreadable? }`.
 */

import { KitError } from '../core/errors.js';
import { walkTree } from '../core/fs-walk.js';
import { matchAny } from '../core/glob.js';
import { maxFileBytesOf } from '../config/defaults.js';

/** The paths that are never part of the working tree. */
const ALWAYS_EXCLUDED = Object.freeze(['.git/**']);

/**
 * The share of the files in scope a stage must have been able to read.
 *
 * The floor of one file was too low: a tree of three files whose two
 * readable ones could not be opened passed the gate on the strength of the
 * single file the scanner did read. The floor is a share now: at least half
 * of the files in scope must have been readable, the files that could not
 * be read and the files the walk dropped included.
 */
export const MIN_READABLE_SHARE = 0.5;

/**
 * The paths of a policy, normalised.
 *
 * @param {object} policy
 * @returns {{ include: string[], exclude: string[] }}
 */
function pathsOf(policy) {
  const paths = policy && typeof policy.paths === 'object' && policy.paths !== null ? policy.paths : {};
  const include = Array.isArray(paths.include) ? paths.include.filter((item) => typeof item === 'string') : [];
  const exclude = Array.isArray(paths.exclude) ? paths.exclude.filter((item) => typeof item === 'string') : [];
  return { include, exclude };
}

/**
 * Computes what a scan of a root is allowed to look at.
 *
 * The files the walk drops (the ones above the size cap) are part of the
 * tree and of the scope: they are files of the repository that the scanner
 * could not open, and the coverage assertion has to see them.
 *
 * The tree is more than its files: the directories are part of it too, and
 * `treePaths` holds both. The deny list of the policy is a statement about
 * the tree, and an empty directory is a path of the tree all the same.
 *
 * @param {string} root the scan root.
 * @param {object} policy the security policy.
 * @param {object} [fs] the file system seam (the real one by default).
 * @returns {{ tree: string[], dirs: string[], treePaths: string[], inScope: string[], dropped: object[], include: string[], exclude: string[], maxFileBytes: number }}
 * @throws {KitError} with the code `E_IO` when the root cannot be read.
 */
export function scopeOf(root, policy, fs = undefined) {
  const { include, exclude } = pathsOf(policy);
  const maxFileBytes = maxFileBytesOf(policy);
  const treeWalk = walkTree(root, { include: [], exclude: [...ALWAYS_EXCLUDED], maxFileBytes, fs });
  const scopeWalk = walkTree(root, { include, exclude: [...exclude, ...ALWAYS_EXCLUDED], maxFileBytes, fs });
  const tree = [...treeWalk.files, ...treeWalk.dropped.map((entry) => entry.path)].sort();
  const dirs = [...treeWalk.dirs].sort();
  const treePaths = [...tree, ...dirs].sort();
  const inScope = [...scopeWalk.files, ...scopeWalk.dropped.map((entry) => entry.path)].sort();
  return {
    tree,
    dirs,
    treePaths,
    inScope,
    dropped: scopeWalk.dropped,
    include,
    exclude,
    maxFileBytes,
  };
}

/**
 * Refuses a policy that would make the scan look at nothing.
 *
 * @param {string} root the scan root.
 * @param {object} policy the security policy.
 * @param {object} [fs] the file system seam (the real one by default).
 * @returns {object} the scope of the scan.
 * @throws {KitError} with the code `E_POLICY` when the policy leaves no file
 *   in scope while the tree holds files.
 */
export function assertPolicyScope(root, policy, fs = undefined) {
  const scope = scopeOf(root, policy, fs);
  if (scope.tree.length === 0) return scope;
  if (scope.inScope.length > 0) return scope;

  const excludedEverywhere = scope.tree.every((path) => matchAny(scope.exclude, path));
  if (excludedEverywhere) {
    throw new KitError('E_POLICY', `the policy excludes every file of the scan root ${root}: the scan would look at nothing`, {
      root,
      files: scope.tree.length,
      exclude: scope.exclude,
    });
  }
  throw new KitError('E_POLICY', `the policy leaves no file in scope in the scan root ${root}: the scan would look at nothing`, {
    root,
    files: scope.tree.length,
    include: scope.include,
    exclude: scope.exclude,
  });
}

/**
 * The sentence that tells what a stage covered.
 *
 * @param {object} stats `{ inspected, filesInScope, dropped }`.
 * @returns {string} e.g. `inspected 3 of 5 (1 dropped)`.
 */
export function coverageLine(stats) {
  const source = stats && typeof stats === 'object' ? stats : {};
  const inspected = Number.isInteger(source.inspected) ? source.inspected : 0;
  const inScope = Number.isInteger(source.filesInScope)
    ? source.filesInScope
    : (Number.isInteger(source.inScope) ? source.inScope : 0);
  const dropped = Number.isInteger(source.dropped) ? source.dropped : 0;
  return `inspected ${inspected} of ${inScope} (${dropped} dropped)`;
}

/**
 * The violation of a stage that looked at nothing.
 *
 * A stage that had files in scope and inspected none of them has lost its
 * coverage: the gate fails closed. A stage that had no file in scope (a tree
 * without source code, for instance) is not a violation. The files the walk
 * dropped count as files in scope: a tree whose files are all above the size
 * cap is a tree the scanner did not open, not an empty tree.
 *
 * A stage that read a single file of a tree it could not read is not an
 * inspection either: the floor is a **share** of the files in scope. The
 * files that could not be read and the files the walk dropped are part of
 * the denominator, so a tree whose files are mostly unreadable cannot pass
 * on the strength of one readable file.
 *
 * @param {object} stage the metadata of the stage.
 * @param {number} [treeFiles] the number of files of the scan root.
 * @returns {object|null} the violation, or null when the stage is fine.
 */
export function coverageViolation(stage, treeFiles = 0) {
  if (!stage || typeof stage !== 'object') return null;
  const name = typeof stage.name === 'string' ? stage.name : 'unknown';
  const status = typeof stage.status === 'string' ? stage.status : '';
  if (status !== 'completed') return null;

  const inspected = Number.isInteger(stage.inspected) ? stage.inspected : null;
  const inScope = Number.isInteger(stage.filesInScope) ? stage.filesInScope : null;
  if (inspected === null || inScope === null) return null;
  if (inScope <= 0) return null;

  const dropped = Number.isInteger(stage.dropped) ? stage.dropped : 0;
  const unreadable = Number.isInteger(stage.unreadable)
    ? stage.unreadable
    : Math.max(0, inScope - inspected - dropped);

  if (inspected <= 0) {
    const droppedPart = dropped > 0 ? `, ${dropped} of them dropped by the walk` : '';
    const detail = treeFiles > 0
      ? `the stage "${name}" inspected 0 of the ${inScope} file(s) in scope${droppedPart} (${treeFiles} file(s) in the scan root): the coverage of the scan vanished`
      : `the stage "${name}" inspected 0 of the ${inScope} file(s) in scope${droppedPart}: the coverage of the scan vanished`;

    return {
      kind: 'stage-no-output',
      detail,
    };
  }

  // The share of the files in scope the stage could really read. The floor
  // is a ratio: a tree the scanner could mostly not open is not a tree the
  // scanner inspected.
  if (inspected / inScope >= MIN_READABLE_SHARE) return null;

  const detail = `the stage "${name}" inspected ${inspected} of the ${inScope} file(s) in scope: the coverage of the scan is too low (at least ${Math.round(MIN_READABLE_SHARE * 100)}% of the files in scope must be readable, ${unreadable} of them could not be read)`;
  return {
    kind: 'stage-coverage',
    detail,
  };
}
