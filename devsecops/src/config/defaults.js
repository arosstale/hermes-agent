/**
 * Built-in, fail-closed policy.
 *
 * The kit must behave safely even when no policy file exists at all: a
 * missing configuration is not a reason to relax the gates. The defaults
 * below are therefore the *strictest* useful setting:
 *
 *   - the gate is closed by default (`fail_closed: true`);
 *   - a critical or a high finding is a violation;
 *   - a medium finding is tolerated up to five times, an informational one
 *     never fails the build;
 *   - every stage is enabled, so a missing stage is a violation instead of
 *     a silent pass;
 *   - the deny list forbids the classic environment files everywhere.
 *
 * The anchoring of the exclusions
 *   A pattern is anchored at the root of the tree unless it starts with a
 *   globstar and a slash (the two characters `**` and `/`). The vendored
 *   and the generated trees are therefore written with that prefix and not
 *   with the bare name of the tree: the bare form (`node_modules/**`)
 *   only matches the tree that sits at the root of the tree, and a nested
 *   one (`scripts/fleet/node_modules/`) would be scanned as if it were
 *   source. The exclusions that really live at the root of the kit - the
 *   rule packs, the fixtures, the artefacts and the object store of git -
 *   stay anchored, and they say so.
 *
 * The object is deeply frozen: a caller that wants to change something
 * works on a copy (see {@link clonePolicy}).
 */

/** Stages the kit knows about. */
export const STAGE_NAMES = Object.freeze(['secrets', 'sast', 'deps', 'sbom']);

/** The default size cap of a single scanned file (2 MB). */
export const DEFAULT_MAX_FILE_BYTES = 2_000_000;

/** Severities, from the least to the most severe. */
export const SEVERITY_NAMES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

/**
 * The built-in policy.
 * @type {Readonly<object>}
 */
export const DEFAULT_POLICY = deepFreeze({
  version: 1,
  fail_closed: true,
  source: 'builtin-default',
  defaults: {
    fail_on: 'high',
  },
  stages: {
    secrets: { enabled: true, severity: 'critical' },
    sast: { enabled: true },
    deps: { enabled: true },
    sbom: { enabled: true },
  },
  thresholds: {
    critical: 0,
    high: 0,
    medium: 5,
    low: -1,
    info: -1,
  },
  required_evidence: [
    'scan-manifest.json',
    'findings.json',
    'sbom.json',
    'sarif.json',
    'summary.md',
  ],
  limits: {
    // The size cap of a single file: a file above the cap is not scanned.
    // The cap is configurable, and the walk always reports what it dropped.
    max_file_bytes: DEFAULT_MAX_FILE_BYTES,
  },
  paths: {
    include: [],
    exclude: [
      // The rule packs are detection patterns: scanning them would report the kit's own detection rules as findings.
      'rules/**',
      // The synthetic fixtures of the tests are generated at runtime.
      'test/fixtures/**',
      // The generated artefacts of a scan.
      'reports/**',
      // The third-party dependencies (the kit has none, the guard stays).
      '**/node_modules/**',
      // The vendored third-party code is not the code of the repository.
      '**/vendor/**',
      // The third-party trees of the other package managers.
      '**/Pods/**',
      // The Python packages of a virtual environment are not the code of the repository.
      '**/site-packages/**',
      // The output of the build of the frameworks is generated, it is not the source.
      '**/.next/**',
      // The output of the build of Nuxt is generated, it is not the source.
      '**/.nuxt/**',
      // The output of the build of the framework is generated, it is not the source.
      '**/.output/**',
      // The output of the build is generated, it is not the source.
      '**/build/**',
      // The output of the bundle is generated, it is not the source.
      '**/dist/**',
      // The output of the build is generated, it is not the source.
      '**/out/**',
      // The output of the build of the toolchain is generated, it is not the source.
      '**/target/**',
      // The virtual environment is generated, it is not the source.
      '**/.venv/**',
      // The virtual environment is generated, it is not the source.
      '**/venv/**',
      // The environments of tox are generated, they are not the source.
      '**/.tox/**',
      // The bytecode cache of Python is generated, it is not the source.
      '**/__pycache__/**',
      // The cache of the type checker is generated, it is not the source.
      '**/.mypy_cache/**',
      // The cache of the test runner is generated, it is not the source.
      '**/.pytest_cache/**',
      // The metadata of the installed Python packages is generated, it is not the source.
      '**/*.egg-info/**',
      // The report of the coverage is generated, it is not the source.
      '**/coverage/**',
      // The cache of the build tools is generated, it is not the source.
      '**/.cache/**',
      // The third-party trees that the toolchains vendor are not the code of the repository.
      '**/third_party/**',
      // The object store of git is not part of the working tree.
      '.git/**',
    ],
    deny: [
      '**/.env',
      '**/.env.*',
    ],
  },
  allowlist: {
    secrets: [],
  },
});

/**
 * The size cap of a single file, read from a policy.
 *
 * The cap is part of the policy: a project that ships legitimately huge
 * files can raise it, and a project that wants a strict budget can lower it.
 * The default is the documented one (2 MB).
 *
 * @param {object} policy
 * @returns {number} the cap, in bytes.
 */
export function maxFileBytesOf(policy) {
  const limits = policy && typeof policy.limits === 'object' && policy.limits !== null ? policy.limits : {};
  const value = limits.max_file_bytes;
  if (Number.isInteger(value) && value > 0) return value;
  return DEFAULT_MAX_FILE_BYTES;
}

/**
 * Deeply freezes an object.
 *
 * @param {object} value
 * @returns {object} the same object, frozen.
 */
function deepFreeze(value) {
  if (typeof value !== 'object' || value === null) return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}

/**
 * Returns a deep, mutable copy of a policy-like object.
 *
 * @param {object} policy
 * @returns {object}
 */
export function clonePolicy(policy) {
  if (Array.isArray(policy)) return policy.map((item) => clonePolicy(item));
  if (typeof policy !== 'object' || policy === null) return policy;
  const out = {};
  for (const key of Object.keys(policy)) out[key] = clonePolicy(policy[key]);
  return out;
}
