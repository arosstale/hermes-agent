/**
 * Glob matching for POSIX relative paths.
 *
 * The kit matches paths against the patterns of the security policy
 * (`paths.include`, `paths.exclude`, `paths.deny`) and against the allow
 * list of the scanners. The dialect is the small, predictable subset that
 * everybody agrees on:
 *
 *   - `**`  matches any number of path segments, including none;
 *   - `*`   matches any run of characters inside a single segment;
 *   - `?`   matches exactly one character inside a single segment;
 *   - `!`   at the start of a pattern *negates* it (see {@link matchAny}).
 *
 * Everything else is literal. There is no brace expansion, no character
 * class and no "match the dot files too" magic: a policy that cannot be
 * understood by reading it is a policy that cannot be reviewed.
 */

/** Cache of compiled segment patterns (patterns are repeated a lot). */
const cache = new Map();

/**
 * Normalises a path: backslashes become slashes, `./` prefixes and leading
 * slashes are removed.
 *
 * @param {string} value
 * @returns {string}
 */
function normalizePath(value) {
  return String(value ?? '')
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '');
}

/**
 * Splits a path into its segments, dropping empty ones.
 *
 * @param {string} value
 * @returns {string[]}
 */
function splitSegments(value) {
  return normalizePath(value).split('/').filter((segment) => segment !== '' && segment !== '.');
}

/**
 * Compiles a single path segment into an anchored regular expression.
 *
 * @param {string} segment
 * @returns {RegExp}
 */
function segmentRegExp(segment) {
  let cached = cache.get(segment);
  if (cached) return cached;
  let source = '';
  for (const ch of segment) {
    if (ch === '*') source += '[^/]*';
    else if (ch === '?') source += '[^/]';
    else source += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  cached = new RegExp(`^${source}$`);
  cache.set(segment, cached);
  return cached;
}

/**
 * Matches a pattern segment against a path segment.
 *
 * @param {string} pattern
 * @param {string} segment
 * @returns {boolean}
 */
function segmentMatches(pattern, segment) {
  if (pattern === '**') return true;
  return segmentRegExp(pattern).test(segment);
}

/**
 * Recursive matcher over the segment lists.
 *
 * @param {string[]} patterns
 * @param {string[]} segments
 * @returns {boolean}
 */
function matchSegments(patterns, segments) {
  if (patterns.length === 0) return segments.length === 0;
  const [head, ...tail] = patterns;
  if (head === '**') {
    // `**` matches zero, one or many segments.
    for (let i = 0; i <= segments.length; i += 1) {
      if (matchSegments(tail, segments.slice(i))) return true;
    }
    return false;
  }
  if (segments.length === 0) return false;
  if (!segmentMatches(head, segments[0])) return false;
  return matchSegments(tail, segments.slice(1));
}

/**
 * Matches a path against a single glob pattern.
 *
 * A leading `!` is accepted and ignored here: the negation itself is
 * implemented by {@link matchAny}, which needs the list context.
 *
 * @param {string} pattern a glob pattern, e.g. `rules/**`.
 * @param {string} relPath a POSIX relative path, e.g. `rules/secrets.yml`.
 * @returns {boolean} true when the path matches the pattern.
 */
export function matchGlob(pattern, relPath) {
  if (typeof pattern !== 'string' || pattern === '') return false;
  let raw = pattern.trim();
  if (raw.startsWith('!')) raw = raw.slice(1).trim();
  if (raw === '') return false;
  const patterns = splitSegments(raw);
  if (patterns.length === 0) return false;
  return matchSegments(patterns, splitSegments(relPath));
}

/**
 * Matches a path against a list of patterns.
 *
 * A pattern starting with `!` negates: when a negated pattern matches, the
 * path is *excluded* whatever the other patterns say. The exclusion always
 * wins, so the result does not depend on the order of the list - a policy
 * must not change meaning when someone reorders it.
 *
 * @param {string[]} patterns a list of glob patterns.
 * @param {string} relPath a POSIX relative path.
 * @returns {boolean} true when the path is selected by the list.
 */
export function matchAny(patterns, relPath) {
  const list = Array.isArray(patterns) ? patterns : [];
  let matched = false;
  for (const raw of list) {
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    const negated = raw.trim().startsWith('!');
    const pattern = negated ? raw.trim().slice(1) : raw.trim();
    if (!matchGlob(pattern, relPath)) continue;
    if (negated) return false;
    matched = true;
  }
  return matched;
}
