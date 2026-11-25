/**
 * The shape of a JSON Web Token.
 *
 * A token is a set of base64 segments separated by dots. The kit knows two
 * families of shapes, and the two of them have a different purpose:
 *
 *   - the **rule shape** (`JWT_RULE_PATTERN`): the header of a token is the
 *     base64 form of a JSON object, so it starts with the encoding of the
 *     two bytes of `{`. The pattern accepts a token of two segments (a
 *     token without a signature) or of three segments (a token with one), a
 *     payload of one character or of none, a signature of one character,
 *     and the standard base64 alphabet with its padding. This is the
 *     pattern of the `jwt` rule of `rules/secrets.yml`: the pack carries
 *     this exact string, and the build checks that it does.
 *
 *   - the **guard shapes** (`JWT_LITERAL_PATTERNS`): the guard of the
 *     repository also refuses a token whose header does not look like a
 *     JSON object, so it adds the generic shapes: two or three substantial
 *     segments, the first one carrying the marks of base64 data (an upper
 *     case letter and a digit). The generic shapes are deliberately strict:
 *     a dotted path or a dotted identifier is not a token.
 *
 * The patterns are written from character classes: the source of the kit
 * never holds a literal token, not even as an example.
 */

/**
 * The alphabet of a segment: base64url, the standard base64 (with its `+`
 * and `/`) and the padding of the standard base64.
 *
 * The `/` is escaped so that the string is the same in a regular expression
 * literal and in the rule pack.
 */
const STANDARD = '[A-Za-z0-9_+\\/=-]';

/**
 * The alphabet of a segment without the `/` of the standard base64: a path
 * is not a token, and a path with two separators would match the generic
 * shapes otherwise.
 */
const URLSAFE = '[A-Za-z0-9_+\\-]';

/**
 * The pattern of the `jwt` rule of the secret rule pack.
 *
 * The rule detects a token in a scanned tree: the shape has to be precise,
 * because a false positive fails the gate of a repository that holds no
 * credential at all.
 *
 * @type {string}
 */
export const JWT_RULE_PATTERN = `\\b[eE][yY][jJ]${STANDARD}{5,}(?:\\.${STANDARD}*\\.${STANDARD}+|\\.${STANDARD}+)`;

/**
 * The patterns of the guard of the repository.
 *
 * The first one is the rule shape; the other ones are the generic shapes of
 * a token, whose first segment carries the marks of base64 data.
 *
 * @type {ReadonlyArray<RegExp>}
 */
export const JWT_LITERAL_PATTERNS = Object.freeze([
  new RegExp(JWT_RULE_PATTERN, 'g'),
  new RegExp(`(?=${URLSAFE}*[A-Z])(?=${URLSAFE}*[0-9])${URLSAFE}{10,}={0,2}\\.${URLSAFE}{10,}={0,2}(?:\\.${URLSAFE}{1,}={0,2})?`, 'g'),
  new RegExp(`${URLSAFE}{10,}={0,2}\\.${URLSAFE}{10,}={0,2}\\.${URLSAFE}{10,}={0,2}`, 'g'),
]);

/**
 * Finds the JSON Web Tokens of a text.
 *
 * Only the line number and the value of the match are returned: the value
 * never has to reach a log, the caller only has to know where the file has
 * to be fixed.
 *
 * @param {string} text the text to read.
 * @returns {{ line: number, value: string }[]} the tokens, in the order of
 *   the file.
 */
export function findJwtLiterals(text) {
  const found = [];
  const lines = String(text ?? '').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    for (const pattern of JWT_LITERAL_PATTERNS) {
      pattern.lastIndex = 0;
      let match = pattern.exec(line);
      while (match !== null) {
        if (match[0] !== '') found.push({ line: index + 1, value: match[0] });
        pattern.lastIndex += 1;
        match = pattern.exec(line);
      }
    }
  }
  return found;
}
