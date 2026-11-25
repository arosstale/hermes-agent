/**
 * Minimal YAML subset parser.
 *
 * The kit ships a fail-closed parser instead of a third-party YAML library:
 * the rule packs and the security policy are configuration, and a parser that
 * silently accepts exotic YAML is a parser that can be used to smuggle
 * surprising configuration past the policy gate.
 *
 * Supported subset
 *   - space indented nesting (tabs are rejected)
 *   - `key: value`, `key:` followed by an indented block
 *   - block sequences (`- scalar`, `- key: value`, `-` + indented block)
 *   - inline `#` comments (only when preceded by whitespace, never inside quotes)
 *   - single and double quoted strings, `true`/`false`, integers, floats,
 *     `null`/`~`, empty value -> null
 *   - inline flow sequences of scalars (`[a, b, c]`)
 *
 * Rejected with a {@link YamlError}
 *   - tab indentation
 *   - anchors (`&x`), aliases (`*x`), tags (`!x`)
 *   - block scalars (`|`, `>`)
 *   - flow mappings (`{a: 1}`) and the flow collections nested more than one
 *     level deep (`[[[a]]]`)
 *   - duplicate keys inside the same mapping
 *   - list items that are neither a scalar nor a mapping
 *
 * Deviation from the plan (documented on purpose): the plan lists "flow
 * collections `{}`/`[]`" among the rejected constructs, but the rule-pack
 * format (plan D2) uses inline flow *sequences* of scalars
 * (`keywords: [apikey, api_key]`). Flow sequences of scalars are therefore
 * accepted, while flow mappings and the flow collections nested more than one
 * level deep are rejected.
 */

import { readFileSync } from 'node:fs';

export class YamlError extends Error {
  /**
   * @param {string} message human readable, never contains a secret value
   * @param {number} line 1-based line number (`0` when unknown)
   * @param {number} column 1-based column number (`0` when unknown)
   * @param {string} [source] file the document came from
   */
  constructor(message, line, column, source) {
    const where = source ? ` of ${source}` : '';
    super(`${message} (line ${line}, column ${column}${where})`);
    this.name = 'YamlError';
    this.line = line;
    this.column = column;
    this.source = source || null;
    /** Stable code so that callers can convert this into a `KitError`. */
    this.code = 'E_YAML';
    this.status = 2;
  }

  /** Serialisable form. */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      line: this.line,
      column: this.column,
      source: this.source,
    };
  }
}

/**
 * Convenience predicate: `isYamlError(value)`.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isYamlError(value) {
  return value instanceof YamlError;
}

const TAB = '\t';

/* ------------------------------------------------------------------ helpers */

function isSpace(ch) {
  return ch === ' ' || ch === TAB;
}

/**
 * Removes an inline comment. A `#` only starts a comment when it is at the
 * beginning of the content or preceded by whitespace and it is not inside a
 * quoted scalar.
 */
function stripComment(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") {
          i++;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || isSpace(text[i - 1]))) {
      return text.slice(0, i);
    }
  }
  return text;
}

function tokenize(text, source) {
  const raw = String(text).split(/\r\n|\r|\n/);
  const lines = [];
  for (let index = 0; index < raw.length; index++) {
    const lineNo = index + 1;
    const line = raw[index];
    let indent = 0;
    while (indent < line.length && isSpace(line[indent])) {
      if (line[indent] === TAB) {
        throw new YamlError('tab characters are not allowed in indentation', lineNo, indent + 1, source);
      }
      indent++;
    }
    const body = line.slice(indent);
    const content = stripComment(body).replace(/\s+$/, '');
    if (content.trim() === '') continue;
    lines.push({ indent, text: content, lineNo, col: indent + 1 });
  }
  return lines;
}

function isSequenceItem(line) {
  return line.text === '-' || line.text.startsWith('- ');
}

/**
 * Assigns a key on a plain object.
 *
 * `Object.defineProperty` is used instead of a plain assignment so that a
 * mapping key such as `__proto__` becomes an ordinary own property instead of
 * mutating the prototype of the parsed document.
 */
function setKey(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function unquote(text, line, source) {
  const quote = text[0];
  if (text.length < 2 || text[text.length - 1] !== quote) {
    throw new YamlError('unterminated quoted string', line.lineNo, line.col, source);
  }
  const body = text.slice(1, -1);
  if (quote === "'") return body.split("''").join("'");
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    const next = body[++i];
    if (next === undefined) {
      out += '\\';
      break;
    }
    if (next === 'n') out += '\n';
    else if (next === 't') out += '\t';
    else if (next === 'r') out += '\r';
    else if (next === '"') out += '"';
    else if (next === '\\') out += '\\';
    else if (next === '/') out += '/';
    else out += `\\${next}`;
  }
  return out;
}

function parseFlowSequence(text, line, source) {
  if (!text.endsWith(']')) {
    throw new YamlError('unterminated flow sequence', line.lineNo, line.col, source);
  }
  const body = text.slice(1, -1).trim();
  if (body === '') return [];
  const parts = [];
  let current = '';
  let quote = null;
  let depth = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quote) {
      current += ch;
      if (quote === '"' && ch === '\\') {
        current += body[i + 1] === undefined ? '' : body[i + 1];
        i++;
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && body[i + 1] === "'") {
          current += body[i + 1];
          i++;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '[') {
      depth++;
      if (depth > 1) {
        throw new YamlError('nested flow collections are not supported', line.lineNo, line.col, source);
      }
      current += ch;
      continue;
    }
    if (ch === ']') {
      depth--;
      current += ch;
      continue;
    }
    if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (quote) {
    throw new YamlError('unterminated quoted string in flow sequence', line.lineNo, line.col, source);
  }
  parts.push(current.trim());
  return parts.map((part) => parseScalar(part, line, source));
}

function parseScalar(text, line, source) {
  const value = text.trim();
  if (value === '') return null;
  if (value[0] === '{') {
    throw new YamlError('flow mappings are not supported', line.lineNo, line.col, source);
  }
  if (value[0] === '[') return parseFlowSequence(value, line, source);
  if (value[0] === '&') {
    throw new YamlError('anchors are not supported', line.lineNo, line.col, source);
  }
  if (value[0] === '*') {
    throw new YamlError('aliases are not supported', line.lineNo, line.col, source);
  }
  if (value[0] === '!') {
    throw new YamlError('tags are not supported', line.lineNo, line.col, source);
  }
  if (value[0] === '|' || value[0] === '>') {
    throw new YamlError('block scalars are not supported', line.lineNo, line.col, source);
  }
  if (value[0] === '"' || value[0] === "'") return unquote(value, line, source);
  if (value === '~' || value === 'null' || value === 'Null' || value === 'NULL') return null;
  if (value === 'true' || value === 'True' || value === 'TRUE') return true;
  if (value === 'false' || value === 'False' || value === 'FALSE') return false;
  if (/^[+-]?\d+$/.test(value)) return Number(value);
  if (/^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$/.test(value)) return Number(value);
  return value;
}

/* ------------------------------------------------------------------ parsing */

function splitKey(line, source) {
  let quote = null;
  for (let i = 0; i < line.text.length; i++) {
    const ch = line.text[i];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && line.text[i + 1] === "'") {
          i++;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ':') {
      const next = line.text[i + 1];
      if (next === undefined || isSpace(next)) {
        const rawKey = line.text.slice(0, i).trim();
        const rest = line.text.slice(i + 1).trim();
        if (rawKey === '') {
          throw new YamlError('empty mapping key', line.lineNo, line.col, source);
        }
        const key = rawKey[0] === '"' || rawKey[0] === "'" ? unquote(rawKey, line, source) : rawKey;
        return { key, rest };
      }
    }
  }
  throw new YamlError('expected "key: value"', line.lineNo, line.col, source);
}

function looksLikeKey(text) {
  try {
    splitKey({ text, lineNo: 0, col: 0 }, null);
    return true;
  } catch {
    return false;
  }
}

function parseMapping(state, index, indent) {
  const { lines, source } = state;
  const map = {};
  let i = index;
  while (i < lines.length) {
    const line = lines[i];
    if (line.indent < indent) break;
    if (line.indent > indent) {
      throw new YamlError('unexpected indentation', line.lineNo, line.col, source);
    }
    if (isSequenceItem(line)) break;
    const { key, rest } = splitKey(line, source);
    if (Object.prototype.hasOwnProperty.call(map, key)) {
      throw new YamlError(`duplicate key "${key}"`, line.lineNo, line.col, source);
    }
    if (rest === '') {
      const next = i + 1 < lines.length ? lines[i + 1] : null;
      if (next && next.indent > indent) {
        const [value, consumed] = parseBlock(state, i + 1, next.indent);
        setKey(map, key, value);
        i = consumed;
        continue;
      }
      if (next && next.indent === indent && isSequenceItem(next)) {
        const [value, consumed] = parseSequence(state, i + 1, indent);
        setKey(map, key, value);
        i = consumed;
        continue;
      }
      setKey(map, key, null);
      i++;
      continue;
    }
    setKey(map, key, parseScalar(rest, line, source));
    i++;
  }
  return [map, i];
}

function parseSequence(state, index, indent) {
  const { lines, source } = state;
  const items = [];
  let i = index;
  while (i < lines.length) {
    const line = lines[i];
    if (line.indent !== indent || !isSequenceItem(line)) break;
    const afterDash = line.text.slice(1);
    const trimmed = afterDash.replace(/^[ \t]+/, '');
    const dashOffset = 1 + (afterDash.length - trimmed.length);
    const contentIndent = indent + dashOffset;
    if (trimmed === '') {
      i++;
      if (i < lines.length && lines[i].indent > indent) {
        const [value, consumed] = parseBlock(state, i, lines[i].indent);
        items.push(value);
        i = consumed;
        continue;
      }
      items.push(null);
      continue;
    }
    if (trimmed[0] === '[' || trimmed[0] === '{') {
      throw new YamlError('sequence items must be scalars or mappings', line.lineNo, line.col, source);
    }
    if (trimmed.startsWith('- ')) {
      throw new YamlError('nested inline sequences are not supported', line.lineNo, line.col, source);
    }
    if (looksLikeKey(trimmed)) {
      state.lines[i] = { ...line, indent: contentIndent, text: trimmed, col: line.col + dashOffset };
      const [value, consumed] = parseMapping(state, i, contentIndent);
      items.push(value);
      i = consumed;
      continue;
    }
    items.push(parseScalar(trimmed, line, source));
    i++;
  }
  return [items, i];
}

function parseBlock(state, index, indent) {
  const line = state.lines[index];
  if (!line) return [null, index];
  if (isSequenceItem(line)) return parseSequence(state, index, indent);
  return parseMapping(state, index, indent);
}

/* -------------------------------------------------------------------- api */

/**
 * Parses a YAML document of the supported subset.
 *
 * @param {string} text
 * @param {{ source?: string }} [opts] `source` is only used in error messages.
 * @returns {unknown} plain objects, arrays and scalars. An empty document
 *   yields an empty object.
 */
export function parseYaml(text, opts = {}) {
  const source = opts.source || null;
  const lines = tokenize(text, source);
  if (lines.length === 0) return {};
  const state = { lines, source };
  const [value, next] = parseBlock(state, 0, lines[0].indent);
  if (next < lines.length) {
    const line = lines[next];
    throw new YamlError('unexpected content', line.lineNo, line.col, source);
  }
  return value;
}

/**
 * Reads and parses a YAML file.
 *
 * @param {string} file
 * @returns {unknown}
 * @throws {YamlError} on an unreadable file or on invalid content.
 */
export function parseYamlFile(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new YamlError('cannot read file', 0, 0, file);
  }
  return parseYaml(text, { source: file });
}
