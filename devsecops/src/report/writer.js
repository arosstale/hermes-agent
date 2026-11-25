/**
 * The report writer.
 *
 * The writer puts the five artefacts of a scan on disk:
 *
 *   scan-manifest.json  the receipt of the scan
 *   findings.json       the findings of the scan
 *   sbom.json           the bill of materials
 *   sarif.json          the SARIF 2.1.0 export
 *   summary.md          the human readable summary
 *
 * The JSON documents are written with `JSON.stringify(doc, null, 2)` and a
 * trailing newline, with LF line endings, so that two runs over the same
 * tree produce byte identical files and `diff` stays useful.
 *
 * Signatures
 *   writeReports(outDir: string, input: {
 *     manifest?: object,
 *     findings?: object,
 *     sbom?: object,
 *     sarif?: object,
 *     summary?: string,
 *   }): string[]
 *       the paths that were written, relative to `outDir`, in a stable order.
 *   writeJson(file: string, document: object): string
 *       writes a JSON document and returns the path that was written.
 *   writeText(file: string, text: string): string
 *       writes a text document and returns the path that was written.
 *
 * Also exported: the constant `ARTEFACTS` (the artefacts of a scan, in the
 * order they are written).
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** The artefacts of a scan, in the order they are written. */
export const ARTEFACTS = Object.freeze([
  { key: 'manifest', file: 'scan-manifest.json', mediaType: 'application/json' },
  { key: 'findings', file: 'findings.json', mediaType: 'application/json' },
  { key: 'sbom', file: 'sbom.json', mediaType: 'application/json' },
  { key: 'sarif', file: 'sarif.json', mediaType: 'application/sarif+json' },
  { key: 'summary', file: 'summary.md', mediaType: 'text/markdown' },
]);

/**
 * Writes a JSON document.
 *
 * @param {string} file the absolute path of the file.
 * @param {object} document the document.
 * @returns {string} the path that was written.
 */
export function writeJson(file, document) {
  writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  return file;
}

/**
 * Writes a text document.
 *
 * @param {string} file the absolute path of the file.
 * @param {string} text the content.
 * @returns {string} the path that was written.
 */
export function writeText(file, text) {
  writeFileSync(file, String(text ?? ''), 'utf8');
  return file;
}

/**
 * Writes the artefacts of a scan.
 *
 * Only the artefacts that are present in the input are written, so a caller
 * that produces a partial scan writes a partial set of files - and the
 * returned list tells exactly which files were written.
 *
 * @param {string} outDir the directory of the artefacts; it is created when
 *   it does not exist.
 * @param {object} input the documents to write.
 * @returns {string[]} the written paths, relative to `outDir`.
 */
export function writeReports(outDir, input) {
  const source = input && typeof input === 'object' ? input : {};
  const directory = typeof outDir === 'string' && outDir !== '' ? outDir : 'reports';
  mkdirSync(directory, { recursive: true });

  const written = [];
  for (const artefact of ARTEFACTS) {
    const value = source[artefact.key];
    if (value === undefined || value === null) continue;
    const file = join(directory, artefact.file);
    if (artefact.key === 'summary') {
      writeText(file, typeof value === 'string' ? value : String(value));
    } else {
      writeJson(file, value);
    }
    written.push(artefact.file);
  }
  return written;
}
