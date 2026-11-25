#!/usr/bin/env node
/**
 * The launcher of the kit.
 *
 * The launcher does exactly one thing: it runs the command line and puts the
 * exit code into `process.exitCode`. Everything else lives in `src/cli.js`,
 * so that the command line can be tested without spawning a process.
 */

import { main } from '../src/cli.js';

process.exitCode = await main();
