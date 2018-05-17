'use strict';
if (typeof require === 'undefined') {
  console.log('1..0 # Skipped: Not being run as CommonJS');
  process.exit(0);
}

const path = require('path');
const { Worker } = require('worker');

new Worker(path.resolve(process.cwd(), process.argv[2]));
