'use strict';

const common = require('../common');
const assert = require('assert');
const fixtures = require('../common/fixtures');

common.crashOnUnhandledRejection();

const buffer = fixtures.readSync('native.wasm');
assert.ok(WebAssembly.validate(buffer), 'Buffer should be valid WebAssembly');

WebAssembly.instantiate(buffer).then((results) => {
  const fd = results.instance.exports.fopen();
  assert.strictEqual(fd, 22);
});


const m = new WebAssembly.Module(buffer);
const instance = new WebAssembly.Instance(m);
assert.strictEqual(instance.exports.fopen(), 22);
