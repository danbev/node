'use strict';

const common = require('../common');
const assert = require('assert');
const fixtures = require('../common/fixtures');

common.crashOnUnhandledRejection();

const buffer = fixtures.readSync('builtin.wasm');
assert.ok(WebAssembly.validate(buffer), 'Buffer should be valid WebAssembly');

/*
const importObject = {
  fopen: {
    nodejs: function(filename, mode) {
      console.log('fopen: filename:', filename, 'mode:', mode);
      return 22;
    }
  },
}
WebAssembly.instantiate(buffer, importObject).then((results) => {
*/
WebAssembly.instantiate(buffer).then((results) => {
  const fd = results.instance.exports.fopen();
  assert.strictEqual(fd, 22);
});
