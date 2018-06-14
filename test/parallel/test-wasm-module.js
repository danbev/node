const common = require('../common');
const assert = require('assert');
const fixtures = require('../common/fixtures');

common.crashOnUnhandledRejection();

const buffer = fixtures.readSync('native.wasm');

WebAssembly.compile(buffer).then((mod) => {
  const imports = WebAssembly.Module.imports(mod);
  const importObject = {
    __node: {
      fopen: function(filename, mode) {
        console.log('fopen: filename:', filename, 'mode:', mode);
        return 22;
      }
    },
  };
  WebAssembly.instantiate(buffer, importObject).then((results) => {
    const fd = results.instance.exports.fopen();
    assert.strictEqual(fd, 22);
  });
});
