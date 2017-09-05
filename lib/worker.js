'use strict';

if (!process.binding('config').experimentalWorker) {
  // TODO(addaleax): Is this the right way to do this?
  // eslint-disable-next-line no-restricted-syntax
  throw new Error('The `worker` module is experimental and may change at ' +
    'any time. Pass --experimental-worker to Node.js in order to enable it.');
}

const { MessagePort, MessageChannel } = require('internal/worker');

module.exports = { MessagePort, MessageChannel };
