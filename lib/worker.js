'use strict';

const {
  isMainThread,
  MessagePort,
  MessageChannel,
  threadId,
  Worker
} = require('internal/worker');

const EventEmitter = require('events');

module.exports = new EventEmitter();

Object.assign(module.exports, {
  isMainThread,
  MessagePort,
  MessageChannel,
  threadId,
  Worker
});
