'use strict'

const { loadNative } = require('./loader')

const { binding, path } = loadNative()

module.exports = {
  CopyLockerNative: binding.CopyLockerNative,
  collectEvidence: binding.collectEvidence,
  nativeBindingPath: path,
}
