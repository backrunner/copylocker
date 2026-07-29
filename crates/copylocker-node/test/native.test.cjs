'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')

test('the local Node-API artifact exports only productive operations and advisory state', async () => {
  const binding = require('..')
  assert.equal(typeof binding.CopyLockerNative, 'function')
  assert.equal(typeof binding.collectEvidence, 'function')
  assert.equal(typeof binding.nativeBindingPath, 'string')
  assert.equal('isLicensed' in binding, false)
  assert.equal('isValid' in binding, false)
})
