'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')
const { isMusl, targetFor } = require('../loader')

test('the loader exposes exactly the supported native target matrix', () => {
  assert.equal(targetFor('darwin', 'arm64'), 'darwin-arm64')
  assert.equal(targetFor('darwin', 'x64'), 'darwin-x64')
  assert.equal(targetFor('win32', 'arm64'), 'win32-arm64-msvc')
  assert.equal(targetFor('win32', 'x64'), 'win32-x64-msvc')
  assert.equal(targetFor('linux', 'arm64'), 'linux-arm64-gnu')
  assert.equal(targetFor('linux', 'x64'), 'linux-x64-gnu')
  assert.equal(targetFor('linux', 'x64', true), 'linux-x64-musl')
  assert.equal(targetFor('linux', 'arm64', true), undefined)
  assert.equal(targetFor('freebsd', 'x64'), undefined)
})

test('musl detection is Linux-only', () => {
  const report = { getReport: () => ({ header: {} }) }
  assert.equal(isMusl(report, 'darwin'), false)
  assert.equal(isMusl(report, 'linux'), true)
})
