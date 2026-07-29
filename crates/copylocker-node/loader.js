'use strict'

const { existsSync } = require('node:fs')
const { join } = require('node:path')

function isMusl(report = process.report, platform = process.platform) {
  if (platform !== 'linux') return false
  if (typeof report?.getReport !== 'function') return false
  return !report.getReport()?.header?.glibcVersionRuntime
}

function targetFor(platform, arch, musl = false) {
  const key = `${platform}:${arch}:${musl ? 'musl' : 'native'}`
  const targets = {
    'darwin:arm64:native': 'darwin-arm64',
    'darwin:x64:native': 'darwin-x64',
    'win32:arm64:native': 'win32-arm64-msvc',
    'win32:x64:native': 'win32-x64-msvc',
    'linux:arm64:native': 'linux-arm64-gnu',
    'linux:x64:native': 'linux-x64-gnu',
    'linux:x64:musl': 'linux-x64-musl',
  }
  return targets[key]
}

function loadNative(options = {}) {
  const platform = options.platform ?? process.platform
  const arch = options.arch ?? process.arch
  const musl = options.musl ?? isMusl(process.report, platform)
  const root = options.root ?? __dirname
  const target = targetFor(platform, arch, musl)
  if (!target) {
    throw new Error(
      `Unsupported CopyLocker native target: ${platform}-${arch}${musl ? '-musl' : ''}`,
    )
  }

  const filename = `copylocker.${target}.node`
  const localPath = join(root, filename)
  if (existsSync(localPath)) {
    return { binding: require(localPath), path: localPath }
  }

  const packageName = `@copylocker/node-${target}`
  try {
    const packagePath = require.resolve(packageName, { paths: [root] })
    return { binding: require(packagePath), path: packagePath }
  } catch (cause) {
    throw new Error(
      `CopyLocker native binding ${filename} is not installed for this platform`,
      { cause },
    )
  }
}

module.exports = { isMusl, loadNative, targetFor }
