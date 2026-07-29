import { access, readdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { flipFuses, getCurrentFuseWire } from '@electron/fuses'
import { packager } from '@electron/packager'
import { statFile } from '@electron/asar'

import {
  APPLICATION_NAME,
  ASAR_OPTIONS,
  EXECUTABLE_NAME,
  FUSE_OPTIONS,
  ICON_FILENAMES,
  SOURCE_IGNORE,
} from './package-config.mjs'

const require = createRequire(import.meta.url)
const exampleDirectory = resolve(fileURLToPath(new URL('..', import.meta.url)))
const electronVersion = require('electron/package.json').version

const buildPaths = await packager({
  arch: process.arch,
  asar: ASAR_OPTIONS,
  dir: exampleDirectory,
  electronVersion,
  executableName: EXECUTABLE_NAME,
  icon: resolve(
    exampleDirectory,
    '../assets',
    ICON_FILENAMES[process.platform] ?? ICON_FILENAMES.linux,
  ),
  ignore: SOURCE_IGNORE,
  name: APPLICATION_NAME,
  out: resolve(exampleDirectory, 'release'),
  overwrite: true,
  platform: process.platform,
  prune: true,
})

for (const buildPath of buildPaths) {
  const executable = packagedExecutable(buildPath, process.platform)
  const resources = packagedResources(buildPath, process.platform)
  const asarPath = join(resources, 'app.asar')
  await access(executable)
  await access(asarPath)
  const renderer = statFile(asarPath, join('dist', 'renderer', 'index.html'))
  if (renderer.unpacked) throw new Error('Renderer entry must remain inside app.asar')
  const nativeBinding = await findNativeBinding(join(resources, 'app.asar.unpacked'))
  await flipFuses(executable, {
    ...FUSE_OPTIONS,
    resetAdHocDarwinSignature: process.platform === 'darwin' && process.arch === 'arm64',
    strictlyRequireAllFuses: true,
  })
  await verifyFuses(executable)
  console.log(`Packaged ${buildPath} (native: ${nativeBinding})`)
}

function packagedExecutable(buildPath, platform) {
  if (platform === 'darwin') {
    return join(
      buildPath,
      `${APPLICATION_NAME}.app`,
      'Contents',
      'MacOS',
      EXECUTABLE_NAME,
    )
  }
  if (platform === 'win32') return join(buildPath, `${EXECUTABLE_NAME}.exe`)
  return join(buildPath, EXECUTABLE_NAME)
}

function packagedResources(buildPath, platform) {
  if (platform === 'darwin') {
    return join(buildPath, `${APPLICATION_NAME}.app`, 'Contents', 'Resources')
  }
  return join(buildPath, 'resources')
}

async function findNativeBinding(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  for (const entry of entries) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) {
      const nested = await findNativeBinding(path)
      if (nested) return nested
    } else if (entry.isFile() && entry.name.endsWith('.node')) {
      return path
    }
  }
  if (directory.endsWith('app.asar.unpacked')) {
    throw new Error('Packaged application does not contain an unpacked native binding')
  }
  return undefined
}

async function verifyFuses(executable) {
  const wire = await getCurrentFuseWire(executable)
  for (const [option, expected] of Object.entries(FUSE_OPTIONS)) {
    if (option === 'version') continue
    const actual = wire[option] === '1'.charCodeAt(0)
    if (actual !== expected) {
      throw new Error(`Fuse ${option} did not persist`)
    }
  }
}
