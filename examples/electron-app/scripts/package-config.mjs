import {
  FuseV1Options,
  FuseVersion,
} from '@electron/fuses'

export const APPLICATION_NAME = 'CopyLocker Native Lab'
export const EXECUTABLE_NAME = 'copylocker-native-lab'
export const ICON_FILENAMES = Object.freeze({
  darwin: 'copylocker-seal.icns',
  win32: 'copylocker-seal.ico',
  linux: 'copylocker-seal.png',
})

export const ASAR_OPTIONS = Object.freeze({
  unpack: '**/*.node',
})

export const FUSE_OPTIONS = Object.freeze({
  version: FuseVersion.V1,
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableCookieEncryption]: true,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
  [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
  [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
  [FuseV1Options.WasmTrapHandlers]: true,
})

export const SOURCE_IGNORE = Object.freeze([
  /^\/(?:release|scripts|src|test)(?:\/|$)/,
  /^\/(?:README\.md|index\.html|package-lock\.json|tsconfig\.json|vite\.config\.ts)$/,
])
