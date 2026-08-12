/** Shared test helpers: synthetic pipeline inputs and a dist-mocking fetch. */

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateLocalKeyFile } from '../src/signer.js'
import type { PipelineInput } from '../src/core.js'

export async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'cl-unplugin-'))
  try {
    return await fn(dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

export async function makeLocalSigner(dir: string): Promise<{ keyFile: string; publicKey: string }> {
  const keyFile = join(dir, 'signer-key.json')
  const publicKey = await generateLocalKeyFile(keyFile)
  return { keyFile, publicKey }
}

export function syntheticInputs(): PipelineInput[] {
  return [
    {
      fileName: 'assets/index-aaa.js',
      kind: 'chunk',
      isEntry: true,
      text: 'console.log("entry");\n',
    },
    {
      fileName: 'assets/chunk-bbb.js',
      kind: 'chunk',
      isEntry: false,
      text: 'export const answer = 42;\n',
    },
    {
      fileName: 'assets/style-ccc.css',
      kind: 'asset',
      isEntry: false,
      bytes: new TextEncoder().encode('body { color: red }\n'),
    },
    {
      fileName: 'assets/index-aaa.js.map',
      kind: 'asset',
      isEntry: false,
      bytes: new TextEncoder().encode('{}'),
    },
  ]
}

/** Fetch mock serving in-memory build output bytes by URL suffix. */
export function distFetch(files: Map<string, Uint8Array>) {
  return async (url: string): Promise<{
    ok: boolean
    status: number
    arrayBuffer: () => Promise<ArrayBuffer>
  }> => {
    for (const [name, bytes] of files) {
      if (url === name || url.endsWith(`/${name}`) || url.endsWith(name)) {
        const copy = new Uint8Array(bytes)
        return {
          ok: true,
          status: 200,
          arrayBuffer: async () => copy.buffer as ArrayBuffer,
        }
      }
    }
    return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) }
  }
}
