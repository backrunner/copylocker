import { copyFile, mkdir, readdir } from 'node:fs/promises'

const source = new URL('../../../crates/copylocker-tauri/guest-js/bindings/', import.meta.url)
const destination = new URL('../src/generated/', import.meta.url)

await mkdir(destination, { recursive: true })
const files = (await readdir(source)).filter((file) => file.endsWith('.ts')).sort()
for (const file of files) {
  await copyFile(new URL(file, source), new URL(file, destination))
}
