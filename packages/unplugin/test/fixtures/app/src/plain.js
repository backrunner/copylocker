import { compute } from './lib.js'

export async function main() {
  const lazy = await import('./lazy.js')
  return compute(20) + lazy.answer
}

main()
