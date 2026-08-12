import { guardedFn } from '@copylocker/guard'
import { compute } from './lib.js'

export const expensive = guardedFn('app.expensive', (n) => {
  let total = 0
  for (let i = 0; i < n; i += 1) total += i
  return total
})

export async function main() {
  const lazy = await import('./lazy.js')
  return compute(20) + expensive(3) + lazy.answer
}

main()
