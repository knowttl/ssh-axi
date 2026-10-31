#!/usr/bin/env node
import { VERSION } from './version.js'

if (process.argv.length === 3 && ['--version', '-v', '-V'].includes(process.argv[2]!)) {
  console.log(VERSION)
} else {
  const { main } = await import('./cli.js')
  await main(process.argv.slice(2))
}
