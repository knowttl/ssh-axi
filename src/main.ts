#!/usr/bin/env node
import { VERSION } from './version.js'
import { tryFastPath } from 'axi-sdk-js/fast-path'

if (!tryFastPath(process.argv.slice(2), { version: VERSION })) {
  const { main } = await import('./cli.js')
  await main(process.argv.slice(2))
}
