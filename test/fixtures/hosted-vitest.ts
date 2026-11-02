import { readFileSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'

const args = process.argv.slice(2)
if (args[0] !== 'exec') {
  const manager = process.env.SSH_AXI_TEST_PNPM!
  const result = spawnSync(process.execPath, [manager, ...args], { stdio: 'inherit', env: { ...process.env, npm_execpath: manager } })
  process.exit(result.status ?? 1)
}
if (args[1] !== 'vitest' || args[2] !== 'run') throw new Error('Expected a Vitest suite invocation.')
const suites = args.slice(3, args.indexOf('--reporter=json'))
const testResults = suites.map(suite => {
  const names = JSON.parse(readFileSync(suite, 'utf8')) as string[]
  return { assertionResults: names.map(fullName => ({ fullName, status: 'passed' })) }
})
writeFileSync(args[args.indexOf('--outputFile') + 1]!, JSON.stringify({ testResults }))
