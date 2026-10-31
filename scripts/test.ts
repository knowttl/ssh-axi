import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

// The namespace has only loopback and no default route. It covers every test
// descendant, including installed CLIs and workers that discard ambient env.
if (process.argv[2] !== '--isolated') {
  const result = spawnSync('unshare', ['-Urnm', '--', process.execPath, fileURLToPath(import.meta.url), '--isolated'], { stdio: 'inherit' })
  if (result.error) throw result.error
  process.exit(result.status ?? 1)
}
const loopback = spawnSync('ip', ['link', 'set', 'lo', 'up'], { stdio: 'inherit' })
if (loopback.status !== 0) process.exit(1)
const privateTmp = spawnSync('mount', ['-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], { stdio: 'inherit' })
if (privateTmp.status !== 0) process.exit(1)
const tests = spawnSync(process.execPath, ['--test', 'test/native.test.ts', 'test/authentication.test.ts', 'test/artium.test.ts'], { stdio: 'inherit' })
process.exit(tests.status ?? 1)
