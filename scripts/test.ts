import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

// The namespace has only loopback and no default route. It covers every test
// descendant, including installed CLIs and workers that discard ambient env.
if (process.argv[2] !== '--isolated') {
  // Keep the installed fixture outside /tmp, which is replaced inside the namespace.
  const root = mkdtempSync(join(homedir(), '.ssh-axi-test-'))
  let status = 1
  try {
    const { name, version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { name: string, version: string }
    const prefix = join(root, 'installed')
    mkdirSync(prefix)
    writeFileSync(join(prefix, 'package.json'), '{"private":true}')
    const tarball = join(root, `${name.replace('@', '').replace('/', '-')}-${version}.tgz`)
    const commands: [string, string[]][] = [
      [process.execPath, [process.env.npm_execpath!, 'pack', '--pack-destination', root]],
      [process.execPath, [process.env.npm_execpath!, '--dir', prefix, '--store-dir', join(root, 'store'), 'add', tarball]],
      ['unshare', ['-Urnm', '--', process.execPath, fileURLToPath(import.meta.url), '--isolated']],
    ]
    for (const [command, args] of commands) {
      const result = spawnSync(command, args, { stdio: 'inherit', env: { ...process.env, SSH_AXI_TEST_PREFIX: prefix } })
      if (result.error) throw result.error
      status = result.status ?? 1
      if (status !== 0) break
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
  process.exit(status)
}
const loopback = spawnSync('ip', ['link', 'set', 'lo', 'up'], { stdio: 'inherit' })
if (loopback.status !== 0) process.exit(1)
const privateTmp = spawnSync('mount', ['-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], { stdio: 'inherit' })
if (privateTmp.status !== 0) process.exit(1)
const tests = spawnSync(process.execPath, ['--test', 'test/native.test.ts', 'test/authentication.test.ts', 'test/execution.test.ts', 'test/artium.test.ts'], { stdio: 'inherit' })
process.exit(tests.status ?? 1)
