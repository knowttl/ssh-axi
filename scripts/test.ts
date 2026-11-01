import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

// The namespace has only loopback and no default route. It covers every test
// descendant, including installed CLIs and workers that discard ambient env.
if (process.argv[2] !== '--isolated') {
  const isolated = spawnSync('unshare', ['-Urnm', '--', process.execPath, fileURLToPath(import.meta.url), '--isolated', ...process.argv.slice(2)], { stdio: 'inherit' })
  process.exit(isolated.status ?? 1)
}
const loopback = spawnSync('ip', ['link', 'set', 'lo', 'up'], { stdio: 'inherit' })
if (loopback.status !== 0) process.exit(1)
const privateTmp = spawnSync('mount', ['-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], { stdio: 'inherit' })
if (privateTmp.status !== 0) process.exit(1)

{
  // Keep the package manager's store and installed fixture on the same filesystem.
  const root = mkdtempSync(join(homedir(), '.ssh-axi-test-'))
  let status = 1
  try {
    const { name, version, dependencies, devDependencies } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      name: string, version: string, dependencies: Record<string, string>, devDependencies: Record<string, string>
    }
    const prefix = join(root, 'installed')
    mkdirSync(prefix)
    writeFileSync(join(prefix, 'package.json'), JSON.stringify({ private: true, dependencies, devDependencies }))
    copyFileSync(new URL('../pnpm-lock.yaml', import.meta.url), join(prefix, 'pnpm-lock.yaml'))
    const tarball = join(root, `${name.replace('@', '').replace('/', '-')}-${version}.tgz`)
    const commands: [string, string[]][] = [
      [process.execPath, [process.env.npm_execpath!, 'pack', '--pack-destination', root]],
      [process.execPath, [process.env.npm_execpath!, '--dir', prefix, 'add', '--offline', '--prod', tarball]],
      [process.execPath, ['--test', ...(process.argv.length > 3 ? process.argv.slice(3) : ['test/package-contract.test.ts', 'test/native.test.ts', 'test/authentication.test.ts', 'test/execution.test.ts', 'test/artium.test.ts'])]],
    ]
    for (const [command, args] of commands) {
      const result = spawnSync(command, args, { stdio: 'inherit', env: { ...process.env, SSH_AXI_TEST_PREFIX: prefix, SSH_AXI_TEST_TARBALL: tarball } })
      if (result.error) throw result.error
      status = result.status ?? 1
      if (status !== 0) break
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
  process.exit(status)
}
