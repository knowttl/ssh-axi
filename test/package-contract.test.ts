import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { existsSync, readFileSync, realpathSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { test } from 'node:test'

// Published sources pinned by the admission inventory, without fixture hashes.
const modules = ['main', 'version', 'cli', 'arguments', 'profile', 'doctor', 'authenticate',
  'worker', 'connection-worker', 'hosted', 'errors', 'output', 'native-execution']
const documents = ['package.json', 'README.md', 'axi-credential.schema.json', 'artium-invocations.json',
  ...(existsSync(new URL('../LICENSE', import.meta.url)) ? ['LICENSE'] : [])]
const prefix = process.env.SSH_AXI_TEST_PREFIX!
const tarball = process.env.SSH_AXI_TEST_TARBALL!
const packageRoot = join(prefix, 'node_modules/@knowttl/ssh-axi')

test('packed package contains only the published contract and no local data', () => {
  const archive = spawnSync('tar', ['-tzf', tarball], { encoding: 'utf8' })
  assert.equal(archive.status, 0, archive.stderr)
  const files = archive.stdout.trim().split('\n').sort()
  const expected = [...documents, ...modules.flatMap(name => [`dist/${name}.js`, `dist/${name}.d.ts`])]
  assert.deepEqual(files, expected.map(file => `package/${file}`).sort())
  for (const file of expected) {
    const content = readFileSync(join(packageRoot, file), 'utf8')
    assert.doesNotMatch(content, /-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|\b(?:npm_[A-Za-z0-9]{36}|gh[pousr]_[A-Za-z0-9]{36})\b/)
    assert.doesNotMatch(content, /(?:file:\/\/|\/home\/|\/Users\/|[A-Z]:\\Users\\)/)
    assert.ok(!content.includes(process.cwd()), `${file} contains the checkout path`)
  }
})

test('offline installed bin exposes help and the package version', () => {
  const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
    name: string, version: string, bin: Record<string, string>
  }
  const local = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
  assert.equal(manifest.name, '@knowttl/ssh-axi')
  assert.equal(manifest.version, local.version)
  assert.deepEqual(manifest.bin, { 'ssh-axi': 'dist/main.js' })
  const bin = join(prefix, 'node_modules/.bin/ssh-axi')
  for (const flag of ['--help', '--version']) {
    const result = spawnSync(bin, [flag], { cwd: prefix, encoding: 'utf8', timeout: 5000,
      env: { ...process.env, XDG_CONFIG_HOME: join(prefix, 'config'), XDG_STATE_HOME: join(prefix, 'state') } })
    assert.equal(result.status, 0, result.stderr)
    if (flag === '--version') assert.equal(result.stdout.trim(), manifest.version)
    else assert.match(result.stdout, /ssh-axi/)
  }
})

test('installed admission entry points resolve inside the package', async () => {
  const require = createRequire(join(prefix, 'package.json'))
  for (const file of [...modules.map(name => `dist/${name}.js`), 'axi-credential.schema.json', 'artium-invocations.json']) {
    assert.equal(realpathSync(require.resolve(`@knowttl/ssh-axi/${file}`)), realpathSync(join(packageRoot, file)))
  }
  // Worker entry points require IPC and are resolved above rather than imported.
  const version = await import(pathToFileURL(require.resolve('@knowttl/ssh-axi/dist/version.js')).href) as { VERSION: string }
  const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as { version: string }
  assert.equal(version.VERSION, manifest.version)
})
