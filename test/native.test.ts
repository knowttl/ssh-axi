import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { decode } from '@toon-format/toon'
import { temporary, run, configuration, peer, privateKey, passphrase, digest } from './support.ts'
import matrix from './fixtures/host-auth.json' with { type: 'json' }

const scratch = await temporary()
const prefix = join(scratch.root, 'installed')
const pnpm = process.env.npm_execpath!
const environment = { PATH: process.env.PATH, HOME: scratch.root, XDG_CONFIG_HOME: join(scratch.root, 'config'),
  TMPDIR: join(scratch.root, 'tmp'), TEST_PRIVATE_KEY: privateKey, TEST_PASSPHRASE: passphrase }
let executable: string
before(async () => {
  await mkdir(environment.TMPDIR, { mode: 0o700 })
  const first = await run(process.execPath, [pnpm, 'pack', '--pack-destination', scratch.root], process.env, resolve('.'))
  assert.equal(first.code, 0, first.stderr)
  const tarball = join(scratch.root, 'knowttl-ssh-axi-0.1.0.tgz')
  const hash = digest(await readFile(tarball))
  const second = await run(process.execPath, [pnpm, 'pack', '--pack-destination', scratch.root], process.env, resolve('.'))
  assert.equal(second.code, 0, second.stderr)
  assert.equal(digest(await readFile(tarball)), hash, 'packing the same source must reproduce the artifact')
  await mkdir(prefix)
  await writeFile(join(prefix, 'package.json'), '{"private":true}')
  const install = await run(process.execPath, [pnpm, '--dir', prefix, '--store-dir', join(process.env.HOME!, '.local/share/pnpm/store'), 'add', '--offline', tarball], process.env)
  assert.equal(install.code, 0, install.stdout + install.stderr)
  executable = join(prefix, 'node_modules', '@knowttl', 'ssh-axi', 'dist', 'main.js')
})
after(() => scratch.close())
const cli = (args: string[], extra: NodeJS.ProcessEnv = {}) => run(process.execPath, [executable, ...args], { ...environment, ...extra })

test('an installed package discovers its offline empty state in both formats', async () => {
  const json = await cli(['host', 'list', '--json'])
  const toon = await cli(['host', 'list'])
  assert.equal(json.code, 0)
  assert.deepEqual(JSON.parse(json.stdout), decode(toon.stdout))
  assert.equal(JSON.parse(json.stdout).count, 0)
  assert.equal(JSON.parse(json.stdout).message, 'No configured hosts found.')
  assert.equal((await cli(['config', 'path', '--json'])).stdout,
    JSON.stringify({ path: join(environment.XDG_CONFIG_HOME, 'ssh-axi', 'config.json') }) + '\n')
})

test('unknown and internal flags fail before configuration is read', async () => {
  for (const flag of ['--unknown', '--private-key', '--host-key', '--user-id', '--worker', '--ipc', '--endpoint']) {
    const result = await cli(['doctor', 'fixture', flag, '--json'], { SSH_AXI_CONFIG: '/unreadable/config' })
    assert.equal(result.code, 2)
    assert.equal(JSON.parse(result.stdout).error.code, 'USAGE')
  }
})

test('host discovery opens no transport and hides secret and trust material', async () => {
  const server = await peer()
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: server.profile })
    const listed = await cli(['host', 'list', '--config', path, '--json'])
    const shown = await cli(['host', 'show', 'fixture', '--config', path, '--json'])
    assert.equal(listed.code, 0)
    assert.deepEqual(JSON.parse(listed.stdout).hosts, [JSON.parse(shown.stdout).host])
    assert.equal(server.observations.transports, 0)
    assert.doesNotMatch(listed.stdout + shown.stdout, /TEST_PRIVATE_KEY|approvedHostKeys|CANARY/)
  } finally { await server.close(); await isolated.close() }
})

test('an explicit file profile ignores competing endpoint environment fields', async () => {
  const server = await peer()
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: server.profile })
    const result = await cli(['auth', 'status', '--config', path, '--profile', 'fixture', '--json'], {
      SSH_AXI_ADDRESS: 'untrusted.invalid', SSH_AXI_PORT: 'invalid' })
    assert.equal(result.code, 0, result.stdout)
    assert.equal(JSON.parse(result.stdout).profile, 'fixture')
    assert.equal(server.observations.transports, 0)
    const partial = await cli(['auth', 'status', '--json'], { SSH_AXI_ADDRESS: '127.0.0.1' })
    assert.equal(partial.code, 1)
    assert.equal(JSON.parse(partial.stdout).error.code, 'CONFIG_INVALID')
  } finally { await server.close(); await isolated.close() }
})

test('inline secrets and unsafe secret files are refused without exposing values', async () => {
  const server = await peer()
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: server.profile })
    await writeFile(path, JSON.stringify({ version: 1, profiles: { fixture: { ...server.profile, privateKey } } }))
    const inline = await cli(['doctor', 'fixture', '--config', path, '--json'])
    assert.equal(JSON.parse(inline.stdout).error.code, 'CONFIG_INVALID')
    const keyPath = join(isolated.root, 'key.pem')
    await writeFile(keyPath, privateKey, { mode: 0o644 })
    await configuration(isolated.root, { fixture: { ...server.profile, privateKey: { file: keyPath } } })
    const insecure = await cli(['doctor', 'fixture', '--config', path, '--json'])
    assert.equal(JSON.parse(insecure.stdout).error.code, 'CONFIG_INSECURE')
    assert.equal(server.observations.transports, 0)
    assert.doesNotMatch(inline.stdout + inline.stderr + insecure.stdout + insecure.stderr, /CANARY|PRIVATE KEY/)
  } finally { await server.close(); await isolated.close() }
})

test('native doctor selects a complete environment profile without a host argument', async () => {
  const server = await peer()
  try {
    const result = await cli(['doctor', '--json'], {
      SSH_AXI_ADDRESS: server.profile.address, SSH_AXI_PORT: String(server.profile.port), SSH_AXI_USERNAME: server.profile.username,
      SSH_AXI_APPROVED_HOST_KEYS: JSON.stringify(server.profile.approvedHostKeys), SSH_AXI_ALLOWED_ADDRESSES: JSON.stringify(server.profile.allowedAddresses),
      SSH_AXI_PRIVATE_KEY: privateKey, SSH_AXI_PASSPHRASE: passphrase })
    assert.equal(result.code, 0, result.stdout)
    assert.equal(JSON.parse(result.stdout).host, 'env')
    assert.equal(JSON.parse(result.stdout).authenticated, true)
    assert.equal(server.observations.commands, 0)
  } finally { await server.close() }
})

for (const fixture of matrix) test(`installed doctor: ${fixture.case}`, async () => {
  const server = await peer()
  const profile = structuredClone(server.profile)
  const extra: NodeJS.ProcessEnv = {}
  if (fixture.case === 'unknown-key' || fixture.case === 'changed-key') {
    profile.approvedHostKeys = ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs']
  }
  if (fixture.case === 'disallowed-address') profile.allowedAddresses = ['192.0.2.1']
  if (fixture.case === 'missing-key') extra.TEST_PRIVATE_KEY = ''
  if (fixture.case === 'bad-passphrase') extra.TEST_PASSPHRASE = 'CANARY-wrong-passphrase'
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: profile })
    const result = await cli(['doctor', 'fixture', '--config', path, '--json'], extra)
    const value = JSON.parse(result.stdout)
    assert.equal(result.code, fixture.expected === 'authenticated' ? 0 : 1, result.stdout + result.stderr)
    if (fixture.expected === 'authenticated') assert.equal(value.authenticated, true)
    else assert.equal(value.error.code, fixture.expected, result.stdout)
    assert.equal(server.observations.auth > 0, fixture.credentialsSent)
    assert.equal(server.observations.channels, 0)
    assert.equal(server.observations.commands, 0)
    assert.equal(server.observations.closed, server.observations.transports)
    assert.deepEqual(await readdir(environment.TMPDIR), [])
    assert.doesNotMatch(result.stdout + result.stderr, /CANARY|PRIVATE KEY|TEST_PRIVATE_KEY/)
  } finally { await server.close(); await isolated.close() }
})
