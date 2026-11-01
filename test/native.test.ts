import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { decode } from '@toon-format/toon'
import { temporary, run, configuration, peer, privateKey, passphrase, digest } from './support.ts'
import matrix from './fixtures/host-auth.json' with { type: 'json' }
import { fork } from 'node:child_process'
import type { ExecutionResult } from '../dist/authenticate.js'

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
  executable = join(prefix, 'node_modules', '.bin', 'ssh-axi')
})
after(() => scratch.close())
const cli = (args: string[], extra: NodeJS.ProcessEnv = {}) => run(executable, args, { ...environment, ...extra })

async function connectionWorker(profile: Parameters<typeof configuration>[1][string]) {
  const privateHome = await temporary()
  await configuration(privateHome.root, { artium: profile })
  const child = fork(join(prefix, 'node_modules/@knowttl/ssh-axi/dist/connection-worker.js'), [], {
    execArgv: [], env: { HOME: privateHome.root, XDG_CONFIG_HOME: join(privateHome.root, 'config'),
      TEST_PRIVATE_KEY: privateKey, TEST_PASSPHRASE: passphrase }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
  const exited = new Promise<void>(resolve => child.once('exit', () => resolve()))
  let sequence = 0
  const request = (operation: string, settings?: unknown) => new Promise<{ ok: boolean, result: Partial<ExecutionResult>, error?: { code: string } }>(resolve => {
    child.once('message', value => resolve(value as never))
    child.send({ revision: 2, id: String(++sequence), operation, ...(settings ? { settings } : {}) })
  })
  return { request, close: async () => { if (child.connected) await request('close'); await exited; await privateHome.close() } }
}

test('installed connection workers reuse separate transports and close only their own transport', async () => {
  const identities: number[] = []
  const server = await peer(false, '127.0.0.1', 0, (_command, stream, _session, id) => {
    identities.push(id); stream.write('fresh process\n'); stream.exit(0); stream.end()
  })
  const alice = await connectionWorker(server.profile)
  const bob = await connectionWorker(server.profile)
  const settings = { command: 'fixture:fresh', timeout: 60, outputLimit: 65536 }
  try {
    assert.equal((await alice.request('open')).ok, true)
    assert.equal((await bob.request('open')).ok, true)
    assert.equal((await alice.request('exec', settings)).result.outcome, 'completed')
    assert.equal((await alice.request('exec', settings)).result.stdout?.text, 'fresh process\n')
    await bob.request('exec', settings)
    await alice.close()
    await bob.request('exec', settings)
    assert.deepEqual(identities, [1, 1, 2, 2])
    assert.equal(server.observations.transports, 2)
  } finally { await bob.close(); await alice.close(); await server.close() }
})

test('installed connection worker protects secrets on a later command after idle reuse', async () => {
  const server = await peer(false, '127.0.0.1', 0, (command, stream) => {
    stream.write(command === 'fixture:later' ? Buffer.from(passphrase).toString('base64') : 'safe\n')
    stream.exit(0); stream.end()
  })
  const worker = await connectionWorker(server.profile)
  try {
    await worker.request('open')
    const settings = { command: 'fixture:first', timeout: 60, outputLimit: 65536 }
    assert.equal((await worker.request('exec', settings)).result.stdout?.text, 'safe\n')
    const result = await worker.request('exec', { ...settings, command: 'fixture:later' })
    assert.equal(result.result.stdout?.text, '')
    assert.equal(result.result.stdout?.withheld, true)
    assert.equal(result.result.outcome, 'failed')
    assert.equal(server.observations.transports, 1)
  } finally { await worker.close(); await server.close() }
})

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

test('installed exec preserves command bytes, separate streams and exit 7 without a local shell', async () => {
  const command = `printf '%s' 'quoted " value' | cat > /never-created-by-local-shell; exit 7`
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.write('remote stdout\n'); stream.stderr.write('remote stderr\n'); stream.exit(7); stream.end()
  })
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: server.profile })
    const result = await cli(['exec', 'fixture', '--command', command, '--confirm', '--config', path, '--json'], { XDG_STATE_HOME: isolated.root })
    assert.equal(result.code, 7, result.stdout + result.stderr)
    const value = JSON.parse(result.stdout)
    assert.equal(value.stdout.text, 'remote stdout\n')
    assert.equal(value.stderr.text, 'remote stderr\n')
    assert.equal(value.remoteExit, 7)
    assert.equal(value.outcome, 'failed')
    assert.deepEqual(server.observations.commandBytes, [command])
    const journal = await readFile(join(isolated.root, 'ssh-axi', 'writes.log'), 'utf8')
    assert.equal(JSON.parse(journal).command, command)
    assert.equal(JSON.parse(journal).id, value.id)
  } finally { await server.close(); await isolated.close() }
})

test('confirmation, read-only policy and secret command refusal occur before journal and transport', async () => {
  const server = await peer()
  const isolated = await temporary()
  try {
    const path = await configuration(isolated.root, { fixture: server.profile })
    const base = ['exec', 'fixture', '--config', path, '--json']
    const missing = await cli([...base, '--command', 'ls'], { XDG_STATE_HOME: isolated.root })
    assert.equal(JSON.parse(missing.stdout).error.code, 'CONFIRM_REQUIRED')
    const readOnly = await cli([...base, '--command', 'ls', '--confirm'], { XDG_STATE_HOME: isolated.root, SSH_AXI_READ_ONLY: 'true' })
    assert.equal(JSON.parse(readOnly.stdout).error.code, 'READ_ONLY')
    const secret = await cli([...base, '--command', `echo ${Buffer.from(passphrase).toString('base64')}`, '--confirm'], { XDG_STATE_HOME: isolated.root })
    assert.equal(JSON.parse(secret.stdout).error.code, 'SECRET_IN_COMMAND')
    assert.doesNotMatch(secret.stdout + secret.stderr, /CANARY/)
    assert.equal(server.observations.transports, 0)
    await assert.rejects(readFile(join(isolated.root, 'ssh-axi', 'writes.log')), { code: 'ENOENT' })
  } finally { await server.close(); await isolated.close() }
})
