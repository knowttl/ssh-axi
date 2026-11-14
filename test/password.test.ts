import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import childProcess, { type ChildProcess, type ForkOptions } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { syncBuiltinESMExports } from 'node:module'
import { copyFile, mkdir, symlink, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { authenticate, execute } from '../dist/authenticate.js'
import { doctor, executeCommand } from '../dist/doctor.js'
import { validateProfile } from '../dist/profile.js'
import { configuration, peer, run, temporary } from './support.ts'

const password = randomBytes(24).toString('hex')
process.env.TEST_PASSWORD = password
process.env.TEST_EMPTY_PASSWORD = ''
process.env.TEST_SHORT_PASSWORD = 'a'

async function passwordPeer(mode = 'password') {
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.write(mode === 'short' ? 'public' : password); stream.exit(0); stream.end()
  }, context => {
    if (context.method === 'password' && mode === 'expired') context.requestChange('untrusted prompt', () => context.reject())
    else if (context.method === 'password' && mode === 'password' && context.password === password) context.accept()
    else if (context.method === 'password' && mode === 'empty' && context.password === '') context.accept()
    else if (context.method === 'password' && mode === 'short' && context.password === 'a') context.accept()
    else if (context.method === 'keyboard-interactive' && mode !== 'password') {
      if (mode === 'zero-only') { context.prompt([], () => context.accept()); return }
      if (mode === 'zero-hidden') {
        context.prompt([], () => context.prompt([{ prompt: 'password', echo: false }], answers => {
          if (answers[0] === password) context.accept()
          else context.reject()
        }))
        return
      }
      if (mode === 'repeated') {
        context.prompt([{ prompt: 'password', echo: false }], () => {
          context.prompt([{ prompt: 'again', echo: false }], () => context.accept())
        })
        return
      }
      const prompts = mode === 'multiple' ? [{ prompt: 'first', echo: false }, { prompt: 'second', echo: false }]
        : [{ prompt: 'password', echo: mode === 'echo' }]
      context.prompt(prompts, answers => {
        if (mode === 'hidden' && answers.length === 1 && answers[0] === password) context.accept()
        else context.reject()
      })
    } else context.reject(['password', 'keyboard-interactive'])
  })
  const { privateKey: _key, passphrase: _phrase, ...endpoint } = server.profile
  return { ...server, profile: { ...endpoint, password: { env: mode === 'empty' ? 'TEST_EMPTY_PASSWORD' : mode === 'short' ? 'TEST_SHORT_PASSWORD' : 'TEST_PASSWORD' } } }
}

test('one-character password permits safe doctor and execution results', async () => {
  const server = await passwordPeer('short')
  try {
    assert.deepEqual(await doctor(server.profile), { authenticated: true, address: '127.0.0.1' })
    const result = await executeCommand(server.profile, { command: 'fixture', timeout: 1, outputLimit: 1024 })
    assert.equal(result.outcome, 'completed')
    assert.equal(result.stdout.text, 'public')
  } finally { await server.close() }
})

for (const mode of ['password', 'empty', 'hidden', 'zero-hidden']) test(`${mode} authentication succeeds through the private worker`, async () => {
  const server = await passwordPeer(mode)
  try {
    assert.deepEqual(await doctor(server.profile), { authenticated: true, address: '127.0.0.1' })
    assert.equal(server.observations.commands, 0)
  } finally { await server.close() }
})

for (const mode of ['multiple', 'echo', 'zero-only', 'repeated']) test(`${mode} keyboard-interactive prompts fail closed`, async () => {
  const server = await passwordPeer(mode)
  try { await assert.rejects(() => doctor(server.profile), { code: 'AUTH_FAILED', message: 'SSH authentication failed; check the selected credential.' }) }
  finally { await server.close() }
})

for (const [source, code] of [
  ['const secrets = [password]', 1],
  ['const secrets = [profile.password, profile.privateKey]', 1],
  ['const secrets = ["password", "privateKey"]', 1],
  ['const methods: ssh2.AuthenticationType[] = [password]', 1],
  ['const methods: ssh2.AuthenticationType[] = ["password", "keyboard-interactive"]', 0],
] as const) test(`secret-list guard validates seeded source: ${source}`, async () => {
  const scratch = await temporary()
  try {
    await mkdir(join(scratch.root, 'scripts'))
    await mkdir(join(scratch.root, 'src'))
    await copyFile(new URL('../scripts/profile-secrets.ts', import.meta.url), join(scratch.root, 'scripts', 'profile-secrets.ts'))
    await copyFile(new URL('../axi-credential.schema.json', import.meta.url), join(scratch.root, 'axi-credential.schema.json'))
    await symlink(fileURLToPath(new URL('../node_modules', import.meta.url)), join(scratch.root, 'node_modules'))
    await writeFile(join(scratch.root, 'src', 'seed.ts'), source)
    const result = await run(process.execPath, [join(scratch.root, 'scripts', 'profile-secrets.ts')], process.env)
    assert.equal(result.code, code, result.stderr)
  } finally { await scratch.close() }
})

test('expired password returns a fixed diagnostic', async () => {
  const server = await passwordPeer('expired')
  try {
    await assert.rejects(() => doctor(server.profile), { code: 'PASSWORD_EXPIRED', message: 'The SSH password must be changed before authentication.' })
  } finally { await server.close() }
})

test('wrong password fails without exposing the credential', async () => {
  const server = await passwordPeer()
  const wrong = randomBytes(24).toString('hex')
  process.env.TEST_WRONG_PASSWORD = wrong
  try {
    await assert.rejects(() => doctor({ ...server.profile, password: { env: 'TEST_WRONG_PASSWORD' } }), error => {
      assert.equal((error as { code: string }).code, 'AUTH_FAILED')
      assert.equal((error as Error).message, 'SSH authentication failed; check the selected credential.')
      assert.equal(JSON.stringify(error).includes(wrong), false)
      return true
    })
  } finally { delete process.env.TEST_WRONG_PASSWORD; await server.close() }
})

test('an unpinned host receives no authentication request', async () => {
  const server = await passwordPeer()
  try {
    await assert.rejects(() => authenticate({ ...server.profile, approvedHostKeys: ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs'] }), { code: 'TRUST_FAILED' })
    await server.disconnected
    assert.equal(server.observations.auth, 0)
  } finally { await server.close() }
})

test('password command admission refuses dispatch at both boundaries', async () => {
  const server = await passwordPeer()
  try {
    for (const invoke of [execute, executeCommand]) {
      await assert.rejects(() => invoke(server.profile, { command: `echo ${password}`, timeout: 1, outputLimit: 1024 }), { code: 'SECRET_IN_COMMAND' })
    }
    assert.equal(server.observations.transports, 0)
  } finally { await server.close() }
})

test('native --command refuses a password without exposing it or opening a transport', async () => {
  const server = await passwordPeer()
  const scratch = await temporary()
  try {
    const path = await configuration(scratch.root, { fixture: server.profile })
    const result = await run(process.execPath, [join('dist', 'main.js'), 'exec', 'fixture', '--command', `echo ${password}`, '--confirm', '--config', path, '--json'], process.env)
    assert.equal(result.code, 1)
    assert.equal(JSON.parse(result.stdout).error.code, 'SECRET_IN_COMMAND')
    assert.equal((result.stdout + result.stderr).includes(password), false)
    assert.equal(server.observations.transports, 0)
  } finally { await scratch.close(); await server.close() }
})

test('supervisor delivers password only in worker environment', async t => {
  const server = await passwordPeer()
  let request: unknown
  let environment: NodeJS.ProcessEnv | undefined
  let argumentsPassed: string[] | undefined
  t.mock.method(childProcess, 'fork', (_path: URL, args: string[], options: ForkOptions) => {
    environment = options.env
    argumentsPassed = args
    const worker = new EventEmitter()
    return Object.assign(worker, { connected: true, kill: () => true, send: (value: unknown) => {
      request = value
      queueMicrotask(() => {
        worker.emit('message', { ok: true, result: { authenticated: true, address: '127.0.0.1' } })
        worker.emit('exit', 0)
      })
    } }) as unknown as ChildProcess
  })
  syncBuiltinESMExports()
  try {
    await doctor(server.profile)
    assert.deepEqual(argumentsPassed, [])
    assert.equal(environment!.ARTIUM_SECRET_0, password)
    assert.deepEqual(request, { revision: 1, operation: 'doctor', profile: { ...server.profile, password: { env: 'ARTIUM_SECRET_0' } } })
    assert.equal(JSON.stringify(request).includes(password), false)
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); await server.close() }
})

test('password echoed by a remote command is withheld', async () => {
  const server = await passwordPeer()
  try {
    const result = await executeCommand(server.profile, { command: 'fixture', timeout: 1, outputLimit: 1024 })
    assert.equal(result.outcome, 'failed')
    assert.equal(result.stdout.text, '')
    assert.equal(result.stdout.withheld, true)
    assert.equal(JSON.stringify(result).includes(password), false)
  } finally { await server.close() }
})

test('password status reports availability and source offline', async () => {
  const server = await passwordPeer()
  const scratch = await temporary()
  try {
    const path = await configuration(scratch.root, { fixture: server.profile })
    for (const available of [true, false]) {
      const env = { ...process.env }
      if (!available) delete env.TEST_PASSWORD
      const result = await run(process.execPath, [join('dist', 'main.js'), 'auth', 'status', '--profile', 'fixture', '--config', path, '--json'], env)
      assert.equal(result.code, 0, result.stderr)
      assert.deepEqual(JSON.parse(result.stdout), { profile: 'fixture', password: available ? 'available' : 'missing', passwordSource: 'env:TEST_PASSWORD', network: 'not checked' })
    }
    assert.equal(server.observations.transports, 0)
  } finally { await scratch.close(); await server.close() }
})

test('empty key and password status reflect authentication availability', async () => {
  const server = await passwordPeer()
  const scratch = await temporary()
  try {
    const empty = join(scratch.root, 'empty')
    await writeFile(empty, '', { mode: 0o600 })
    const key = { ...server.profile, password: undefined, privateKey: { env: 'TEST_EMPTY_PASSWORD' } }
    const path = await configuration(scratch.root, { key, keyfile: { ...key, privateKey: { file: empty } },
      password: { ...server.profile, password: { env: 'TEST_EMPTY_PASSWORD' } }, passwordfile: { ...server.profile, password: { file: empty } } })
    for (const [profile, field, expected] of [['key', 'privateKey', 'missing'], ['keyfile', 'privateKey', 'missing'],
      ['password', 'password', 'available'], ['passwordfile', 'password', 'available']] as const) {
      const result = await run(process.execPath, [join('dist', 'main.js'), 'auth', 'status', '--profile', profile, '--config', path, '--json'], process.env)
      assert.equal(result.code, 0, result.stderr)
      assert.equal(JSON.parse(result.stdout)[field], expected)
    }
  } finally { await scratch.close(); await server.close() }
})

test('credential schema requires exactly one referenced authentication method', async () => {
  const server = await passwordPeer()
  try {
    assert.deepEqual(validateProfile(server.profile), server.profile)
    for (const invalid of [
      { ...server.profile, privateKey: { env: 'KEY' } },
      { ...server.profile, passphrase: { env: 'PHRASE' } },
      { ...server.profile, password },
      { ...server.profile, password: undefined },
    ]) assert.throws(() => validateProfile(invalid), { code: 'CONFIG_INVALID' })
  } finally { await server.close() }
})

test('native environment profile selects SSH_AXI_PASSWORD', async () => {
  const server = await passwordPeer()
  const scratch = await temporary()
  try {
    const env = { ...process.env, SSH_AXI_ADDRESS: server.profile.address, SSH_AXI_PORT: String(server.profile.port),
      SSH_AXI_USERNAME: server.profile.username, SSH_AXI_APPROVED_HOST_KEYS: JSON.stringify(server.profile.approvedHostKeys),
      SSH_AXI_ALLOWED_ADDRESSES: JSON.stringify(server.profile.allowedAddresses), SSH_AXI_PASSWORD: password }
    const result = await run(process.execPath, [join('dist', 'main.js'), 'auth', 'status', '--config', join(scratch.root, 'missing'), '--json'], env)
    assert.equal(result.code, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), { profile: 'env', password: 'available', passwordSource: 'env:SSH_AXI_PASSWORD', network: 'not checked' })
    assert.equal(server.observations.transports, 0)
  } finally { await scratch.close(); await server.close() }
})
