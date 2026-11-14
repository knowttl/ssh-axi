import { test } from 'node:test'
import assert from 'node:assert/strict'
import childProcess, { type ChildProcess, type ForkOptions } from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { EventEmitter } from 'node:events'
import { join } from 'node:path'
import { execute, type ExecutionSettings } from '../dist/authenticate.js'
import type { Profile } from '../dist/profile.js'
import { executeCommand } from '../dist/doctor.js'
import { executeNative } from '../dist/native-execution.js'
import { parseArguments } from '../dist/arguments.js'
import { configuration, peer, privateKey, passphrase, run, temporary } from './support.ts'

process.env.TEST_PRIVATE_KEY = privateKey
process.env.TEST_PASSPHRASE = passphrase
const settings = { command: 'fixture', timeout: 1, outputLimit: 1024 }
const workerResult = { address: '127.0.0.1', outcome: 'completed', remoteExit: 0, remoteSignal: null,
  termination: 'remote-exit', durationMs: 0,
  stdout: { text: '', receivedBytes: 0, retainedBytes: 0, truncated: false, encodingLoss: false, withheld: false, unit: 'bytes' },
  stderr: { text: '', receivedBytes: 0, retainedBytes: 0, truncated: false, encodingLoss: false, withheld: false, unit: 'bytes' } }

for (const [name, value] of [['privateKey', Buffer.from(privateKey).toString('base64')], ['passphrase', passphrase]] as const) {
  for (const [site, invoke] of [
    ['transport admission', execute], ['supervisor admission', executeCommand],
    ['native admission', (profile: Profile, options: ExecutionSettings) => executeNative('fixture', profile,
      parseArguments(['exec', 'fixture', '--command', options.command, '--confirm']))],
  ] as const) test(`${site} refuses ${name} before dispatch`, async () => {
    const server = await peer()
    try {
      await assert.rejects(() => invoke(server.profile, { ...settings, command: `echo ${value}` }), { code: 'SECRET_IN_COMMAND' })
      assert.equal(server.observations.transports, 0)
    } finally { await server.close() }
  })

  test(`worker output withholds ${name}`, async () => {
    const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
      stream.write(value); stream.stderr.write('public'); stream.exit(0); stream.end()
    })
    try {
      const result = await executeCommand(server.profile, settings)
      assert.equal(result.outcome, 'failed')
      assert.equal(result.stdout.text, '')
      assert.equal(result.stderr.text, '')
      assert.equal(result.diagnostic, 'Protected output withheld.')
    } finally { await server.close() }
  })

  test(`parent boundary rejects ${name} in a worker result`, async t => {
    const server = await peer()
    t.mock.method(childProcess, 'fork', () => {
      const worker = new EventEmitter()
      return Object.assign(worker, { connected: true, kill: () => true, send: () => {
        queueMicrotask(() => {
          worker.emit('message', { ok: true, result: { ...workerResult, outcome: 'failed', diagnostic: value } })
          worker.emit('exit', 0)
        })
      } }) as unknown as ChildProcess
    })
    syncBuiltinESMExports()
    try {
      await assert.rejects(() => executeCommand(server.profile, settings), { code: 'SECRET_IN_OUTPUT' })
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); await server.close() }
  })
}

test('auth status reports both sources without exposing either value', async () => {
  const server = await peer()
  const scratch = await temporary()
  try {
    const path = await configuration(scratch.root, { fixture: server.profile })
    const result = await run(process.execPath, [join('dist', 'main.js'), 'auth', 'status', '--profile', 'fixture', '--config', path, '--json'], process.env)
    assert.equal(result.code, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), { profile: 'fixture', privateKey: 'available', passphrase: 'available',
      privateKeySource: 'env:TEST_PRIVATE_KEY', passphraseSource: 'env:TEST_PASSPHRASE', network: 'not checked' })
    assert.equal(server.observations.transports, 0)
  } finally { await server.close(); await scratch.close() }
})

test('supervisor delivers both secrets only as numbered environment references', async t => {
  const server = await peer()
  let delivered: unknown
  let environment: NodeJS.ProcessEnv | undefined
  t.mock.method(childProcess, 'fork', (_path: URL, _args: string[], options: ForkOptions) => {
    environment = options.env
    const worker = new EventEmitter()
    return Object.assign(worker, { connected: true, kill: () => true, send: (request: unknown) => {
      delivered = request
      queueMicrotask(() => { worker.emit('message', { ok: true, result: workerResult }); worker.emit('exit', 0) })
    } }) as unknown as ChildProcess
  })
  syncBuiltinESMExports()
  try {
    await executeCommand(server.profile, settings)
    assert.equal(environment!.ARTIUM_SECRET_0, privateKey)
    assert.equal(environment!.ARTIUM_SECRET_1, passphrase)
    assert.deepEqual(delivered, { revision: 1, operation: 'exec', settings,
      profile: { ...server.profile, privateKey: { env: 'ARTIUM_SECRET_0' }, passphrase: { env: 'ARTIUM_SECRET_1' } } })
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); await server.close() }
})
