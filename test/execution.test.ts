import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execute } from '../dist/authenticate.js'
import { executeCommand } from '../dist/doctor.js'
import { peer, privateKey, passphrase } from './support.ts'

process.env.TEST_PRIVATE_KEY = privateKey
process.env.TEST_PASSPHRASE = passphrase
const settings = { command: 'synthetic command', timeout: 60, outputLimit: 65536 }

test('missing status is unknown and retained output remains capped while both streams drain', async () => {
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.write(Buffer.alloc(131072, 65)); stream.stderr.write(Buffer.alloc(131072, 66)); stream.end()
  })
  try {
    const result = await executeCommand(server.profile, { ...settings, outputLimit: 4096 })
    assert.equal(result.outcome, 'unknown')
    assert.equal(result.remoteExit, null)
    assert.equal(result.termination, 'unknown')
    assert.equal(result.stdout.text, 'A'.repeat(4096))
    assert.equal(result.stderr.text, 'B'.repeat(4096))
    assert.equal(result.stdout.receivedBytes, 131072)
    assert.equal(result.stderr.receivedBytes, 131072)
    assert.equal(result.stdout.truncated, true)
  } finally { await server.close() }
})

for (const [name, canary] of [
  ['raw', passphrase], ['encoded', Buffer.from(passphrase).toString('base64')],
  ['escaped', JSON.stringify(privateKey).slice(1, -1)], ['PEM', privateKey.split('\n')[0]!],
] as const) test(`split ${name} secret output is withheld even after retention fills`, async () => {
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.write('public prefix'.repeat(1000))
    for (const character of canary) stream.write(character)
    stream.stderr.write('also withheld'); stream.exit(0); stream.end()
  })
  try {
    const result = await executeCommand(server.profile, { ...settings, outputLimit: 32 })
    assert.equal(result.outcome, 'failed')
    assert.equal(result.stdout.text, '')
    assert.equal(result.stderr.text, '')
    assert.equal(result.diagnostic, 'Protected output withheld.')
    assert.ok(!JSON.stringify(result).includes(canary))
  } finally { await server.close() }
})

test('UTF-8 chunks decode together and invalid bytes and terminal controls are reported safely', async () => {
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.write(Buffer.from([0xe2])); stream.write(Buffer.from([0x82, 0xac, 0xff, 0x1b])); stream.write('[31m'); stream.exit(0); stream.end()
  })
  try {
    const result = await executeCommand(server.profile, settings)
    assert.equal(result.stdout.text, '€\uFFFD')
    assert.equal(result.stdout.encodingLoss, true)
    assert.equal(result.stdout.receivedBytes, 9)
  } finally { await server.close() }
})

test('deadline signals an ignoring peer then tears down locally with unknown termination', async context => {
  let admitted!: () => void
  const dispatched = new Promise<void>(resolve => { admitted = resolve })
  const server = await peer(false, '127.0.0.1', 0, () => admitted())
  context.mock.timers.enable({ apis: ['setTimeout'] })
  try {
    const pending = execute(server.profile, { ...settings, timeout: 1 })
    await dispatched
    context.mock.timers.tick(1000)
    await server.signalled
    context.mock.timers.tick(200)
    const result = await pending
    await server.disconnected
    assert.equal(result.outcome, 'timed_out')
    assert.equal(result.termination, 'unknown')
    assert.equal(result.remoteExit, null)
    assert.deepEqual(server.observations.signals, ['TERM'])
    assert.equal(server.observations.closed, 1)
  } finally { context.mock.timers.reset(); await server.close() }
})

test('explicit cancellation closes an ignoring peer and preserves non-success', async () => {
  let admitted!: () => void
  const dispatched = new Promise<void>(resolve => { admitted = resolve })
  const server = await peer(false, '127.0.0.1', 0, () => admitted())
  const cancellation = new AbortController()
  try {
    const pending = executeCommand(server.profile, settings, cancellation.signal)
    await dispatched
    cancellation.abort()
    const result = await pending
    assert.equal(result.outcome, 'cancelled')
    assert.equal(result.termination, 'unknown')
    assert.equal(result.remoteExit, null)
    assert.equal(server.observations.closed, 1)
  } finally { await server.close() }
})

test('a flooding peer is stopped after the combined received-byte threshold', async () => {
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    const block = Buffer.alloc(32768, 65)
    const pump = () => {
      while (!stream.destroyed && stream.write(block)) { /* Respect SSH backpressure. */ }
    }
    stream.on('drain', pump); stream.on('error', () => {}); pump()
  })
  try {
    const result = await executeCommand(server.profile, settings)
    assert.equal(result.outcome, 'unknown')
    assert.equal(result.termination, 'unknown')
    assert.equal(result.stdout.retainedBytes, 65536)
    assert.ok(result.stdout.receivedBytes > 16 * 1024 * 1024)
    assert.match(result.diagnostic!, /flood/)
  } finally { await server.close() }
})
