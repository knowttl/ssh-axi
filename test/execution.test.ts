import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { join } from 'node:path'
import { execute } from '../dist/authenticate.js'
import { executeCommand } from '../dist/doctor.js'
import { configuration, peer, privateKey, passphrase, temporary } from './support.ts'

process.env.TEST_PRIVATE_KEY = privateKey
process.env.TEST_PASSPHRASE = passphrase
const settings = { command: 'synthetic command', timeout: 60, outputLimit: 65536 }

test('unused remote stdin reaches EOF while both output streams drain', async () => {
  let received = 0
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.on('data', (bytes: Buffer) => { received += bytes.length })
    stream.on('end', () => {
      stream.write(String(received)); stream.stderr.write('stdin closed'); stream.exit(0); stream.end()
    })
  })
  try {
    const result = await executeCommand(server.profile, { ...settings, timeout: 1 })
    assert.equal(result.outcome, 'completed')
    assert.equal(result.remoteExit, 0)
    assert.equal(result.stdout.text, '0')
    assert.equal(result.stderr.text, 'stdin closed')
  } finally { await server.close() }
})

test('process-group SIGINT after stdin EOF cancels native execution through the private worker', { timeout: 10000 }, async () => {
  let admitted!: () => void
  const dispatched = new Promise<void>(resolve => { admitted = resolve })
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.resume()
    stream.on('end', admitted)
  })
  const isolated = await temporary()
  const path = await configuration(isolated.root, { fixture: server.profile })
  const child = spawn(process.execPath, ['dist/main.js', 'exec', 'fixture', '--command', settings.command,
    '--confirm', '--config', path, '--json'], {
    detached: true,
    env: { ...process.env, XDG_STATE_HOME: isolated.root },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', chunk => { stdout += String(chunk) })
  child.stderr.on('data', chunk => { stderr += String(chunk) })
  const closed = once(child, 'close')
  try {
    await dispatched
    process.kill(-child.pid!, 'SIGINT')
    const [code, signal] = await closed
    assert.equal(signal, null, stderr)
    assert.equal(code, 1, stdout + stderr)
    const result = JSON.parse(stdout)
    assert.equal(result.outcome, 'cancelled')
    assert.equal(result.termination, 'unknown')
    assert.deepEqual(server.observations.signals, ['TERM'])
    assert.equal(server.observations.closed, 1)
  } finally { child.kill('SIGKILL'); await server.close(); await isolated.close() }
})

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

test('deadline after stdin EOF signals an ignoring peer then tears down locally with unknown termination', { timeout: 10000 }, async () => {
  let stdinClosed = false
  const server = await peer(false, '127.0.0.1', 0, (_command, stream) => {
    stream.resume()
    stream.on('end', () => { stdinClosed = true })
  })
  try {
    const result = await execute(server.profile, { ...settings, timeout: 1 })
    await server.disconnected
    assert.equal(stdinClosed, true)
    assert.equal(result.outcome, 'timed_out')
    assert.equal(result.termination, 'unknown')
    assert.equal(result.remoteExit, null)
    assert.deepEqual(server.observations.signals, ['TERM'])
    assert.equal(server.observations.closed, 1)
  } finally { await server.close() }
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

for (const [response, signal, termination] of [
  ['exit-signal', 'SIGTERM', 'remote-exit'], ['channel-loss', null, 'unknown'],
] as const) test(`cancellation reports honest certainty after remote ${response}`, async () => {
  let admitted!: () => void
  const dispatched = new Promise<void>(resolve => { admitted = resolve })
  const server = await peer(false, '127.0.0.1', 0, (_command, stream, session) => {
    session.on('signal', () => {
      if (response === 'exit-signal') stream.exit('TERM')
      stream.end()
    })
    admitted()
  })
  const cancellation = new AbortController()
  try {
    const pending = executeCommand(server.profile, settings, cancellation.signal)
    await dispatched
    cancellation.abort()
    const result = await pending
    assert.equal(result.outcome, 'cancelled')
    assert.equal(result.remoteExit, null)
    assert.equal(result.remoteSignal, signal)
    assert.equal(result.termination, termination)
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
