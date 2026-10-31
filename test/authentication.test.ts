import { test } from 'node:test'
import assert from 'node:assert/strict'
import { authenticate } from '../dist/authenticate.js'
import { peer, privateKey, passphrase } from './support.ts'
import dns from 'node:dns/promises'
import { syncBuiltinESMExports } from 'node:module'

test('a stalled peer is disconnected at the 15-second authentication deadline', async context => {
  process.env.TEST_PRIVATE_KEY = privateKey
  process.env.TEST_PASSPHRASE = passphrase
  const server = await peer(true)
  context.mock.timers.enable({ apis: ['setTimeout'] })
  try {
    const result = assert.rejects(authenticate(server.profile), { code: 'AUTH_TIMEOUT' })
    await server.authentication
    context.mock.timers.tick(15_000)
    await result
    await server.disconnected
    assert.equal(server.observations.commands, 0)
    assert.equal(server.observations.channels, 0)
    assert.equal(server.observations.closed, 1)
  } finally { context.mock.timers.reset(); await server.close() }
})

test('each new transport resolves again and dials exactly the validated address', async context => {
  process.env.TEST_PRIVATE_KEY = privateKey
  process.env.TEST_PASSPHRASE = passphrase
  const first = await peer()
  const second = await peer(false, '127.0.0.2', first.profile.port)
  const lookup = context.mock.method(dns, 'lookup', async () => [{ address: '127.0.0.1', family: 4 }])
  syncBuiltinESMExports()
  try {
    const profile = { ...first.profile, address: 'controlled.invalid', allowedAddresses: ['127.0.0.1', '127.0.0.2'] }
    await authenticate(profile)
    lookup.mock.mockImplementation(async () => [{ address: '127.0.0.2', family: 4 }])
    await authenticate(profile)
    await Promise.all([first.disconnected, second.disconnected])
    assert.equal(first.observations.transports, 1)
    assert.equal(second.observations.transports, 1)
    assert.equal(first.observations.commands + second.observations.commands, 0)
  } finally {
    lookup.mock.restore()
    syncBuiltinESMExports()
    await Promise.all([first.close(), second.close()])
  }
})
