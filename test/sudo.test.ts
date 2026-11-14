import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { fork } from 'node:child_process'
import { once } from 'node:events'
import { executeCommand } from '../dist/doctor.js'
import { configuration, peer, temporary } from './support.ts'

const password = randomBytes(24).toString('hex')
process.env.TEST_SUDO_PASSWORD = password
const settings = { command: 'synthetic sudo command', timeout: 1, outputLimit: 65536 }

for (const mode of ['matching', 'absent', 'different', 'repeated', 'echoed', 'partial', 'denied', 'failed'] as const) {
  test(`sudo ${mode} prompt controls one password line through the execution worker`, async () => {
    let sudoPrompt = ''
    let input = ''
    const server = await peer(false, '127.0.0.1', 0, (command, stream) => {
      const markers = /^sudo -S -k -p (\S+) -- \/bin\/sh -c 'printf %s (\S+);/.exec(command)!
      sudoPrompt = markers[1]!
      const sudoSuccess = markers[2]!
      stream.on('data', (bytes: Buffer) => { input += String(bytes) })
      stream.on('end', () => {
        if (mode === 'repeated') stream.stderr.write(sudoPrompt)
        if (mode !== 'repeated' && mode !== 'denied') for (const character of sudoSuccess) stream.write(character)
        if (mode === 'echoed') stream.write(input)
        else stream.write('command output')
        stream.exit(['repeated', 'denied', 'failed'].includes(mode) ? 1 : 0); stream.end()
      })
      if (mode === 'absent' || mode === 'different' || mode === 'partial') {
        stream.stderr.write(mode === 'different' ? 'Password: ' : mode === 'partial' ? sudoPrompt.slice(0, -1) : '')
        stream.write('command output'); stream.exit(0); stream.end()
      } else {
        stream.stderr.write('before ')
        for (const character of sudoPrompt) stream.stderr.write(character)
        stream.stderr.write(' after')
      }
    }, context => {
      if (context.method === 'password' && context.password === password) context.accept()
      else context.reject()
    })
    const { privateKey: _key, passphrase: _phrase, ...host } = server.profile
    const profile = { ...host, password: { env: 'TEST_SUDO_PASSWORD' } }
    try {
      const pending = executeCommand(profile, { ...settings, sudoPassword: true })
      if (mode === 'repeated' || mode === 'denied') {
        await assert.rejects(pending, error => {
          assert.equal((error as { code: string }).code, 'SUDO_DENIED')
          assert.ok(!String(error).includes(password))
          return true
        })
      } else {
        const result = await pending
        assert.equal(result.outcome, mode === 'echoed' || mode === 'failed' ? 'failed' : 'completed')
        assert.equal(result.stdout.text, mode === 'echoed' ? '' : 'command output')
        assert.equal(result.stderr.text, mode === 'different' ? 'Password: ' : mode === 'partial' ? sudoPrompt.slice(0, -1) : mode === 'absent' || mode === 'echoed' ? '' : 'before  after')
        assert.ok(!JSON.stringify(result).includes(password))
      }
      assert.equal(input, ['matching', 'repeated', 'echoed', 'denied', 'failed'].includes(mode) ? `${password}\n` : '')
    } finally { await server.close() }
  })
}

test('connection worker answers each execution with its bound credential and a fresh nonce', async () => {
  const inputs: string[] = []
  const server = await peer(false, '127.0.0.1', 0, (command, stream) => {
    const markers = /^sudo -S -k -p (\S+) -- \/bin\/sh -c 'printf %s (\S+);/.exec(command)!
    const [, sudoPrompt, sudoSuccess] = markers
    let input = ''
    stream.on('data', (bytes: Buffer) => { input += String(bytes) })
    stream.on('end', () => {
      inputs.push(input); stream.write(sudoSuccess! + 'completed'); stream.exit(0); stream.end()
    })
    stream.stderr.write(sudoPrompt!)
  }, context => {
    if (context.method === 'password' && context.password === password) context.accept()
    else context.reject()
  })
  const isolated = await temporary()
  const { privateKey: _key, passphrase: _phrase, ...host } = server.profile
  const path = await configuration(isolated.root, { artium: { ...host, password: { env: 'TEST_SUDO_PASSWORD' } } })
  const child = fork(new URL('../dist/connection-worker.js', import.meta.url), [], {
    execArgv: [], env: { SSH_AXI_CONFIG: path, TEST_SUDO_PASSWORD: password }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  })
  let output = ''
  child.stdout!.on('data', bytes => { output += String(bytes) })
  child.stderr!.on('data', bytes => { output += String(bytes) })
  const request = async (operation: string, execution?: typeof settings & { sudoPassword: boolean }) => {
    const response = once(child, 'message')
    child.send({ revision: 2, id: operation, operation, ...(execution ? { settings: execution } : {}) })
    return (await response)[0]
  }
  try {
    assert.equal((await request('open')).ok, true)
    for (const _execution of [1, 2]) {
      const response = await request('exec', { ...settings, sudoPassword: true })
      assert.equal(response.ok, true)
      assert.equal(response.result.stdout.text, 'completed')
      assert.equal(response.result.stderr.text, '')
      assert.ok(!JSON.stringify(response).includes(password))
    }
    assert.deepEqual(inputs, [`${password}\n`, `${password}\n`])
    assert.equal(server.observations.transports, 1)
    const closed = once(child, 'exit')
    await request('close'); await closed
    assert.equal(output, '')
  } finally { child.kill('SIGKILL'); await server.close(); await isolated.close() }
})

test('short passwords work across repeated password sudo executions', async () => {
  process.env.TEST_SHORT_SUDO_PASSWORD = 'a'
  let inputs = 0
  const server = await peer(false, '127.0.0.1', 0, (command, stream) => {
    const [, prompt, success] = /^sudo -S -k -p (\S+) -- \/bin\/sh -c 'printf %s (\S+);/.exec(command)!
    let input = ''
    stream.on('data', (bytes: Buffer) => { input += String(bytes) })
    stream.on('end', () => {
      assert.equal(input, 'a\n')
      inputs++
      stream.write(success! + 'OK'); stream.exit(0); stream.end()
    })
    stream.stderr.write(prompt!)
  }, context => {
    if (context.method === 'password' && context.password === 'a') context.accept()
    else context.reject()
  })
  const { privateKey: _key, passphrase: _phrase, ...host } = server.profile
  try {
    for (let i = 0; i < 20; i++) {
      const result = await executeCommand({ ...host, password: { env: 'TEST_SHORT_SUDO_PASSWORD' } },
        { command: 'id', timeout: 2, outputLimit: 1024, sudoPassword: true })
      assert.equal(result.outcome, 'completed')
      assert.equal(result.stdout.text, 'OK')
    }
    assert.equal(inputs, 20)
  } finally { await server.close(); delete process.env.TEST_SHORT_SUDO_PASSWORD }
})

for (const repeated of [false, true]) test(`cancellation ignores a ${repeated ? 'repeated' : 'first'} sudo prompt`, async () => {
  let admitted!: () => void
  const dispatched = new Promise<void>(resolve => { admitted = resolve })
  let input = ''
  const server = await peer(false, '127.0.0.1', 0, (command, stream, session) => {
    const prompt = /^sudo -S -k -p (\S+) /.exec(command)![1]!
    stream.on('data', (bytes: Buffer) => { input += String(bytes) })
    stream.on('end', () => { if (repeated) admitted() })
    session.on('signal', () => { stream.stderr.write(prompt); stream.exit('TERM'); stream.end() })
    if (repeated) stream.stderr.write(prompt)
    else admitted()
  }, context => {
    if (context.method === 'password' && context.password === password) context.accept()
    else context.reject()
  })
  const { privateKey: _key, passphrase: _phrase, ...host } = server.profile
  const cancellation = new AbortController()
  try {
    const pending = executeCommand({ ...host, password: { env: 'TEST_SUDO_PASSWORD' } },
      { ...settings, sudoPassword: true }, cancellation.signal)
    await dispatched
    cancellation.abort()
    const result = await pending
    assert.equal(result.outcome, 'cancelled')
    assert.equal(input, repeated ? `${password}\n` : '')
  } finally { await server.close() }
})
