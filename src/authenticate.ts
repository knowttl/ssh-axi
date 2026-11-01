import { lookup } from 'node:dns/promises'
import { BlockList, isIP, connect, type Socket } from 'node:net'
import ssh2 from 'ssh2'
import { SshError } from './errors.js'
import { resolveSecret, type Profile } from './profile.js'
import { checkCommand, Output, secretPatterns } from './output.js'

export const AUTHENTICATION_DEADLINE_MS = 15_000
export interface ExecutionSettings { command: string, timeout: number, outputLimit: number }
export interface ExecutionResult {
  address: string
  outcome: 'completed' | 'failed' | 'cancelled' | 'timed_out' | 'unknown'
  remoteExit: number | null
  remoteSignal: string | null
  termination: 'remote-exit' | 'unknown'
  stdout: ReturnType<Output['finish']>
  stderr: ReturnType<Output['finish']>
  durationMs: number
  diagnostic?: string
}

export async function authenticate(profile: Profile): Promise<{ authenticated: true, address: string }> {
  const connection = await openTransport(profile)
  await connection.close()
  return { authenticated: true, address: connection.address }
}

export async function execute(profile: Profile, settings: ExecutionSettings, signal?: AbortSignal): Promise<ExecutionResult> {
  validateSettings(settings)
  checkCommand(settings.command, [resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!, resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false) ?? ''])
  const started = performance.now()
  const connection = await openTransport(profile, signal)
  try { return { ...await connection.execute(settings, signal), durationMs: Math.round(performance.now() - started) } }
  finally { await connection.close() }
}

function validateSettings(settings: ExecutionSettings) {
  if (!Number.isInteger(settings.timeout) || settings.timeout < 1 || settings.timeout > 600
    || !Number.isInteger(settings.outputLimit) || settings.outputLimit < 0 || settings.outputLimit > 1024 * 1024) {
    throw new SshError('USAGE', 'Timeout must be 1-600 seconds and output limit 0-1048576 bytes.', 2)
  }
}

// Each command starts a fresh channel. The private worker retains only the
// authenticated transport and its lifetime secret protection between commands.
export async function openTransport(profile: Profile, signal?: AbortSignal) {
  const passphrase = resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false)
  const privateKey = Buffer.from(resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!)
  const secrets = [privateKey.toString(), passphrase ?? '']
  const patterns = secretPatterns(secrets)
  const client = new ssh2.Client()
  let socket: Socket | undefined
  let closed = false
  let trusted = false
  let address = ''
  let active: (() => void) | undefined
  let closedResolve!: () => void
  const disconnected = new Promise<void>(resolve => { closedResolve = resolve })
  client.on('close', () => { closed = true; active?.(); closedResolve() })
  client.on('error', () => { closed = true; active?.() })
  const close = async () => {
    closed = true
    client.destroy(); socket?.destroy(); active?.()
    await disconnected
  }
  try {
    await new Promise<void>((resolve, reject) => {
      let finished = false
      const finish = (error?: SshError) => {
        if (finished) return
        finished = true
        clearTimeout(deadline)
        signal?.removeEventListener('abort', abort)
        client.off('error', failure); client.off('close', failure)
        if (error) { closed = true; client.destroy(); socket?.destroy(); reject(error) }
        else resolve()
      }
      const failure = () => finish(new SshError(trusted ? 'AUTH_FAILED' : 'TRUST_FAILED',
        trusted ? 'SSH key authentication failed; check the selected key and passphrase.' : 'SSH host trust could not be established.'))
      const abort = () => finish(new SshError('COMMAND_CANCELLED', 'Connection cancelled before dispatch.'))
      const deadline = setTimeout(() => finish(new SshError('AUTH_TIMEOUT', 'SSH authentication exceeded 15 seconds.')), AUTHENTICATION_DEADLINE_MS)
      client.once('ready', () => finish())
      client.once('error', failure); client.once('close', failure)
      signal?.addEventListener('abort', abort, { once: true })
      if (signal?.aborted) { abort(); return }
      void (async () => {
        const addresses = isIP(profile.address) ? [{ address: profile.address, family: isIP(profile.address) }]
          : await lookup(profile.address, { all: true, verbatim: true })
        if (finished) return
        const allowed = new BlockList()
        for (const value of profile.allowedAddresses) allowed.addAddress(value, isIP(value) === 6 ? 'ipv6' : 'ipv4')
        if (!addresses.length || addresses.some(value => !allowed.check(value.address, value.family === 6 ? 'ipv6' : 'ipv4'))) {
          finish(new SshError('ADDRESS_DENIED', 'The resolved endpoint is outside the approved address set.')); return
        }
        address = addresses[0]!.address
        socket = connect({ host: address, port: profile.port, family: addresses[0]!.family })
        socket.on('error', () => finish(new SshError('CONNECTION_FAILED', 'Cannot connect to the approved SSH endpoint.')))
        client.connect({ sock: socket, username: profile.username, privateKey,
          ...(passphrase === undefined ? {} : { passphrase }), readyTimeout: AUTHENTICATION_DEADLINE_MS,
          authHandler: ['publickey'], hostVerifier: (key: Buffer) => {
            trusted = profile.approvedHostKeys.some(value => Buffer.from(value.split(' ')[1]!, 'base64').equals(key))
            return trusted
          } })
      })().catch(() => finish(new SshError('AUTH_FAILED', 'Cannot authenticate with the selected endpoint and encrypted key.')))
    })
  } finally { privateKey.fill(0) }

  return { address, disconnected, close,
    execute(settings: ExecutionSettings, signal?: AbortSignal): Promise<ExecutionResult> {
      if (closed) throw new SshError('CONNECTION_CLOSED', 'The connection is closed. Open a new connection explicitly.')
      if (active) throw new SshError('CONNECTION_BUSY', 'A command is already active on this connection.')
      validateSettings(settings)
      checkCommand(settings.command, secrets)
      if (signal?.aborted) throw new SshError('COMMAND_CANCELLED', 'Execution cancelled before dispatch.')
      return new Promise(resolve => {
        let finished = false
        let channel: ssh2.ClientChannel | undefined
        let remoteExit: number | null = null
        let remoteSignal: string | null = null
        let outcome: ExecutionResult['outcome'] = 'unknown'
        let diagnostic: string | undefined
        let grace: NodeJS.Timeout | undefined
        const started = performance.now()
        const stdout = new Output(patterns, settings.outputLimit)
        const stderr = new Output(patterns, settings.outputLimit)
        const finish = () => {
          if (finished) return
          finished = true
          clearTimeout(deadline); clearTimeout(grace)
          signal?.removeEventListener('abort', abort)
          active = undefined
          const streams = { stdout: stdout.finish(), stderr: stderr.finish() }
          if (streams.stdout.withheld || streams.stderr.withheld) {
            for (const stream of Object.values(streams)) { stream.text = ''; stream.retainedBytes = 0; stream.withheld = true }
            diagnostic = 'Protected output withheld.'
            if (outcome === 'completed') outcome = 'failed'
          }
          resolve({ address, outcome, remoteExit, remoteSignal,
            termination: remoteExit !== null || remoteSignal !== null ? 'remote-exit' : 'unknown',
            ...streams, durationMs: Math.round(performance.now() - started), ...(diagnostic ? { diagnostic } : {}) })
        }
        const terminate = () => {
          if (!channel) return
          // ssh2's public signal() refuses after stdin EOF; SSH still permits
          // channel requests until close. The pinned transport keeps stdin closed.
          const transport = channel as ssh2.ClientChannel & { outgoing: { id: number, state: string },
            _client: { _protocol: { signal(channel: number, name: string): void } } }
          if (['open', 'eof'].includes(transport.outgoing.state)) transport._client._protocol.signal(transport.outgoing.id, 'TERM')
        }
        const cancel = (reason: ExecutionResult['outcome'], message?: string) => {
          if (finished || grace) return
          outcome = reason; diagnostic = message
          terminate()
          grace = setTimeout(() => { channel?.close(); void close(); finish() }, 200)
        }
        const abort = () => cancel('cancelled')
        const deadline = setTimeout(() => cancel('timed_out'), settings.timeout * 1000)
        active = finish
        signal?.addEventListener('abort', abort, { once: true })
        client.exec(settings.command, { pty: false }, (error, stream) => {
          if (finished) { stream?.destroy(); return }
          if (error) { outcome = 'failed'; finish(); return }
          channel = stream
          if (grace) terminate()
          const receive = (output: Output, bytes: Buffer) => {
            output.push(bytes)
            if (stdout.receivedBytes + stderr.receivedBytes > 16 * 1024 * 1024) cancel('unknown', 'Output flood limit exceeded; inspect remote state before retrying.')
          }
          stream.on('data', (bytes: Buffer) => receive(stdout, bytes))
          stream.stderr.on('data', (bytes: Buffer) => receive(stderr, bytes))
          stream.on('exit', (code: number | null, name?: string) => { remoteExit = typeof code === 'number' ? code : null; remoteSignal = name ?? null })
          stream.on('error', () => { void close(); finish() })
          stream.on('close', () => {
            if (!grace) outcome = remoteExit === 0 ? 'completed' : remoteExit !== null || remoteSignal ? 'failed' : 'unknown'
            finish()
          })
          stream.end()
        })
      })
    } }
}
