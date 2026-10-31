import { lookup } from 'node:dns/promises'
import { BlockList, isIP, connect, type Socket } from 'node:net'
import ssh2 from 'ssh2'
import { SshError } from './errors.js'
import { resolveSecret, type Profile } from './profile.js'
import { checkCommand, Output, secretPatterns } from './output.js'

export const AUTHENTICATION_DEADLINE_MS = 15_000

// Authentication and execution share the exact trust/address boundary and close
// the validated-address socket before returning. A probe never requests a channel.
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

export function authenticate(profile: Profile): Promise<{ authenticated: true, address: string }> {
  return transport(profile) as Promise<{ authenticated: true, address: string }>
}

export function execute(profile: Profile, settings: ExecutionSettings, signal?: AbortSignal): Promise<ExecutionResult> {
  if (!Number.isInteger(settings.timeout) || settings.timeout < 1 || settings.timeout > 600
    || !Number.isInteger(settings.outputLimit) || settings.outputLimit < 0 || settings.outputLimit > 1024 * 1024) {
    throw new SshError('USAGE', 'Timeout must be 1-600 seconds and output limit 0-1048576 bytes.', 2)
  }
  return transport(profile, settings, signal) as Promise<ExecutionResult>
}

async function transport(profile: Profile, settings?: ExecutionSettings, signal?: AbortSignal): Promise<unknown> {
  const privateKey = Buffer.from(resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!)
  try {
    const passphrase = resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false)
    const patterns = secretPatterns([privateKey.toString(), passphrase ?? ''])
    if (settings) checkCommand(settings.command, [privateKey.toString(), passphrase ?? ''])
    return await new Promise((resolve, reject) => {
      const client = new ssh2.Client()
      let socket: Socket | undefined
      let finished = false
      let trusted = false
      let selected = ''
      let channel: ssh2.ClientChannel | undefined
      let dispatched = false
      let remoteExit: number | null = null
      let remoteSignal: string | null = null
      let outcome: ExecutionResult['outcome'] = 'unknown'
      let diagnostic: string | undefined
      let commandDeadline: NodeJS.Timeout | undefined
      let grace: NodeJS.Timeout | undefined
      const started = performance.now()
      const stdout = new Output(patterns, settings?.outputLimit ?? 0)
      const stderr = new Output(patterns, settings?.outputLimit ?? 0)
      const cancel = (reason: 'cancelled' | 'timed_out' | 'unknown', message?: string) => {
        if (finished || grace) return
        outcome = reason
        diagnostic = message
        channel?.signal('TERM')
        grace = setTimeout(() => { channel?.close(); finish() }, 200)
      }
      const abort = () => cancel('cancelled')
      const finish = (error?: SshError) => {
        if (finished) return
        finished = true
        clearTimeout(deadline)
        clearTimeout(commandDeadline)
        clearTimeout(grace)
        signal?.removeEventListener('abort', abort)
        const complete = () => {
          if (!settings || !dispatched) {
            if (error) reject(error)
            else if (settings) reject(new SshError('COMMAND_CANCELLED', 'Execution cancelled before dispatch.'))
            else resolve({ authenticated: true, address: selected })
            return
          }
          const streams = { stdout: stdout.finish(), stderr: stderr.finish() }
          if (streams.stdout.withheld || streams.stderr.withheld) {
            streams.stdout.text = ''; streams.stderr.text = ''
            streams.stdout.retainedBytes = 0; streams.stderr.retainedBytes = 0
            streams.stdout.withheld = true; streams.stderr.withheld = true
            diagnostic = 'Protected output withheld.'
            if (outcome === 'completed') outcome = 'failed'
          }
          resolve({ address: selected, outcome, remoteExit, remoteSignal,
            termination: remoteExit !== null || remoteSignal !== null ? 'remote-exit' : 'unknown',
            ...streams, durationMs: Math.round(performance.now() - started),
            ...(diagnostic ? { diagnostic } : {}) })
        }
        if (socket && !socket.closed) {
          socket.once('close', complete)
          client.destroy()
          socket.destroy()
        } else { client.destroy(); complete() }
      }
      const deadline = setTimeout(() => finish(new SshError('AUTH_TIMEOUT', 'SSH authentication exceeded 15 seconds.')), AUTHENTICATION_DEADLINE_MS)
      client.on('ready', () => {
        clearTimeout(deadline)
        if (!settings) { finish(); return }
        if (signal?.aborted) { finish(); return }
        // ssh2 sends these exact bytes to the remote exec channel. No local shell.
        dispatched = true
        commandDeadline = setTimeout(() => cancel('timed_out'), settings.timeout * 1000)
        client.exec(settings.command, { pty: false }, (error, stream) => {
          if (finished) { stream?.destroy(); return }
          if (error) { outcome = 'failed'; finish(); return }
          channel = stream
          if (grace) stream.signal('TERM')
          const receive = (output: Output, bytes: Buffer) => {
            output.push(bytes)
            if (stdout.receivedBytes + stderr.receivedBytes > 16 * 1024 * 1024) cancel('unknown', 'Output flood limit exceeded; inspect remote state before retrying.')
          }
          stream.on('data', (bytes: Buffer) => receive(stdout, bytes))
          stream.stderr.on('data', (bytes: Buffer) => receive(stderr, bytes))
          stream.on('exit', (code: number | null, name?: string) => {
            remoteExit = typeof code === 'number' ? code : null
            remoteSignal = name ?? null
          })
          stream.on('error', () => finish())
          stream.on('close', () => {
            if (!grace) outcome = remoteExit === 0 ? 'completed' : remoteExit !== null || remoteSignal ? 'failed' : 'unknown'
            finish()
          })
        })
      })
      client.on('error', () => finish(new SshError(trusted ? 'AUTH_FAILED' : 'TRUST_FAILED',
        trusted ? 'SSH key authentication failed; check the selected key and passphrase.' : 'SSH host trust could not be established.')))
      client.on('close', () => finish(new SshError('AUTH_FAILED', 'SSH transport closed before authentication.')))
      signal?.addEventListener('abort', abort, { once: true })
      if (signal?.aborted) { finish(new SshError('COMMAND_CANCELLED', 'Execution cancelled before dispatch.')); return }
      void (async () => {
        const addresses = isIP(profile.address)
          ? [{ address: profile.address, family: isIP(profile.address) }]
          : await lookup(profile.address, { all: true, verbatim: true })
        if (finished) return
        const allowed = new BlockList()
        for (const address of profile.allowedAddresses) allowed.addAddress(address, isIP(address) === 6 ? 'ipv6' : 'ipv4')
        if (!addresses.length || addresses.some(({ address, family }) => !allowed.check(address, family === 6 ? 'ipv6' : 'ipv4'))) {
          finish(new SshError('ADDRESS_DENIED', 'The resolved endpoint is outside the approved address set.'))
          return
        }
        selected = addresses[0]!.address
        socket = connect({ host: selected, port: profile.port, family: addresses[0]!.family })
        socket.on('error', () => finish(new SshError('CONNECTION_FAILED', 'Cannot connect to the approved SSH endpoint.')))
        client.connect({ sock: socket, username: profile.username, privateKey,
          ...(passphrase === undefined ? {} : { passphrase }),
          readyTimeout: AUTHENTICATION_DEADLINE_MS,
          authHandler: ['publickey'],
          hostVerifier: (key: Buffer) => {
            trusted = profile.approvedHostKeys.some(approved => Buffer.from(approved.split(' ')[1]!, 'base64').equals(key))
            return trusted
          } })
      })().catch(() => finish(new SshError('AUTH_FAILED', 'Cannot authenticate with the selected endpoint and encrypted key.')))
    })
  } finally { privateKey.fill(0) }
}
