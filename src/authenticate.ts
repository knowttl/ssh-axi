import { lookup } from 'node:dns/promises'
import { BlockList, isIP, connect, type Socket } from 'node:net'
import ssh2 from 'ssh2'
import { SshError } from './errors.js'
import { profileSecrets, type Profile } from './profile.js'
import { checkCommand, containsSecret, Output, secretPatterns } from './output.js'

export const AUTHENTICATION_DEADLINE_MS = 15_000
export const OUTPUT_WITHHELD = 'Protected output withheld.'
export const OUTPUT_FLOOD = 'Output flood limit exceeded; inspect remote state before retrying.'
export interface ExecutionSettings { command: string, timeout: number, outputLimit: number, sudoPrompt?: string, sudoSuccess?: string }
export interface ExecutionResult {
  address: string
  outcome: 'completed' | 'failed' | 'cancelled' | 'timed_out' | 'unknown'
  remoteExit: number | null
  remoteSignal: string | null
  termination: 'remote-exit' | 'deadline' | 'unknown'
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
  checkCommand(settings.command, profileSecrets(profile).map(secret => secret.value ?? ''))
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
  if (settings.sudoPrompt !== undefined || settings.sudoSuccess !== undefined) {
    if (typeof settings.sudoPrompt !== 'string' || typeof settings.sudoSuccess !== 'string'
      || !/^[A-Za-z0-9_-]{32,128}$/.test(settings.sudoPrompt) || !/^[A-Za-z0-9_-]{32,128}$/.test(settings.sudoSuccess)
      || settings.sudoPrompt === settings.sudoSuccess) {
      throw new SshError('USAGE', 'Sudo prompt and success markers must be distinct nonces of 32-128 ASCII letters, digits, underscores or hyphens.', 2)
    }
  }
}

// Each command starts a fresh channel. The private worker retains only the
// authenticated transport and its lifetime secret protection between commands.
export async function openTransport(profile: Profile, signal?: AbortSignal) {
  const resolved = profileSecrets(profile, 'passphrase')
  const passphrase = resolved.find(secret => secret.name === 'passphrase')?.value
  const key = resolved.find(secret => secret.name === 'privateKey')?.value
  const privateKey = key === undefined ? undefined : Buffer.from(key)
  const password = resolved.find(secret => secret.name === 'password')?.value
  const secrets = resolved.map(secret => secret.value ?? '')
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
        trusted ? 'SSH authentication failed; check the selected credential.' : 'SSH host trust could not be established.'))
      const abort = () => finish(new SshError('COMMAND_CANCELLED', 'Connection cancelled before dispatch.'))
      const deadline = setTimeout(() => finish(new SshError('AUTH_TIMEOUT', 'SSH authentication exceeded 15 seconds.')), AUTHENTICATION_DEADLINE_MS)
      let method: ssh2.AuthenticationType | undefined
      let answered = false
      client.once('ready', () => {
        if (method === 'keyboard-interactive' && !answered) { failure(); return }
        finish()
      })
      client.once('error', failure); client.once('close', failure)
      client.on('change password', () => finish(new SshError('PASSWORD_EXPIRED', 'The SSH password must be changed before authentication.')))
      client.on('keyboard-interactive', (_name, _instructions, _language, prompts, answer) => {
        if (password === undefined || answered || prompts.length !== 1 || prompts[0]!.echo !== false) {
          finish(new SshError('AUTH_FAILED', 'SSH authentication failed; check the selected credential.')); return
        }
        answered = true
        answer(resolved.filter(secret => secret.name === 'password').map(secret => secret.value!))
      })
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
        const methods: ssh2.AuthenticationType[] = password === undefined ? ['publickey'] : ['password', 'keyboard-interactive']
        let attempt = 0
        client.connect({ sock: socket, username: profile.username,
          ...(privateKey === undefined ? {} : { privateKey }),
          ...(passphrase === undefined ? {} : { passphrase }), readyTimeout: AUTHENTICATION_DEADLINE_MS,
          ...(password === undefined ? {} : { password, tryKeyboard: true }),
          authHandler: (_remaining, partial, next) => {
            method = methods[attempt++]
            if (!method || partial) return false
            next(method)
          }, hostVerifier: (key: Buffer) => {
            trusted = profile.approvedHostKeys.some(value => Buffer.from(value.split(' ')[1]!, 'base64').equals(key))
            return trusted
          } })
      })().catch(() => finish(new SshError('AUTH_FAILED', 'SSH authentication failed; check the selected credential.')))
    })
  } finally { privateKey?.fill(0) }

  return { address, disconnected, close,
    execute(settings: ExecutionSettings, signal?: AbortSignal): Promise<ExecutionResult> {
      if (closed) throw new SshError('CONNECTION_CLOSED', 'The connection is closed. Open a new connection explicitly.')
      if (active) throw new SshError('CONNECTION_BUSY', 'A command is already active on this connection.')
      validateSettings(settings)
      checkCommand(settings.command, secrets)
      if (settings.sudoPrompt !== undefined) {
        checkCommand(settings.sudoPrompt, secrets)
        checkCommand(settings.sudoSuccess!, secrets)
        if (password === undefined) throw new SshError('USAGE', 'Sudo password input requires a password credential.', 2)
      }
      if (signal?.aborted) throw new SshError('COMMAND_CANCELLED', 'Execution cancelled before dispatch.')
      return new Promise((resolve, reject) => {
        let finished = false
        let channel: ssh2.ClientChannel | undefined
        let remoteExit: number | null = null
        let remoteSignal: string | null = null
        let outcome: ExecutionResult['outcome'] = 'unknown'
        let diagnostic: string | undefined
        let grace: NodeJS.Timeout | undefined
        let answeredSudo = false
        let sudoDenied = false
        let sudoSucceeded = false
        let pendingPrompt = Buffer.alloc(0)
        let pendingSuccess = Buffer.alloc(0)
        let receivedBytes = 0
        const prompt = settings.sudoPrompt === undefined ? undefined : Buffer.from(settings.sudoPrompt)
        const success = settings.sudoSuccess === undefined ? undefined : Buffer.from(settings.sudoSuccess)
        const started = performance.now()
        const stdout = new Output(patterns, settings.outputLimit)
        const stderr = new Output(patterns, settings.outputLimit)
        const finish = () => {
          if (finished) return
          finished = true
          clearTimeout(deadline); clearTimeout(grace)
          signal?.removeEventListener('abort', abort)
          active = undefined
          stderr.push(pendingPrompt)
          stdout.push(pendingSuccess)
          if (sudoDenied && !sudoSucceeded) { reject(new SshError('SUDO_DENIED', 'Sudo authentication failed; check the selected credential.')); return }
          const streams = { stdout: stdout.finish(), stderr: stderr.finish() }
          if (streams.stdout.withheld || streams.stderr.withheld || remoteSignal !== null && containsSecret(remoteSignal, patterns)) {
            remoteSignal = null
            for (const stream of Object.values(streams)) { stream.text = ''; stream.retainedBytes = 0; stream.withheld = true }
            diagnostic = OUTPUT_WITHHELD
            if (outcome === 'completed') outcome = 'failed'
          }
          resolve({ address, outcome, remoteExit, remoteSignal,
            termination: remoteExit !== null || remoteSignal !== null ? outcome === 'timed_out' ? 'deadline' : 'remote-exit' : 'unknown',
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
          const count = (bytes: Buffer) => {
            receivedBytes += bytes.length
            if (receivedBytes > 16 * 1024 * 1024) cancel('unknown', OUTPUT_FLOOD)
          }
          stream.on('data', (bytes: Buffer) => {
            count(bytes)
            if (!success) { stdout.push(bytes); return }
            pendingSuccess = Buffer.concat([pendingSuccess, bytes])
            let match = pendingSuccess.indexOf(success)
            while (match !== -1) {
              stdout.push(pendingSuccess.subarray(0, match))
              pendingSuccess = pendingSuccess.subarray(match + success.length)
              sudoSucceeded = true
              match = pendingSuccess.indexOf(success)
            }
            let retained = Math.min(pendingSuccess.length, success.length - 1)
            while (retained > 0 && !pendingSuccess.subarray(-retained).equals(success.subarray(0, retained))) retained--
            stdout.push(pendingSuccess.subarray(0, pendingSuccess.length - retained))
            pendingSuccess = pendingSuccess.subarray(pendingSuccess.length - retained)
          })
          stream.stderr.on('data', (bytes: Buffer) => {
            count(bytes)
            if (!prompt) { stderr.push(bytes); return }
            pendingPrompt = Buffer.concat([pendingPrompt, bytes])
            let match = pendingPrompt.indexOf(prompt)
            while (match !== -1) {
              stderr.push(pendingPrompt.subarray(0, match))
              pendingPrompt = pendingPrompt.subarray(match + prompt.length)
              if (answeredSudo) { sudoDenied = true; stream.end() }
              else { answeredSudo = true; stream.end(`${password!}\n`) }
              match = pendingPrompt.indexOf(prompt)
            }
            let retained = Math.min(pendingPrompt.length, prompt.length - 1)
            while (retained > 0 && !pendingPrompt.subarray(-retained).equals(prompt.subarray(0, retained))) retained--
            stderr.push(pendingPrompt.subarray(0, pendingPrompt.length - retained))
            pendingPrompt = pendingPrompt.subarray(pendingPrompt.length - retained)
          })
          stream.on('exit', (code: number | null, name?: string) => { remoteExit = typeof code === 'number' ? code : null; remoteSignal = name ?? null })
          stream.on('error', () => { void close(); finish() })
          stream.on('close', () => {
            if (!grace) outcome = remoteExit === 0 ? 'completed' : remoteExit !== null || remoteSignal ? 'failed' : 'unknown'
            if (!grace && answeredSudo && !sudoSucceeded && (remoteExit !== null || remoteSignal !== null)) sudoDenied = true
            finish()
          })
          if (!prompt) stream.end()
        })
      })
    } }
}
