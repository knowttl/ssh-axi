import { lookup } from 'node:dns/promises'
import { BlockList, isIP, connect, type Socket } from 'node:net'
import ssh2 from 'ssh2'
import { SshError } from './errors.js'
import { resolveSecret, type Profile } from './profile.js'

export const AUTHENTICATION_DEADLINE_MS = 15_000

// A probe authenticates once, never requests a channel, and returns only after
// the validated-address socket closes. The worker's lifetime bounds key custody.
export async function authenticate(profile: Profile): Promise<{ authenticated: true, address: string }> {
  const privateKey = Buffer.from(resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!)
  const passphrase = resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false)
  try {
    return await new Promise((resolve, reject) => {
      const client = new ssh2.Client()
      let socket: Socket | undefined
      let finished = false
      let trusted = false
      let selected = ''
      const finish = (error?: SshError) => {
        if (finished) return
        finished = true
        clearTimeout(deadline)
        const complete = () => error ? reject(error) : resolve({ authenticated: true, address: selected })
        if (socket && !socket.closed) {
          socket.once('close', complete)
          client.destroy()
          socket.destroy()
        } else { client.destroy(); complete() }
      }
      const deadline = setTimeout(() => finish(new SshError('AUTH_TIMEOUT', 'SSH authentication exceeded 15 seconds.')), AUTHENTICATION_DEADLINE_MS)
      client.on('ready', () => finish())
      client.on('error', () => finish(new SshError(trusted ? 'AUTH_FAILED' : 'TRUST_FAILED',
        trusted ? 'SSH key authentication failed; check the selected key and passphrase.' : 'SSH host trust could not be established.')))
      client.on('close', () => finish(new SshError('AUTH_FAILED', 'SSH transport closed before authentication.')))
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
