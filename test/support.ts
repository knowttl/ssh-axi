import { generateKeyPairSync, createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import ssh2 from 'ssh2'
import type { Profile } from '../dist/profile.js'

export const passphrase = 'CANARY-disposable-key-passphrase'
export const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs1', format: 'pem', cipher: 'aes-256-cbc', passphrase },
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' } }).privateKey
const parsed = ssh2.utils.parseKey(privateKey, passphrase)
if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('Cannot generate the disposable SSH key')
const signingKey = parsed
export const publicKey = parsed.getPublicSSH()
export const hostPrivateKey = generateKeyPairSync('rsa', { modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'pkcs1', format: 'pem' } }).privateKey
const host = ssh2.utils.parseKey(hostPrivateKey)
if (host instanceof Error || Array.isArray(host)) throw new Error('Cannot generate the disposable host key')
export const hostKey = `${host.type} ${host.getPublicSSH().toString('base64')}`

export async function peer(stall = false, address = '127.0.0.1', port = 0, execute?: (command: string, stream: ssh2.ServerChannel, session: ssh2.Session) => void) {
  const observations = { transports: 0, auth: 0, commands: 0, channels: 0, closed: 0, addresses: [] as string[], commandBytes: [] as string[], signals: [] as string[] }
  let observedAuth: (() => void) | undefined
  let observedClose: (() => void) | undefined
  let observedSignal!: () => void
  const authentication = new Promise<void>(resolve => { observedAuth = resolve })
  const disconnected = new Promise<void>(resolve => { observedClose = resolve })
  const signalled = new Promise<void>(resolve => { observedSignal = resolve })
  const server = new ssh2.Server({ hostKeys: [hostPrivateKey] }, client => {
    observations.transports++
    client.on('error', () => {})
    client.on('close', () => { observations.closed++; observedClose!() })
    client.on('authentication', context => {
      observations.auth++
      observedAuth!()
      if (stall) return
      if (context.method === 'publickey' && context.username === 'ordinary'
        && context.key.data.equals(publicKey) && (!context.signature || signingKey.verify(context.blob!, context.signature, context.hashAlgo) === true)) context.accept()
      else context.reject(['publickey'])
    })
    client.on('session', accept => {
      observations.channels++
      const session = accept()
      // ssh2's server marks the session ended on stdin EOF and drops later
      // requests. Model SSH half-close: signals remain valid until close.
      session.on('eof', () => { (session as ssh2.Session & { _ending: boolean })._ending = false })
      session.on('signal', (_accept, _reject, info) => { observations.signals.push(info.name); observedSignal() })
      session.on('exec', (accept, reject, info) => {
        observations.commands++; observations.commandBytes.push(info.command)
        if (execute) execute(info.command, accept(), session)
        else reject()
      })
    })
  })
  await new Promise<void>(resolve => server.listen(port, address, resolve))
  const endpoint = server.address()
  if (!endpoint || typeof endpoint === 'string') throw new Error('Missing loopback peer address')
  const profile: Profile = { address, port: endpoint.port, username: 'ordinary',
    approvedHostKeys: [hostKey], allowedAddresses: ['127.0.0.1'],
    privateKey: { env: 'TEST_PRIVATE_KEY' }, passphrase: { env: 'TEST_PASSPHRASE' } }
  return { observations, authentication, disconnected, signalled, profile,
    close: () => new Promise<void>(resolve => server.close(() => resolve())) }
}

export async function temporary() {
  const root = await mkdtemp(join(tmpdir(), 'ssh-axi-test-'))
  return { root, close: () => rm(root, { recursive: true, force: true }) }
}

export async function configuration(root: string, profiles: Record<string, Profile>) {
  const directory = join(root, 'config', 'ssh-axi')
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const path = join(directory, 'config.json')
  await writeFile(path, JSON.stringify({ version: 1, profiles }), { mode: 0o600 })
  return path
}

export function run(executable: string, args: string[], env: NodeJS.ProcessEnv, cwd?: string) {
  return new Promise<{ code: number | null, stdout: string, stderr: string }>((resolve, reject) => {
    const child = spawn(executable, args, { env, ...(cwd ? { cwd } : {}) })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', chunk => { stdout += String(chunk) })
    child.stderr.on('data', chunk => { stderr += String(chunk) })
    child.once('error', reject)
    child.once('exit', code => resolve({ code, stdout, stderr }))
  })
}

export const digest = (data: Uint8Array) => createHash('sha256').update(data).digest('hex')
