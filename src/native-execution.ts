import { constants, openSync, closeSync, fsyncSync, writeFileSync, fstatSync, mkdirSync } from 'node:fs'
import { dirname, isAbsolute, join } from 'node:path'
import { homedir } from 'node:os'
import { randomUUID } from 'node:crypto'
import { executeCommand } from './doctor.js'
import { checkCommand } from './output.js'
import { readPrivateFile, resolveSecret, type Profile } from './profile.js'
import { SshError } from './errors.js'
import type { parseArguments } from './arguments.js'

export async function executeNative(host: string, profile: Profile, parsed: ReturnType<typeof parseArguments>) {
  if (parsed.values.confirm !== true) throw new SshError('CONFIRM_REQUIRED', 'Every arbitrary command requires --confirm.', 2)
  if (process.env.SSH_AXI_READ_ONLY && process.env.SSH_AXI_READ_ONLY !== 'false' && process.env.SSH_AXI_READ_ONLY !== '0') throw new SshError('READ_ONLY', 'Arbitrary execution is disabled by read-only policy.')
  if (parsed.values.sudo || parsed.values.detach || parsed.values['request-key']) throw new SshError('HOSTED_REQUIRED', 'This option requires a managed execution and matching host grants.')
  if (typeof parsed.values.command !== 'string') throw new SshError('USAGE', 'Use --command <text> --confirm.', 2)
  const command = parsed.values.command
  checkCommand(command, [resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!, resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false) ?? ''])
  const state = process.platform === 'win32' ? process.env.LOCALAPPDATA : process.env.XDG_STATE_HOME && isAbsolute(process.env.XDG_STATE_HOME)
    ? process.env.XDG_STATE_HOME : join(homedir(), '.local', 'state')
  if (!state || process.platform === 'win32') throw new SshError('PLATFORM_PENDING', 'Native Windows custody validation is pending.')
  const file = process.env.SSH_AXI_WRITE_LOG ?? join(state, 'ssh-axi', 'writes.log')
  if (!isAbsolute(file)) throw new SshError('CONFIG_INSECURE', 'Write journal path must be absolute.')
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  // Reuse the private-file ownership/parent checks before appending.
  const descriptor = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600)
  const id = `exec_${randomUUID()}`
  const startedAt = new Date().toISOString()
  try {
    readPrivateFile(file, true)
    if (!fstatSync(descriptor).isFile()) throw new SshError('CONFIG_INSECURE', 'Journal must be a private regular file.')
    writeFileSync(descriptor, JSON.stringify({ id, host, command, confirmed: true, startedAt, outcome: 'unknown' }) + '\n')
    fsyncSync(descriptor)
  } finally { closeSync(descriptor) }
  const cancellation = new AbortController()
  const cancel = () => cancellation.abort()
  process.once('SIGINT', cancel)
  try {
    return { id, host, account: profile.username, sudo: false, connectionId: null, startedAt,
      ...await executeCommand(profile, { command, timeout: parsed.timeout, outputLimit: parsed.outputLimit }, cancellation.signal),
      finishedAt: new Date().toISOString(), help: ['Inspect remote state before retrying an uncertain execution. No automatic replay.'] }
  } finally { process.off('SIGINT', cancel) }
}
