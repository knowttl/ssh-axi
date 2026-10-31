import { fork } from 'node:child_process'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SshError } from './errors.js'
import { type Profile, resolveSecret } from './profile.js'
import type { ExecutionResult, ExecutionSettings } from './authenticate.js'
import { checkCommand, containsSecret, secretPatterns } from './output.js'

// Both native and hosted callers use this one-shot supervisor. Artium supplies
// only the selected binding's profile; no public caller can supply worker state.
export async function doctor(profile: Profile): Promise<{ authenticated: true, address: string }> {
  return supervise(profile) as Promise<{ authenticated: true, address: string }>
}

export async function executeCommand(profile: Profile, settings: ExecutionSettings, signal?: AbortSignal): Promise<ExecutionResult> {
  return supervise(profile, settings, signal) as Promise<ExecutionResult>
}

async function supervise(profile: Profile, settings?: ExecutionSettings, signal?: AbortSignal): Promise<unknown> {
  const privateKey = resolveSecret(profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)!
  const passphrase = resolveSecret(profile.passphrase, 'SSH_AXI_PASSPHRASE', false)
  if (settings) checkCommand(settings.command, [privateKey, passphrase ?? ''])
  const directory = await mkdtemp(join(tmpdir(), 'ssh-axi-'))
  try {
    for (const name of ['config', 'state', 'tmp']) await mkdir(join(directory, name), { mode: 0o700 })
    const environment: NodeJS.ProcessEnv = { HOME: directory, USERPROFILE: directory,
      XDG_CONFIG_HOME: join(directory, 'config'), XDG_STATE_HOME: join(directory, 'state'),
      APPDATA: join(directory, 'config'), LOCALAPPDATA: join(directory, 'state'),
      TMPDIR: join(directory, 'tmp'), TMP: join(directory, 'tmp'), TEMP: join(directory, 'tmp'),
      ARTIUM_SECRET_0: privateKey, ...(passphrase === undefined ? {} : { ARTIUM_SECRET_1: passphrase }) }
    return await new Promise((resolve, reject) => {
      const child = fork(new URL('./worker.js', import.meta.url), [], { env: environment,
        execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'] })
      let response: unknown
      const deadline = setTimeout(() => child.kill('SIGKILL'), 17_000 + (settings?.timeout ?? 0) * 1000)
      const cancel = () => { if (child.connected) child.send({ cancel: true }) }
      signal?.addEventListener('abort', cancel, { once: true })
      child.once('error', () => reject(new SshError('WORKER_FAILED', 'Cannot start the private SSH probe.')))
      child.once('message', value => { response = value })
      child.once('exit', () => {
        clearTimeout(deadline)
        signal?.removeEventListener('abort', cancel)
        const value = response as { ok?: boolean, result?: ExecutionResult, error?: { code: string, message: string } } | undefined
        if (value?.ok && value.result) {
          if (containsSecret(JSON.stringify(value.result), secretPatterns([privateKey, passphrase ?? '']))) {
            reject(new SshError('SECRET_IN_OUTPUT', 'Protected worker output withheld.'))
          } else resolve(value.result)
        }
        else reject(value?.error ? new SshError(value.error.code, value.error.message) : new SshError('WORKER_FAILED', 'The private SSH probe stopped without a result.'))
      })
      child.send({ revision: 1, operation: settings ? 'exec' : 'doctor', ...(settings ? { settings } : {}), profile: { ...profile, privateKey: { env: 'ARTIUM_SECRET_0' },
        ...(passphrase === undefined ? {} : { passphrase: { env: 'ARTIUM_SECRET_1' } }) } })
      if (signal?.aborted) cancel()
    })
  } finally { await rm(directory, { recursive: true, force: true }) }
}
