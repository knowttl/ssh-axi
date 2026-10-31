import { authenticate, execute, type ExecutionSettings } from './authenticate.js'
import { validateProfile } from './profile.js'
import { SshError } from './errors.js'

// No listener or public argv mode exists. Only the supervising parent's inherited
// IPC channel can deliver one bounded authentication or execution request.
if (!process.send || process.argv.length !== 2) process.exit(2)
const cancellation = new AbortController()
process.on('message', (value: unknown) => {
  if (value && typeof value === 'object' && 'cancel' in value && value.cancel === true) cancellation.abort()
})
process.once('message', async (value: unknown) => {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SshError('IPC_INVALID', 'Invalid worker request.')
    const request = value as Record<string, unknown>
    if (request.revision !== 1 || !['doctor', 'exec'].includes(String(request.operation))
      || Object.keys(request).some(key => !['revision', 'operation', 'profile', 'settings'].includes(key))) throw new SshError('IPC_INVALID', 'Incompatible worker protocol.')
    const profile = validateProfile(request.profile)
    const result = request.operation === 'doctor' ? await authenticate(profile)
      : await execute(profile, request.settings as ExecutionSettings, cancellation.signal)
    process.exitCode = 0
    process.send!({ ok: true, result }, undefined, undefined, () => process.disconnect())
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('AUTH_FAILED', 'SSH authentication failed.')
    process.send!({ ok: false, error: { code: safe.code, message: safe.message } }, undefined, undefined, () => process.disconnect())
    process.exitCode = 1
  }
})
process.on('disconnect', () => process.exit(process.exitCode ?? 1))
