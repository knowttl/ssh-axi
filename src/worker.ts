import { authenticate } from './authenticate.js'
import { validateProfile } from './profile.js'
import { SshError } from './errors.js'

// No listener or public argv mode exists. Only the supervising parent's inherited
// IPC channel can deliver one bounded doctor request (protocol revision 1).
if (!process.send || process.argv.length !== 2) process.exit(2)
process.once('message', async (value: unknown) => {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SshError('IPC_INVALID', 'Invalid worker request.')
    const request = value as Record<string, unknown>
    if (request.revision !== 1 || request.operation !== 'doctor'
      || Object.keys(request).some(key => !['revision', 'operation', 'profile'].includes(key))) throw new SshError('IPC_INVALID', 'Incompatible worker protocol.')
    const result = await authenticate(validateProfile(request.profile))
    process.exitCode = 0
    process.send!({ ok: true, result }, undefined, undefined, () => process.disconnect())
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('AUTH_FAILED', 'SSH authentication failed.')
    process.send!({ ok: false, error: { code: safe.code, message: safe.message } }, undefined, undefined, () => process.disconnect())
    process.exitCode = 1
  }
})
process.on('disconnect', () => process.exit(process.exitCode ?? 1))
