import { openTransport, type ExecutionSettings } from './authenticate.js'
import { configPath, loadConfiguration, selectProfile } from './profile.js'
import { SshError } from './errors.js'

// Only the host can opt in through inherited IPC. It owns profile custody.
if (!process.send || process.argv.length !== 2) process.exit(2)
let connection: Awaited<ReturnType<typeof openTransport>> | undefined
let opening = false
let fenced = false
let active: AbortController | undefined
const authentication = new AbortController()
const send = (value: unknown) => { if (process.connected) process.send!(value) }
process.on('disconnect', () => process.exit(1))
process.on('message', async (value: unknown) => {
  let id: string | undefined
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SshError('IPC_INVALID', 'Invalid connection request.')
    const request = value as Record<string, unknown>
    if (request.revision !== 2 || typeof request.id !== 'string'
      || !['open', 'exec', 'cancel', 'close'].includes(String(request.operation))
      || Object.keys(request).some(key => !['revision', 'id', 'operation', 'settings'].includes(key))) throw new SshError('IPC_INVALID', 'Incompatible connection protocol.')
    id = request.id
    if (request.operation === 'close') {
      fenced = true; authentication.abort(); active?.abort()
      await connection?.close()
      send({ id, ok: true, result: { closed: true } })
      if (process.connected) process.disconnect()
      return
    }
    if (fenced) throw new SshError('CONNECTION_CLOSED', 'Connection is fenced.')
    if (request.operation === 'cancel') { active?.abort(); send({ id, ok: true, result: { cancelled: true } }); return }
    if (request.operation === 'open') {
      if (opening) throw new SshError('IPC_INVALID', 'Connection already initialized.')
      opening = true
      connection = await openTransport(selectProfile(loadConfiguration(configPath()), 'artium').profile, authentication.signal)
      if (fenced) { await connection.close(); return }
      void connection.disconnected.then(() => { if (!fenced && process.connected) process.disconnect() })
      send({ id, ok: true, result: { authenticated: true, address: connection.address } })
      return
    }
    if (!connection) throw new SshError('CONNECTION_CLOSED', 'Connection is not authenticated.')
    if (active) throw new SshError('CONNECTION_BUSY', 'A command is already active on this connection.')
    active = new AbortController()
    try { send({ id, ok: true, result: await connection.execute(request.settings as ExecutionSettings, active.signal) }) }
    finally { active = undefined }
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('WORKER_FAILED', 'Private connection operation failed.')
    send({ id, ok: false, error: { code: safe.code, message: safe.message } })
  }
})
