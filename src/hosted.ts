import { encode } from '@toon-format/toon'
import { parseArguments } from './arguments.js'
import { configPath, loadConfiguration, selectProfile } from './profile.js'
import { doctor, executeCommand } from './doctor.js'
import type { ExecutionSettings } from './authenticate.js'
import { SshError } from './errors.js'
import { VERSION } from './version.js'

interface Host { id: string, address: string, port: number, username: string }
interface Context { revision: 1, hosts: Host[], execution?: ExecutionSettings }
if (!process.send) process.exit(2)
process.once('message', async (message: unknown) => {
  const output = (value: unknown) => console.log(process.argv.includes('--json') ? JSON.stringify(value) : encode(value as Record<string, unknown>))
  try {
    if (process.argv.length === 3 && ['--version', '-v', '-V'].includes(process.argv[2]!)) {
      console.log(VERSION)
      return
    }
    const parsed = parseArguments(process.argv.slice(2))
    if (parsed.config || process.argv.includes('--profile')) throw new SshError('USAGE', 'Hosted profile overrides are refused.', 2)
    const context = message as Context
    if (context.revision !== 1 || !Array.isArray(context.hosts)) throw new SshError('IPC_INVALID', 'Incompatible host context.')
    if (context.execution) {
      if (context.hosts.length !== 1) throw new SshError('IPC_INVALID', 'A single selected execution host is required.')
      const cancellation = new AbortController()
      const cancel = () => cancellation.abort()
      process.on('message', (value: unknown) => {
        if (value && typeof value === 'object' && 'cancel' in value && value.cancel === true) cancel()
      })
      process.once('SIGTERM', cancel)
      process.once('SIGINT', cancel)
      try {
        const selected = selectProfile(loadConfiguration(configPath()), 'artium')
        const result = await executeCommand(selected.profile, context.execution, cancellation.signal)
        output(result)
        process.exitCode = result.outcome === 'completed' ? 0 : 1
      } finally { process.off('SIGTERM', cancel); process.off('SIGINT', cancel) }
      return
    }
    if (parsed.help) {
      output({ description: 'Discover granted hosts and run confirmed bounded commands.', commands: ['host list', 'host show <host>', 'doctor <host>', 'exec <host> --command <text> --confirm', 'execution list', 'execution show <id>', 'execution cancel <id> --confirm'], flags: '--help, --json' })
    } else if (parsed.command === '' || parsed.command === 'host list') {
      output({ hosts: context.hosts, count: context.hosts.length,
        ...(context.hosts.length ? {} : { message: 'No granted hosts found.' }), help: ['ssh-axi host show <host>', 'ssh-axi doctor <host>'] })
    } else {
      const host = context.hosts.find(host => host.id === parsed.profile)
      if (!host) throw new SshError('NOT_FOUND', 'Host not found.')
      if (parsed.command === 'host show') output({ host })
      else if (parsed.command === 'doctor') {
        const selected = selectProfile(loadConfiguration(configPath()), 'artium')
        output({ host: host.id, ...await doctor(selected.profile), commandsExecuted: 0 })
      } else throw new SshError('USAGE', 'Use host list, host show <host> or doctor <host>.', 2)
    }
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('HOSTED_FAILED', 'The hosted SSH check failed.')
    output({ error: { code: safe.code, message: safe.message } })
    process.exitCode = safe.exitCode
  } finally { if (process.connected) process.disconnect() }
})
