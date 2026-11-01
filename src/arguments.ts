import schema from '../axi-credential.schema.json' with { type: 'json' }
import { SshError } from './errors.js'

export const commands: Record<string, { arguments: number, description: string, flags?: Record<string, string> }> = schema['x-commands']
export const flagHelp = '--json, --help, --config <absolute-path>, --profile <name>'

export function commandHelp(command: string, hosted = false) {
  const definition = commands[command]!
  const managed = command.startsWith('execution ') || command.startsWith('connection ')
  const invocation = managed ? 'artium-axi ssh-axi' : 'ssh-axi'
  const argument = managed && command !== 'connection open' ? ' <id>' : ' <host>'
  const usage = command === 'exec' ? 'exec <host> --command <text> --confirm'
    : command === 'execution cancel' ? 'execution cancel <id> --confirm'
      : command === 'connection set' ? 'connection set <id> --idle-timeout <duration>'
        : `${command}${definition.arguments ? argument : ''}`
  return {
    description: definition.description,
    ...(managed ? { availability: 'Managed (Artium) only; use artium-axi ssh-axi.' } : {}),
    ...(command === '' ? { commands: Object.keys(commands).filter(Boolean).map(name => `${name}${name.startsWith('execution ') || name.startsWith('connection ') ? ' (managed, Artium only)' : ''}`) } : {}),
    flags: (hosted ? '--json, --help' : flagHelp) + Object.entries(definition.flags ?? {}).map(([key, type]) => `, --${key}${type === 'boolean' ? '' : ' <value>'}`).join(''),
    ...(command === 'exec' ? { defaults: { timeout: '60s', outputLimit: '65536 bytes', confirm: false, detach: false, sudo: false } } : {}),
    examples: command === '' ? ['ssh-axi host list', 'ssh-axi doctor <host>', 'ssh-axi config path']
      : [`${invocation} ${usage}`, `${invocation} ${usage} --json`],
  }
}

export function parseArguments(args: readonly string[]) {
  let prefix = 0
  while (['--json', '--help', '--config', '--profile'].includes(args[prefix]!)) prefix += ['--config', '--profile'].includes(args[prefix]!) ? 2 : 1
  const commandName = args[prefix] === 'exec' || args[prefix] === 'doctor' ? args[prefix]! : args.slice(prefix, prefix + 2).join(' ')
  const extraFlags = commands[commandName]?.flags ?? {}
  const values: Record<string, string | boolean> = {}
  const positional: string[] = []
  let json = false
  let help = false
  let config: string | undefined
  let profile: string | undefined
  const seen = new Set<string>()
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!
    if (!arg.startsWith('-')) { positional.push(arg); continue }
    if (!['--json', '--help', '--config', '--profile', ...Object.keys(extraFlags).map(key => `--${key}`)].includes(arg)) {
      throw new SshError('USAGE', `Unknown flag. Valid flags: ${flagHelp}${Object.keys(extraFlags).map(key => `, --${key}`).join('')}.`, 2)
    }
    if (seen.has(arg)) throw new SshError('USAGE', 'Flags may only appear once.', 2)
    seen.add(arg)
    if (arg === '--json') json = true
    else if (arg === '--help') help = true
    else if (extraFlags[arg.slice(2)] === 'boolean') values[arg.slice(2)] = true
    else {
      const value = args[++index]
      if (value === undefined || (arg !== '--command' && (!value || value.startsWith('-')))) throw new SshError('USAGE', `A flag value is required. Valid flags: ${flagHelp}.`, 2)
      if (arg === '--config') config = value
      else if (arg === '--profile') profile = value
      else values[arg.slice(2)] = value
    }
  }
  const command = ['doctor', 'exec'].includes(positional[0]!) ? positional[0]! : positional.slice(0, 2).join(' ')
  const definition = commands[command]
  const count = command === '' ? 0 : ['doctor', 'exec'].includes(command) ? 1 : 2
  const selectedDoctor = command === 'doctor' && positional.length === count
  const receiptLookup = command === 'execution show' && positional.length === count
  if (!definition || positional.length !== count + definition.arguments && !selectedDoctor && !receiptLookup && !(help && positional.length === count)) {
    throw new SshError('USAGE', 'Use ssh-axi host list, host show <host>, doctor <host>, exec <host> --command <text> --confirm, or execution list/show/cancel (managed, Artium only).', 2)
  }
  if (['doctor', 'host show', 'exec'].includes(command) && positional[count] !== undefined) {
    if (profile !== undefined) throw new SshError('USAGE', 'Use the host argument to select the profile for this command.', 2)
    profile = positional[count]
  }
  if (command === 'execution show' && positional[count] && values['request-key']) throw new SshError('USAGE', 'Use an execution ID or --request-key, not both.', 2)
  const timeoutValue = values.timeout ?? '60s'
  const timeout = typeof timeoutValue === 'string' && /^\d+s?$/.test(timeoutValue) ? Number(timeoutValue.replace(/s$/, '')) : NaN
  const outputValue = values['output-limit'] ?? '65536'
  const outputLimit = typeof outputValue === 'string' && /^\d+$/.test(outputValue) ? Number(outputValue) : NaN
  if (command === 'exec' && (!Number.isInteger(timeout) || timeout < 1 || timeout > 600 || !Number.isInteger(outputLimit) || outputLimit < 0 || outputLimit > 1024 * 1024)) {
    throw new SshError('USAGE', 'Use --timeout 1s-600s and --output-limit 0-1048576 (bytes).', 2)
  }
  return { command, json, help, config, profile, values, timeout, outputLimit, id: positional[count] }
}
