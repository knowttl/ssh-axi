import { encode } from '@toon-format/toon'
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import schema from '../axi-credential.schema.json' with { type: 'json' }
import { configPath, loadConfiguration, selectProfile, resolveSecret, type Profile } from './profile.js'
import { doctor } from './doctor.js'
import { SshError } from './errors.js'
import { executeNative } from './native-execution.js'

const commands: Record<string, { arguments: number, description: string, flags?: Record<string, string> }> = schema['x-commands']
const flagHelp = '--json, --help, --config <absolute-path>, --profile <name>'

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
      if (value === undefined || (arg !== '--command' && value.startsWith('-'))) throw new SshError('USAGE', `A flag value is required. Valid flags: ${flagHelp}.`, 2)
      if (arg === '--config') config = value
      else if (arg === '--profile') profile = value
      else values[arg.slice(2)] = value
    }
  }
  const command = ['doctor', 'exec'].includes(positional[0]!) ? positional[0]! : positional.slice(0, 2).join(' ')
  const definition = commands[command]
  const count = command === '' ? 0 : ['doctor', 'exec'].includes(command) ? 1 : 2
  const selectedDoctor = command === 'doctor' && positional.length === count
  const keyLookup = command === 'execution show' && typeof values['request-key'] === 'string' && positional.length === count
  if (!definition || positional.length !== count + definition.arguments && !selectedDoctor && !keyLookup && !(help && positional.length === count)) {
    throw new SshError('USAGE', 'Use ssh-axi host list, host show <host>, doctor <host>, auth status, profile list, or config path.', 2)
  }
  if (['doctor', 'host show', 'exec'].includes(command) && positional[count] !== undefined) {
    if (profile !== undefined) throw new SshError('USAGE', 'Use the host argument to select the profile for this command.', 2)
    profile = positional[count]
  }
  const timeoutValue = values.timeout ?? '60s'
  const timeout = typeof timeoutValue === 'string' && /^\d+s?$/.test(timeoutValue) ? Number(timeoutValue.replace(/s$/, '')) : NaN
  const outputValue = values['output-limit'] ?? '65536'
  const outputLimit = typeof outputValue === 'string' && /^\d+$/.test(outputValue) ? Number(outputValue) : NaN
  if (command === 'exec' && (!Number.isInteger(timeout) || timeout < 1 || timeout > 600 || !Number.isInteger(outputLimit) || outputLimit < 0 || outputLimit > 1024 * 1024)) {
    throw new SshError('USAGE', 'Use --timeout 1s-600s and --output-limit 0-1048576 (bytes).', 2)
  }
  return { command, json, help, config, profile, values, timeout, outputLimit, id: positional[count] }
}

function projection(name: string, profile: Profile) {
  return { id: name, address: profile.address, port: profile.port, username: profile.username }
}

export async function main(args: readonly string[]): Promise<void> {
  const json = args.includes('--json')
  const output = (value: unknown) => console.log(json ? JSON.stringify(value) : encode(value as Record<string, unknown>))
  try {
    const parsed = parseArguments(args)
    if (parsed.help) {
      output({ description: commands[parsed.command]!.description, flags: flagHelp + Object.keys(commands[parsed.command]!.flags ?? {}).map(key => `, --${key}`).join(''),
        examples: parsed.command === '' ? ['ssh-axi host list', 'ssh-axi doctor <host>', 'ssh-axi config path']
          : [`ssh-axi ${parsed.command}${commands[parsed.command]!.arguments ? ' <host>' : ''}`,
            `ssh-axi ${parsed.command}${commands[parsed.command]!.arguments ? ' <host>' : ''} --json`] })
      return
    }
    const path = configPath(parsed.config)
    if (parsed.command === 'config path') { output({ path }); return }
    if (parsed.command.startsWith('execution ')) throw new SshError('HOSTED_REQUIRED', 'Use artium-axi ssh-axi execution for durable managed executions.')
    const config = loadConfiguration(path)
    if (['', 'host list', 'profile list'].includes(parsed.command)) {
      const hosts = Object.entries(config.profiles).map(([name, profile]) => projection(name, profile))
      output({ ...(parsed.command === '' ? { bin: resolve(fileURLToPath(new URL('./main.js', import.meta.url))).replace(homedir(), '~'),
        description: 'Discover approved SSH hosts and run confirmed bounded commands.' } : {}),
        hosts, count: hosts.length, ...(hosts.length ? {} : { message: 'No configured hosts found.' }),
        help: hosts.length ? ['ssh-axi host show <host>', 'ssh-axi doctor <host>'] : ['ssh-axi config path', 'ssh-axi profile list --help'] })
      return
    }
    const selected = selectProfile(config, parsed.profile)
    if (parsed.command === 'exec') {
      const result = await executeNative(selected.name, selected.profile, parsed)
      output(result)
      process.exitCode = result.outcome === 'completed' ? 0 : result.remoteExit && result.remoteExit > 0 && result.remoteExit <= 255 ? result.remoteExit : 1
      return
    }
    if (parsed.command === 'host show') { output({ host: projection(selected.name, selected.profile) }); return }
    if (parsed.command === 'auth status') {
      const key = resolveSecret(selected.profile.privateKey, 'SSH_AXI_PRIVATE_KEY', true)
      const passphrase = resolveSecret(selected.profile.passphrase, 'SSH_AXI_PASSPHRASE', false)
      output({ profile: selected.name, privateKey: key ? 'available' : 'missing', passphrase: passphrase ? 'available' : 'absent', network: 'not checked' })
      return
    }
    output({ host: selected.name, ...await doctor(selected.profile), commandsExecuted: 0 })
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('INTERNAL_ERROR', 'The SSH operation failed.')
    output({ error: { code: safe.code, message: safe.message }, help: ['ssh-axi --help'] })
    process.exitCode = safe.exitCode
  }
}
