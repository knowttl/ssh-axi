import { encode } from '@toon-format/toon'
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import schema from '../axi-credential.schema.json' with { type: 'json' }
import { configPath, loadConfiguration, selectProfile, resolveSecret, type Profile } from './profile.js'
import { doctor } from './doctor.js'
import { SshError } from './errors.js'

const commands: Record<string, { arguments: number, description: string }> = schema['x-commands']
const flagHelp = '--json, --help, --config <absolute-path>, --profile <name>'

export function parseArguments(args: readonly string[]) {
  const positional: string[] = []
  let json = false
  let help = false
  let config: string | undefined
  let profile: string | undefined
  const seen = new Set<string>()
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!
    if (!arg.startsWith('-')) { positional.push(arg); continue }
    if (!['--json', '--help', '--config', '--profile'].includes(arg)) {
      throw new SshError('USAGE', `Unknown flag. Valid flags: ${flagHelp}.`, 2)
    }
    if (seen.has(arg)) throw new SshError('USAGE', 'Flags may only appear once.', 2)
    seen.add(arg)
    if (arg === '--json') json = true
    else if (arg === '--help') help = true
    else {
      const value = args[++index]
      if (!value || value.startsWith('-')) throw new SshError('USAGE', `A flag value is required. Valid flags: ${flagHelp}.`, 2)
      if (arg === '--config') config = value
      else profile = value
    }
  }
  const command = positional[0] === 'doctor' ? 'doctor' : positional.slice(0, 2).join(' ')
  const definition = commands[command]
  const count = command === '' ? 0 : command === 'doctor' ? 1 : 2
  if (!definition || positional.length !== count + definition.arguments && !(help && positional.length === count)) {
    throw new SshError('USAGE', 'Use ssh-axi host list, host show <host>, doctor <host>, auth status, profile list, or config path.', 2)
  }
  if (command === 'doctor' || command === 'host show') {
    if (profile !== undefined) throw new SshError('USAGE', 'Use the host argument to select the profile for this command.', 2)
    profile = positional[count]
  }
  return { command, json, help, config, profile }
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
      output({ description: commands[parsed.command]!.description, flags: flagHelp,
        examples: parsed.command === '' ? ['ssh-axi host list', 'ssh-axi doctor <host>', 'ssh-axi config path']
          : [`ssh-axi ${parsed.command}${commands[parsed.command]!.arguments ? ' <host>' : ''}`,
            `ssh-axi ${parsed.command}${commands[parsed.command]!.arguments ? ' <host>' : ''} --json`] })
      return
    }
    const path = configPath(parsed.config)
    if (parsed.command === 'config path') { output({ path }); return }
    const config = loadConfiguration(path)
    if (['', 'host list', 'profile list'].includes(parsed.command)) {
      const hosts = Object.entries(config.profiles).map(([name, profile]) => projection(name, profile))
      output({ ...(parsed.command === '' ? { bin: resolve(fileURLToPath(new URL('./main.js', import.meta.url))).replace(homedir(), '~'),
        description: 'Discover approved SSH hosts and check authentication.' } : {}),
        hosts, count: hosts.length, ...(hosts.length ? {} : { message: 'No configured hosts found.' }),
        help: hosts.length ? ['ssh-axi host show <host>', 'ssh-axi doctor <host>'] : ['ssh-axi config path', 'ssh-axi profile list --help'] })
      return
    }
    const selected = selectProfile(config, parsed.profile)
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
