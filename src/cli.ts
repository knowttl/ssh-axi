import { encode } from '@toon-format/toon'
import { homedir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { configPath, loadConfiguration, selectProfile, resolveSecret, type Profile } from './profile.js'
import { doctor } from './doctor.js'
import { SshError } from './errors.js'
import { executeNative } from './native-execution.js'

import { commands, flagHelp, parseArguments } from './arguments.js'

function projection(name: string, profile: Profile) {
  return { id: name, address: profile.address, port: profile.port, username: profile.username }
}

export async function main(args: readonly string[]): Promise<void> {
  const json = args.includes('--json')
  const output = (value: unknown) => console.log(json ? JSON.stringify(value) : encode(value as Record<string, unknown>))
  try {
    const parsed = parseArguments(args)
    if (parsed.help) {
      const usage = parsed.command === 'exec' ? 'exec <host> --command <text> --confirm'
        : parsed.command === 'execution cancel' ? 'execution cancel <id> --confirm'
          : parsed.command === 'execution show' ? 'execution show <id>'
            : parsed.command === 'connection set' ? 'connection set <id> --idle-timeout 5m'
              : ['connection show', 'connection close'].includes(parsed.command) ? `${parsed.command} <id>`
            : `${parsed.command}${commands[parsed.command]!.arguments ? ' <host>' : ''}`
      output({ description: commands[parsed.command]!.description, flags: flagHelp + Object.keys(commands[parsed.command]!.flags ?? {}).map(key => `, --${key}`).join(''),
        ...(parsed.command === 'exec' ? { defaults: { timeout: '60s', outputLimit: '65536 bytes' } } : {}),
        examples: parsed.command === '' ? ['ssh-axi host list', 'ssh-axi doctor <host>', 'ssh-axi config path']
          : [`ssh-axi ${usage}`, `ssh-axi ${usage} --json`] })
      return
    }
    const path = configPath(parsed.config)
    if (parsed.command === 'config path') { output({ path }); return }
    if (parsed.command.startsWith('execution ') || parsed.command.startsWith('connection ')) throw new SshError('HOSTED_REQUIRED', 'Use artium-axi ssh-axi for managed connections and executions.')
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
      const source = (reference: Profile['privateKey'], fallback: string) => reference && 'file' in reference ? 'protected file' : `env:${reference?.env ?? fallback}`
      output({ profile: selected.name, privateKey: key ? 'available' : 'missing', passphrase: passphrase ? 'available' : 'absent',
        privateKeySource: source(selected.profile.privateKey, 'SSH_AXI_PRIVATE_KEY'),
        passphraseSource: source(selected.profile.passphrase, 'SSH_AXI_PASSPHRASE'), network: 'not checked' })
      return
    }
    output({ host: selected.name, ...await doctor(selected.profile), commandsExecuted: 0 })
  } catch (error) {
    const safe = error instanceof SshError ? error : new SshError('INTERNAL_ERROR', 'The SSH operation failed.')
    output({ error: { code: safe.code, message: safe.message }, help: ['ssh-axi --help'] })
    process.exitCode = safe.exitCode
  }
}
