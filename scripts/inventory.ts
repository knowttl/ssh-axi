import { readFileSync, writeFileSync } from 'node:fs'

const root = new URL('../', import.meta.url)
const schema = JSON.parse(readFileSync(new URL('axi-credential.schema.json', root), 'utf8')) as {
  'x-protocol-revision': number, 'x-commands': Record<string, { arguments: number, flags?: Record<string, string> }>
}
const output = JSON.stringify({ revision: schema['x-protocol-revision'],
  commands: Object.entries(schema['x-commands']).map(([command, value]) => ({ command: command || 'home',
    arguments: value.arguments, flags: { help: 'boolean', json: 'boolean', ...value.flags }, effect: ['exec', 'execution cancel', 'connection close'].includes(command) ? 'write' : 'read' })) }, null, 2) + '\n'
const target = new URL('artium-invocations.json', root)
if (process.argv.includes('--write')) writeFileSync(target, output)
else if (readFileSync(target, 'utf8') !== output) throw new Error('SSH invocation inventory is stale; run pnpm inventory:write')
