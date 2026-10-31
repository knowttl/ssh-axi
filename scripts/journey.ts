import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const args = process.argv.slice(2).filter(arg => arg !== '--')
if (args.length !== 2 || args[0] !== '--slice' || args[1] !== 'B1.1') throw new Error('Use --slice B1.1; no other slice is implemented.')
if (!process.env.ARTIUM_FIXTURE_ROOT) throw new Error('ARTIUM_FIXTURE_ROOT must identify the admitted frozen fixture export.')
const result = spawnSync(process.execPath, [fileURLToPath(new URL('./test.ts', import.meta.url))], { stdio: 'inherit' })
process.exit(result.status ?? 1)
