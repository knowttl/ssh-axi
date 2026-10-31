import { test } from 'node:test'
import assert from 'node:assert/strict'
import { run } from './support.ts'

const root = process.env.ARTIUM_FIXTURE_ROOT
test('Artium discovery and managed execution journeys', { skip: root ? false : 'Opt in with ARTIUM_FIXTURE_ROOT pointing at the frozen admitted fixture; native tests require no fixture.' }, async () => {
  const result = await run(process.execPath, [process.env.npm_execpath!, 'exec', 'vitest', 'run', 'test/ssh-admission.test.ts'], process.env, root)
  assert.equal(result.code, 0, result.stdout + result.stderr)
})
