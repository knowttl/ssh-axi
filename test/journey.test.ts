import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { run, temporary } from './support.ts'
import evidence from './fixtures/hosted-conformance.json' with { type: 'json' }

const admission = 'test/ssh-admission.test.ts'
const rotation = 'test/integration/ssh-rotation.test.ts'
const earlier = { [admission]: ['approved host discovery and managed execution'] }
const b3 = { [admission]: evidence.b3 }
const b4 = { ...b3, [rotation]: evidence.b4 }

for (const [slice, suites, code, diagnostic] of [
  ['B1.1', earlier, 0, 'pass 1'],
  ['B2.1', earlier, 0, 'pass 1'],
  ['B2.2', earlier, 0, 'pass 1'],
  ['B3.1', b3, 0, 'pass 1'],
  ['B3.2', b3, 0, 'pass 1'],
  ['B4.1', b4, 0, 'pass 1'],
  ['B4.2', b4, 0, 'pass 1'],
  ['B4.3', b4, 0, 'pass 1'],
  ['B3.2', earlier, 1, 'Missing required hosted conformance: two users'],
  ['B4.3', { ...b3, [rotation]: [] }, 1, 'Missing required hosted conformance: public host administration'],
  ['B4.3', { ...earlier, [rotation]: evidence.b4 }, 1, 'Missing required hosted conformance: two users'],
  ['', b4, 0, 'pass 1'],
  ['', b3, 1, 'ssh-rotation.test.ts'],
] as const) test(`hosted ${slice || 'default'} journey with ${Object.keys(suites).join(', ')} returns ${code}: ${diagnostic}`, async () => {
  const fixture = await temporary()
  try {
    for (const [suite, names] of Object.entries(suites)) {
      const path = join(fixture.root, suite)
      await mkdir(dirname(path), { recursive: true })
      await writeFile(path, JSON.stringify(names))
    }
    const env: NodeJS.ProcessEnv = { ...process.env, ARTIUM_FIXTURE_ROOT: fixture.root,
      npm_execpath: fileURLToPath(new URL('./fixtures/hosted-vitest.ts', import.meta.url)) }
    delete env.SSH_AXI_JOURNEY_SLICE
    delete env.NODE_TEST_CONTEXT
    const result = await run(process.execPath, ['--test', 'test/artium.test.ts'], { ...env,
      ...(slice ? { SSH_AXI_JOURNEY_SLICE: slice } : {}) })
    assert.equal(result.code, code, result.stdout + result.stderr)
    assert.ok((result.stdout + result.stderr).includes(diagnostic), result.stdout + result.stderr)
  } finally { await fixture.close() }
})
