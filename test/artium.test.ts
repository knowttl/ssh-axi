import { test } from 'node:test'
import assert from 'node:assert/strict'
import { run } from './support.ts'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = process.env.ARTIUM_FIXTURE_ROOT
test('Artium discovery, execution, connection lifetime and recovery journeys', { skip: root ? false : 'Opt in with ARTIUM_FIXTURE_ROOT pointing at the frozen admitted fixture; native tests require no fixture.' }, async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'ssh-axi-journey-'))
  try {
    const report = join(scratch, 'results.json')
    const result = await run(process.execPath, [process.env.npm_execpath!, 'exec', 'vitest', 'run', 'test/ssh-admission.test.ts', 'test/integration/ssh-rotation.test.ts', '--reporter=json', '--outputFile', report], process.env, root)
    assert.equal(result.code, 0, result.stdout + result.stderr)
    const evidence = JSON.parse(await readFile(report, 'utf8')) as {
      testResults: { assertionResults: { fullName: string, status: string }[] }[]
    }
    const passed = new Set(evidence.testResults.flatMap(file => file.assertionResults.filter(result => result.status === 'passed').map(result => result.fullName)))
    // A stale B2 fixture must not report a B3 journey as passing with no B3 checks.
    for (const behavior of [
      'two users on the same account reuse private transports and one close preserves the other exact transport',
      'busy connection refuses overlap and active close requires confirmation before teardown',
      'idle changes use the original monotonic idle start and enforce the host ceiling',
      'server idle timer closes a transport without another client request',
      'opening connections count against the user quota and revocation fences stalled authentication',
      'global quota includes sixteen simultaneous authentications from distinct users',
      'revocation discards a dispatch queued behind shared active-job admission',
      'refresh retains connection ownership while logout fences only that session family',
      'detected refresh-token reuse closes its family before returning the rejection',
      'hard worker loss leaves the durable execution uncertain, cleans files and never replays',
      'hard server crash before send never replays the durable dispatch claim',
      'hard server crash after send never replays the durable dispatch claim',
      'public host administration confirms changes, rejects stale revisions and separates credential authority',
      'sudo dispatch selects a distinct key and account and never reuses an ordinary connection',
      'audit reads enforce current authority and prune output separately from attributable metadata',
      'administration pages render escaped audit text and confirmed host forms in a real browser',
      'offline master-key rotation preserves encrypted SSH output samples',
    ]) assert.ok(passed.has(behavior), `Missing required hosted conformance: ${behavior}`)
  } finally { await rm(scratch, { recursive: true, force: true }) }
})
