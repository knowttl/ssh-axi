import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Output, secretPatterns } from '../dist/output.js'

for (const limit of [1, 1024]) test(`sanitized output withholds a secret across chunks with limit ${limit}`, () => {
  const output = new Output(secretPatterns(['abc']), limit)
  output.push(Buffer.from('a\x1b[3'))
  output.push(Buffer.from('1mbc'))
  const result = output.finish()
  assert.equal(result.withheld, true)
  assert.equal(result.text, '')
})
