import test from 'node:test'
import assert from 'node:assert/strict'
import { inspectPayload } from '../src/core.js'

test('allows ordinary payload', () => {
  assert.equal(inspectPayload({ query: 'hello world' }).action, 'allow')
})

test('blocks private keys', () => {
  const d = inspectPayload({ body: '-----BEGIN PRIVATE KEY----- abc' })
  assert.equal(d.action, 'block')
  assert.equal(d.findings[0]?.kind, 'private-key')
})

test('detects sensitive field names', () => {
  const d = inspectPayload({ password: 'correct horse battery staple' })
  assert.equal(d.action, 'block')
  assert.ok(d.findings.some((f) => f.kind === 'sensitive-field-name'))
})

test('can defer to approval', () => {
  const d = inspectPayload({ api_key: 'abcdefghijklmnop' }, { actionOnFinding: 'ask', maxSerializedBytes: 1000 })
  assert.equal(d.action, 'ask')
})

test('fails closed on oversized payload', () => {
  const d = inspectPayload({ text: 'x'.repeat(200) }, { actionOnFinding: 'block', maxSerializedBytes: 20 })
  assert.equal(d.action, 'block')
  assert.equal(d.reasonCode, 'PAYLOAD_TOO_LARGE')
})
