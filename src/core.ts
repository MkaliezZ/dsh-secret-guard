export type GuardAction = 'allow' | 'ask' | 'block'
export interface SecretFinding { kind: string; path: string }
export interface GuardDecision { action: GuardAction; findings: SecretFinding[]; reasonCode: string }
export interface GuardPolicy { actionOnFinding: 'ask' | 'block'; maxSerializedBytes: number }

const patterns: Array<[string, RegExp]> = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i],
  ['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
  ['github-token', /\bgh[ps]_[A-Za-z0-9_]{20,}\b/],
  ['generic-secret-assignment', /\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*["']?[A-Za-z0-9_\-\/.+=]{12,}/i],
]

function walk(value: unknown, path: string, findings: SecretFinding[], seen: Set<object>): void {
  if (typeof value === 'string') {
    for (const [kind, pattern] of patterns) if (pattern.test(value)) findings.push({ kind, path })
    return
  }
  if (!value || typeof value !== 'object') return
  if (seen.has(value as object)) return
  seen.add(value as object)
  if (Array.isArray(value)) value.forEach((item, i) => walk(item, `${path}[${i}]`, findings, seen))
  else for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const next = path ? `${path}.${key}` : key
    if (/^(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)$/i.test(key) && typeof item === 'string' && item.length > 0) findings.push({ kind: 'sensitive-field-name', path: next })
    walk(item, next, findings, seen)
  }
}

export function inspectPayload(value: unknown, policy: GuardPolicy = { actionOnFinding: 'block', maxSerializedBytes: 128_000 }): GuardDecision {
  let serialized: string
  try { serialized = JSON.stringify(value) } catch { return { action: 'block', findings: [{ kind: 'unserializable-payload', path: '$' }], reasonCode: 'PAYLOAD_UNSERIALIZABLE' } }
  if (serialized.length > policy.maxSerializedBytes) return { action: 'block', findings: [{ kind: 'payload-too-large', path: '$' }], reasonCode: 'PAYLOAD_TOO_LARGE' }
  const findings: SecretFinding[] = []
  walk(value, '$', findings, new Set())
  if (findings.length === 0) return { action: 'allow', findings, reasonCode: 'NO_SECRET_PATTERN' }
  return { action: policy.actionOnFinding, findings, reasonCode: 'SECRET_LIKE_PAYLOAD' }
}
