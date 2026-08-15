import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution, PreToolDecision } from '@deepseek-ai/dsh-tools'
import { inspectPayload, type GuardPolicy } from './core.js'

export const name = 'secret-guard'

export interface Config {
  actionOnFinding?: 'ask' | 'block'
  maxSerializedBytes?: number
  protectedTools?: string[]
}

export function apply(ctx: Context, config: Config = {}): void {
  const policy: GuardPolicy = {
    actionOnFinding: config.actionOnFinding ?? 'block',
    maxSerializedBytes: config.maxSerializedBytes ?? 128_000,
  }
  const protectedTools = new Set(config.protectedTools ?? [])
  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (protectedTools.size > 0 && !protectedTools.has(exec.name)) return next()
    const decision = inspectPayload(exec.arguments, policy)
    if (decision.action === 'allow') return next()
    const kinds = [...new Set(decision.findings.map((f) => f.kind))].join(', ')
    const reason = `Secret Guard ${decision.action}: ${decision.reasonCode} (${kinds})`
    if (decision.action === 'ask') return { kind: 'ask', reason }
    return { kind: 'deny', reason }
  })
}

export * from './core.js'
