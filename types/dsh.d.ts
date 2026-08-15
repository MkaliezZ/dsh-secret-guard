declare module '@deepseek-ai/cordis' { export interface Context { on(event: string, listener: (...args: any[]) => any): void } }
declare module '@deepseek-ai/dsh-tools' {
  export interface ToolExecution { name: string; arguments: unknown }
  export type PreToolDecision = { kind: 'allow' } | { kind: 'deny'; reason: string } | { kind: 'ask'; reason: string }
}
