# dsh-secret-guard

A fail-closed secret-like payload guard for DeepSeek Harness (DSH) tool calls.

The plugin inspects model-supplied tool arguments at `tools/pre-execute` and returns `allow`, `ask`, or `deny` before the tool body runs. v0.1 deliberately does **not** rewrite/redact arguments: DSH freezes execution identity and arguments before policy, so mutating them inside a guard would violate the runtime contract.

## v0.1

- detects common private-key/token/key patterns;
- detects obvious sensitive field names;
- bounds serialized payload size and fails closed above the configured limit;
- optional tool-name scope (`protectedTools`); empty means inspect every tool;
- `actionOnFinding: block|ask`;
- no raw secret values in the denial reason.

## Non-claims

- heuristic secret detection, not complete DLP;
- no guarantee every credential format is detected;
- no argument redaction in v0.1;
- not a sandbox or malware detector;
- should be composed with a policy boundary such as AgentFuse when broader action authorization is required.

## Development

```bash
npm test
```

## License

MIT
