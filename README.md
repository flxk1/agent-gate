# agent-gate

The enforcement host for agents governed by Loomground and a2a-compliance.

It does only what a plane-neutral library cannot: it sits on the host, in the
path of every action. It decides nothing about policy.

## Scope

| Job | What it does |
|---|---|
| Gate | Intercepts every tool call (the agent host's `PreToolUse` hook, MCP proxy) and holds it until a verified a2a `ExecutionPermit` matches the exact tool and arguments. |
| Identity | Binds each action to the session that made it (session id + process start time), so a permit is consumed by the actor it names. |
| Locks and seals | Egress lock and at-rest seal on folders: protection that holds while no agent is acting. |

Records are a2a's: every gated call yields an a2a `ToolReceipt` (refusals included), chained by `prev_digest`. agent-gate keeps no chain format of its own.

## Not in scope

- Policy authoring, norm extraction, grounding: Loomground (`policy_compile`, `policy_check`, versum).
- Admission, permits, reconciliation, certification: a2a-compliance (`admit`, `issue_permit`, `consume_and_execute`, `certify`).
- Fleet coordination and steering: ctrl.

agent-gate implements a2a-compliance's `ExecutorPort` and is the host that
attests `no_alternate_path_attested`. Without it, a2a enforcement is advisory.

## Status

Design only. See [docs/adr/0001-scope.md](docs/adr/0001-scope.md).
