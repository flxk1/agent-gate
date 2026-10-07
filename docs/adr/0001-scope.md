# ADR 0001: agent-gate is a thin enforcement host

Status: proposed
Date: 2026-10-07

## Context

An earlier enforcement engine does three things Loomground repos cannot: intercept every tool call,
know which session acted, and lock and seal folders. It also carries its own policy engine, per-folder policy loading
and a console. Felix ruled on 2026-09-27 that it is too complicated to carry
the music policy and the swarm desk.

Meanwhile a2a-compliance (E0 to E5, merged 2026-09-16) provides admission,
signed single-use permits, mediated execution, reconciliation and
certification. It deliberately owns no host effects. Its `mediated` grade
requires a host that attests no alternate path to the tool, and no such host
exists yet.

Loomground cannot fill the gap. `repo-standards/topology.md` makes it the base,
and a base that blocks tool calls or seals folders would own host effects.

## Decision

Build a new repo, `agent-gate`, in the governance plane. It contains:

1. **Gate.** `PreToolUse` hook and MCP proxy. Each call becomes an a2a
   `ControlRequest`. The call proceeds only through `consume_and_execute` with a
   permit whose action digest matches the actual tool and arguments. No permit
   means hold, not allow.
2. **Identity.** Session binding ported from the earlier engine (session id join, process
   start-time bind). The permit's actor must equal the bound session.
3. **Locks and seals.** Egress lock and at-rest seal on folders, ported from
   the earlier engine's privacy lock. A folder is a scope coordinate and a sealable thing,
   never a container with its own policy.

Three jobs, nothing more. The record of what the gate saw is not a fourth
component: each gated call, refusals included, is written as an a2a
`ToolReceipt` linked by `prev_digest` and checked with a2a's `verify_chain`.
agent-gate owns no chain format.

It contains no policy engine, no policy files, no grounding and no UI. Policy
questions go to Loomground `policy_check` and a2a `admit`. It publishes its
grade through a2a's `Profile` and must pass `run_conformance` with its own
`ExecutorPort` before claiming `mediated`.

## Dependency direction

`agent-gate → a2a-compliance → Loomground`. Nothing in Loomground or
a2a-compliance depends on agent-gate. ctrl may call it.

## Consequences

- a2a's `mediated` grade becomes reachable on a real host.
- The earlier engine overlaps with agent-gate. Retiring or shrinking it is a
  separate decision for its owner, not taken here.
- Porting identity and lock code from the earlier engine needs its owner's agreement.
- Enforcement is still only as strong as the host. Host hooks can be
  disabled by the user, so the honest default grade is `advisory` until the
  gate owns the maker's only credential or transport.

## Open questions

1. Hook mode: block (`deny` on missing permit) or monitor first.
2. Who signs gate receipts: a host key held by agent-gate, or evidence-emitter's signer port.
3. Whether the swarm desk reads presence from agent-gate instead of the earlier engine.
4. Licence and visibility (private for now).
