# agent-gate

The enforcement host for agents governed by Loomground and a2a-compliance.

It does only what a plane-neutral library cannot: it sits on the host, in the
path of every action. It decides nothing about policy.

## Scope

| Job | What it does |
|---|---|
| Gate | Intercepts every tool call (the agent host's `PreToolUse` hook, MCP proxy). A call with a risk footprint is held until a verified a2a `ExecutionPermit` matches the exact tool and arguments; a call with no risk footprint is allowed without a permit (see [No risk footprint](#no-risk-footprint)). |
| Identity | Binds each agent session id to the process that owns it: the hook's first non-shell ancestor, by pid and start time, persisted in `sessions.json` under `AGENT_GATE_HOME`. A session bound to another live process is refused; a dead or recycled owner can be replaced. A permit is consumed only by the actor it names. |
| Locks and seals | Egress lock and at-rest seal on folders: protection that holds while no agent is acting. |

Records are a2a's: every gated call yields an a2a `ToolReceipt` (refusals included), chained by `prev_digest`. A call allowed for having no risk footprint is not gated and yields no receipt. agent-gate keeps no chain format of its own.

## No risk footprint

`agent_gate.gate.hook.classify` gives each call a footprint. Only `Bash`
commands matching the irreversible patterns (`rm -rf`, `git reset --hard`,
`git push --force`, `mkfs`, `dd if=`, ...) or the security patterns (`sudo`,
`chown`, `launchctl`, `curl ... | sh`, ...), shell redirects into sensitive
paths, and `Write`/`Edit`/`MultiEdit`/`NotebookEdit` on sensitive paths
(`/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/System/`, `/Library/LaunchDaemons`,
`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.claude`, `~/.config/gcloud`) carry one.

- Empty footprint: allowed (exit 0) without a permit, no receipt.
- `AGENT_GATE_HOOK_STRICT` set to `1`, `true` or `yes` (case-sensitive,
  surrounding whitespace ignored): an empty
  footprint goes through the permit path like any other call.
- Non-empty footprint, or strict: a2a admission and `consume_and_execute`.
  No permit is a hold, surfaced as the host's `ask`; a deny exits 2; any
  internal error or the `AGENT_GATE_HOOK_DEADLINE` (default 15 s) fails closed
  with exit 2.
- `AGENT_GATE_HOOK_MODE`: `monitor` (default: evaluates, appends the receipt
  to the chain under `AGENT_GATE_HOME`, never blocks, exit 0), `enforce`
  (hold, deny and fail as above), `off` (exit 0, nothing evaluated or
  recorded). Any other value behaves as `enforce`.

## Host home and policy

Each hook call is a new process; all state lives under `AGENT_GATE_HOME`
(default `~/.agent-gate`) and is shared across calls:

- `host_ed25519.key` (created once with mode 0600): the host key that signs permits and
  receipts; its public key is registered under `identity/` for
  `ExecutionPermit` and `ToolReceipt` and read back through
  `AgentKeyTrustStore`.
- `chain.jsonl`: the receipt chain, appended under a file lock and linked by
  `prev_digest` across processes.
- `sessions.json`, `nonces/`, `revocations.jsonl`: session bindings
  (written under a lock; an unreadable file fails closed), single-use permit
  nonces (`O_EXCL` marker files, one per `tool_use_id`, so a replayed tool
  call is refused) and revocations.

The hook creates the home on first use; `agent-gate init` does the same
explicitly. For a footprinted call, any error opening the home, loading
the host key or a store, or evaluating the call fails closed (exit 2 in
`enforce`, reported on stderr in `monitor`); it is never an allow.

Policy is the `.lg` patch at `AGENT_GATE_POLICY`, compiled by
policy-compiler on each call. If the variable is unset or the file is
missing or does not compile, no footprinted call is admitted: each one is
held (`ask`) in `enforce` and reported on stderr in `monitor`, and still
recorded as a refusal receipt. A policy verdict short of `permitted` is
likewise a hold; `forbidden` is never admitted.

## Plugin and CLI

The repo is an agent-host plugin (`.claude-plugin/plugin.json`): it
registers `agent-gate-hook` for `PreToolUse` and `PostToolUse` on every
tool, with no mode override, and ships the `agent-gate-setup` skill. The
`agent-gate` package must be installed so both commands are on `PATH`.
`PostToolUse` currently records nothing.

- `agent-gate init`: creates the home and host key, prints JSON with
  `root`, `key_id`, `keys_root` and `chain_path`; idempotent (same `key_id`).
- `agent-gate status`: prints the home state as JSON (`initialized`,
  `key_id`, `chain_verified`, `policy_loaded`, `mode`, ...); exits non-zero
  when the home is not initialised, the host key is revoked, or the chain
  exists and does not verify.
- `agent-gate audit tail CHAIN --keys-root DIR -n N`: prints the last `N`
  verified receipts; `-n 0` prints nothing. Exits 1 if the chain does not
  verify.
- `seal`, `unseal`, `keys`, `backup`, `restore`: folder seals, agent keys
  and encrypted backups of keys and chain.

## Not in scope

- Policy authoring, norm extraction, grounding: Loomground (`policy_compile`, `policy_check`, versum).
- Admission, permits, reconciliation, certification: a2a-compliance (`admit`, `issue_permit`, `consume_and_execute`, `certify`).
- Fleet coordination and steering: ctrl.

agent-gate implements a2a-compliance's `ExecutorPort`. It publishes the a2a
grade `advisory` (`agent_gate.gate.profile`); `mediated` needs a host that
attests no alternate path to the tool, which a host hook alone cannot.

## Status

Implemented, unreleased (0.1.0). Gate, identity, locks and seals, cards,
records, conformity, ops, host CLI, plugin packaging and the model cascade
are in the tree. See
[docs/adr/0001-scope.md](docs/adr/0001-scope.md) and
[docs/adr/0002-cut-list.md](docs/adr/0002-cut-list.md).

Records are only read through a verified chain: without a trust store, or
with any signature, link or payload digest failing, readers return nothing
and the rate, loop and budget guards trip.

Known limits of the chain:

- Removing the last entries is not detected: nothing outside the chain
  anchors its head.
- A bare receipt counts as the gate's own when its signed `executor.id`
  starts with `agent-gate:`. Any key trusted for `ToolReceipt` can sign one,
  so register only keys you trust to write gate records.
- A process killed while creating the host key can leave a 0600 temporary
  key file (`.host_ed25519.key.*`) in the home; it is never used.

Gate receipts name the session in their signed `executor.id`:
`agent-gate:gate:<session>` and `agent-gate:host:<session>` for calls of a
session bound to the caller, `agent-gate:refused:<session>` for calls whose
session is unbound or owned by another process. The rate, loop and budget
guards count only the first two, so a refused takeover never counts against
the session it named.

A revoked host key stays revoked and stops signing at once, also in a
long-running process such as the egress proxy: the signer re-checks the key
before every signature. The hook fails closed, `agent-gate init` and
`agent-gate status` exit 1, `restore` never overwrites an existing key
record, and an egress policy check that errors refuses the request.

## Dependencies

First-party dependencies are pinned to exact commits, except the optional
`certification` extra, which is pinned to the governance-certification
`v0.2.0` tag:

| Package | Commit | Ref |
|---|---|---|
| a2a-compliance (`schema`, `crypto` extras) | `914bef25bafbebdc8d255a64392f1c72a35aa894` | `main`, after v0.4.0 |
| policy-compiler | `d14e9a859661421738c3e0c8d2d79ae1941fbc2f` | policy-compiler-v0.3.0 |
| loomground-audit-chain | `d70323c1664be4fba6e96f5d2e49251b63cb89d0` | `main`, after loomground-audit-chain-v0.1.0 |
| loomground-lock | `f99e24b79278f42c7fcfdf5394bb6aea8173a91f` | loomground-lock-v0.2.0 |
| loomground-drift | `e8279ec38255f278b978752fc13dffb51acfd448` | loomground-drift-v0.2.0 |
| loomground-lane | `9bac236ed7034b6183470e2a49137fde477d9b59` | loomground-lane-v0.1.0 |
| loomground-vertical | `0de4fb4aa03399bc6799be0bf23c2bcbe9bc56e6` | v0.1.0 |
| loomground-workspace | `b022d61f7c5e5d3dae85cf037f09ec4d446a3eb7` | v0.1.0 |
| loomground-governance | `82c7613e4a2247218a7281dd99933ed7c9e31218` | loomground-governance-v0.11.1 |
| loomground-erasure (`erasure` extra) | `df098be5815e5dc418d36d397a8d9b24697279e7` | loomground-erasure-v0.1.0 |
| governance-certification (`certification` extra) | none (tag pin) | tag `v0.2.0` |

a2a-compliance v0.4.0 has no `wire.admission`, `wire.executor` or
`wire.conformance_kit`, which the gate imports, so it is pinned to that `main`
commit. loomground-audit-chain v0.1.0 lacks `mutation_log.LOG_ROOT_ENV`, so it
is pinned to the later `main` commit. loomground-workspace and
loomground-governance are not imported directly; they are pinned because the
siblings require them and they are not on an index. The optional
`governance_certification` import in `records/cert.py` falls back to a local
re-check when the `certification` extra is absent.

## Licence

AGPL-3.0-only; see [NOTICE](NOTICE).
