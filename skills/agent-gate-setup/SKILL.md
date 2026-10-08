---
name: agent-gate-setup
description: Set up and check the agent-gate hook — initialise the host home (key + receipt chain), report its status, and switch the hook mode between monitor, enforce and off. Use when the user says "set up agent-gate", "agent-gate init", "agent-gate status", "is the gate recording", "switch the gate to enforce", "turn the gate off", or asks where the gate keeps its keys, chain or policy.
---

# agent-gate setup

The plugin registers `agent-gate-hook` for `PreToolUse` and `PostToolUse` on
every tool. The `agent-gate` and `agent-gate-hook` commands must be on `PATH`
(install the `agent-gate` Python package).

## Environment

| Variable | Meaning | Default |
|---|---|---|
| `AGENT_GATE_HOME` | Host home: host key, key registry, session bindings, nonces, revocations, `chain.jsonl` | `~/.agent-gate` |
| `AGENT_GATE_POLICY` | Path to the `.lg` policy patch, compiled by policy-compiler | unset |
| `AGENT_GATE_HOOK_MODE` | `monitor`, `enforce` or `off` | `monitor` |

Set these in the environment the agent host is started from (or in the `env`
block of `.claude/settings.json`).

## Init

```
agent-gate init
```

Creates `AGENT_GATE_HOME` if needed, writes the host Ed25519 key (`host_ed25519.key`,
mode 0600) and registers its public key for `ExecutionPermit` and `ToolReceipt`
under `identity/`. Prints JSON with `root`, `key_id`, `keys_root` and
`chain_path`. Idempotent: a second run keeps the same key and `key_id`. The
hook also initialises the home on first use.

## Status

```
agent-gate status
```

Prints JSON: `initialized`, `key_id`, `chain_path`, `chain_verified`,
`policy_path`, `policy_loaded`, `mode`. Exits non-zero when the home is not
initialised or when the chain exists and does not verify against the host key
registry. Read the chain with `agent-gate audit tail "$AGENT_GATE_HOME/chain.jsonl"
--keys-root "$AGENT_GATE_HOME/identity" -n 20`.

## Mode

- `monitor`: every footprinted call is evaluated and its receipt appended to
  the chain; nothing is blocked, would-be holds and blocks go to stderr.
- `enforce`: a footprinted call without an admitted permit is held (the host's
  `ask`), a deny exits 2, any internal error fails closed with exit 2.
- `off`: the hook exits 0 without evaluating or recording.

## Policy

Without `AGENT_GATE_POLICY`, or with a file that is missing or does not
compile, `status` shows `policy_loaded: false` and no footprinted call is
admitted: each one is held in `enforce` and reported in `monitor`. Calls with
no risk footprint are allowed without a receipt unless `AGENT_GATE_HOOK_STRICT`
is `1`, `true` or `yes`.
