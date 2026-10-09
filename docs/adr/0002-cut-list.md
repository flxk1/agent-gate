# ADR 0002: what agent-gate takes from the earlier engine

Status: accepted (Felix, 2026-10-07)
Date: 2026-10-07
Supersedes the three-job scope of ADR 0001: agent-gate takes everything the
earlier enforcement engine does that the Loomground family and a2a-compliance do not.

Source: a read-only inventory of the earlier engine's server package (220 modules, ~64k
LOC), each module checked against loomground-repos, a2a-compliance,
policy-compiler, privacy-shield, evidence-emitter and oversight-ladder.
Inventory tables are kept outside the repo.

## Depend, do not port

Already extracted into family packages, which the earlier engine itself never imports:

| Earlier module | Package |
|---|---|
| signing, mutation_log, audit_drop, witness_escape | loomground-audit-chain |
| seal, seal_binding, lock_classify, lock/ core | loomground-lock |
| erasure, pending_erase, forgotten_subjects, redaction | loomground-erasure |
| breaker, drift_monitor | loomground-drift |
| folder_context, _storage_paths | loomground-workspace |
| governance_lane, lane_capabilities | loomground-lane |
| approvals, admission, permits, execution | a2a-compliance wire |

## A. Port (host jobs)

| Area | Modules |
|---|---|
| Gate | hook (minus multi-workspace resolution), verdict, context_resolve (as scope coordinate only) |
| Identity | connected_agents, governance_live (session join), agent_keys, web_bot_auth, session_capability, session_admission (token re-check), principal (request part), parties, party_resolver, subject |
| Locks and egress | lock/egress_proxy (minus scanning), track_broker, broker_probe, connectors (as credential source), lock_wiring, disclosure |
| Human gate | review_card, card_gate, card_store (re-keyed on subject) |
| Records | oversight_log, oversight_dispatch, governance_cert (minting), web_capture, llm_capture, ingest_quarantine |
| Host settings | policy.py host part (air-gap, cost cap, opt-out with acknowledgement), re-keyed on subject; published_policy_pack (fail-closed import) |
| Ops | guardian_watch counters, backup, cli |

## B. Rewrite as thin glue, do not port

governance (`decide_action`), govern, oversight, operations: the earlier engine's
policy engine. Replaced by one call path: loomground-drift breaker, then
`policy_check`, then a2a `admit` / `issue_permit` / `consume_and_execute`.

## C. Model routing: optional extra

cascade, cascade_binding (re-keyed on subject), local_llm, model_capability,
models_registry (~1.8k LOC) port as `agent-gate[models]`. The core gate never
imports it.

## D. Reporting: conformity only

conformity (clause-keyed projections over the signed log) ports. calibration,
discipline, lens, lens_service and mirror_editor are dropped.

## E. Grounding gaps: hand-off

39 modules, ~9.3k LOC, that exist only in the earlier engine but are grounding work
(grounder, legal_corpus, legal_kg, xml_legal, use_case_nd, matcher,
oversight_extractor, national_citations, urn, ...). By topology they belong
in Loomground repos, not in a host adapter. They go to the owner sessions as a
per-repo hand-off; agent-gate does not touch loomground-repos.

## Drop

~80 modules: per-folder policy and workspace fiction, the monolithic MCP
server, console and graph projections, chat and intent routing, workflow
runner, `_quarantine/`, dead adapters.
