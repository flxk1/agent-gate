from __future__ import annotations

import ast
import pathlib

import pytest

import agent_gate
from a2a_compliance.wire import canonical
from loomground_drift.breaker import BreakerState

from agent_gate.cards import review_card as rc
from agent_gate.conformity import conformity as cf
from agent_gate.ops import guardian_watch
from agent_gate.records import chain_receipt
from agent_gate.records.llm_capture import LLMExchange, capture_llm_exchange, recorded_spend_cents
from agent_gate.records.llm_capture import IngestMode, OversightLevel

SRC = pathlib.Path(agent_gate.__file__).resolve().parent
RAW_READERS = {"entries", "payloads", "receipts"}
CHAIN_RECEIPT_FILE = "records/chain_receipt.py"

ALLOWLIST_EXACT = {
    ("ops/backup", "create_backup"),
    ("ops/backup", "restore_backup"),
    ("cli", "_cmd_audit_tail"),
}
ALLOWLIST_CLASS_PREFIX = {
    ("ops/backup", "JsonlChain"),
}


def _modname(rel: str) -> str:
    if rel.endswith("/__init__.py"):
        return rel[: -len("/__init__.py")]
    return rel[:-3]


def _qualname(stack: list[str]) -> str:
    return ".".join(stack) if stack else "<module>"


def _allowed(rel: str, qualname: str) -> bool:
    modname = _modname(rel)
    if (modname, qualname) in ALLOWLIST_EXACT:
        return True
    head = qualname.split(".")[0]
    return (modname, head) in ALLOWLIST_CLASS_PREFIX


def scan_raw_chain_reads(rel: str, source: str) -> list[tuple[str, str, int, str]]:
    offenders: list[tuple[str, str, int, str]] = []
    tree = ast.parse(source)
    stack: list[str] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack.append(node.name)
            for child in ast.iter_child_nodes(node):
                visit(child)
            stack.pop()
            return
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "all":
            offenders.append((rel, _qualname(stack), node.lineno, ".all()"))
        if (isinstance(node, ast.Attribute) and node.attr in RAW_READERS
                and isinstance(node.value, ast.Name) and node.value.id == "chain_receipt"):
            offenders.append((rel, _qualname(stack), node.lineno, f"chain_receipt.{node.attr}"))
        if isinstance(node, ast.ImportFrom) and (node.module or "").rsplit(".", 1)[-1] == "chain_receipt":
            for alias in node.names:
                if alias.name in RAW_READERS:
                    offenders.append((rel, _qualname(stack), node.lineno, f"from ... import {alias.name}"))
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return offenders


def _override(chain, issuer):
    card = rc.review_card(node_id="n1", stage="lock", what="x", why="y")
    rc.record_override(chain=chain, signer=issuer, card=card, actor="felix", field="verdict",
                       old_value="hold", new_value="deny", rationale="keep blocked")


def _forge(chain):
    entry = chain.all()[-1]
    entry["payload"]["new_value"] = "permit"
    entry["payload"]["rationale"] = "forged"
    receipt = entry["receipt"]
    d = canonical.digest_hex(entry["payload"])
    for field in ("arguments_digest", "effect_digest", "action_digest"):
        if field in receipt:
            receipt[field] = d
    receipt["subject_digest"] = canonical.subject_digest(receipt)


def test_readers_refuse_a_chain_without_trust_store(chain, issuer):
    _override(chain, issuer)
    assert chain_receipt.verify(chain).ok is False
    assert rc.overrides_for(chain) == []
    assert cf.oversight_attestation(chain)["chain_intact"] is False


@pytest.mark.parametrize("with_trust", [False, True])
def test_recomputed_digest_forgery_is_never_reported(chain, issuer, trust_store, with_trust):
    _override(chain, issuer)
    kw = {"trust_store": trust_store} if with_trust else {}
    assert len(rc.overrides_for(chain, **kw)) == (1 if with_trust else 0)
    _forge(chain)
    assert chain_receipt.verify(chain, trust_store=trust_store).ok is False
    assert rc.overrides_for(chain, **kw) == []
    assert rc.recurrence_flags(chain, threshold=1, **kw) == []
    att = cf.oversight_attestation(chain, **kw)
    assert att["chain_intact"] is False
    assert "forged" not in repr(att)


@pytest.mark.parametrize("kind", ["rate", "loop", "budget"])
def test_guards_trip_on_an_unverifiable_chain(chain, issuer, running_breaker, trust_store, kind):
    chain_receipt.build_record(signer=issuer, chain=chain, tool="Bash", payload={"cost_usd": 0.0},
                               executor_id="actor-1", executor_role="agent")
    chain.all()[-1]["payload"]["cost_usd"] = -1000.0
    rule = guardian_watch.WatchRule("g", kind, 1000.0, window_seconds=3600)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.QUARANTINED


def test_guards_trip_without_trust_store(chain, issuer, running_breaker):
    chain_receipt.build_record(signer=issuer, chain=chain, tool="Bash", payload={"cost_usd": 0.0},
                               executor_id="actor-1", executor_role="agent")
    rule = guardian_watch.WatchRule("g", "budget", 1000.0)
    assert guardian_watch.watch(chain, "actor-1", running_breaker, [rule]).state is BreakerState.QUARANTINED


def test_spend_is_unbounded_on_an_unverifiable_chain(chain, issuer, trust_store):
    capture_llm_exchange(LLMExchange(model="m", prompt_context="p", response="r", cost_estimate_cents=5.0),
                         mode=IngestMode.AGENTIC, oversight=OversightLevel.APPROVE, chain=chain, signer=issuer)
    assert recorded_spend_cents(chain, trust_store=trust_store) == 5.0
    assert recorded_spend_cents(chain) == float("inf")
    chain.all()[-1]["payload"]["facets"]["cost_estimate_cents"] = 0.0
    assert recorded_spend_cents(chain, trust_store=trust_store) == float("inf")


def test_no_module_reads_the_chain_unverified():
    offenders = []
    files = list(SRC.rglob("*.py"))
    assert len(files) > 50
    for path in files:
        rel = path.relative_to(SRC).as_posix()
        if rel == CHAIN_RECEIPT_FILE:
            continue
        for rel_, qualname, lineno, what in scan_raw_chain_reads(rel, path.read_text()):
            if _allowed(rel_, qualname):
                continue
            offenders.append(f"{rel_}:{lineno} [{qualname}] {what}")
    assert offenders == []


def test_allowlist_is_exactly_the_four_named_sites():
    assert ALLOWLIST_EXACT == {
        ("ops/backup", "create_backup"),
        ("ops/backup", "restore_backup"),
        ("cli", "_cmd_audit_tail"),
    }
    assert ALLOWLIST_CLASS_PREFIX == {("ops/backup", "JsonlChain")}


def test_scanner_flags_unallowed_dot_all_call():
    src = "def handle(chain):\n    return chain.all()\n"
    offenders = scan_raw_chain_reads("identity/rogue.py", src)
    assert offenders == [("identity/rogue.py", "handle", 2, ".all()")]
    assert not _allowed("identity/rogue.py", "handle")


def test_scanner_flags_unallowed_entries_import():
    src = "from agent_gate.records.chain_receipt import entries\n"
    offenders = scan_raw_chain_reads("identity/rogue.py", src)
    assert offenders == [("identity/rogue.py", "<module>", 1, "from ... import entries")]
    assert not _allowed("identity/rogue.py", "<module>")


def test_scanner_flags_unallowed_payloads_attribute_use():
    src = "from . import chain_receipt\n\ndef f(chain):\n    return chain_receipt.payloads(chain)\n"
    offenders = scan_raw_chain_reads("identity/rogue.py", src)
    assert offenders == [("identity/rogue.py", "f", 4, "chain_receipt.payloads")]
    assert not _allowed("identity/rogue.py", "f")


def test_scanner_finds_allowlisted_site_but_allowlist_filters_it():
    src = "class JsonlChain:\n    def tail(self):\n        return self.all()\n"
    offenders = scan_raw_chain_reads("ops/backup.py", src)
    assert offenders == [("ops/backup.py", "JsonlChain.tail", 3, ".all()")]
    assert _allowed("ops/backup.py", "JsonlChain.tail")


def test_scanner_ignores_a_non_chain_all_method():
    src = "def handle(widget):\n    return widget.all()\n"
    offenders = scan_raw_chain_reads("identity/rogue.py", src)
    assert offenders == [("identity/rogue.py", "handle", 2, ".all()")]


def _hold(chain, issuer):
    chain_receipt.build_record(signer=issuer, chain=chain, tool="quarantine.hold",
                               payload={"item": "evil.pdf", "held": True},
                               executor_id="system", executor_role="system")


def test_stripping_a_record_payload_fails_verify(chain, issuer, trust_store):
    _override(chain, issuer)
    _hold(chain, issuer)
    assert chain_receipt.verify(chain, trust_store=trust_store).ok
    chain._records[1] = chain._records[1]["receipt"]
    assert chain_receipt.verify(chain, trust_store=trust_store).ok is False
    assert chain_receipt.verified_payloads(chain, trust_store=trust_store) == []


def test_build_record_refuses_the_gate_executor_prefix(chain, issuer):
    with pytest.raises(ValueError):
        chain_receipt.build_record(signer=issuer, chain=chain, tool="x", payload={},
                                   executor_id="agent-gate:gate", executor_role="gate")
    assert chain.all() == []


def test_non_dict_payload_fails_verify(chain, issuer, trust_store):
    chain_receipt.build_record(signer=issuer, chain=chain, tool="t", payload={},
                               executor_id="system", executor_role="system")
    assert chain_receipt.verify(chain, trust_store=trust_store).ok
    chain._records[0]["payload"] = ["anything"]
    assert chain_receipt.verify(chain, trust_store=trust_store).ok is False
