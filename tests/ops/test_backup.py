from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a2a_compliance.wire.chain import verify_chain

from agent_gate.identity import agent_keys
from agent_gate.ops import backup as backup_ops
from agent_gate.records import chain_receipt


def _pem():
    pk = Ed25519PrivateKey.generate()
    return pk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def test_backup_restore_round_trips_keys_and_chain(tmp_path, chain, issuer):
    keys_root = tmp_path / "keys"
    agent_keys.register_agent_key("agent-1", _pem(), root=str(keys_root))
    for i in range(3):
        chain_receipt.build_record(
            signer=issuer, chain=chain, tool="Bash", payload={"i": i},
            executor_id="actor-1", executor_role="agent",
        )

    out = tmp_path / "backup.enc"
    created = backup_ops.create_backup(str(out), passphrase="s3cret", chain=chain, keys_root=str(keys_root))
    assert created["keys"] == 1
    assert created["chain"] == 3

    restored_chain = backup_ops.JsonlChain(str(tmp_path / "restored_chain.jsonl"))
    restored_keys_root = tmp_path / "keys_restored"
    restored = backup_ops.restore_backup(
        str(out), passphrase="s3cret", chain=restored_chain, keys_root=str(restored_keys_root))
    assert restored["keys"] == 1
    assert restored["chain"] == 3

    receipts = chain_receipt.receipts(restored_chain)
    result = verify_chain(receipts, "ToolReceipt")
    assert result.ok, result.errors

    restored_keys = agent_keys.list_agent_keys(root=str(restored_keys_root), include_dead=True)
    assert len(restored_keys) == 1
    assert restored_keys[0]["agent"] == "agent-1"


def test_restore_with_wrong_passphrase_fails_closed(tmp_path, chain, issuer):
    chain_receipt.build_record(
        signer=issuer, chain=chain, tool="Bash", payload={},
        executor_id="actor-1", executor_role="agent")
    out = tmp_path / "backup.enc"
    backup_ops.create_backup(str(out), passphrase="right", chain=chain)

    restored_chain = backup_ops.JsonlChain(str(tmp_path / "restored.jsonl"))
    with pytest.raises(backup_ops.BackupError):
        backup_ops.restore_backup(str(out), passphrase="wrong", chain=restored_chain)


def test_restore_refuses_a_non_empty_chain(tmp_path, chain, issuer):
    chain_receipt.build_record(
        signer=issuer, chain=chain, tool="Bash", payload={},
        executor_id="actor-1", executor_role="agent")
    out = tmp_path / "backup.enc"
    backup_ops.create_backup(str(out), passphrase="s3cret", chain=chain)

    nonempty = backup_ops.JsonlChain(str(tmp_path / "nonempty.jsonl"))
    nonempty.append({"not": "empty"})
    with pytest.raises(backup_ops.BackupError):
        backup_ops.restore_backup(str(out), passphrase="s3cret", chain=nonempty)


def test_create_backup_requires_a_passphrase(chain):
    with pytest.raises(backup_ops.BackupError):
        backup_ops.create_backup("/tmp/unused.enc", passphrase="", chain=chain)


def test_jsonl_chain_tail_and_all_round_trip(tmp_path):
    store = backup_ops.JsonlChain(str(tmp_path / "chain.jsonl"))
    assert store.tail() is None
    assert store.all() == []
    store.append({"a": 1})
    store.append({"a": 2})
    assert store.tail() == {"a": 2}
    assert store.all() == [{"a": 1}, {"a": 2}]


def _link_worker(path: str, n: int) -> None:
    import json as _json

    from a2a_compliance.wire import canonical as _canonical

    store = backup_ops.JsonlChain(path)
    with store.lock_for_append():
        last = store.tail()
        prev = _canonical.subject_digest(last) if last else None
        rec = {"i": n}
        if prev:
            rec["prev_digest"] = prev
        store.append(rec)


def test_jsonl_chain_lock_for_append_links_across_two_processes(tmp_path):
    import multiprocessing

    path = str(tmp_path / "linked.jsonl")
    p1 = multiprocessing.Process(target=_link_worker, args=(path, 1))
    p2 = multiprocessing.Process(target=_link_worker, args=(path, 2))
    p1.start()
    p2.start()
    p1.join()
    p2.join()

    from a2a_compliance.wire import canonical

    records = backup_ops.JsonlChain(path).all()
    assert len(records) == 2
    assert "prev_digest" not in records[0] or records[0]["prev_digest"] is None
    second = records[1]
    first_digest = canonical.subject_digest(records[0])
    assert second.get("prev_digest") == first_digest


def test_concurrent_signed_appends_form_one_verifiable_chain(tmp_path):
    import os
    import subprocess
    import sys
    from agent_gate.host.home import init_home
    from agent_gate.identity.agent_keys import AgentKeyTrustStore
    from agent_gate.records import chain_receipt

    info = init_home(tmp_path)
    code = (
        "import sys; from agent_gate.host.home import host_issuer, chain_path; "
        "from agent_gate.ops.backup import JsonlChain; from agent_gate.records import chain_receipt; "
        f"root={str(tmp_path)!r}; c=JsonlChain(chain_path(root)); s=host_issuer(root); "
        "[chain_receipt.build_record(signer=s, chain=c, tool='t', payload={'w': sys.argv[1], 'i': i}, "
        "executor_id='w', executor_role='system') for i in range(15)]"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    procs = [subprocess.Popen([sys.executable, "-c", code, str(w)], env=env) for w in range(6)]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    chain = backup_ops.JsonlChain(info["chain_path"])
    assert len(chain.all()) == 90
    result = chain_receipt.verify(chain, trust_store=AgentKeyTrustStore(root=info["keys_root"]))
    assert result.ok, result.errors[:3]


def test_restore_never_resurrects_a_revoked_key(tmp_path):
    from agent_gate.host.home import init_home
    from agent_gate.identity import agent_keys
    info = init_home(tmp_path / "home")
    out = tmp_path / "b.enc"
    backup_ops.create_backup(str(out), passphrase="pw", chain=backup_ops.JsonlChain(tmp_path / "c.jsonl"),
                             keys_root=info["keys_root"])
    assert agent_keys.revoke_agent_key(info["key_id"], root=info["keys_root"])
    backup_ops.restore_backup(str(out), passphrase="pw", chain=backup_ops.JsonlChain(tmp_path / "r.jsonl"),
                              keys_root=info["keys_root"])
    assert agent_keys.get_agent_key(info["key_id"], root=info["keys_root"]) is None


def test_restore_skips_unsafe_key_ids(tmp_path, monkeypatch):
    manifest = {"magic": backup_ops._MAGIC, "backup_id": "b", "chain": [],
                "keys": [{"keyid": "../escape"}, {"keyid": "a/b"}]}
    monkeypatch.setattr(backup_ops, "read_manifest", lambda path, passphrase: manifest)
    keys = tmp_path / "keys"
    backup_ops.restore_backup("x", passphrase="pw", chain=backup_ops.JsonlChain(tmp_path / "c.jsonl"),
                              keys_root=str(keys))
    assert not (tmp_path / "escape.json").exists()
    assert not list(tmp_path.rglob("*.json"))
