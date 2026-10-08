from __future__ import annotations

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pytest

from agent_gate.cli import _build_parser, main
from agent_gate.identity.agent_keys import AgentKeyTrustStore


def _pem_file(tmp_path):
    pk = Ed25519PrivateKey.generate()
    pem = pk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    path = tmp_path / "key.pem"
    path.write_text(pem)
    return path


def test_help_exits_zero(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_keys_add_list_revoke_round_trip(tmp_path, capsys):
    pem_path = _pem_file(tmp_path)
    keys_root = tmp_path / "keys"

    rc = main(["keys", "add", "agent-1", str(pem_path), "--root", str(keys_root)])
    assert rc == 0
    added = json.loads(capsys.readouterr().out.strip())
    keyid = added["keyid"]

    rc = main(["keys", "list", "--root", str(keys_root)])
    assert rc == 0
    listed = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert any(r["keyid"] == keyid for r in listed)

    store = AgentKeyTrustStore(root=str(keys_root))
    assert store.resolve(keyid) is not None

    rc = main(["keys", "revoke", "--root", str(keys_root), "--", keyid])
    assert rc == 0
    capsys.readouterr()

    assert store.resolve(keyid) is None


def test_keys_revoke_unknown_key_fails(tmp_path, capsys):
    rc = main(["keys", "revoke", "nope", "--root", str(tmp_path / "keys")])
    assert rc == 1


class _Signer:
    def __init__(self, key_id, private_bytes):
        self.identity, self.key_id, self._pk = "agent-gate:test", key_id, private_bytes

    def sign(self, obj):
        from a2a_compliance.wire.signing import dev_sign_subject
        return dev_sign_subject(obj, self._pk)


def _signed_chain(tmp_path, capsys, n=1):
    import agent_gate.ops.backup as backup_ops
    from agent_gate.records import chain_receipt
    pk = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "signer.pem"
    pem_path.write_text(pk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    keys_root = tmp_path / "keys"
    main(["keys", "add", "agent-1", str(pem_path), "--root", str(keys_root),
          "--object-types", "ToolReceipt", "--roles", "agent"])
    keyid = json.loads(capsys.readouterr().out.strip())["keyid"]
    raw = pk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    chain_file = tmp_path / "chain.jsonl"
    chain = backup_ops.JsonlChain(str(chain_file))
    for i in range(n):
        chain_receipt.build_record(
            signer=_Signer(keyid, raw), chain=chain, tool="Bash", payload={"i": i},
            executor_id="actor-1", executor_role="agent")
    return chain_file, keys_root


def test_backup_restore_and_audit_tail_round_trip(tmp_path, capsys):
    chain_file, keys_root = _signed_chain(tmp_path, capsys)
    out_path = tmp_path / "backup.enc"
    rc = main(["backup", str(out_path), "--chain-file", str(chain_file),
               "--keys-root", str(keys_root), "--passphrase", "s3cret"])
    assert rc == 0
    capsys.readouterr()

    restored_chain_file = tmp_path / "restored_chain.jsonl"
    restored_keys_root = tmp_path / "keys_restored"
    rc = main(["restore", str(out_path), "--chain-file", str(restored_chain_file),
               "--keys-root", str(restored_keys_root), "--passphrase", "s3cret"])
    assert rc == 0
    capsys.readouterr()

    rc = main(["audit", "tail", str(restored_chain_file), "-n", "5",
               "--keys-root", str(restored_keys_root)])
    assert rc == 0
    tailed = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert len(tailed) == 1
    assert tailed[0]["tool"] == "Bash"


def test_audit_tail_refuses_without_trust_store(tmp_path, capsys):
    chain_file, _keys_root = _signed_chain(tmp_path, capsys)
    rc = main(["audit", "tail", str(chain_file), "-n", "5"])
    assert rc == 1
    assert capsys.readouterr().out == ""


def test_audit_tail_refuses_tampered_payload(tmp_path, capsys):
    chain_file, keys_root = _signed_chain(tmp_path, capsys, n=3)
    lines = chain_file.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"]["i"] = 99
    lines[1] = json.dumps(rec)
    chain_file.write_text("\n".join(lines) + "\n")
    rc = main(["audit", "tail", str(chain_file), "-n", "5", "--keys-root", str(keys_root)])
    assert rc == 1
    assert capsys.readouterr().out == ""


def test_restore_wrong_passphrase_fails(tmp_path, capsys):
    chain_file = tmp_path / "chain.jsonl"
    import agent_gate.ops.backup as backup_ops
    chain = backup_ops.JsonlChain(str(chain_file))
    chain.append({"receipt": {"tool": "Bash"}, "payload": {}})
    out_path = tmp_path / "backup.enc"
    backup_ops.create_backup(str(out_path), passphrase="right", chain=chain)
    capsys.readouterr()

    rc = main(["restore", str(out_path), "--chain-file", str(tmp_path / "r2.jsonl"),
               "--passphrase", "wrong"])
    assert rc == 1


def test_restore_tampered_backup_fails(tmp_path):
    import agent_gate.ops.backup as backup_ops
    chain_file = tmp_path / "chain.jsonl"
    chain = backup_ops.JsonlChain(str(chain_file))
    chain.append({"receipt": {"tool": "Bash"}, "payload": {}})
    out_path = tmp_path / "backup.enc"
    backup_ops.create_backup(str(out_path), passphrase="right", chain=chain)

    raw = bytearray(out_path.read_bytes())
    raw[-1] ^= 0xFF
    out_path.write_bytes(bytes(raw))

    rc = main(["restore", str(out_path), "--chain-file", str(tmp_path / "r2.jsonl"),
               "--passphrase", "right"])
    assert rc == 1


def test_exact_subcommand_set():
    parser = _build_parser()
    top = parser._subparsers._group_actions[0].choices
    assert set(top) == {"init", "status", "seal", "unseal", "audit", "keys", "backup", "restore"}
    audit = top["audit"]._subparsers._group_actions[0].choices
    assert set(audit) == {"tail"}
    keys = top["keys"]._subparsers._group_actions[0].choices
    assert set(keys) == {"list", "add", "revoke"}


def test_unknown_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code != 0
