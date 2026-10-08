from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Optional, Sequence

from ..identity import agent_keys
from ..ops import backup as backup_ops
from ..records import chain_receipt


def _passphrase(args: argparse.Namespace) -> str:
    if getattr(args, "passphrase", None):
        return args.passphrase
    env = os.environ.get("AGENT_GATE_PASSPHRASE")
    if env:
        return env
    return getpass.getpass("passphrase: ")


def _cmd_seal(args: argparse.Namespace) -> int:
    from loomground_lock.seal import SealError, seal_folder
    try:
        result = seal_folder(args.folder, passphrase=_passphrase(args), log_root=args.log_root)
    except SealError as exc:
        print(f"seal failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


def _cmd_unseal(args: argparse.Namespace) -> int:
    from loomground_lock.seal import SealError, unseal_folder
    try:
        result = unseal_folder(args.folder, passphrase=_passphrase(args), log_root=args.log_root)
    except SealError as exc:
        print(f"unseal failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


def _cmd_audit_tail(args: argparse.Namespace) -> int:
    chain = backup_ops.JsonlChain(args.chain_file)
    trust_store = agent_keys.AgentKeyTrustStore(root=args.keys_root) if args.keys_root else None
    receipts = chain_receipt.verified_receipts(chain, trust_store=trust_store)
    if not receipts and chain.all():
        print("audit tail failed: chain does not verify", file=sys.stderr)
        return 1
    for receipt in receipts[len(receipts) - max(args.n, 0):]:
        print(json.dumps(receipt))
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    from ..host import home as host_home
    try:
        print(json.dumps(host_home.init_home()))
    except host_home.HostKeyRevoked as exc:
        print(f"init failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    from ..host import home as host_home
    status = host_home.home_status()
    print(json.dumps(status))
    if not status["initialized"] or not status["key_live"]:
        return 1
    if os.path.exists(status["chain_path"]) and not status["chain_verified"]:
        return 1
    return 0


def _cmd_keys_list(args: argparse.Namespace) -> int:
    recs = agent_keys.list_agent_keys(agent=args.agent, include_dead=args.include_dead, root=args.root)
    for rec in recs:
        print(json.dumps(rec))
    return 0


def _cmd_keys_add(args: argparse.Namespace) -> int:
    with open(args.pem_file, encoding="utf-8") as fh:
        pem = fh.read()
    try:
        rec = agent_keys.register_agent_key(
            args.agent, pem,
            expires=args.expires,
            object_types=args.object_types,
            roles=args.roles,
            root=args.root,
        )
    except ValueError as exc:
        print(f"keys add failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(rec))
    return 0


def _cmd_keys_revoke(args: argparse.Namespace) -> int:
    ok = agent_keys.revoke_agent_key(args.keyid, root=args.root)
    if not ok:
        print(f"no such key: {args.keyid}", file=sys.stderr)
        return 1
    print(json.dumps({"revoked": True, "keyid": args.keyid}))
    return 0


def _cmd_backup(args: argparse.Namespace) -> int:
    chain = backup_ops.JsonlChain(args.chain_file)
    try:
        result = backup_ops.create_backup(
            args.out_path, passphrase=_passphrase(args), chain=chain,
            keys_root=args.keys_root, backup_id=args.backup_id,
        )
    except backup_ops.BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    chain = backup_ops.JsonlChain(args.chain_file)
    try:
        result = backup_ops.restore_backup(
            args.in_path, passphrase=_passphrase(args), chain=chain, keys_root=args.keys_root,
        )
    except backup_ops.BackupError as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-gate", description="agent-gate host CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create the host key under AGENT_GATE_HOME")
    p_init.set_defaults(func=_cmd_init)

    p_status = sub.add_parser("status", help="report the AGENT_GATE_HOME state")
    p_status.set_defaults(func=_cmd_status)

    p_seal = sub.add_parser("seal", help="seal a folder's memory at rest")
    p_seal.add_argument("folder")
    p_seal.add_argument("--passphrase")
    p_seal.add_argument("--log-root")
    p_seal.set_defaults(func=_cmd_seal)

    p_unseal = sub.add_parser("unseal", help="unseal a folder's memory")
    p_unseal.add_argument("folder")
    p_unseal.add_argument("--passphrase")
    p_unseal.add_argument("--log-root")
    p_unseal.set_defaults(func=_cmd_unseal)

    p_audit = sub.add_parser("audit", help="inspect the gate's own receipt chain")
    audit_sub = p_audit.add_subparsers(dest="audit_command", required=True)
    p_tail = audit_sub.add_parser("tail", help="print the last N verified receipts")
    p_tail.add_argument("chain_file")
    p_tail.add_argument("-n", type=int, default=10)
    p_tail.add_argument("--keys-root")
    p_tail.set_defaults(func=_cmd_audit_tail)

    p_keys = sub.add_parser("keys", help="manage agent identity keys")
    keys_sub = p_keys.add_subparsers(dest="keys_command", required=True)

    p_keys_list = keys_sub.add_parser("list")
    p_keys_list.add_argument("--agent")
    p_keys_list.add_argument("--include-dead", action="store_true")
    p_keys_list.add_argument("--root")
    p_keys_list.set_defaults(func=_cmd_keys_list)

    p_keys_add = keys_sub.add_parser("add")
    p_keys_add.add_argument("agent")
    p_keys_add.add_argument("pem_file")
    p_keys_add.add_argument("--expires", type=float)
    p_keys_add.add_argument("--object-types", nargs="*", default=None)
    p_keys_add.add_argument("--roles", nargs="*", default=None)
    p_keys_add.add_argument("--root")
    p_keys_add.set_defaults(func=_cmd_keys_add)

    p_keys_revoke = keys_sub.add_parser("revoke")
    p_keys_revoke.add_argument("keyid")
    p_keys_revoke.add_argument("--root")
    p_keys_revoke.set_defaults(func=_cmd_keys_revoke)

    p_backup = sub.add_parser("backup", help="back up keys + the receipt chain")
    p_backup.add_argument("out_path")
    p_backup.add_argument("--chain-file", required=True)
    p_backup.add_argument("--keys-root")
    p_backup.add_argument("--backup-id")
    p_backup.add_argument("--passphrase")
    p_backup.set_defaults(func=_cmd_backup)

    p_restore = sub.add_parser("restore", help="restore keys + the receipt chain")
    p_restore.add_argument("in_path")
    p_restore.add_argument("--chain-file", required=True)
    p_restore.add_argument("--keys-root")
    p_restore.add_argument("--passphrase")
    p_restore.set_defaults(func=_cmd_restore)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


__all__ = ["main"]
