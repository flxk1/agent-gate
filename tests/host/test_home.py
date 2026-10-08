from __future__ import annotations

import os
import stat

import pytest

from agent_gate.host import home


def test_init_home_creates_root_and_key(tmp_path):
    root = tmp_path / "ag-home"
    info = home.init_home(root=str(root))
    assert root.exists()
    kp = root / home.KEY_FILE
    assert kp.exists()
    mode = stat.S_IMODE(os.stat(kp).st_mode)
    assert mode == 0o600
    assert info["key_id"]


def test_init_home_registers_public_key_with_object_types(tmp_path):
    root = tmp_path / "ag-home"
    info = home.init_home(root=str(root))
    from agent_gate.identity import agent_keys

    rec = agent_keys.get_agent_key(info["key_id"], root=info["keys_root"])
    assert rec is not None
    assert set(rec["object_types"]) == {"ExecutionPermit", "ToolReceipt"}


def test_init_home_is_idempotent_key_id_unchanged(tmp_path):
    root = tmp_path / "ag-home"
    first = home.init_home(root=str(root))
    private_bytes_1 = (root / home.KEY_FILE).read_bytes()
    second = home.init_home(root=str(root))
    private_bytes_2 = (root / home.KEY_FILE).read_bytes()
    assert first["key_id"] == second["key_id"]
    assert private_bytes_1 == private_bytes_2


def test_init_home_never_rotates_existing_key_even_if_registry_wiped(tmp_path):
    root = tmp_path / "ag-home"
    first = home.init_home(root=str(root))
    private_bytes_before = (root / home.KEY_FILE).read_bytes()
    import shutil

    shutil.rmtree(first["keys_root"])
    second = home.init_home(root=str(root))
    private_bytes_after = (root / home.KEY_FILE).read_bytes()
    assert private_bytes_before == private_bytes_after
    assert first["key_id"] == second["key_id"]


def test_host_issuer_signs_with_the_persisted_key(tmp_path):
    root = tmp_path / "ag-home"
    info = home.init_home(root=str(root))
    issuer = home.host_issuer(root=str(root))
    assert issuer.key_id == info["key_id"]
    subject = {"a": 1}
    sig = issuer.sign(subject)
    assert isinstance(sig, str) and sig

    from agent_gate.identity.agent_keys import AgentKeyTrustStore
    from a2a_compliance.wire.signing import verify_signature

    trust_store = AgentKeyTrustStore(root=info["keys_root"])
    binding = trust_store.resolve(issuer.key_id)
    assert binding is not None
    errors = verify_signature({**subject, "signature": sig}, binding.public_key)
    assert errors == []


def test_host_issuer_without_init_raises(tmp_path):
    root = tmp_path / "ag-home-never-initialized"
    import pytest

    with pytest.raises(RuntimeError):
        home.host_issuer(root=str(root))


def test_home_root_honors_env(tmp_path, monkeypatch):
    monkeypatch.setenv(home.HOME_ENV, str(tmp_path / "via-env"))
    assert home.home_root() == tmp_path / "via-env"


def test_home_root_default_override_wins_over_env(tmp_path, monkeypatch):
    monkeypatch.setenv(home.HOME_ENV, str(tmp_path / "via-env"))
    assert home.home_root(tmp_path / "explicit") == tmp_path / "explicit"


def test_home_status_shape(tmp_path):
    root = tmp_path / "ag-home"
    info = home.init_home(root=str(root))
    status = home.home_status(root=str(root))
    for key in ("root", "initialized", "key_id", "keys_root", "chain_path",
               "policy_path", "policy_loaded", "chain_verified", "mode"):
        assert key in status
    assert status["initialized"] is True
    assert status["key_id"] == info["key_id"]


def test_home_status_not_initialized(tmp_path):
    root = tmp_path / "ag-home-fresh"
    status = home.home_status(root=str(root))
    assert status["initialized"] is False
    assert status["key_id"] is None


def test_init_home_unreadable_root_fails_closed(tmp_path):
    import pytest

    root = tmp_path / "locked"
    root.mkdir()
    os.chmod(root, 0o000)
    try:
        with pytest.raises(Exception):
            home.init_home(root=str(root / "home"))
    finally:
        os.chmod(root, 0o700)


def test_host_issuer_unreadable_key_fails_closed(tmp_path):
    import pytest

    root = tmp_path / "ag-home"
    home.init_home(root=str(root))
    kp = root / home.KEY_FILE
    os.chmod(kp, 0o000)
    try:
        with pytest.raises(Exception):
            home.host_issuer(root=str(root))
    finally:
        os.chmod(kp, 0o600)


def test_concurrent_init_converges_on_one_key(tmp_path):
    import subprocess
    import sys
    import time
    from agent_gate.host.home import init_home
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    for rnd in range(3):
        root = tmp_path / f"r{rnd}"
        t0 = time.time() + 1.5
        code = ("import time; from agent_gate.host.home import init_home; "
                f"time.sleep(max(0.0, {t0} - time.time())); "
                f"print(init_home({str(root)!r})['key_id'])")
        procs = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, env=env)
                 for _ in range(16)]
        ids = {p.communicate(timeout=60)[0].strip() for p in procs}
        assert len(ids) == 1 and "" not in ids, (rnd, ids)
        assert init_home(root)["key_id"] in ids


def test_a_revoked_host_key_is_never_re_registered(tmp_path):
    from agent_gate.host.home import HostKeyRevoked, init_home
    from agent_gate.identity import agent_keys
    info = init_home(tmp_path)
    assert agent_keys.revoke_agent_key(info["key_id"], root=info["keys_root"])
    with pytest.raises(HostKeyRevoked):
        init_home(tmp_path)
    assert agent_keys.get_agent_key(info["key_id"], root=info["keys_root"]) is None


def test_a_cached_issuer_stops_signing_once_the_key_is_revoked(tmp_path):
    from agent_gate.host.home import HostKeyRevoked, host_issuer, init_home
    from agent_gate.identity import agent_keys
    info = init_home(tmp_path)
    issuer = host_issuer(tmp_path)
    assert issuer.sign({"x": 1})
    assert agent_keys.revoke_agent_key(info["key_id"], root=info["keys_root"])
    with pytest.raises(HostKeyRevoked):
        issuer.sign({"x": 2})
