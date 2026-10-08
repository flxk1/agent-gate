from __future__ import annotations

from agent_gate.host import policy_load


def test_load_policy_missing_env(monkeypatch):
    monkeypatch.delenv(policy_load.POLICY_ENV, raising=False)
    result = policy_load.load_policy()
    assert result.policy is None
    assert result.loaded is False
    assert result.error


def test_load_policy_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv(policy_load.POLICY_ENV, str(tmp_path / "nope.lg"))
    result = policy_load.load_policy()
    assert result.policy is None
    assert result.loaded is False
    assert result.error


def test_load_policy_unreadable_file_fails_closed(monkeypatch, tmp_path):
    import os

    p = tmp_path / "policy.lg"
    p.write_text("felix must not delete production.\n", encoding="utf-8")
    os.chmod(p, 0o000)
    monkeypatch.setenv(policy_load.POLICY_ENV, str(p))
    try:
        result = policy_load.load_policy()
        assert result.policy is None
        assert result.loaded is False
        assert result.error
    finally:
        os.chmod(p, 0o600)


def test_load_policy_valid_file(monkeypatch, tmp_path):
    p = tmp_path / "policy.lg"
    p.write_text("felix must not delete production.\n", encoding="utf-8")
    monkeypatch.setenv(policy_load.POLICY_ENV, str(p))
    result = policy_load.load_policy()
    assert result.loaded is True
    assert result.policy is not None
    assert result.error is None
    assert result.path == str(p)
