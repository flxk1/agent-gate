from __future__ import annotations

import pytest

from agent_gate.host import settings
from agent_gate.subject import agent as agent_subject
from agent_gate.subject import global_subject, session as session_subject


def test_lock_opt_out_without_acknowledgement_is_refused(tmp_path):
    subject = agent_subject("agent-1")
    with pytest.raises(settings.SettingsError):
        settings.set_lock_opt_out(subject, True, root=str(tmp_path))
    with pytest.raises(settings.SettingsError):
        settings.set_lock_opt_out(subject, True, acknowledged_by="felix", root=str(tmp_path))
    with pytest.raises(settings.SettingsError):
        settings.set_lock_opt_out(subject, True, rationale="because", root=str(tmp_path))


def test_lock_opt_out_with_acknowledgement_is_recorded(tmp_path):
    subject = agent_subject("agent-1")
    settings.set_lock_opt_out(
        subject, True, acknowledged_by="felix", rationale="pilot deployment", root=str(tmp_path))
    got = settings.get_settings(subject, root=str(tmp_path))
    assert got.lock_opt_out is True
    assert got.lock_opt_out_ack["by"] == "felix"
    assert got.lock_opt_out_ack["rationale"] == "pilot deployment"


def test_oversight_opt_out_without_acknowledgement_is_refused(tmp_path):
    subject = agent_subject("agent-2")
    with pytest.raises(settings.SettingsError):
        settings.set_oversight_opt_out(subject, True, root=str(tmp_path))


def test_oversight_opt_out_with_acknowledgement_is_recorded(tmp_path):
    subject = agent_subject("agent-2")
    settings.set_oversight_opt_out(
        subject, True, acknowledged_by="felix", rationale="pilot", root=str(tmp_path))
    got = settings.get_settings(subject, root=str(tmp_path))
    assert got.oversight_opt_out is True
    assert got.oversight_opt_out_ack["by"] == "felix"


def test_opt_out_off_clears_acknowledgement_and_never_needs_one(tmp_path):
    subject = agent_subject("agent-3")
    settings.set_lock_opt_out(
        subject, True, acknowledged_by="felix", rationale="pilot", root=str(tmp_path))
    settings.set_lock_opt_out(subject, False, root=str(tmp_path))
    got = settings.get_settings(subject, root=str(tmp_path))
    assert got.lock_opt_out is False
    assert got.lock_opt_out_ack is None


def test_settings_are_keyed_on_subject_not_folder(tmp_path):
    a1 = agent_subject("agent-1")
    a2 = agent_subject("agent-2")
    settings.set_air_gap(a1, True, root=str(tmp_path))
    assert settings.get_settings(a1, root=str(tmp_path)).air_gapped is True
    assert settings.get_settings(a2, root=str(tmp_path)).air_gapped is False

    sess = session_subject("sess-1")
    settings.set_cost_cap(sess, 5.0, root=str(tmp_path))
    assert settings.get_settings(sess, root=str(tmp_path)).cost_cap_usd == 5.0

    glob = global_subject()
    settings.set_cost_cap(glob, 1.0, root=str(tmp_path))
    assert settings.get_settings(glob, root=str(tmp_path)).cost_cap_usd == 1.0
    assert settings.get_settings(sess, root=str(tmp_path)).cost_cap_usd == 5.0


def test_no_folder_parameter_on_any_host_settings_function():
    import inspect
    for name, fn in vars(settings).items():
        if not inspect.isfunction(fn):
            continue
        params = inspect.signature(fn).parameters
        assert "folder" not in params, f"{name} takes a folder argument"


def test_negative_cost_cap_is_rejected(tmp_path):
    subject = agent_subject("agent-4")
    with pytest.raises(settings.SettingsError):
        settings.set_cost_cap(subject, -1.0, root=str(tmp_path))
