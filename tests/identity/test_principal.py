from agent_gate.identity import principal as pr


def teardown_function(_fn):
    pr.clear_request_principal()


def test_no_principal_is_a_noop():
    assert pr.get_request_principal() is None
    assert pr.apply_principal_to_params(None, {}) is None


def test_resolved_principal_injects_actor():
    pr.set_request_principal("alice", "agent:alice")
    params = {}

    def fn(actor=None):
        return actor

    assert pr.apply_principal_to_params(fn, params) is None
    assert params["actor"] == "agent:alice"


def test_unresolved_principal_refuses_folder_addressed_call():
    pr.set_request_principal("mallory", None)
    result = pr.apply_principal_to_params(None, {"folder_context": "/x"})
    assert result is not None
    assert result["ok"] is False


def test_unresolved_principal_refuses_actor_accepting_call():
    pr.set_request_principal("mallory", None)

    def fn(actor=None):
        return actor

    result = pr.apply_principal_to_params(fn, {})
    assert result is not None
    assert result["ok"] is False


def test_remote_storage_root_override_refused():
    pr.set_request_principal("alice", "agent:alice")
    result = pr.apply_principal_to_params(None, {"log_root": "/tmp/evil"})
    assert result is not None
    assert result["refused_params"] == ["log_root"]
